import { MachineTokenError, PERMANENT_ERROR_CODES } from "./errors";

/** The `token_use` value the provider stamps on a `client_credentials` access token. */
export const MACHINE_TOKEN_USE = "client";

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Configuration for {@link createMachineClient}. */
export interface MachineClientOptions {
  /** The provider's base URL, e.g. `https://id.wilsoon.dev`. */
  issuer: string;
  /** The client identifier registered with the provider. */
  clientId: string;
  /** The client secret. The grant is confidential-only, so a public client is refused by the provider outright. */
  clientSecret: string;
  /**
   * Fraction of the token's lifetime after which a renewal starts (default `0.75`).
   * Renewing at `exp` would hand out tokens that die in flight once clock skew and request latency are counted.
   */
  refreshAt?: number;
  /** Seconds before `exp` at which a token is already treated as expired (default `30`). */
  skewSeconds?: number;
  /** Override the token endpoint, when the provider does not mount it at `<issuer>/api/token`. */
  tokenEndpoint?: string;
  /** Injectable `fetch`, for tests and for runtimes that do not expose a global one. */
  fetch?: FetchLike;
}

/** Options for {@link MachineClient.getToken}. */
export interface GetTokenOptions {
  /** Discard the cached token and obtain a new one, even if the current one is still valid. */
  force?: boolean;
}

/** A cached machine token and the two deadlines that govern it. */
export interface MachineClient {
  /**
   * Returns a valid access token, from cache when possible.
   * Only a cold or fully expired cache makes the caller wait. Inside the refresh-ahead window, the current token is served while a renewal runs in the background.
   */
  getToken(options?: GetTokenOptions): Promise<string>;
  /**
   * Performs a request with the machine token attached as a bearer credential.
   * A 401 triggers exactly one forced refresh and one retry, never a loop.
   */
  fetch(url: string, init?: RequestInit): Promise<Response>;
  /** Drops the cached token, so the next call obtains a fresh one. */
  reset(): void;
}

interface CachedToken {
  token: string;
  /** Epoch seconds after which a renewal should start. */
  renewAt: number;
  /** Epoch seconds after which the token must not be served at all. */
  expiresAt: number;
}

/**
 * Whether a set of verified token claims describes a machine token rather than a user.
 * Recognises `token_use: "client"` and an RFC 9068 `sub` equal to `client_id`; pass claims that have already been verified, since an unverified decode reports only what the bearer chose to claim.
 */
export function isMachineToken(claims: Record<string, unknown> | null | undefined): boolean {
  if (!claims) return false;
  if (claims.token_use === MACHINE_TOKEN_USE) return true;

  // RFC 9068 §5: a client_credentials access token's `sub` SHOULD be the client id. Checking it means a provider that emits no `token_use` is still recognised, rather than every machine token quietly reading as a user.
  const subject = claims.sub;
  return typeof subject === "string" && subject.length > 0 && subject === claims.client_id;
}

/**
 * Creates a cached `client_credentials` token source for server-to-server calls.
 *
 * The grant itself is a form POST. Concurrent callers on a cold cache collapse onto one token request, renewal happens ahead of expiry rather than at it, and a rejected token is retried exactly once.
 *
 * ```ts
 * const machine = createMachineClient({
 *   issuer: "https://id.wilsoon.dev",
 *   clientId: process.env.WILSOON_CLIENT_ID!,
 *   clientSecret: process.env.WILSOON_CLIENT_SECRET!,
 * });
 * const res = await machine.fetch("https://api.wilsoon.dev/reports");
 * ```
 *
 * @throws {Error} If called in a browser, or if any credential is missing.
 */
export function createMachineClient(options: MachineClientOptions): MachineClient {
  const { issuer, clientId, clientSecret, refreshAt = 0.75, skewSeconds = 30 } = options;

  // A bundler that reaches this package has already put the secret in a file someone can read.
  if (typeof window !== "undefined") throw new Error("@wilsoon/auth-machine is server-only: it holds a client secret and must never be bundled for a browser.");
  if (!issuer || !clientId || !clientSecret) throw new Error("@wilsoon/auth-machine requires `issuer`, `clientId` and `clientSecret`.");

  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("No global `fetch` is available. Pass one as `fetch`, or run on Node.js 18 or newer.");

  const tokenUrl = options.tokenEndpoint ?? `${issuer.replace(/\/+$/, "")}/api/token`;
  const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64");

  let cached: CachedToken | null = null;
  let inflight: Promise<string> | null = null;

  const now = () => Math.floor(Date.now() / 1000);

  async function request(): Promise<CachedToken> {
    const response = await fetchImpl(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        Authorization: `Basic ${basic}`,
      },
      body: "grant_type=client_credentials",
    });

    const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;

    if (!response.ok) {
      const code = typeof body.error === "string" ? body.error : "unknown_error";
      const description = typeof body.error_description === "string" ? body.error_description : `Token request failed (${response.status}).`;
      throw new MachineTokenError(description, code, response.status, PERMANENT_ERROR_CODES.includes(code));
    }

    const token = typeof body.access_token === "string" ? body.access_token : "";
    if (!token) throw new MachineTokenError("The token endpoint returned no access token.", "invalid_response", response.status, false);

    // 900s matches the provider's default `auth_flow_duration`
    const lifetime = Number(body.expires_in) || 900;
    const issuedAt = now();

    return { token, expiresAt: issuedAt + lifetime - skewSeconds, renewAt: issuedAt + Math.floor(lifetime * refreshAt) };
  }

  function refresh(): Promise<string> {
    if (inflight) return inflight;

    const mine: Promise<string> = request()
      .then((next) => {
        cached = next;
        return next.token;
      })
      .finally(() => {
        if (inflight === mine) inflight = null;
      });

    inflight = mine;
    return mine;
  }

  async function getToken(getTokenOptions: GetTokenOptions = {}): Promise<string> {
    if (getTokenOptions.force) {
      cached = null;
      inflight = null;
      return refresh();
    }

    if (!cached || now() >= cached.expiresAt) return refresh();
    if (now() < cached.renewAt) return cached.token;

    // Inside the refresh-ahead window the cached token is still good, so serve it and renew behind the caller.
    // This renewal has no caller to report to, and the next getToken() will surface the failure itself.
    const stillValid = cached.token;
    refresh().catch(() => undefined);
    return stillValid;
  }

  return {
    getToken,
    reset() {
      cached = null;
    },
    async fetch(url: string, init: RequestInit = {}): Promise<Response> {
      const send = (token: string) =>
        fetchImpl(url, {
          ...init,
          headers: { ...(init.headers as Record<string, string> | undefined), Authorization: `Bearer ${token}` },
        });

      const response = await send(await getToken());
      if (response.status !== 401) return response;

      // Exactly one forced retry. A rotated secret or a token rejected mid-flight is worth one more attempt.
      cached = null;
      return send(await getToken({ force: true }));
    },
  };
}

export { MachineTokenError, PERMANENT_ERROR_CODES } from "./errors";

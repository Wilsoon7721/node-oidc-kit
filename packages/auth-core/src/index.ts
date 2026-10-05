import { AuthenticationChallenge, readAuthenticationChallenge } from "./challenge";
import { readClaimList } from "./claims";
import { AuthorizeDeviceOptions, DEVICE_GRANT_TYPE, DeviceAuthorization, DeviceAuthorizationOptions, DeviceGrantResult } from "./device";
import { AuthError, AuthorizationDeniedError, AuthorizationExpiredError, AuthorizationResponseError, ClaimValidationError, DeviceFlowError, DiscoveryError, IssuerMismatchError, LogoutError, MachineTokenNotAllowedError, NonceMismatchError, NotAMachineTokenError, NoTokenError, StateMismatchError, StorageUnavailableError, TokenExchangeError, TokenRefreshError, TokenVerificationError, UserInfoError } from "./errors";
import { CreateEscalationOptions, ESCALATION_TOKEN_TYPE, EscalationRequest, EscalationResult, ReauthorizeOptions, VerifiedEscalation } from "./escalation";
import { decodeTokenPayloadUnsafe, RemoteKeySet, verifyCompactJwt } from "./jwt";
import { LiveAccess, ProfileContext, ProfileExtensions, ProviderProfile } from "./profile";
import { ACCESS_DENIED, AUTHORIZATION_PENDING, EXPIRED_TOKEN, PollStep, pollUntilResolved, SLOW_DOWN } from "./polling";
import { AuthStorage, BrowserStorage, DEFAULT_STORAGE_PREFIX, isUsableStorage, StorageKeys, storageKeysFor, UnavailableStorage } from "./storage";
import { AccessTokenClaims, AuthConfig, AuthenticatedUser, AuthorizeRequest, AuthorizeUrlOptions, CallbackResult, DiscoveryDocument, HandleCallbackOptions, IntrospectionResponse, MachineClient, PlatformSessionOptions, ProfileUser, SilentAuthorizeOptions, TokenResponse, TokenUse, UnverifiedUser, VerifyAccessTokenOptions, VerifyIdTokenOptions } from "./types";
import { generateNonce, generatePKCE, generateState, normalizeIssuer, timingSafeEqual } from "./utils";

/**
 * The storage names 2.x used, which the `wilsoon()` profile keeps so nobody is signed out by the upgrade.
 * @deprecated Since 3.0.0 - names now come from `storagePrefix` or the profile. Read `client.storageKeys` for the names a client actually uses.
 */
export const STORAGE_KEYS = {
  /** The persisted token response. */
  tokens: "wilsoon_id_tokens",
  /** The pending authorization request's CSRF state. */
  state: "wilsoon_auth_state",
  /** The pending authorization request's ID token nonce. */
  nonce: "wilsoon_auth_nonce",
  /** The pending authorization request's PKCE code verifier. */
  codeVerifier: "wilsoon_auth_verifier",
} as const;

const DEFAULT_SCOPES = ["openid", "profile", "email"];
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 60;
const DEFAULT_SILENT_TIMEOUT_MS = 10_000;

/** Authorization request parameters the library controls and `extraParams` may not override. */
const RESERVED_AUTHORIZE_PARAMS = new Set(["client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"]);

/**
 * The `error` values a `prompt=none` request returns when the user would have to interact.
 * Each means "not signed in silently", not a failure.
 */
export const SILENT_AUTH_ERRORS: readonly string[] = ["login_required", "consent_required", "interaction_required", "account_selection_required"];

/** Whether an error from `handleCallback()` after a `prompt=none` request just means "not signed in". */
export function isSilentAuthError(error: unknown): boolean {
  return error instanceof AuthorizationResponseError && SILENT_AUTH_ERRORS.includes(error.error);
}

/** The fields a profile's `mapUser` may not override, because they identify the token rather than describe the user. */
const PROTECTED_USER_FIELDS = ["id", "issuer", "audience", "expiresAt", "issuedAt", "claims", "source", "nonce"] as const;

/**
 * Fallback seconds between polls, used only when the provider doesn't provide an interval
 */
const DEFAULT_POLL_INTERVAL_SECONDS = 5;

const warned = new Set<string>();
const warnOnce = (key: string, message: string) => {
  if (warned.has(key)) return;
  warned.add(key);
  if (typeof console !== "undefined") console.warn(`[node-oidc-kit] ${message}`);
};

const union = (a: readonly string[], b: readonly string[]): string[] => Array.from(new Set([...a, ...b]));

const encodeBasic = (id: string, secret: string): string => {
  const raw = `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`;
  return typeof btoa === "function" ? btoa(raw) : Buffer.from(raw).toString("base64");
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

const asString = (value: unknown): string | undefined => (typeof value === "string" && value.length > 0 ? value : undefined);

const asStringArray = (value: unknown): string[] => (Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : []);

const asNumber = (value: unknown): number | undefined => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  // Some providers serialise numeric claims as strings.
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) return Number(value);
  return undefined;
};

const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * An OIDC relying party: discovery, authorization requests, code exchange, token verification and profile lookup for one registered client.
 *
 * Framework-agnostic: it depends on `fetch`, Web Crypto and an {@link AuthStorage} adapter and nothing else - so the same client works in a browser, in Node, and on an edge runtime.
 * One rule governs everything below: authorization decisions must come from {@link AuthClient.verifyIdToken}, {@link AuthClient.verifyAccessToken} or {@link AuthClient.resolveSession}.
 * Those are the only methods that check a signature against the provider's published keys. Every `*Unsafe` method may return attacker-controlled data.
 *
 * Provider-specific behaviour comes from {@link AuthConfig.profile}. Use {@link createAuthClient} to get its extensions typed under `client.<profile name>`.
 */
export class AuthClient {
  private discoveryCache: DiscoveryDocument | null = null;
  private storage: AuthStorage;
  private keySet: RemoteKeySet;
  private refreshInFlight = new Map<string, Promise<TokenResponse>>();
  private profile?: ProviderProfile<string, object>;
  private context?: ProfileContext;
  private extensions: Record<string, unknown> = {};

  /** The names this client stores its tokens and transient values under, from `storagePrefix` or the profile. */
  public readonly storageKeys: Readonly<StorageKeys>;

  /**
   * @param storage Defaults to `localStorage` in the browser. On the server there is no
   * safe default, so storage-backed calls throw a {@link StorageUnavailableError} naming
   * the operation instead of failing later with a `TypeError` - pass an adapter.
   * @throws {AuthError} If required configuration is missing, the issuer is not a URL, or the profile's name collides with a client member.
   */
  constructor(
    private config: AuthConfig,
    storage?: AuthStorage,
  ) {
    if (!config || typeof config !== "object") throw new AuthError("AuthClient requires a configuration object.", "INVALID_CONFIG");
    if (!asString(config.clientId)) throw new AuthError("AuthClient requires a `clientId`.", "INVALID_CONFIG");
    if (!asString(config.issuer)) throw new AuthError("AuthClient requires an `issuer`.", "INVALID_CONFIG");
    // `redirectUri` is validated where it is used

    let issuerUrl: URL;
    try {
      issuerUrl = new URL(config.issuer);
    } catch {
      throw new AuthError(`AuthClient \`issuer\` must be an absolute URL, received "${config.issuer}".`, "INVALID_CONFIG");
    }
    if (issuerUrl.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(issuerUrl.hostname)) {
      warnOnce(`insecure-issuer:${config.issuer}`, `The issuer "${config.issuer}" is not HTTPS. Tokens and discovery metadata are fetched over an unauthenticated channel.`);
    }

    this.storage = storage || (typeof window !== "undefined" ? new BrowserStorage() : new UnavailableStorage());
    this.keySet = new RemoteKeySet(config.jwks);

    this.profile = config.profile;
    const prefix = config.storagePrefix ?? this.profile?.storagePrefix ?? DEFAULT_STORAGE_PREFIX;
    // An explicit `storagePrefix` is the app's own choice, so it wins over the profile's exact legacy names.
    this.storageKeys = Object.freeze({ ...storageKeysFor(prefix), ...(config.storagePrefix === undefined ? this.profile?.storageKeys : {}) });

    if (this.profile) this.attachProfile(this.profile);
  }

  /** The configured profile's name, or `undefined` when the client runs standards-only. */
  public get profileName(): string | undefined {
    return this.profile?.name;
  }

  private attachProfile(profile: ProviderProfile<string, object>): void {
    const name = asString(profile.name);
    if (!name) throw new AuthError("A provider profile needs a non-empty `name`.", "INVALID_CONFIG");
    if (name in this) throw new AuthError(`The profile name "${name}" collides with an AuthClient member. Choose another name for its namespace.`, "INVALID_CONFIG");

    const extensions = profile.extend?.(this.profileContext()) ?? {};
    this.extensions = extensions as Record<string, unknown>;
    Object.defineProperty(this, name, { value: Object.freeze({ ...extensions }), enumerable: false, configurable: false, writable: false });
  }

  /** The context handed to profile hooks, built once per client. */
  private profileContext(): ProfileContext {
    if (this.context) return this.context;

    this.context = Object.freeze({
      config: this.config,
      client: this,
      storage: this.storage,
      storageKeys: this.storageKeys,
      getEndpoints: () => this.getEndpoints(),
      clientFetch: (url: string, init: RequestInit = {}) => this.clientFetch(url, init),
      verifyJwt: async (token: string, options: { audience?: string | string[]; typ?: string } = {}) => {
        if (!asString(token)) throw new NoTokenError("No token was provided.");
        const { jwks_uri } = await this.getEndpoints();
        return (await verifyCompactJwt(this.keySet, token, {
          jwksUri: jwks_uri,
          issuer: await this.issuerCandidates(),
          audience: options.audience ?? this.config.clientId,
          clockTolerance: this.clockTolerance(),
          typ: options.typ,
        })) as Record<string, unknown>;
      },
      introspect: (token: string) => this.introspectToken(token),
      toUser: (claims: Record<string, unknown>, details: { source: "id_token" | "access_token"; audience: string }) => this.toAuthenticatedUser(claims, details),
      classifyTokenUse: (claims: Record<string, unknown>) => this.classifyTokenUse(claims),
      warnOnce,
    });
    return this.context;
  }

  /** Fetch with HTTP Basic client authentication, which keeps the secret out of the body. */
  private clientFetch(url: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers);
    const secret = asString(this.config.clientSecret);
    if (secret && !headers.has("Authorization")) headers.set("Authorization", `Basic ${encodeBasic(this.config.clientId, secret)}`);
    if (!headers.has("Accept")) headers.set("Accept", "application/json");
    return fetch(url, { ...init, headers });
  }

  /** The access token audience: the config's, else the profile's default. */
  private apiAudience(): string | undefined {
    return asString(this.config.apiAudience) ?? asString(this.profile?.apiAudience);
  }

  /**
   * Looks up a profile extension for a 2.x method that moved out of core.
   * @throws {AuthError} With code `PROFILE_REQUIRED` when no configured profile provides it.
   */
  private extension<F extends (...args: never[]) => unknown>(method: string): F {
    const fn = this.extensions[method];
    if (typeof fn !== "function") throw new AuthError(`\`${method}()\` is provider-specific and moved out of @wilsoon/auth-core in 3.0.0. ` + "Configure a provider profile that provides it, such as the WilsoonID profile.", "PROFILE_REQUIRED");

    warnOnce(`forwarder:${method}`, `client.${method}() is deprecated and will be removed in 4.0. Call client.${this.profile?.name}.${method}() on a client made with createAuthClient().`);
    return fn as F;
  }

  /** Whether this client has a usable storage implementation. */
  public hasStorage(): boolean {
    return isUsableStorage(this.storage);
  }

  /** @throws {StorageUnavailableError} If no storage implementation is available. */
  public saveTokens(tokens: TokenResponse): void {
    this.storage.setItem(this.storageKeys.tokens, JSON.stringify(tokens));
  }

  /**
   * Reads the persisted token response, or `null` if there is none or it is unusable.
   *
   * Never throws on a malformed value: a corrupt or truncated cookie should log the user out, not crash the request.
   * Also works with a URI-encoded blob which is how a provider that writes the cookie itself typically stores it.
   */
  public getStoredTokens(): TokenResponse | null {
    const raw = this.readStorage(this.storageKeys.tokens);
    if (!raw) return null;

    const parse = (value: string): TokenResponse | null => {
      try {
        const parsed = JSON.parse(value);
        return isRecord(parsed) && asString(parsed.access_token) ? (parsed as unknown as TokenResponse) : null;
      } catch {
        return null;
      }
    };

    const direct = parse(raw);
    if (direct) return direct;

    try {
      return raw.includes("%") ? parse(decodeURIComponent(raw)) : null;
    } catch {
      return null;
    }
  }

  /**
   * Removes the tokens and the transient `state`/`nonce`/verifier entries.
   * Local state only - this does not end the session at the identity provider. Use {@link AuthClient.getLogoutUrl} for that.
   */
  public clearStorage(): void {
    if (!this.hasStorage()) return;

    this.storage.removeItem(this.storageKeys.tokens);
    this.clearTransientState();
  }

  /**
   * Fetches `/.well-known/openid-configuration`, cached for the life of the client.
   *
   * @throws {DiscoveryError} If the document cannot be fetched or lacks a required endpoint.
   * @throws {IssuerMismatchError} If the advertised issuer is not the configured one.
   */
  private async getEndpoints(): Promise<DiscoveryDocument> {
    if (this.discoveryCache) return this.discoveryCache;

    const discoveryUrl = `${normalizeIssuer(this.config.issuer)}/.well-known/openid-configuration`;

    let document: unknown;
    try {
      const response = await fetch(discoveryUrl, { headers: { Accept: "application/json" } });
      if (!response.ok) throw new DiscoveryError(discoveryUrl);
      document = await response.json();
    } catch (error) {
      if (error instanceof DiscoveryError) throw error;
      throw new DiscoveryError(discoveryUrl);
    }

    if (!isRecord(document) || !asString(document.issuer) || !asString(document.authorization_endpoint) || !asString(document.token_endpoint) || !asString(document.userinfo_endpoint) || !asString(document.jwks_uri)) {
      throw new DiscoveryError(discoveryUrl);
    }

    // Guard against an issuer the application did not choose: everything downstream - token validation included - trusts these endpoints.
    if (!this.config.expectedIssuer && normalizeIssuer(document.issuer as string) !== normalizeIssuer(this.config.issuer)) {
      throw new IssuerMismatchError(this.config.issuer, document.issuer as string);
    }

    this.discoveryCache = document as unknown as DiscoveryDocument;
    return this.discoveryCache;
  }

  /** The `iss` values a token may carry, accepting an optional trailing slash. */
  private async issuerCandidates(): Promise<string[]> {
    const configured = this.config.expectedIssuer ?? (await this.getEndpoints()).issuer;
    const normalized = normalizeIssuer(configured);
    return Array.from(new Set([configured, normalized]));
  }

  private clockTolerance(): number {
    const configured = this.config.clockToleranceSeconds;
    return typeof configured === "number" && configured >= 0 ? configured : DEFAULT_CLOCK_TOLERANCE_SECONDS;
  }

  private readStorage(key: string): string | null {
    if (!this.hasStorage()) return null;
    try {
      return this.storage.getItem(key);
    } catch {
      return null;
    }
  }

  private clearTransientState(): void {
    if (!this.hasStorage()) return;
    for (const key of [this.storageKeys.state, this.storageKeys.nonce, this.storageKeys.codeVerifier]) {
      try {
        this.storage.removeItem(key);
      } catch {}
    }
  }

  /** @throws {ClaimValidationError} If the userinfo response carries no subject identifier. */
  private toProfileUser(raw: unknown): ProfileUser {
    if (!isRecord(raw)) throw new ClaimValidationError("The userinfo endpoint returned an unexpected payload.");

    const id = asString(raw.sub) ?? asString(raw.id);
    if (!id) throw new ClaimValidationError("The userinfo response is missing the `sub` claim.");

    return {
      id,
      email: asString(raw.email),
      emailVerified: typeof raw.email_verified === "boolean" ? raw.email_verified : undefined,
      name: asString(raw.name),
      picture: asString(raw.picture),
    };
  }

  /**
   * Maps claims that have already passed signature, issuer, audience and expiry checks onto {@link AuthenticatedUser}.
   * Standard claims first, then the profile's `mapUser`, then the configured `rolesClaim` / `permissionsClaim`, which win.
   *
   * @throws {ClaimValidationError} If `sub` or `exp` is missing.
   */
  private toAuthenticatedUser(claims: Record<string, unknown>, details: { source: "id_token" | "access_token"; audience: string } = { source: "id_token", audience: this.config.clientId }): AuthenticatedUser {
    const label = details.source === "id_token" ? "ID token" : "access token";

    const id = asString(claims.sub);
    if (!id) throw new ClaimValidationError(`The ${label} is missing the \`sub\` claim.`);

    const expiresAt = asNumber(claims.exp);
    if (expiresAt === undefined) throw new ClaimValidationError(`The ${label} is missing the \`exp\` claim.`);

    const frozen = Object.freeze({ ...claims });
    const base: AuthenticatedUser = {
      id,
      email: asString(claims.email),
      emailVerified: typeof claims.email_verified === "boolean" ? claims.email_verified : undefined,
      name: asString(claims.name),
      picture: asString(claims.picture),
      roles: [],
      permissions: [],
      authMethods: asStringArray(claims.amr),
      sid: asString(claims.sid),
      issuer: asString(claims.iss) ?? "",
      audience: details.audience,
      source: details.source,
      issuedAt: asNumber(claims.iat),
      expiresAt,
      authTime: asNumber(claims.auth_time),
      nonce: asString(claims.nonce),
      claims: frozen,
    };

    // Dropping `undefined` keeps a profile from blanking a standard claim it did not mean to touch.
    const extras = Object.fromEntries(Object.entries(this.profile?.mapUser?.(frozen) ?? {}).filter(([key, value]) => value !== undefined && !(PROTECTED_USER_FIELDS as readonly string[]).includes(key)));

    const user = { ...base, ...extras } as AuthenticatedUser;
    user.roles = this.config.rolesClaim ? readClaimList(frozen, this.config.rolesClaim) : asStringArray(user.roles);
    user.permissions = this.config.permissionsClaim ? readClaimList(frozen, this.config.permissionsClaim) : asStringArray(user.permissions);
    return user;
  }

  /** Roles and permissions for verified access token claims, read the same way as for a user. */
  private accessTokenGrants(claims: Readonly<Record<string, unknown>>): { roles: string[]; permissions: string[] } {
    const mapped = this.profile?.mapUser?.(claims) ?? {};
    return {
      roles: this.config.rolesClaim ? readClaimList(claims, this.config.rolesClaim) : asStringArray(mapped.roles),
      permissions: this.config.permissionsClaim ? readClaimList(claims, this.config.permissionsClaim) : asStringArray(mapped.permissions),
    };
  }

  /**
   * Adds the roles and permissions a session's own access token carries, since providers often put them only there.
   * Only a token that verifies, names this client as `client_id` and has the same subject counts. Anything else leaves the user unchanged.
   */
  private async withAccessTokenGrants(user: AuthenticatedUser, accessToken: string | undefined): Promise<AuthenticatedUser> {
    if (!asString(accessToken) || !this.apiAudience()) return user;

    let claims: AccessTokenClaims;
    try {
      claims = await this.verifyAccessToken(accessToken as string);
    } catch (error) {
      warnOnce("access-token-grants", `The session's access token did not verify against \`apiAudience\`, so its roles and permissions were not read (${error instanceof Error ? error.message : String(error)}).`);
      return user;
    }

    if (claims.subject !== user.id || claims.clientId !== this.config.clientId) return user;

    return { ...user, roles: union(user.roles, claims.roles), permissions: union(user.permissions, claims.permissions), sid: user.sid ?? claims.sid };
  }

  /** Maps decoded-but-unverified claims onto the legacy user shape. */
  private toUnverifiedUser(claims: Record<string, unknown>): UnverifiedUser {
    const fields = isRecord(claims.oidc_fields) ? claims.oidc_fields : claims;

    return {
      id: asString(fields.id) ?? asString(claims.sub),
      email: asString(claims.email) ?? asString(fields.email),
      name: asString(claims.name) ?? asString(fields.name),
      picture: asString(claims.picture) ?? asString(fields.picture),
      role: asString(fields.role ?? claims.role),
      authMethods: asStringArray(claims.amr ?? fields.amr),
      sessionVersion: asNumber(fields.session_version ?? claims.session_version),
    };
  }

  /**
   * Generates a PKCE-compliant authorization URL to initiate the user login flow.
   *
   * The request includes a `nonce`, which binds the resulting ID token to this request.
   * When storage is available, it persists `state`, `nonce` and the PKCE verifier so that {@link AuthClient.handleCallback} can complete the flow.
   *
   * @param options Persistence and OIDC request options.
   * @returns A promise resolving to the authorization URL and the values bound to it.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   * @throws {StorageUnavailableError} If persistence was requested but no storage is available.
   */
  public async createAuthorizeUrl(options: AuthorizeUrlOptions = {}): Promise<AuthorizeRequest> {
    const redirectUri = asString(this.config.redirectUri);
    if (!redirectUri) throw new AuthError("A `redirectUri` is required to start an authorization request.", "INVALID_CONFIG");

    const { codeVerifier, codeChallenge } = await generatePKCE();
    const state = generateState();
    const nonce = generateNonce();

    const { authorization_endpoint } = await this.getEndpoints();
    const url = new URL(authorization_endpoint);

    for (const [key, value] of Object.entries(options.extraParams || {})) {
      if (RESERVED_AUTHORIZE_PARAMS.has(key)) {
        warnOnce(`reserved-authorize-param:${key}`, `Ignoring \`extraParams.${key}\`: the library owns that authorization parameter.`);
        continue;
      }
      url.searchParams.set(key, value);
    }

    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", (options.scope || this.config.scope || DEFAULT_SCOPES).join(" "));
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");

    if (options.prompt) url.searchParams.set("prompt", options.prompt);
    if (options.loginHint) url.searchParams.set("login_hint", options.loginHint);
    if (typeof options.maxAge === "number" && Number.isFinite(options.maxAge) && options.maxAge >= 0) {
      url.searchParams.set("max_age", String(Math.floor(options.maxAge)));
    }
    if (options.acrValues) url.searchParams.set("acr_values", Array.isArray(options.acrValues) ? options.acrValues.join(" ") : options.acrValues);

    const persist = options.persist ?? this.hasStorage();
    if (persist) {
      if (!this.hasStorage()) throw new StorageUnavailableError("Persisting the authorization request");

      this.storage.setItem(this.storageKeys.state, state);
      this.storage.setItem(this.storageKeys.nonce, nonce);
      this.storage.setItem(this.storageKeys.codeVerifier, codeVerifier);
    } else if (options.persist === undefined) {
      warnOnce("authorize-not-persisted", "createAuthorizeUrl() did not persist `state`, `nonce` or the PKCE verifier because no storage is configured. " + "Store all three yourself and pass them to handleCallback({ expected }), or construct the client with a storage implementation.");
    }
    return { url: url.toString(), state, nonce, codeVerifier };
  }

  /**
   * Completes an authorization code callback in one call: validates `state`, exchanges the code with the PKCE verifier, verifies the returned ID token (signature, issuer, audience, expiry and nonce) and clears the transient request state.
   *
   * @param input The full callback URL, or its query parameters.
   * @param options Supplied expectations, token persistence and cleanup behaviour.
   * @returns The tokens, the verified user (when an ID token was issued) and the state.
   * @throws {AuthorizationResponseError} If the provider returned an error response.
   * @throws {StateMismatchError} If `state` is missing or does not match.
   * @throws {NonceMismatchError} If the ID token was not bound to this request.
   * @throws {TokenExchangeError} If the code could not be exchanged.
   * @throws {TokenVerificationError} If the ID token fails verification.
   */
  public async handleCallback(input: string | URL | URLSearchParams, options: HandleCallbackOptions = {}): Promise<CallbackResult> {
    const params = input instanceof URLSearchParams ? input : new URL(typeof input === "string" ? input : input.toString()).searchParams;

    const clearTransient = options.clearTransient !== false;

    await this.checkResponseIssuer(params, clearTransient);

    const providerError = params.get("error");
    if (providerError) {
      if (clearTransient) this.clearTransientState();
      throw new AuthorizationResponseError(providerError, params.get("error_description") || undefined);
    }

    const code = params.get("code");
    const returnedState = params.get("state");
    if (!code) throw new AuthError("The authorization callback is missing the `code` parameter.", "INVALID_CALLBACK");

    if (!options.expected && !this.hasStorage()) throw new StorageUnavailableError("Reading the pending authorization request");

    const expectedState = options.expected?.state ?? this.readStorage(this.storageKeys.state);
    const expectedNonce = options.expected?.nonce ?? this.readStorage(this.storageKeys.nonce);
    const codeVerifier = options.expected?.codeVerifier ?? this.readStorage(this.storageKeys.codeVerifier);

    // Throws when absent or mismatched: the CSRF check cannot be skipped on this path.
    this.validateState(returnedState || "", expectedState || "");

    if (!codeVerifier) {
      if (clearTransient) this.clearTransientState();
      throw new AuthError("The PKCE code verifier for this authorization request is missing, so the code cannot be exchanged. " + "It expired, was never persisted, or belongs to a different browser session.", "INVALID_CALLBACK");
    }

    try {
      const tokens = await this.exchangeCodeForToken(code, codeVerifier);

      const requestedOpenId = (this.config.scope || DEFAULT_SCOPES).includes("openid");
      if (!tokens.id_token && requestedOpenId) throw new NoTokenError("The token endpoint did not return an `id_token` for an OpenID Connect request.");

      let user: AuthenticatedUser | null = null;
      if (tokens.id_token) {
        if (!expectedNonce) warnOnce("callback-without-nonce", "Verifying an ID token without a nonce: the token is not bound to this authorization request. " + "Persist the nonce from createAuthorizeUrl() and pass it via handleCallback({ expected: { nonce } }).");
        user = await this.withAccessTokenGrants(await this.verifyIdToken(tokens.id_token, { nonce: expectedNonce || undefined }), tokens.access_token);
      }

      if (options.persistTokens) this.saveTokens(tokens);

      return { tokens, user, state: returnedState as string };
    } finally {
      if (clearTransient) this.clearTransientState();
    }
  }

  /**
   * RFC 9207: an `iss` on the authorization response must be this provider's, which stops a mix-up between providers.
   * Required when discovery advertises `authorization_response_iss_parameter_supported`.
   */
  private async checkResponseIssuer(params: URLSearchParams, clearTransient: boolean): Promise<void> {
    const returned = params.get("iss");
    const discovery = await this.getEndpoints();
    const required = (discovery as unknown as Record<string, unknown>).authorization_response_iss_parameter_supported === true;
    if (returned === null && !required) return;

    if (returned === null || !(await this.issuerCandidates()).includes(returned)) {
      if (clearTransient) this.clearTransientState();
      throw new IssuerMismatchError(this.config.expectedIssuer ?? discovery.issuer, returned ?? "(none)");
    }
  }

  /**
   * Signs the user in without showing them anything, using an OIDC `prompt=none` request.
   *
   * In `"iframe"` mode (the default) the request runs in a hidden iframe and resolves with the verified result, or `null` when the user is not signed in at the provider or would have to interact.
   * The `redirectUri` must be on this page's origin, and the provider must allow its authorization endpoint to be framed.
   *
   * @returns The callback result, or `null` when there is no silent session.
   * @throws {AuthorizationResponseError} For a provider error other than the {@link SILENT_AUTH_ERRORS}, such as `access_denied`.
   * @throws {AuthError} If there is no browser document to run in.
   */
  public async silentAuthorize(options: SilentAuthorizeOptions = {}): Promise<CallbackResult | null> {
    const { mode = "iframe", timeoutMs = DEFAULT_SILENT_TIMEOUT_MS, ...authorize } = options;

    if (typeof window === "undefined" || typeof document === "undefined") throw new AuthError("silentAuthorize() needs a browser. Server-rendered apps keep tokens server-side and refresh them instead.", "SILENT_AUTH_UNAVAILABLE");

    if (mode === "redirect") {
      const { url } = await this.createAuthorizeUrl({ ...authorize, prompt: "none" });
      window.location.assign(url);
      return null;
    }

    // Not persisted: the values stay in this closure, so a silent attempt cannot clobber an interactive login in progress.
    const request = await this.createAuthorizeUrl({ ...authorize, prompt: "none", persist: false });
    const callbackUrl = await this.runInHiddenFrame(request.url, timeoutMs);
    if (!callbackUrl) return null;

    try {
      return await this.handleCallback(callbackUrl, { expected: { state: request.state, nonce: request.nonce, codeVerifier: request.codeVerifier }, clearTransient: false });
    } catch (error) {
      if (isSilentAuthError(error)) return null;
      throw error;
    }
  }

  /**
   * Loads `url` in a hidden iframe and returns the URL it lands on once it is back on this origin with a `code` or `error`.
   * Resolves `null` on timeout, or as soon as the frame lands somewhere unreadable, which is what a provider page or a framing refusal looks like.
   */
  private runInHiddenFrame(url: string, timeoutMs: number): Promise<string | null> {
    return new Promise((resolve) => {
      const frame = document.createElement("iframe");
      frame.setAttribute("aria-hidden", "true");
      frame.setAttribute("tabindex", "-1");
      frame.title = "Silent sign-in";
      frame.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden";

      let settled = false;
      const finish = (result: string | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        frame.remove();
        resolve(result);
      };
      const timer = setTimeout(() => finish(null), timeoutMs);

      frame.addEventListener("load", () => {
        let href: string;
        try {
          href = frame.contentWindow?.location.href ?? "";
        } catch {
          // Cross-origin: the provider rendered a page (it wants interaction) or refused to be framed.
          return finish(null);
        }
        if (!href || href === "about:blank") return;

        const landed = new URL(href);
        if (landed.searchParams.has("code") || landed.searchParams.has("error")) finish(href);
      });

      frame.src = url;
      document.body.appendChild(frame);
    });
  }

  /**
   * Exchanges an authorization code for tokens.
   *
   * Prefer {@link AuthClient.handleCallback}, which also validates `state`, verifies the returned ID token and clears the transient request state.
   * Call this directly only when you are in control of the authorization flow yourself.
   *
   * @param codeVerifier The PKCE verifier from the {@link AuthClient.createAuthorizeUrl} call that started this login.
   * @throws {TokenExchangeError} If the exchange fails.
   */
  public async exchangeCodeForToken(code: string, codeVerifier: string): Promise<TokenResponse> {
    if (!asString(code)) throw new AuthError("No authorization code was provided.", "INVALID_REQUEST");
    if (!asString(codeVerifier)) throw new AuthError("No PKCE code verifier was provided.", "INVALID_REQUEST");

    const redirectUri = asString(this.config.redirectUri);
    if (!redirectUri) throw new AuthError("A `redirectUri` is required to exchange an authorization code.", "INVALID_CONFIG");

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      code,
      code_verifier: codeVerifier,
    });

    if (this.config.clientSecret) params.append("client_secret", this.config.clientSecret);

    const { token_endpoint } = await this.getEndpoints();
    const response = await fetch(token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
      credentials: "include",
    });

    if (!response.ok) throw new TokenExchangeError(await this.readErrorBody(response));

    return this.readTokenResponse(response, new TokenExchangeError("The token endpoint returned no access token."));
  }

  /**
   * Fetches the user's profile information using an active access token.
   *
   * The userinfo endpoint returns display claims only - it does **not** return `role`, `amr` or `session_version`.
   * Use {@link AuthClient.verifyIdToken} when you need to authorize.
   *
   * @throws {ClaimValidationError} If an ID token was passed instead of an access token.
   * @throws {UserInfoError} If the profile cannot be retrieved.
   */
  public async getUser(accessToken: string): Promise<ProfileUser> {
    if (!asString(accessToken)) throw new NoTokenError("No access token was provided.");
    this.assertNotIdToken(accessToken);

    const { userinfo_endpoint } = await this.getEndpoints();
    const response = await fetch(userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
      credentials: "include",
    });

    if (!response.ok) throw new UserInfoError();

    const raw = await response.json();
    return this.toProfileUser(raw);
  }

  /**
   * Restores a browser session through the profile's non-standard `restoreSession` hook, such as a provider cookie.
   *
   * @deprecated Since 3.0.0 - use {@link AuthClient.silentAuthorize}, which is standard OIDC and returns a verified user. Without a profile that restores sessions this resolves `null`.
   * @returns The profile, or `null` if there is no usable session. Never throws.
   */
  public async hydrateSession(): Promise<ProfileUser | null> {
    return this.restoreSession();
  }

  /** The profile's `restoreSession`, or `null` without one. Never throws. @internal */
  public async restoreSession(): Promise<ProfileUser | null> {
    const restore = this.profile?.restoreSession;
    if (!restore) {
      warnOnce("restore-without-profile", "hydrateSession() has nothing to restore from: cookie-based restore is provider-specific since 3.0.0. Use silentAuthorize(), or configure a profile.");
      return null;
    }
    try {
      return await restore.call(this.profile, this.profileContext());
    } catch {
      return null;
    }
  }

  /**
   * Builds an RP-initiated logout URL from the provider's advertised `end_session_endpoint`.
   * Redirect the user agent to it to end the session at the provider, then clear your own storage.
   *
   * @param idToken Sent as `id_token_hint`, so the provider knows which session to end. Without one, `client_id` is sent and the provider may ask the user to confirm.
   * @param postLogoutRedirectUri Must be registered with the provider, or it will be ignored.
   * @throws {LogoutError} If the provider advertises no `end_session_endpoint`.
   */
  public async getLogoutUrl(idToken: string | null | undefined, postLogoutRedirectUri: string): Promise<string> {
    const { end_session_endpoint } = await this.getEndpoints();
    if (!end_session_endpoint) throw new LogoutError();

    const url = new URL(end_session_endpoint);
    if (asString(idToken)) url.searchParams.set("id_token_hint", idToken as string);
    else url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);

    return url.toString();
  }

  /**
   * Requests a new access token using a valid refresh token.
   *
   * Concurrent calls for the same refresh token share a single request: the identity provider rotates refresh tokens and revokes the whole family when one is replayed, so parallel refreshes would invalidate each other's session.
   * The rotated token response is written back to storage when the library is already managing the stored tokens, so the new refresh token is not lost.
   *
   * @param options Set `persist` to force or suppress writing the result to storage.
   * @throws {TokenRefreshError} If the refresh fails.
   */
  public async refreshAccessToken(refreshToken: string, options: { persist?: boolean } = {}): Promise<TokenResponse> {
    if (!asString(refreshToken)) throw new NoTokenError("No refresh token was provided.");

    const inFlight = this.refreshInFlight.get(refreshToken);
    if (inFlight) return inFlight;

    const request = this.performRefresh(refreshToken, options).finally(() => this.refreshInFlight.delete(refreshToken));

    this.refreshInFlight.set(refreshToken, request);
    return request;
  }

  private async performRefresh(refreshToken: string, options: { persist?: boolean }): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.config.clientId,
      refresh_token: refreshToken,
    });

    if (this.config.clientSecret) {
      params.append("client_secret", this.config.clientSecret);
    }

    const { token_endpoint } = await this.getEndpoints();
    const response = await fetch(token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
      credentials: "include",
    });

    if (!response.ok) throw new TokenRefreshError(await this.readErrorBody(response));

    const tokens = await this.readTokenResponse(response, new TokenRefreshError("The token endpoint returned no access token."));

    const persist = options.persist ?? (this.hasStorage() && this.readStorage(this.storageKeys.tokens) !== null);
    if (persist) this.saveTokens(tokens);

    return tokens;
  }

  /**
   * Verifies an ID token and returns the identity it asserts.
   * This is the authorization path. In one pass it checks the RS256 signature against the provider's JWKS (cached, `kid`-aware), that `iss` is the configured issuer, that `aud` is this client.
   *
   * @param options The nonce to require, and an optional maximum authentication age.
   * @returns The verified user, safe to authorize on.
   * @throws {TokenVerificationError} If the signature, algorithm, issuer, audience or expiry fails.
   * Tokens carrying an `evt` claim are refused: those assert one event (a completed step-up,
   * say) rather than an authenticated session, and the two must not be interchangeable.
   *
   * @throws {NonceMismatchError} If the token is not bound to the supplied nonce.
   * @throws {ClaimValidationError} If a required claim is missing, or the token is an event token rather than an ID token.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   */
  public async verifyIdToken(idToken: string, options: VerifyIdTokenOptions = {}): Promise<AuthenticatedUser> {
    if (!asString(idToken)) throw new NoTokenError("No ID token was provided.");

    const { jwks_uri } = await this.getEndpoints();
    const claims = (await verifyCompactJwt(this.keySet, idToken, {
      jwksUri: jwks_uri,
      issuer: await this.issuerCandidates(),
      audience: this.config.clientId,
      clockTolerance: this.clockTolerance(),
    })) as Record<string, unknown>;

    // An ID token never carries `evt`; the provider stamps it on purpose-built tokens like the escalation proof, which are otherwise identical - same issuer, same audience, same algorithm.
    // Without this, a step-up proof would verify here as a login, which is a much stronger claim than the one it actually makes.
    const eventType = asString(claims.evt);
    if (eventType) throw new ClaimValidationError(`This is a "${eventType}" token, not an ID token. It asserts a single event rather than an ` + "authenticated session, so it cannot stand in for a login. Verify it with the method that matches " + `its type - the profile's \`verifyEscalationToken\` for evt: "${ESCALATION_TOKEN_TYPE}".`);

    if (options.nonce !== undefined) {
      if (!timingSafeEqual(asString(claims.nonce) || "", options.nonce)) throw new NonceMismatchError();
    }

    if (options.requiredAcr !== undefined) {
      const accepted = Array.isArray(options.requiredAcr) ? options.requiredAcr : [options.requiredAcr];
      const presented = asString(claims.acr);
      if (!presented || !accepted.includes(presented)) {
        throw new ClaimValidationError(`The ID token's authentication context is "${presented || "none"}", which does not satisfy [${accepted.join(", ")}]. ` + "An authorization server may ignore `acr_values` and still return a valid token, so the request alone guarantees nothing.");
      }
    }

    if (options.maxAuthAgeSeconds !== undefined) {
      const authTime = asNumber(claims.auth_time);
      if (authTime === undefined) throw new ClaimValidationError("The ID token has no `auth_time` claim, so its authentication age cannot be checked.");
      if (nowSeconds() - authTime > options.maxAuthAgeSeconds + this.clockTolerance()) throw new ClaimValidationError(`The user authenticated more than ${options.maxAuthAgeSeconds}s ago; re-authentication is required.`);
    }

    return this.toAuthenticatedUser(claims);
  }

  /**
   * Verifies an access token presented to a resource server.
   *
   * The provider may issue access tokens with an audience shared across applications, so the accepted audience must be pinned explicitly - either per call or via {@link AuthConfig.apiAudience}.
   * Verifying only the signature would let a token obtained by any client be replayed against any resource server.
   *
   * Access tokens carry no `role`, `amr` or `session_version` - those live in the ID token.
   * A `client_credentials` token is **refused by default**. Pass `allowMachineTokens: true` to handle both, then branch on `tokenUse`; or call {@link AuthClient.verifyMachineToken} when only a machine is expected.
   *
   * @param accessToken The bearer token to verify.
   * @param options The audience to accept, scopes to require, and whether machine tokens pass.
   * @returns The verified access token claims.
   * @throws {ClaimValidationError} If no audience was configured, or a required scope is missing.
   * @throws {MachineTokenNotAllowedError} If a machine token arrives and `allowMachineTokens` is not set.
   * @throws {TokenVerificationError} If the signature, algorithm, issuer, audience or expiry fails.
   */
  public async verifyAccessToken(accessToken: string, options: VerifyAccessTokenOptions = {}): Promise<AccessTokenClaims> {
    if (!asString(accessToken)) throw new NoTokenError("No access token was provided.");

    const audience = options.audience ?? this.apiAudience();
    if (!audience || (Array.isArray(audience) && audience.length === 0)) throw new ClaimValidationError("verifyAccessToken requires the audience this resource server accepts. " + "Pass `{ audience }` or set `apiAudience` on AuthConfig - the provider issues access tokens with an " + "audience shared across applications, so it cannot be defaulted safely.");

    const { jwks_uri } = await this.getEndpoints();
    const claims = (await verifyCompactJwt(this.keySet, accessToken, {
      jwksUri: jwks_uri,
      issuer: await this.issuerCandidates(),
      audience,
      clockTolerance: this.clockTolerance(),
    })) as Record<string, unknown>;

    const subject = asString(claims.sub);
    if (!subject) throw new ClaimValidationError("The access token is missing the `sub` claim.");

    const tokenUse = this.classifyTokenUse(claims);
    if (tokenUse === "client" && !options.allowMachineTokens) throw new MachineTokenNotAllowedError(`This access token was issued to the client "${subject}" through the client_credentials grant, ` + "not to a user, so its `sub` is a client_id. Pass `{ allowMachineTokens: true }` and branch on " + "`tokenUse` if this endpoint serves both, or use `verifyMachineToken` if it only serves machines.", subject);

    const expiresAt = asNumber(claims.exp);
    if (expiresAt === undefined) throw new ClaimValidationError("The access token is missing the `exp` claim.");

    const scopes = (asString(claims.scope) || "").split(/\s+/).filter(Boolean);
    const missing = (options.requiredScopes || []).filter((scope) => !scopes.includes(scope));
    if (missing.length > 0) throw new ClaimValidationError(`The access token is missing required scope(s): ${missing.join(", ")}.`);

    const audienceClaim = typeof claims.aud === "string" ? [claims.aud] : asStringArray(claims.aud);
    const frozen = Object.freeze({ ...claims });
    const grants = tokenUse === "client" ? { roles: [], permissions: [] } : this.accessTokenGrants(frozen);

    return {
      subject,
      tokenUse,
      clientId: asString(claims.client_id),
      scopes,
      roles: grants.roles,
      permissions: grants.permissions,
      sid: asString(claims.sid),
      issuer: asString(claims.iss) || "",
      audience: audienceClaim,
      issuedAt: asNumber(claims.iat),
      expiresAt,
      jwtId: asString(claims.jti),
      claims: frozen,
    };
  }

  /**
   * Verifies a **machine** access token - one obtained through the `client_credentials` grant, where a server authenticated as itself and no user was involved.
   *
   * The mirror image of {@link AuthClient.verifyAccessToken}: this one refuses *user* tokens.
   * The result is a {@link MachineClient}, which has no `id`, `role` or `authMethods` - a caller cannot accidentally read a user out of it, because there is no user to read.
   *
   * Two provider behaviours worth knowing. The grant accepts **no scope** (every scope the provider defines describes a user), so `requiredScopes` has nothing to check against and is not offered here.
   * An issued machine token **cannot be revoked**: the grant does not generate a refresh token, so rotating the client secret stops new issuance but leaves outstanding tokens valid until they expire.
   *
   * @param accessToken The bearer token to verify.
   * @param options The audience this resource server accepts.
   * @returns The verified client identity.
   * @throws {NotAMachineTokenError} If the token was issued to a user.
   * @throws {ClaimValidationError} If no audience was configured, or a claim is unusable.
   * @throws {TokenVerificationError} If the signature, algorithm, issuer, audience or expiry fails.
   */
  public async verifyMachineToken(accessToken: string, options: Pick<VerifyAccessTokenOptions, "audience"> = {}): Promise<MachineClient> {
    const claims = await this.verifyAccessToken(accessToken, { ...options, allowMachineTokens: true });

    if (claims.tokenUse !== "client") throw new NotAMachineTokenError();

    return {
      clientId: claims.clientId || claims.subject,
      tokenUse: "client",
      issuer: claims.issuer,
      audience: claims.audience,
      issuedAt: claims.issuedAt,
      expiresAt: claims.expiresAt,
      jwtId: claims.jwtId,
      claims: claims.claims,
    };
  }

  /**
   * Decodes an ID token locally **without verifying it**.
   *
   * No signature, issuer, audience or expiry check is performed, so every field is attacker-controlled: anyone can generate a JWT with `role: "admin"` and an empty signature.
   * Use it to render a name or avatar while a verification round-trip is in flight - never to decide what a caller may do. Call {@link AuthClient.verifyIdToken} for that.
   *
   * @param idToken The ID token to decode.
   * @returns The unverified claims in the library's user shape.
   * @throws {NoTokenError} If the ID token is malformed or cannot be decoded.
   */
  public decodeIdTokenUnsafe(idToken: string): UnverifiedUser {
    return this.toUnverifiedUser(decodeTokenPayloadUnsafe(idToken));
  }

  /**
   * Decodes any JWT's payload locally **without verifying it**, for diagnostics.
   * @param token The token to decode.
   * @returns The raw claims.
   * @throws {NoTokenError} If the token is malformed or cannot be decoded.
   */
  public decodeTokenPayloadUnsafe(token: string): Record<string, unknown> {
    return decodeTokenPayloadUnsafe(token);
  }

  /**
   * Timing-safe CSRF check on the callback's `state`. An empty value on either side fails.
   *
   * {@link AuthClient.handleCallback} already does this. Call it directly only when you are processing the callback yourself.
   * @throws {StateMismatchError} If either value is missing or they differ.
   */
  public validateState(returnedState: string, storedState: string): void {
    if (!timingSafeEqual(returnedState || "", storedState || "")) throw new StateMismatchError();
  }

  /**
   * Reports whether a token is at or near its expiry, for refresh scheduling.
   * This is just a hint: it reads an unverified payload. Expiry is enforced as part of {@link AuthClient.verifyIdToken} / {@link AuthClient.verifyAccessToken}.
   *
   * A token that cannot be parsed, or that carries no `exp`, is reported as expired rather than valid forever.
   *
   * @param offsetSeconds How far ahead of the real expiry to report the token as due (default 60s), so a refresh has time to complete.
   */
  public isTokenNearExpiry(token: string, offsetSeconds = 60): boolean {
    try {
      const payload = decodeTokenPayloadUnsafe(token);
      const exp = asNumber(payload.exp);
      if (exp === undefined) return true;

      return exp < nowSeconds() + offsetSeconds;
    } catch {
      return true;
    }
  }

  /**
   * Resolves the verified user behind a token response, whichever way the deployment is wired.
   *
   * An ID token issued to this client is verified directly, with the session's access token adding its roles and permissions.
   * A session holding only another client's tokens goes to the profile's `resolveSharedSession`, such as WilsoonID's shared platform cookie.
   *
   * @param tokens The token response read from your session store.
   * @param options Shared-session cache behaviour, when that branch is taken.
   * @returns The verified user, safe to authorize on.
   * @throws {NoTokenError} If there is nothing usable to verify.
   * @throws {AuthError} If the session belongs to another client and this one cannot resolve it.
   * @throws {MachineTokenNotAllowedError} If the session holds a `client_credentials` token.
   * @throws {TokenVerificationError} If verification fails.
   */
  public async resolveSession(tokens: Partial<Pick<TokenResponse, "id_token" | "access_token">>, options: PlatformSessionOptions = {}): Promise<AuthenticatedUser> {
    const idToken = asString(tokens?.id_token);
    const accessToken = asString(tokens?.access_token);

    if (idToken && this.isAddressedToThisClient(idToken)) return this.withAccessTokenGrants(await this.verifyIdToken(idToken), accessToken);

    if (accessToken && this.looksLikeMachineToken(accessToken)) throw new MachineTokenNotAllowedError("This session holds a client_credentials token, which represents a client rather than a user, so no " + "session can be resolved from it. Verify machine callers with `verifyMachineToken`.");

    if (accessToken || idToken) {
      const shared = this.profile?.resolveSharedSession;
      // Shared sessions are resolved through introspection, which needs a pinned audience and a confidential client.
      if (accessToken && shared && this.apiAudience() && asString(this.config.clientSecret)) return shared.call(this.profile, this.profileContext(), accessToken, options);

      throw new AuthError("This session was established by another application, and this client cannot resolve shared sessions. " + "That needs a profile that supports them (such as `wilsoon()`), `apiAudience` and a `clientSecret`; " + "otherwise give this application its own session cookie.", "FOREIGN_SESSION");
    }

    throw new NoTokenError("The session holds no tokens to verify.");
  }

  /**
   * Whether a token *claims* to be a machine token. A routing hint, never a trust decision.
   *
   * Unverified, and only ever used to produce a clearer refusal - the authoritative check happens in {@link AuthClient.verifyAccessToken} against verified claims.
   * A forged `token_use` can therefore only cost its bearer a session it was never going to get.
   */
  private looksLikeMachineToken(token: string): boolean {
    try {
      return this.classifyTokenUse(decodeTokenPayloadUnsafe(token)) === "client";
    } catch {
      return false;
    }
  }

  /**
   * Decides whether verified claims describe a machine caller.
   * {@link AuthConfig.detectMachineToken} wins, then the profile's `isMachineToken`, then RFC 9068's `sub === client_id`.
   */
  private classifyTokenUse(claims: Record<string, unknown>): TokenUse {
    const detect = this.config.detectMachineToken ?? this.profile?.isMachineToken?.bind(this.profile);
    if (detect) return detect(claims) ? "client" : "user";

    const subject = asString(claims.sub);
    return subject !== undefined && subject === asString(claims.client_id) ? "client" : "user";
  }

  /** Whether a token *claims* this client's audience. A routing hint, never a trust decision. */
  private isAddressedToThisClient(token: string): boolean {
    try {
      const payload = decodeTokenPayloadUnsafe(token);
      const audience = typeof payload.aud === "string" ? [payload.aud] : asStringArray(payload.aud);
      return audience.includes(this.config.clientId);
    } catch {
      return false;
    }
  }

  /**
   * Resolves a verified session from a platform access token issued to a sibling client.
   *
   * @deprecated Since 3.0.0 - call `client.wilsoon.verifyPlatformSession()` from the `wilsoon()` profile. Removed in 4.0.
   * @throws {AuthError} With code `PROFILE_REQUIRED` when no profile provides it.
   */
  public async verifyPlatformSession(accessToken: string, options: PlatformSessionOptions = {}): Promise<AuthenticatedUser> {
    return this.extension<(token: string, options: PlatformSessionOptions) => Promise<AuthenticatedUser>>("verifyPlatformSession")(accessToken, options);
  }

  /**
   * Calls the provider's RFC 7662 introspection endpoint.
   *
   * Requires a confidential client - the provider rejects introspection without a client secret, so never call this from a browser.
   *
   * @param token An access token or ID token this client legitimately holds.
   * @returns The introspection response; `{ active: false }` for an unusable token.
   * @throws {AuthError} If the provider advertises no introspection endpoint, no client secret is configured, or the request fails.
   */
  public async introspectToken(token: string): Promise<IntrospectionResponse> {
    if (!asString(token)) throw new NoTokenError("No token was provided to introspect.");

    if (!asString(this.config.clientSecret)) throw new AuthError("Token introspection requires a `clientSecret`. Public clients (browsers) cannot introspect - do this from your server.", "INTROSPECTION_UNAVAILABLE");

    const { introspection_endpoint } = await this.getEndpoints();
    if (!introspection_endpoint) throw new AuthError("The identity provider does not advertise an `introspection_endpoint`.", "INTROSPECTION_UNAVAILABLE");

    const response = await fetch(introspection_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret as string,
      }),
    });

    if (!response.ok) throw new AuthError(`Token introspection failed with status ${response.status}.`, "INTROSPECTION_FAILED");

    const body = await response.json().catch(() => null);
    if (!isRecord(body) || typeof body.active !== "boolean") throw new AuthError("The introspection endpoint returned an unexpected payload.", "INTROSPECTION_FAILED");

    return body as unknown as IntrospectionResponse;
  }

  /**
   * Asks the provider whether a token may still be used, and with which permissions, right now.
   * Uses the profile's `liveAccess` when it has one, otherwise plain introspection, which answers `active` and whatever `permissions` the provider returns.
   *
   * @throws {AuthError} If introspection is unavailable to this client.
   */
  public async liveAccess(token: string): Promise<LiveAccess> {
    const hook = this.profile?.liveAccess;
    if (hook) return hook.call(this.profile, this.profileContext(), token);

    const result = await this.introspectToken(token);
    return {
      active: result.active,
      ...(Array.isArray(result.permissions) ? { permissions: asStringArray(result.permissions) } : {}),
      ...(asString(result.sid) ? { sid: asString(result.sid) } : {}),
    };
  }

  /**
   * Checks a verified identity's WilsoonID `session_version` against the live one.
   *
   * @deprecated Since 3.0.0 - call `client.wilsoon.isSessionCurrent()` from the `wilsoon()` profile. Removed in 4.0.
   * @throws {AuthError} With code `PROFILE_REQUIRED` when no profile provides it.
   */
  public async isSessionCurrent(user: Pick<AuthenticatedUser, "id" | "sessionVersion">, options: { token?: string } = {}): Promise<boolean> {
    return this.extension<(user: Pick<AuthenticatedUser, "id" | "sessionVersion">, options: { token?: string }) => Promise<boolean>>("isSessionCurrent")(user, options);
  }

  /**
   * Starts an RFC 8628 device authorization: the grant for a client that can print a short string but cannot host a redirect URI.
   *
   * Returns a code to show the user and a device code to poll with. See {@link AuthClient.authorizeDevice} for the whole exchange as one call.
   *
   * The client must be registered for the device grant at the provider, or this is refused with `unauthorized_client`.
   * A public client is expected and needs no secret, one that registered a secret must still present it.
   *
   * @param options The scopes to request.
   * @returns The started authorization.
   * @throws {DeviceFlowError} If the provider advertises no device endpoint, or refuses the request.
   */
  public async requestDeviceCode(options: DeviceAuthorizationOptions = {}): Promise<DeviceAuthorization> {
    const { device_authorization_endpoint } = await this.getEndpoints();
    if (!device_authorization_endpoint) throw new DeviceFlowError("The identity provider does not advertise a `device_authorization_endpoint`, so it does not support " + "the device grant.", "unsupported_grant_type");

    const scope = (options.scope ?? this.config.scope ?? DEFAULT_SCOPES).join(" ");
    const secret = asString(this.config.clientSecret);

    const response = await fetch(device_authorization_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        client_id: this.config.clientId,
        ...(secret ? { client_secret: secret } : {}),
        scope,
      }),
    });

    const body = await response.json().catch(() => null);
    if (!response.ok || !isRecord(body)) {
      const error = isRecord(body) ? asString(body.error) : undefined;
      const description = isRecord(body) ? asString(body.error_description) : undefined;
      throw new DeviceFlowError(description || `The device authorization request was refused (status ${response.status}).`, error);
    }

    const deviceCode = asString(body.device_code);
    const userCode = asString(body.user_code);
    const verificationUri = asString(body.verification_uri);
    if (!deviceCode || !userCode || !verificationUri) throw new DeviceFlowError("The provider returned a device authorization without a device code, user code or verification URI.");

    const expiresIn = asNumber(body.expires_in) ?? 0;
    return {
      deviceCode,
      userCode,
      verificationUri,
      verificationUriComplete: asString(body.verification_uri_complete),
      expiresIn,
      expiresAt: nowSeconds() + expiresIn,
      interval: asNumber(body.interval) ?? DEFAULT_POLL_INTERVAL_SECONDS,
    };
  }

  /**
   * Polls the token endpoint for a device authorization **once**.
   *
   * Returns `pending` while the user has not finished, and throws for every terminal outcome. Most callers want {@link AuthClient.authorizeDevice}.
   *
   * @returns `done` with the token response, or `pending` with the interval to wait.
   * @throws {AuthorizationDeniedError} If the user refused.
   * @throws {AuthorizationExpiredError} If the device code expired.
   * @throws {DeviceFlowError} If the code was already redeemed, or the client may not use the grant.
   */
  public async pollDeviceToken(authorization: Pick<DeviceAuthorization, "deviceCode" | "interval">): Promise<PollStep<TokenResponse>> {
    const { token_endpoint } = await this.getEndpoints();
    const secret = asString(this.config.clientSecret);

    const response = await fetch(token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        grant_type: DEVICE_GRANT_TYPE,
        device_code: authorization.deviceCode,
        client_id: this.config.clientId,
        ...(secret ? { client_secret: secret } : {}),
      }),
    });

    const body = await response.json().catch(() => null);
    if (!isRecord(body)) throw new DeviceFlowError(`The token endpoint returned an unreadable response (status ${response.status}).`);

    if (!response.ok) {
      const error = asString(body.error) || "invalid_grant";
      const description = asString(body.error_description) || "The device authorization was refused.";

      if (error === AUTHORIZATION_PENDING || error === SLOW_DOWN) {
        return {
          state: "pending",
          interval: asNumber(body.interval) ?? authorization.interval,
          slowDown: error === SLOW_DOWN,
        };
      }

      if (error === EXPIRED_TOKEN) throw new AuthorizationExpiredError(description);
      if (error === ACCESS_DENIED) throw new AuthorizationDeniedError(description);

      throw new DeviceFlowError(description, error);
    }

    if (!asString(body.access_token)) throw new DeviceFlowError("The token endpoint returned no access token.");
    return { state: "done", value: body as unknown as TokenResponse };
  }

  /**
   * Signs a device in: the whole RFC 8628 exchange as one call.
   *
   * Starts the authorization, hands the code to `onUserCode` to display, polls until the user approves or the provider gives up, and verifies the resulting ID token.
   *
   * ```ts
   * const { user, tokens } = await client.authorizeDevice({
   *   scope: ['openid', 'profile', 'email', 'offline_access'],
   *   onUserCode: ({ userCode, verificationUri }) =>
   *     console.log(`Go to ${verificationUri} and enter ${userCode}`),
   * });
   * ```
   *
   * As with escalation, the deadline is the provider's: this polls until it reports `expired_token` rather than timing out on its own clock.
   *
   * @param options Scopes, how to display the code, and polling behaviour.
   * @returns The tokens, and the verified user unless `verifyUser: false`.
   * @throws {AuthorizationDeniedError} If the user refused.
   * @throws {AuthorizationExpiredError} If the code expired before it was approved.
   * @throws {DeviceFlowError} If the provider refuses the request.
   */
  public async authorizeDevice(options: AuthorizeDeviceOptions = {}): Promise<DeviceGrantResult> {
    const authorization = await this.requestDeviceCode(options);

    await options.onUserCode?.(authorization);

    const tokens = await pollUntilResolved(() => this.pollDeviceToken(authorization), authorization.interval, options);

    const idToken = asString(tokens.id_token);
    const user = options.verifyUser !== false && idToken ? await this.verifyIdToken(idToken) : null;

    return { tokens, user, authorization };
  }

  /**
   * Turns an RFC 9470 challenge from a resource server into the authorization request that answers it.
   *
   * This is the portable step-up path: `acr_values` and `max_age` are OIDC Core, so it works against any conforming provider rather than needing an endpoint only some providers have.
   *
   * ```ts
   * const challenge = readAuthenticationChallenge(res.headers.get("www-authenticate"));
   * if (isStepUpChallenge(challenge)) {
   *   const { url } = await client.createStepUpRequest(challenge);
   *   return redirect(url);
   * }
   * ```
   *
   * Values in `options` win over the challenge, so a caller can tighten what the resource asked for but never has to accept less than it demanded by accident.
   *
   * Only `acr_values` and `max_age` are carried across. A challenge arrives from a resource server over the network, and those two can only ever ask for *stronger* authentication; a `scope` taken from the same header would let that server widen what the client requests on the user's behalf, so it is read into {@link AuthenticationChallenge.scope} and deliberately not applied.
   *
   * @param challenge A parsed challenge, or the raw `WWW-Authenticate` header.
   * @param options Anything else the authorization request needs.
   * @throws {AuthError} If the header cannot be parsed, or names neither `acr_values` nor `max_age`.
   */
  public async createStepUpRequest(challenge: AuthenticationChallenge | string, options: AuthorizeUrlOptions = {}): Promise<AuthorizeRequest> {
    const parsed = typeof challenge === "string" ? readAuthenticationChallenge(challenge) : challenge;
    if (!parsed) throw new AuthError("The WWW-Authenticate header could not be parsed as an authentication challenge.", "INVALID_CHALLENGE");

    if (parsed.acrValues.length === 0 && parsed.maxAge === undefined) {
      throw new AuthError("This challenge names neither `acr_values` nor `max_age`, so there is nothing to step up to. " + "Check `isStepUpChallenge()` first - a 401 without them is an ordinary authentication failure, and the answer to it is a plain login.", "INVALID_CHALLENGE");
    }

    return this.createAuthorizeUrl({
      ...options,
      acrValues: options.acrValues ?? (parsed.acrValues.length > 0 ? parsed.acrValues : undefined),
      maxAge: options.maxAge ?? parsed.maxAge,
    });
  }

  /**
   * Creates a WilsoonID method escalation request.
   *
   * @deprecated Since 3.0.0 - call `client.wilsoon.createEscalation()` from the `wilsoon()` profile. Removed in 4.0.
   * @throws {AuthError} With code `PROFILE_REQUIRED` when no profile provides it.
   */
  public async createEscalation(options: CreateEscalationOptions): Promise<EscalationRequest> {
    return this.extension<(options: CreateEscalationOptions) => Promise<EscalationRequest>>("createEscalation")(options);
  }

  /**
   * Polls a WilsoonID escalation once.
   *
   * @deprecated Since 3.0.0 - call `client.wilsoon.pollEscalation()` from the `wilsoon()` profile. Removed in 4.0.
   * @throws {AuthError} With code `PROFILE_REQUIRED` when no profile provides it.
   */
  public async pollEscalation(request: Pick<EscalationRequest, "escalationId" | "pollToken" | "interval">): Promise<PollStep<EscalationResult>> {
    return this.extension<(request: Pick<EscalationRequest, "escalationId" | "pollToken" | "interval">) => Promise<PollStep<EscalationResult>>>("pollEscalation")(request);
  }

  /**
   * Requires a stronger authentication method through WilsoonID escalation, and waits for the answer.
   *
   * @deprecated Since 3.0.0 - call `client.wilsoon.reauthorize()` from the `wilsoon()` profile, or use the portable {@link AuthClient.createStepUpRequest}. Removed in 4.0.
   * @throws {AuthError} With code `PROFILE_REQUIRED` when no profile provides it.
   */
  public async reauthorize(use: string | string[], force = false, options: Omit<ReauthorizeOptions, "use" | "force"> = {}): Promise<EscalationResult> {
    return this.extension<(use: string | string[], force: boolean, options: Omit<ReauthorizeOptions, "use" | "force">) => Promise<EscalationResult>>("reauthorize")(use, force, options);
  }

  /**
   * Verifies a WilsoonID escalation token.
   *
   * @deprecated Since 3.0.0 - call `client.wilsoon.verifyEscalationToken()` from the `wilsoon()` profile. Removed in 4.0.
   * @throws {AuthError} With code `PROFILE_REQUIRED` when no profile provides it.
   */
  public async verifyEscalationToken(escalationToken: string): Promise<VerifiedEscalation> {
    return this.extension<(token: string) => Promise<VerifiedEscalation>>("verifyEscalationToken")(escalationToken);
  }

  /**
   * Rejects an ID token that was passed where an access token is required.
   * Uses an unverified decode, which is safe here because the result is only ever used to reject: an ID token carries this client's ID as its audience and no `scope` claim.
   */
  private assertNotIdToken(token: string): void {
    let payload: Record<string, unknown>;
    try {
      payload = decodeTokenPayloadUnsafe(token);
    } catch {
      return; // Not a JWT we can inspect: let the provider reject it.
    }

    const audience = typeof payload.aud === "string" ? [payload.aud] : asStringArray(payload.aud);
    if (audience.includes(this.config.clientId) && !asString(payload.scope)) throw new ClaimValidationError("An ID token was passed where an access token is required. ID tokens identify the user to this " + "application; access tokens authorize API calls. Use `tokens.access_token` here, and " + "`verifyIdToken(tokens.id_token)` to establish identity.");
  }

  private async readErrorBody(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      return { status: response.status };
    }
  }

  private async readTokenResponse(response: Response, onInvalid: AuthError): Promise<TokenResponse> {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw onInvalid;
    }

    if (!isRecord(body) || !asString(body.access_token)) throw onInvalid;
    return body as unknown as TokenResponse;
  }
}

/**
 * Creates an {@link AuthClient} with the profile's extensions typed under its name, e.g. `client.wilsoon.reauthorize()`.
 * `new AuthClient(config)` attaches the same extensions at runtime, just without the types.
 *
 * ```ts
 * const client = createAuthClient({ issuer, clientId, profile: wilsoon() });
 * await client.wilsoon.reauthorize(["passkey"]);
 * ```
 */
export function createAuthClient<const P extends ProviderProfile<string, object> | undefined = undefined>(config: AuthConfig & { profile?: P }, storage?: AuthStorage): AuthClient & ProfileExtensions<P> {
  return new AuthClient(config, storage) as AuthClient & ProfileExtensions<P>;
}

export * from "./amr";
export * from "./challenge";
export * from "./claims";
export * from "./device";
export * from "./errors";
export * from "./escalation";
export { ALLOWED_ALGORITHMS, decodeTokenHeaderUnsafe, decodeTokenPayloadUnsafe, splitJwt } from "./jwt";
export * from "./machine";
export * from "./polling";
export * from "./profile";
export * from "./storage";
export * from "./types";
export * from "./utils";

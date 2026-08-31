import { AuthenticationChallenge, readAuthenticationChallenge } from "./challenge";
import { AuthorizeDeviceOptions, DEVICE_GRANT_TYPE, DeviceAuthorization, DeviceAuthorizationOptions, DeviceGrantResult } from "./device";
import { AuthError, AuthorizationDeniedError, AuthorizationExpiredError, AuthorizationResponseError, ClaimValidationError, DeviceFlowError, DiscoveryError, EscalationError, IssuerMismatchError, LogoutError, MachineTokenNotAllowedError, NonceMismatchError, NotAMachineTokenError, NoTokenError, SessionCheckUnavailableError, StateMismatchError, StorageUnavailableError, TokenExchangeError, TokenRefreshError, TokenVerificationError, UserInfoError } from "./errors";
import { CreateEscalationOptions, ESCALATION_TOKEN_TYPE, EscalationRequest, EscalationResult, ReauthorizeOptions, VerifiedEscalation } from "./escalation";
import { decodeTokenPayloadUnsafe, RemoteKeySet, verifyCompactJwt } from "./jwt";
import { tokenUseOf } from "./machine";
import { ACCESS_DENIED, AUTHORIZATION_PENDING, EXPIRED_TOKEN, PollStep, pollUntilResolved, SLOW_DOWN } from "./polling";
import { AuthStorage, BrowserStorage, isUsableStorage, UnavailableStorage } from "./storage";
import { AccessTokenClaims, AuthConfig, AuthenticatedUser, AuthorizeRequest, AuthorizeUrlOptions, CallbackResult, DiscoveryDocument, HandleCallbackOptions, IntrospectionResponse, MachineClient, PlatformSessionOptions, ProfileUser, TokenResponse, TokenUse, UnverifiedUser, USER_ROLES, UserRole, VerifyAccessTokenOptions, VerifyIdTokenOptions } from "./types";
import { generateNonce, generatePKCE, generateState, normalizeIssuer, timingSafeEqual } from "./utils";

/**
 * The names the library reads and writes through {@link AuthStorage}.
 *
 * Exported because a storage adapter usually needs to tell them apart - the token blob is long-lived, the other three are single-use and expire in minutes.
 * See `ServerCookieStorage` in `@wilsoon/auth-next` for that split in practice.
 *
 * These are fixed at the library level. To put the token blob under a different cookie name, map it inside your adapter.
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

const TOKEN_KEY = STORAGE_KEYS.tokens;

const DEFAULT_SCOPES = ["openid", "profile", "email"];
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 60;

/** Authorization request parameters the library controls and `extraParams` may not override. */
const RESERVED_AUTHORIZE_PARAMS = new Set(["client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"]);

/** Upper bound on cached platform sessions, so a long-lived client cannot grow unbounded. */
const SESSION_CACHE_MAX_ENTRIES = 500;

/**
 * Fallback seconds between polls, used only when the provider names no interval of its own.
 * Matches RFC 8628's recommended default, which the escalation flow reuses.
 */
const DEFAULT_POLL_INTERVAL_SECONDS = 5;

const warned = new Set<string>();
const warnOnce = (key: string, message: string) => {
  if (warned.has(key)) return;
  warned.add(key);
  if (typeof console !== "undefined") console.warn(`[WilsoonID] ${message}`);
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

const asString = (value: unknown): string | undefined => (typeof value === "string" && value.length > 0 ? value : undefined);

const asStringArray = (value: unknown): string[] => (Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : []);

const asNumber = (value: unknown): number | undefined => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  // The provider reads session_version out of Postgres, which can surface as a string.
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) return Number(value);
  return undefined;
};

const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * An OIDC relying party: discovery, authorization requests, code exchange, token verification and profile lookup for one registered client.
 *
 * Framework-agnostic: it depends on `fetch`, Web Crypto and an {@link AuthStorage} adapter and nothing else - so the same client works in a browser, in Node, and on an edge runtime.
 *
 * One rule governs everything below: authorization decisions must come from
 * {@link AuthClient.verifyIdToken}, {@link AuthClient.verifyAccessToken} or
 * {@link AuthClient.verifyPlatformSession}. Those are the only methods that check a
 * signature against the provider's published keys. Every `*Unsafe` method returns
 * attacker-controlled data by design.
 */
export class AuthClient {
  private discoveryCache: DiscoveryDocument | null = null;
  private storage: AuthStorage;
  private keySet: RemoteKeySet;
  private refreshInFlight = new Map<string, Promise<TokenResponse>>();
  private sessionCache = new Map<string, { user: AuthenticatedUser; expiresAt: number }>();

  /**
   * @param storage Defaults to `localStorage` in the browser. On the server there is no
   * safe default, so storage-backed calls throw a {@link StorageUnavailableError} naming
   * the operation instead of failing later with a `TypeError` - pass an adapter.
   * @throws {AuthError} If required configuration is missing or the issuer is not a URL.
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
  }

  /** Whether this client has a usable storage implementation. */
  public hasStorage(): boolean {
    return isUsableStorage(this.storage);
  }

  /** @throws {StorageUnavailableError} If no storage implementation is available. */
  public saveTokens(tokens: TokenResponse): void {
    this.storage.setItem(TOKEN_KEY, JSON.stringify(tokens));
  }

  /**
   * Reads the persisted token response, or `null` if there is none or it is unusable.
   *
   * Never throws on a malformed value: a corrupt or truncated cookie should log the user out, not crash the request.
   * Also tolerates a URI-encoded blob, which is how a provider that writes the cookie itself typically stores it.
   */
  public getStoredTokens(): TokenResponse | null {
    const raw = this.readStorage(TOKEN_KEY);
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
   * Removes the tokens and the transient `state`/`nonce`/verifier entries. No-ops when no storage is available.
   *
   * Local state only - this does not end the session at the identity provider. Use {@link AuthClient.getLogoutUrl} for that.
   */
  public clearStorage(): void {
    if (!this.hasStorage()) return;

    this.storage.removeItem(TOKEN_KEY);
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
    for (const key of [STORAGE_KEYS.state, STORAGE_KEYS.nonce, STORAGE_KEYS.codeVerifier]) {
      try {
        this.storage.removeItem(key);
      } catch {}
    }
  }

  /**
   * Narrows a raw `role` claim to {@link UserRole} instead of asserting it.
   * Absent means least-privileged (`'user'`). Unrecognised values throw.
   *
   * @throws {ClaimValidationError} If the provider emitted a role outside {@link USER_ROLES}.
   */
  private toRole(value: unknown): UserRole {
    const raw = asString(value);
    if (!raw) return "user";
    if ((USER_ROLES as readonly string[]).includes(raw)) return raw as UserRole;

    throw new ClaimValidationError(`The identity provider issued an unrecognised role "${raw}". Expected one of: ${USER_ROLES.join(", ")}. ` + "Refusing to map it onto a known role - update @wilsoon/auth-core rather than guessing at its privileges.");
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
   * Maps claims that have already passed signature, issuer, audience and expiry checks onto
   * {@link AuthenticatedUser}.
   *
   * @throws {ClaimValidationError} If a required claim is missing or the role is unrecognised.
   */
  private toAuthenticatedUser(claims: Record<string, unknown>): AuthenticatedUser {
    const fields = isRecord(claims.oidc_fields) ? claims.oidc_fields : claims;

    const id = asString(claims.sub);
    if (!id) throw new ClaimValidationError("The ID token is missing the `sub` claim.");

    const expiresAt = asNumber(claims.exp);
    if (expiresAt === undefined) throw new ClaimValidationError("The ID token is missing the `exp` claim.");

    return {
      id,
      email: asString(fields.email) ?? asString(claims.email),
      emailVerified: typeof claims.email_verified === "boolean" ? claims.email_verified : undefined,
      name: asString(fields.name) ?? asString(claims.name),
      picture: asString(fields.picture) ?? asString(claims.picture),
      role: this.toRole(fields.role ?? claims.role),
      authMethods: asStringArray(claims.amr ?? fields.amr),
      sessionVersion: asNumber(fields.session_version ?? claims.session_version),
      issuer: asString(claims.iss) ?? "",
      audience: this.config.clientId,
      source: "id_token",
      issuedAt: asNumber(claims.iat),
      expiresAt,
      authTime: asNumber(claims.auth_time),
      nonce: asString(claims.nonce),
      claims: Object.freeze({ ...claims }),
    };
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

      this.storage.setItem(STORAGE_KEYS.state, state);
      this.storage.setItem(STORAGE_KEYS.nonce, nonce);
      this.storage.setItem(STORAGE_KEYS.codeVerifier, codeVerifier);
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

    const providerError = params.get("error");
    if (providerError) {
      if (clearTransient) this.clearTransientState();
      throw new AuthorizationResponseError(providerError, params.get("error_description") || undefined);
    }

    const code = params.get("code");
    const returnedState = params.get("state");
    if (!code) throw new AuthError("The authorization callback is missing the `code` parameter.", "INVALID_CALLBACK");

    if (!options.expected && !this.hasStorage()) throw new StorageUnavailableError("Reading the pending authorization request");

    const expectedState = options.expected?.state ?? this.readStorage(STORAGE_KEYS.state);
    const expectedNonce = options.expected?.nonce ?? this.readStorage(STORAGE_KEYS.nonce);
    const codeVerifier = options.expected?.codeVerifier ?? this.readStorage(STORAGE_KEYS.codeVerifier);

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
        user = await this.verifyIdToken(tokens.id_token, { nonce: expectedNonce || undefined });
      }

      if (options.persistTokens) this.saveTokens(tokens);

      return { tokens, user, state: returnedState as string };
    } finally {
      if (clearTransient) this.clearTransientState();
    }
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
   * Restores browser session state when the tokens live in an HttpOnly cookie.
   *
   * Calls the userinfo endpoint with `credentials: 'include'` and no `Authorization` header: the browser attaches the session cookie itself, and the provider answers from it.
   * This is the only way a browser can learn who it is signed in as when it cannot read the token.
   *
   * The result carries display claims only and is not sufficient to authorize on - that requires a provider whose userinfo endpoint accepts a cookie-authenticated request and sends CORS credentials headers for your origin.
   *
   * @returns The profile, or `null` if there is no usable session. Never throws.
   */
  public async hydrateSession(): Promise<ProfileUser | null> {
    try {
      const { userinfo_endpoint } = await this.getEndpoints();
      const response = await fetch(userinfo_endpoint, {
        credentials: "include",
      });

      if (!response.ok) return null;

      const raw = await response.json();
      return this.toProfileUser(raw);
    } catch {
      return null;
    }
  }

  /**
   * Builds an RP-initiated logout URL from the provider's advertised `end_session_endpoint`.
   * Redirect the user agent to it to end the session at the provider, then clear your own storage.
   *
   * @param idToken Sent as `id_token_hint`, so the provider knows which session to end.
   * @param postLogoutRedirectUri Must be registered with the provider, or it will be ignored.
   * @throws {LogoutError} If the provider advertises no `end_session_endpoint`.
   */
  public async getLogoutUrl(idToken: string, postLogoutRedirectUri: string): Promise<string> {
    const { end_session_endpoint } = await this.getEndpoints();
    if (!end_session_endpoint) throw new LogoutError();

    const url = new URL(end_session_endpoint);
    url.searchParams.set("id_token_hint", idToken);
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

    const persist = options.persist ?? (this.hasStorage() && this.readStorage(TOKEN_KEY) !== null);
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
   * @throws {ClaimValidationError} If a required claim is missing, the role is unrecognised,
   * or the token is an event token rather than an ID token.
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
    if (eventType) throw new ClaimValidationError(`This is a "${eventType}" token, not an ID token. It asserts a single event rather than an ` + "authenticated session, so it cannot stand in for a login. Verify it with the method that matches " + `its type - \`verifyEscalationToken\` for evt: "${ESCALATION_TOKEN_TYPE}".`);

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

    const audience = options.audience ?? this.config.apiAudience;
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

    return {
      subject,
      tokenUse,
      clientId: asString(claims.client_id),
      scopes,
      issuer: asString(claims.iss) || "",
      audience: audienceClaim,
      issuedAt: asNumber(claims.iat),
      expiresAt,
      jwtId: asString(claims.jti),
      claims: Object.freeze({ ...claims }),
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
   * Decodes the ID token locally to get user data without a network call.
   *
   * @deprecated Since v2.0.0 - this method never verified the token's signature, issuer, audience or expiry, and it was the only way to reach `role`, `amr` and `session_version`.
   * Any check built on its result can be bypassed by generating an unsigned JWT. Use {@link AuthClient.verifyIdToken} for authorization, or {@link AuthClient.decodeIdTokenUnsafe} when you knowingly want display-only claims.
   *
   * @param idToken The ID token obtained from a previous token exchange.
   * @returns The unverified claims in the library's user shape.
   * @throws {NoTokenError} If the ID token is invalid or cannot be parsed.
   */
  // eslint-disable-next-line @typescript-eslint/naming-convention -- frozen 1.x name
  public parseIdToken(idToken: string): UnverifiedUser {
    warnOnce("parseIdToken", "parseIdToken() does not verify the ID token - its signature, issuer, audience and expiry are all unchecked, " + "so `role`, `authMethods` and `sessionVersion` from it are attacker-controlled. " + "Use `await client.verifyIdToken(idToken)` for anything that gates access.");
    return this.decodeIdTokenUnsafe(idToken);
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
   * Checks if a JWT token is expired or about to expire.
   *
   * @deprecated Since v2.0.0 - renamed to {@link AuthClient.isTokenNearExpiry} because the ame read like a security check while parsing an unverified payload.
   * Behaviour is otherwise identical, except that a token with no `exp` claim is now reported as expired instead of valid forever.
   *
   * @param token The JWT string.
   * @param offsetSeconds Buffer time (default 60s) to refresh before actual expiry.
   * @returns True when the token should be treated as expired.
   */
  public isTokenExpired(token: string, offsetSeconds = 60): boolean {
    warnOnce("isTokenExpired", "isTokenExpired() is deprecated; use isTokenNearExpiry(). It is a refresh hint, not a security check - real expiry enforcement happens in verifyIdToken()/verifyAccessToken().");
    return this.isTokenNearExpiry(token, offsetSeconds);
  }

  /**
   * Resolves the verified user behind a token response, whichever way the deployment is wired.
   *
   * @param tokens The token response read from your session store.
   * @param options Platform-session cache behaviour, when that branch is taken.
   * @returns The verified user, safe to authorize on.
   * @throws {NoTokenError} If there is nothing usable to verify.
   * @throws {AuthError} If the cookie belongs to a sibling service but this client is not
   * configured for platform sessions.
   * @throws {MachineTokenNotAllowedError} If the session holds a `client_credentials` token.
   * @throws {TokenVerificationError} If verification fails.
   */
  public async resolveSession(tokens: Partial<Pick<TokenResponse, "id_token" | "access_token">>, options: PlatformSessionOptions = {}): Promise<AuthenticatedUser> {
    const idToken = asString(tokens?.id_token);
    const accessToken = asString(tokens?.access_token);

    if (idToken && this.isAddressedToThisClient(idToken)) return this.verifyIdToken(idToken);

    if (accessToken && this.looksLikeMachineToken(accessToken)) throw new MachineTokenNotAllowedError("This session holds a client_credentials token, which represents a client rather than a user, so no " + "session can be resolved from it. Verify machine callers with `verifyMachineToken`.");

    if (accessToken || idToken) {
      if (accessToken && asString(this.config.apiAudience)) return this.verifyPlatformSession(accessToken, options);

      throw new AuthError("This session was established by another application, and this client is not configured for shared " + "platform sessions. Set `apiAudience` (and `clientSecret`) to resolve them, or give this application " + "its own session cookie.", "FOREIGN_SESSION");
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
   * Decides whether verified claims describe a machine caller, honouring {@link AuthConfig.detectMachineToken}.
   * A configured predicate replaces the built-in signals entirely, so a provider that marks machine tokens its own way is not fighting a default that disagrees.
   */
  private classifyTokenUse(claims: Record<string, unknown>): TokenUse {
    const detect = this.config.detectMachineToken;
    if (detect) return detect(claims) ? "client" : "user";
    return tokenUseOf(claims);
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
   * Resolves a verified session from a **platform access token** - the token that rides in the shared, domain-wide session cookie and is addressed to the platform API audience rather than to any one application.
   * Requires `apiAudience` and a `clientSecret` (introspection is for confidential clients).
   *
   * @param accessToken The access token from the shared session.
   * @param options Cache behaviour for this call.
   * @returns The verified user, safe to authorize on.
   * @throws {TokenVerificationError} If the token fails verification, or the session is no
   * longer active (revoked, or superseded by a newer one).
   * @throws {ClaimValidationError} If no audience is pinned, or a claim is unusable.
   * @throws {MachineTokenNotAllowedError} If the token came from the `client_credentials` grant.
   * @throws {AuthError} If introspection is unavailable to this client.
   */
  public async verifyPlatformSession(accessToken: string, options: PlatformSessionOptions = {}): Promise<AuthenticatedUser> {
    if (!asString(accessToken)) throw new NoTokenError("No access token was provided.");

    const cacheSeconds = options.cacheSeconds ?? this.config.platformSessionCacheSeconds ?? 0;
    if (!options.force && cacheSeconds > 0) {
      const cached = this.readCachedSession(accessToken);
      if (cached) return cached;
    }

    const claims = await this.verifyAccessToken(accessToken, { allowMachineTokens: true });
    if (claims.tokenUse === "client") throw new MachineTokenNotAllowedError(`A platform session cannot be resolved from a client_credentials token: it was issued to the client ` + `"${claims.subject}" with no user behind it, so there is no identity to return. Machine callers should ` + "be authorized with `verifyMachineToken` instead of being given a session.", claims.subject);

    const introspection = await this.introspectToken(accessToken);

    if (!introspection.active) throw new TokenVerificationError("The platform session is no longer active: it was revoked, or superseded by a newer session.");
    if (introspection.sub && introspection.sub !== claims.subject) throw new ClaimValidationError("The introspection response describes a different subject than the token.");

    const user: AuthenticatedUser = {
      id: claims.subject,
      email: asString(introspection.email),
      emailVerified: typeof introspection.email_verified === "boolean" ? introspection.email_verified : undefined,
      name: asString(introspection.name),
      picture: asString(introspection.picture),
      role: this.toRole(introspection.role),
      authMethods: asStringArray(introspection.amr),
      sessionVersion: asNumber(introspection.session_version),
      issuer: claims.issuer,
      audience: claims.audience[0] ?? "",
      source: "access_token",
      issuedAt: claims.issuedAt,
      expiresAt: claims.expiresAt,
      authTime: asNumber(introspection.auth_time),
      claims: claims.claims,
    };

    if (cacheSeconds > 0) this.cacheSession(accessToken, user, cacheSeconds);
    return user;
  }

  private readCachedSession(token: string): AuthenticatedUser | undefined {
    const entry = this.sessionCache.get(token);
    if (!entry) return undefined;

    if (entry.expiresAt <= Date.now()) {
      this.sessionCache.delete(token);
      return undefined;
    }
    return entry.user;
  }

  private cacheSession(token: string, user: AuthenticatedUser, cacheSeconds: number): void {
    // Never cache past the token's own expiry
    const expiresAt = Math.min(Date.now() + cacheSeconds * 1000, user.expiresAt * 1000);
    if (expiresAt <= Date.now()) return;

    if (this.sessionCache.size >= SESSION_CACHE_MAX_ENTRIES) {
      const oldest = this.sessionCache.keys().next();
      if (!oldest.done) this.sessionCache.delete(oldest.value);
    }
    this.sessionCache.set(token, { user, expiresAt });
  }

  /**
   * Calls the provider's RFC 7662 introspection endpoint.
   *
   * Answers whether the token has been revoked, and what the user's `role` and `session_version` are **right now**.
   * It is also how a resource server that only ever sees an access token learns the role, since access tokens do not carry one.
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
   * Checks a verified identity's `session_version` against the user's current version, so that a "sign out everywhere" performed at the identity provider can be honoured before the token's own expiry.
   *
   * Resolves the live version in one of two ways:
   * 1. {@link AuthConfig.resolveSessionVersion}, if configured - useful when your backend already knows the value, or when the client is public;
   * 2. otherwise, introspection - pass the token you verified as `options.token`. This needs a confidential client.
   *
   * It will throw an error rather than assuming the session is still current.
   *
   * @param options The token to introspect, when relying on introspection.
   * @returns True when the token's session version is the current one.
   * @throws {SessionCheckUnavailableError} If neither route is available, the token asserts no version, or the live version cannot be determined.
   * @throws {MachineTokenNotAllowedError} If `options.token` is a machine token, which has no user and so nothing to revoke against.
   */
  public async isSessionCurrent(user: Pick<AuthenticatedUser, "id" | "sessionVersion">, options: { token?: string } = {}): Promise<boolean> {
    if (!user || !asString(user.id)) throw new SessionCheckUnavailableError("A verified user with an `id` is required to check the session version.");
    if (typeof user.sessionVersion !== "number") throw new SessionCheckUnavailableError("This token asserts no `session_version`, so revocation cannot be checked.");

    const resolver = this.config.resolveSessionVersion;
    if (resolver) {
      const current = asNumber(await resolver(user.id));
      if (current === undefined) throw new SessionCheckUnavailableError("`resolveSessionVersion` did not return the current session version.");

      return user.sessionVersion === current;
    }

    if (options.token) {
      if (this.looksLikeMachineToken(options.token)) throw new MachineTokenNotAllowedError("A client_credentials token has no user and therefore no `session_version` to check. Machine tokens " + "cannot be revoked at all - the grant issues no refresh token - so a short lifetime is the only " + "control. Do not gate machine callers on this check.");

      const introspection = await this.introspectToken(options.token);
      if (!introspection.active) return false;

      const current = asNumber(introspection.session_version);
      if (current === undefined) throw new SessionCheckUnavailableError("The introspection response carried no `session_version`.");

      return user.sessionVersion === current;
    }

    throw new SessionCheckUnavailableError();
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
   * Where the escalation API lives.
   * Assumed rather than discovered - escalation is not an OIDC endpoint, so the discovery document says nothing about it. {@link AuthConfig.escalationEndpoint} overrides.
   */
  private escalationEndpoints(): { create: string; poll: string } {
    const base = (asString(this.config.escalationEndpoint) || `${normalizeIssuer(this.config.issuer)}/api/escalate`).replace(/\/+$/, "");
    return { create: base, poll: `${base}/poll` };
  }

  /**
   * Client authentication for the escalation endpoints, which follow the token endpoint's rule: a client with a registered secret must present it, a public client need not.
   */
  private escalationClientAuth(): Record<string, string> {
    const secret = asString(this.config.clientSecret);
    return { client_id: this.config.clientId, ...(secret ? { client_secret: secret } : {}) };
  }

  /**
   * Creates a method escalation request: asks the provider to require a stronger authentication method from a user who is already signed in.
   * This is the back channel. It returns a URL to put in front of the user and a poll token to collect the outcome with - see {@link AuthClient.reauthorize} for the whole exchange as one call, which is what most callers want.
   *
   * The subject must be named, and how you may name it depends on what kind of client you are: {@link CreateEscalationOptions.idTokenHint} always works and is always preferred, while {@link CreateEscalationOptions.subject} is accepted only from a confidential client.
   * Either way the provider only lets a client demand step-up from a user it has already been issued a token for.
   *
   * @param options The methods to require, whether to force a fresh assertion, and the subject.
   * @returns The created request, including the deadline the server chose.
   * @throws {EscalationError} If the provider refuses the request - an unknown method (`invalid_use`), an unusable `id_token_hint`, or an unknown subject.
   */
  public async createEscalation(options: CreateEscalationOptions): Promise<EscalationRequest> {
    const use = Array.isArray(options.use) ? options.use.join(" ") : asString(options.use);
    if (!use) throw new EscalationError("`use` is required: an escalation must say which methods would satisfy it.");

    const idTokenHint = asString(options.idTokenHint);
    const subject = asString(options.subject);
    if (!idTokenHint && !subject) throw new EscalationError("An escalation must name its subject. Pass `idTokenHint` (preferred, and the only option for a public " + "client) or `subject` from a confidential client.");

    const response = await fetch(this.escalationEndpoints().create, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        ...this.escalationClientAuth(),
        use,
        force: options.force ? "true" : "false",
        ...(idTokenHint ? { id_token_hint: idTokenHint } : {}),
        ...(!idTokenHint && subject ? { sub: subject } : {}),
        ...(options.expiresInSeconds !== undefined ? { expires_in: String(options.expiresInSeconds) } : {}),
      }),
    });

    const body = await response.json().catch(() => null);
    if (!response.ok || !isRecord(body)) {
      const error = isRecord(body) ? asString(body.error) : undefined;
      const description = isRecord(body) ? asString(body.error_description) : undefined;
      throw new EscalationError(description || `The escalation request was refused (status ${response.status}).`, error);
    }

    const escalationId = asString(body.escalation_id);
    const escalationUrl = asString(body.escalation_url);
    const pollToken = asString(body.poll_token);
    if (!escalationId || !escalationUrl || !pollToken) throw new EscalationError("The provider returned an escalation without an id, URL or poll token.");

    return {
      escalationId,
      escalationUrl,
      strategies: asStringArray(body.strategies),
      force: body.force === true,
      pollToken,
      expiresIn: asNumber(body.expires_in) ?? 0,
      expiresAt: asNumber(body.expires_at) ?? 0,
      interval: asNumber(body.interval) ?? DEFAULT_POLL_INTERVAL_SECONDS,
    };
  }

  /**
   * Polls an escalation once.
   *
   * Returns `pending` while the provider is still waiting, and throws for every terminal outcome - the user refused, or the deadline passed.
   * Most callers want {@link AuthClient.reauthorize}, which handles the whole flow to an answer. Use this when you need to control the loop (such as an event loop that cannot block).
   *
   * @returns `done` with the result, or `pending` with the interval to wait.
   * @throws {AuthorizationDeniedError} If the user refused.
   * @throws {AuthorizationExpiredError} If the provider says the request expired.
   * @throws {EscalationError} If the request is unknown, or the poll token does not match.
   */
  public async pollEscalation(request: Pick<EscalationRequest, "escalationId" | "pollToken" | "interval">): Promise<PollStep<EscalationResult>> {
    const response = await fetch(this.escalationEndpoints().poll, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        ...this.escalationClientAuth(),
        escalation_id: request.escalationId,
        poll_token: request.pollToken,
      }),
    });

    const body = await response.json().catch(() => null);
    if (!isRecord(body)) throw new EscalationError(`The escalation poll returned an unreadable response (status ${response.status}).`);

    if (!response.ok) {
      const error = asString(body.error) || "invalid_grant";
      const description = asString(body.error_description) || "The escalation poll was refused.";

      // The provider raises its own interval on `slow_down`, so the number in the body is authoritative - adopting it is the whole point of the signal.
      if (error === AUTHORIZATION_PENDING || error === SLOW_DOWN) {
        return {
          state: "pending",
          interval: asNumber(body.interval) ?? request.interval,
          slowDown: error === SLOW_DOWN,
          expiresAt: asNumber(body.expires_at),
        };
      }

      if (error === EXPIRED_TOKEN) throw new AuthorizationExpiredError(description, asNumber(body.expires_at));
      if (error === ACCESS_DENIED) throw new AuthorizationDeniedError(description, asString(body.reason));

      throw new EscalationError(description, error);
    }

    return {
      state: "done",
      value: {
        escalationId: asString(body.escalation_id) || request.escalationId,
        alreadySatisfied: body.already_satisfied === true,
        satisfiedBy: asString(body.satisfied_by),
        authMethods: asStringArray(body.amr),
        acr: asString(body.acr),
        authTime: asNumber(body.auth_time),
        escalationToken: asString(body.escalation_token),
      },
    };
  }

  /**
   * Requires a stronger authentication method from the signed-in user, and waits for the
   * answer.
   *
   * The whole exchange in one call: create the request, hand the URL to `openUrl`, poll until the provider gives a verdict, and verify the token it returns.
   *
   * ```ts
   * const result = await client.reauthorize(['passkey', 'fido'], true, {
   *   idTokenHint: tokens.id_token,
   *   openUrl: (url) => console.log(`Confirm at: ${url}`),
   * });
   * if (!result.alreadySatisfied) console.log(`Verified by ${result.satisfiedBy}.`);
   * ```
   *
   * With `force: false` a session that already qualifies completes on the first poll, and `openUrl` is never called.
   *
   * The deadline belongs to the server. This keeps polling until the provider says the request expired, rather than deciding for itself that too long has passed. Pass `maxWaitSeconds` only to bound a hung process, and `signal` to cancel.
   *
   * @param use The methods that would satisfy the requirement.
   * @param force Require a fresh assertion even if the session already qualifies.
   * @param options The subject, how to show the URL, and polling behaviour.
   * @returns The completed escalation.
   * @throws {AuthorizationDeniedError} If the user refused.
   * @throws {AuthorizationExpiredError} If the request expired before it was completed.
   * @throws {EscalationError} If the provider refuses the request, or returns a token that fails verification.
   */
  public async reauthorize(use: string | string[], force = false, options: Omit<ReauthorizeOptions, "use" | "force"> = {}): Promise<EscalationResult> {
    const request = await this.createEscalation({ ...options, use, force });
    const first = await this.pollEscalation(request);

    let result: EscalationResult;
    if (first.state === "done") {
      result = first.value;
    } else {
      await options.openUrl?.(request.escalationUrl, request);
      result = await pollUntilResolved(() => this.pollEscalation(request), first.interval, options);
    }

    if (options.verifyToken !== false && result.escalationToken) await this.verifyEscalationToken(result.escalationToken);

    return result;
  }

  /**
   * Verifies an escalation token against the provider's JWKS.
   *
   * Checks the signature, issuer, audience and expiry as any token check would, and one thing besides: that `evt` is `escalation`.
   * That claim is the only difference between this and an ID token - same issuer, same audience, same algorithm - so without the check, either would pass where the other belongs, and they authorize very different things.
   *
   * @param escalationToken The token from {@link EscalationResult.escalationToken}.
   * @returns The verified outcome, safe to act on and to forward to a resource server.
   * @throws {EscalationError} If the token is not an escalation token.
   * @throws {TokenVerificationError} If the signature, issuer, audience or expiry fails.
   */
  public async verifyEscalationToken(escalationToken: string): Promise<VerifiedEscalation> {
    if (!asString(escalationToken)) throw new NoTokenError("No escalation token was provided.");

    const { jwks_uri } = await this.getEndpoints();
    const claims = (await verifyCompactJwt(this.keySet, escalationToken, {
      jwksUri: jwks_uri,
      issuer: await this.issuerCandidates(),
      audience: this.config.clientId,
      clockTolerance: this.clockTolerance(),
    })) as Record<string, unknown>;

    const eventType = asString(claims.evt);
    if (eventType !== ESCALATION_TOKEN_TYPE) throw new EscalationError(`Expected an escalation token (evt: "${ESCALATION_TOKEN_TYPE}") but this one carries evt: ` + `"${eventType || "none"}". An ID token is not proof of a step-up, and refusing it here is what keeps ` + "the two from being interchangeable.");

    const subject = asString(claims.sub);
    if (!subject) throw new ClaimValidationError("The escalation token is missing the `sub` claim.");

    const expiresAt = asNumber(claims.exp);
    if (expiresAt === undefined) throw new ClaimValidationError("The escalation token is missing the `exp` claim.");

    return {
      subject,
      satisfiedBy: asString(claims.satisfied_by),
      alreadySatisfied: claims.already_satisfied === true,
      authMethods: asStringArray(claims.amr),
      acr: asString(claims.acr),
      authTime: asNumber(claims.auth_time),
      issuer: asString(claims.iss) || "",
      audience: this.config.clientId,
      expiresAt,
      claims: Object.freeze({ ...claims }),
    };
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

export * from "./amr";
export * from "./challenge";
export * from "./device";
export * from "./errors";
export * from "./escalation";
export { ALLOWED_ALGORITHMS, decodeTokenHeaderUnsafe, decodeTokenPayloadUnsafe, splitJwt } from "./jwt";
export * from "./machine";
export * from "./polling";
export * from "./storage";
export * from "./storage/CookieStorage";
export * from "./types";
export * from "./utils";

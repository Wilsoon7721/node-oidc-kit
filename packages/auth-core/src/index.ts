import {
  AuthError,
  AuthorizationResponseError,
  ClaimValidationError,
  DiscoveryError,
  IssuerMismatchError,
  LogoutError,
  NoTokenError,
  NonceMismatchError,
  SessionCheckUnavailableError,
  StateMismatchError,
  StorageUnavailableError,
  TokenExchangeError,
  TokenRefreshError,
  TokenVerificationError,
  UserInfoError,
} from "./errors";
import { decodeTokenPayloadUnsafe, RemoteKeySet, verifyCompactJwt } from "./jwt";
import { AuthStorage, BrowserStorage, isUsableStorage, UnavailableStorage } from "./storage";
import {
  AccessTokenClaims,
  AuthConfig,
  AuthenticatedUser,
  AuthorizeRequest,
  AuthorizeUrlOptions,
  CallbackResult,
  DiscoveryDocument,
  HandleCallbackOptions,
  IntrospectionResponse,
  PlatformSessionOptions,
  ProfileUser,
  TokenResponse,
  UnverifiedUser,
  USER_ROLES,
  UserRole,
  VerifyAccessTokenOptions,
  VerifyIdTokenOptions,
} from "./types";
import { generateNonce, generatePKCE, generateState, normalizeIssuer, timingSafeEqual } from "./utils";

/**
 * The core client for interacting with the Wilsoon Identity platform.
 * Provides methods for OIDC discovery, authorization URL generation,
 * token exchange, verification, and user profile management.
 *
 * Authorization decisions must be based on {@link AuthClient.verifyIdToken} (or
 * {@link AuthClient.verifyAccessToken} on a resource server). Those are the only methods
 * that check a signature against the provider's published keys.
 */

/** Storage keys the SDK owns. Exported so consumers can mirror them in their own stores. */
export const STORAGE_KEYS = {
  /** The persisted token response. */
  tokens: 'wilsoon_id_tokens',
  /** The pending authorization request's CSRF state. */
  state: 'wilsoon_auth_state',
  /** The pending authorization request's ID token nonce. */
  nonce: 'wilsoon_auth_nonce',
  /** The pending authorization request's PKCE code verifier. */
  codeVerifier: 'wilsoon_auth_verifier',
} as const;

const TOKEN_KEY = STORAGE_KEYS.tokens;

const DEFAULT_SCOPES = ['openid', 'profile', 'email'];
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 60;

/** Authorization request parameters the SDK controls and `extraParams` may not override. */
const RESERVED_AUTHORIZE_PARAMS = new Set([
  'client_id', 'redirect_uri', 'response_type', 'scope', 'state', 'nonce',
  'code_challenge', 'code_challenge_method',
]);

/** Upper bound on cached platform sessions, so a long-lived client cannot grow unbounded. */
const SESSION_CACHE_MAX_ENTRIES = 500;

const warned = new Set<string>();
const warnOnce = (key: string, message: string) => {
  if (warned.has(key)) return;
  warned.add(key);
  if (typeof console !== 'undefined') console.warn(`[WilsoonID] ${message}`);
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const asString = (value: unknown): string | undefined => (typeof value === 'string' && value.length > 0 ? value : undefined);

const asStringArray = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : [];

const asNumber = (value: unknown): number | undefined => {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  // The provider reads session_version out of Postgres, which can surface as a string.
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  return undefined;
};

const nowSeconds = () => Math.floor(Date.now() / 1000);

export class AuthClient {
  private discoveryCache: DiscoveryDocument | null = null;
  private storage: AuthStorage;
  private keySet: RemoteKeySet;
  private refreshInFlight = new Map<string, Promise<TokenResponse>>();
  private sessionCache = new Map<string, { user: AuthenticatedUser; expiresAt: number }>();

  /**
   * Initializes a new instance of the AuthClient.
   * @param config The configuration object containing client credentials and issuer details.
   * @param storage An optional custom storage implementation. Defaults to browser
   * localStorage in the browser. On the server, storage-backed operations throw a
   * descriptive {@link StorageUnavailableError} instead of failing later with a `TypeError`.
   * @throws {AuthError} If required configuration is missing or the issuer is not a URL.
   */
  constructor(private config: AuthConfig, storage?: AuthStorage) {
    if (!config || typeof config !== 'object') throw new AuthError('AuthClient requires a configuration object.', 'INVALID_CONFIG');
    if (!asString(config.clientId)) throw new AuthError('AuthClient requires a `clientId`.', 'INVALID_CONFIG');
    if (!asString(config.issuer)) throw new AuthError('AuthClient requires an `issuer`.', 'INVALID_CONFIG');
    // `redirectUri` is validated where it is used, so a client built only to verify tokens
    // (middleware, a resource server) does not have to invent one.

    let issuerUrl: URL;
    try {
      issuerUrl = new URL(config.issuer);
    } catch {
      throw new AuthError(`AuthClient \`issuer\` must be an absolute URL, received "${config.issuer}".`, 'INVALID_CONFIG');
    }
    if (issuerUrl.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(issuerUrl.hostname)) {
      warnOnce(`insecure-issuer:${config.issuer}`, `The issuer "${config.issuer}" is not HTTPS. Tokens and discovery metadata are fetched over an unauthenticated channel.`);
    }

    this.storage = storage || (typeof window !== 'undefined' ? new BrowserStorage() : new UnavailableStorage());
    this.keySet = new RemoteKeySet(config.jwks);
  }

  /**
   * Reports whether this client can read and write persistent state.
   * @returns True when a usable storage implementation is configured.
   */
  public hasStorage(): boolean {
    return isUsableStorage(this.storage);
  }

  /**
   * Persists the OIDC token response to the configured storage.
   * @param tokens The token response object to save.
   * @throws {StorageUnavailableError} If no storage implementation is available.
   */
  public saveTokens(tokens: TokenResponse): void {
    this.storage.setItem(TOKEN_KEY, JSON.stringify(tokens));
  }

  /**
   * Retrieves the persisted OIDC token response from storage.
   * Tolerates the URI-encoded form the identity provider writes into its cookie.
   * @returns The stored TokenResponse or null if none is found or it cannot be parsed.
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

    // The identity provider writes its cookie as encodeURIComponent(JSON.stringify(tokens)).
    try {
      return raw.includes('%') ? parse(decodeURIComponent(raw)) : null;
    } catch {
      return null;
    }
  }

  /**
   * Clears all authentication-related data from the configured storage.
   * This includes tokens, security state, PKCE verifiers and the ID token nonce.
   * No-ops when no storage implementation is available.
   */
  public clearStorage(): void {
    if (!this.hasStorage()) return;

    this.storage.removeItem(TOKEN_KEY);
    this.clearTransientState();
  }

  /**
   * Retrieves the OIDC discovery document from the identity provider.
   * Results are cached internally after the first successful request.
   * @returns A promise that resolves to the OIDC Discovery Document.
   * @throws {DiscoveryError} If the discovery document cannot be fetched or is incomplete.
   * @throws {IssuerMismatchError} If the advertised issuer is not the configured issuer.
   * @private
   */
  private async getEndpoints(): Promise<DiscoveryDocument> {
    if (this.discoveryCache) return this.discoveryCache;

    const discoveryUrl = `${normalizeIssuer(this.config.issuer)}/.well-known/openid-configuration`;

    let document: unknown;
    try {
      const response = await fetch(discoveryUrl, { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new DiscoveryError(discoveryUrl);
      document = await response.json();
    } catch (error) {
      if (error instanceof DiscoveryError) throw error;
      throw new DiscoveryError(discoveryUrl);
    }

    if (!isRecord(document)
      || !asString(document.issuer)
      || !asString(document.authorization_endpoint)
      || !asString(document.token_endpoint)
      || !asString(document.userinfo_endpoint)
      || !asString(document.jwks_uri)) {
      throw new DiscoveryError(discoveryUrl);
    }

    // Guard against an issuer the application did not choose: everything downstream -
    // token validation included - trusts these endpoints.
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
    return typeof configured === 'number' && configured >= 0 ? configured : DEFAULT_CLOCK_TOLERANCE_SECONDS;
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
      } catch {
        // Best effort: a read-only store (e.g. a Server Component cookie jar) cannot clear
        // these, and the values are single-use and short-lived either way.
      }
    }
  }

  /**
   * Narrows a raw `role` claim to {@link UserRole} instead of asserting it.
   * @param value The raw claim value.
   * @returns The validated role, defaulting to the least-privileged role when absent.
   * @throws {ClaimValidationError} If the provider emitted a role the SDK does not model.
   * @private
   */
  private toRole(value: unknown): UserRole {
    const raw = asString(value);
    if (!raw) return 'user';
    if ((USER_ROLES as readonly string[]).includes(raw)) return raw as UserRole;

    throw new ClaimValidationError(
      `The identity provider issued an unrecognised role "${raw}". Expected one of: ${USER_ROLES.join(', ')}. ` +
      'Refusing to map it onto a known role - update @wilsoon/auth-core rather than guessing at its privileges.'
    );
  }

  /**
   * Maps a userinfo response to a profile.
   * @param raw The raw payload received from the OIDC userinfo endpoint.
   * @returns A profile with display attributes only.
   * @throws {ClaimValidationError} If the response has no subject identifier.
   * @private
   */
  private toProfileUser(raw: unknown): ProfileUser {
    if (!isRecord(raw)) throw new ClaimValidationError('The userinfo endpoint returned an unexpected payload.');

    const id = asString(raw.sub) ?? asString(raw.id);
    if (!id) throw new ClaimValidationError('The userinfo response is missing the `sub` claim.');

    return {
      id,
      email: asString(raw.email),
      emailVerified: typeof raw.email_verified === 'boolean' ? raw.email_verified : undefined,
      name: asString(raw.name),
      picture: asString(raw.picture),
    };
  }

  /**
   * Maps verified ID token claims to an authenticated identity.
   * @param claims Claims that have already passed signature, issuer, audience and expiry checks.
   * @returns The authenticated user.
   * @throws {ClaimValidationError} If a required claim is missing or a role is unrecognised.
   * @private
   */
  private toAuthenticatedUser(claims: Record<string, unknown>): AuthenticatedUser {
    // The token endpoint spreads identity claims flat; the documented example nests them
    // under `oidc_fields`. Accept either shape, preferring the nested one when present.
    const fields = isRecord(claims.oidc_fields) ? claims.oidc_fields : claims;

    const id = asString(claims.sub);
    if (!id) throw new ClaimValidationError('The ID token is missing the `sub` claim.');

    const expiresAt = asNumber(claims.exp);
    if (expiresAt === undefined) throw new ClaimValidationError('The ID token is missing the `exp` claim.');

    return {
      id,
      email: asString(fields.email) ?? asString(claims.email),
      emailVerified: typeof claims.email_verified === 'boolean' ? claims.email_verified : undefined,
      name: asString(fields.name) ?? asString(claims.name),
      picture: asString(fields.picture) ?? asString(claims.picture),
      role: this.toRole(fields.role ?? claims.role),
      authMethods: asStringArray(claims.amr ?? fields.amr),
      sessionVersion: asNumber(fields.session_version ?? claims.session_version),
      issuer: asString(claims.iss) ?? '',
      audience: this.config.clientId,
      source: 'id_token',
      issuedAt: asNumber(claims.iat),
      expiresAt,
      authTime: asNumber(claims.auth_time),
      nonce: asString(claims.nonce),
      claims: Object.freeze({ ...claims }),
    };
  }

  /**
   * Maps decoded-but-unverified claims to the legacy user shape.
   * @param claims Raw claims from an unverified token.
   * @returns The unverified user shape.
   * @private
   */
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
   * The request includes a `nonce`, which binds the resulting ID token to this request, and
   * - when storage is available - persists `state`, `nonce` and the PKCE verifier so that
   * {@link AuthClient.handleCallback} can complete the flow without the caller
   * reimplementing the storage half of the contract.
   *
   * @param options Persistence and OIDC request options.
   * @returns A promise resolving to the authorization URL and the values bound to it.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   * @throws {StorageUnavailableError} If persistence was requested but no storage is available.
   */
  public async createAuthorizeUrl(options: AuthorizeUrlOptions = {}): Promise<AuthorizeRequest> {
    const redirectUri = asString(this.config.redirectUri);
    if (!redirectUri) throw new AuthError('A `redirectUri` is required to start an authorization request.', 'INVALID_CONFIG');

    const { codeVerifier, codeChallenge } = await generatePKCE();
    const state = generateState();
    const nonce = generateNonce();

    const { authorization_endpoint } = await this.getEndpoints();
    const url = new URL(authorization_endpoint);

    for (const [key, value] of Object.entries(options.extraParams || {})) {
      if (RESERVED_AUTHORIZE_PARAMS.has(key)) {
        warnOnce(`reserved-authorize-param:${key}`, `Ignoring \`extraParams.${key}\`: the SDK owns that authorization parameter.`);
        continue;
      }
      url.searchParams.set(key, value);
    }

    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', (options.scope || this.config.scope || DEFAULT_SCOPES).join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    if (options.prompt) url.searchParams.set('prompt', options.prompt);
    if (options.loginHint) url.searchParams.set('login_hint', options.loginHint);
    if (options.acrValues) {
      url.searchParams.set('acr_values', Array.isArray(options.acrValues) ? options.acrValues.join(' ') : options.acrValues);
    }

    const persist = options.persist ?? this.hasStorage();
    if (persist) {
      if (!this.hasStorage()) throw new StorageUnavailableError('Persisting the authorization request');

      this.storage.setItem(STORAGE_KEYS.state, state);
      this.storage.setItem(STORAGE_KEYS.nonce, nonce);
      this.storage.setItem(STORAGE_KEYS.codeVerifier, codeVerifier);
    } else if (options.persist === undefined) {
      // Only when persistence was not deliberately declined.
      warnOnce(
        'authorize-not-persisted',
        'createAuthorizeUrl() did not persist `state`, `nonce` or the PKCE verifier because no storage is configured. ' +
        'Store all three yourself and pass them to handleCallback({ expected }), or construct the client with a storage implementation.'
      );
    }

    return { url: url.toString(), state, nonce, codeVerifier };
  }

  /**
   * Completes an authorization code callback in one call: validates `state`, exchanges the
   * code with the PKCE verifier, verifies the returned ID token (signature, issuer,
   * audience, expiry and nonce) and clears the transient request state.
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
    const params = input instanceof URLSearchParams
      ? input
      : new URL(typeof input === 'string' ? input : input.toString()).searchParams;

    const clearTransient = options.clearTransient !== false;

    const providerError = params.get('error');
    if (providerError) {
      if (clearTransient) this.clearTransientState();
      throw new AuthorizationResponseError(providerError, params.get('error_description') || undefined);
    }

    const code = params.get('code');
    const returnedState = params.get('state');
    if (!code) throw new AuthError('The authorization callback is missing the `code` parameter.', 'INVALID_CALLBACK');

    if (!options.expected && !this.hasStorage()) {
      throw new StorageUnavailableError('Reading the pending authorization request');
    }

    const expectedState = options.expected?.state ?? this.readStorage(STORAGE_KEYS.state);
    const expectedNonce = options.expected?.nonce ?? this.readStorage(STORAGE_KEYS.nonce);
    const codeVerifier = options.expected?.codeVerifier ?? this.readStorage(STORAGE_KEYS.codeVerifier);

    // Throws when absent or mismatched: the CSRF check cannot be skipped on this path.
    this.validateState(returnedState || '', expectedState || '');

    if (!codeVerifier) {
      if (clearTransient) this.clearTransientState();
      throw new AuthError(
        'The PKCE code verifier for this authorization request is missing, so the code cannot be exchanged. ' +
        'It expired, was never persisted, or belongs to a different browser session.',
        'INVALID_CALLBACK'
      );
    }

    try {
      const tokens = await this.exchangeCodeForToken(code, codeVerifier);

      const requestedOpenId = (this.config.scope || DEFAULT_SCOPES).includes('openid');
      if (!tokens.id_token && requestedOpenId) {
        throw new NoTokenError('The token endpoint did not return an `id_token` for an OpenID Connect request.');
      }

      let user: AuthenticatedUser | null = null;
      if (tokens.id_token) {
        if (!expectedNonce) {
          warnOnce(
            'callback-without-nonce',
            'Verifying an ID token without a nonce: the token is not bound to this authorization request. ' +
            'Persist the nonce from createAuthorizeUrl() and pass it via handleCallback({ expected: { nonce } }).'
          );
        }
        user = await this.verifyIdToken(tokens.id_token, { nonce: expectedNonce || undefined });
      }

      if (options.persistTokens) this.saveTokens(tokens);

      return { tokens, user, state: returnedState as string };
    } finally {
      if (clearTransient) this.clearTransientState();
    }
  }

  /**
   * Exchanges an authorization code for OIDC tokens (access, ID, and refresh tokens).
   * @param code The authorization code received from the callback redirect.
   * @param codeVerifier The PKCE code verifier used when generating the initial authorize URL.
   * @returns A promise that resolves to the full OIDC Token Response.
   * @throws {TokenExchangeError} If the code exchange fails.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   */
  public async exchangeCodeForToken(code: string, codeVerifier: string): Promise<TokenResponse> {
    if (!asString(code)) throw new AuthError('No authorization code was provided.', 'INVALID_REQUEST');
    if (!asString(codeVerifier)) throw new AuthError('No PKCE code verifier was provided.', 'INVALID_REQUEST');

    const redirectUri = asString(this.config.redirectUri);
    if (!redirectUri) throw new AuthError('A `redirectUri` is required to exchange an authorization code.', 'INVALID_CONFIG');

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      code,
      code_verifier: codeVerifier,
    });

    if (this.config.clientSecret) {
      params.append('client_secret', this.config.clientSecret);
    }

    const { token_endpoint } = await this.getEndpoints();
    const response = await fetch(token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
      credentials: 'include',
    });

    if (!response.ok) throw new TokenExchangeError(await this.readErrorBody(response));

    return this.readTokenResponse(response, new TokenExchangeError('The token endpoint returned no access token.'));
  }

  /**
   * Fetches the user's profile information using an active access token.
   *
   * The userinfo endpoint returns display claims only - it does **not** return `role`,
   * `amr` or `session_version`. Use {@link AuthClient.verifyIdToken} when you need to
   * authorize.
   *
   * @param accessToken A valid OIDC access token.
   * @returns A promise that resolves to the user's profile.
   * @throws {ClaimValidationError} If an ID token was passed instead of an access token.
   * @throws {UserInfoError} If the user information cannot be retrieved.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   */
  public async getUser(accessToken: string): Promise<ProfileUser> {
    if (!asString(accessToken)) throw new NoTokenError('No access token was provided.');
    this.assertNotIdToken(accessToken);

    const { userinfo_endpoint } = await this.getEndpoints();
    const response = await fetch(userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
      credentials: 'include',
    });

    if (!response.ok) throw new UserInfoError();

    const raw = await response.json();
    return this.toProfileUser(raw);
  }

  /**
   * Hydrates the current session by calling the userinfo endpoint with credentials.
   * The browser automatically attaches the HttpOnly `wilsoon_id_tokens` cookie.
   * The server reads the cookie, extracts and validates the access token,
   * and returns the user profile.
   *
   * Use this method on page load to restore authentication state when tokens
   * are stored in HttpOnly cookies and are invisible to JavaScript. The result carries
   * display claims only and is **not** sufficient for an authorization decision.
   *
   * @returns A promise that resolves to the user's profile, or null if no valid session exists.
   */
  public async hydrateSession(): Promise<ProfileUser | null> {
    try {
      const { userinfo_endpoint } = await this.getEndpoints();
      const response = await fetch(userinfo_endpoint, {
        credentials: 'include',
      });

      if (!response.ok) return null;

      const raw = await response.json();
      return this.toProfileUser(raw);
    } catch {
      return null;
    }
  }

  /**
   * Generates the standardized logout URL for the Wilsoon Identity platform.
   * @param idToken The user's ID Token from their session.
   * @param postLogoutRedirectUri Where the user should be sent after logout.
   * @returns A promise that resolves to the generated logout URL.
   * @throws {LogoutError} If the logout URL cannot be generated.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   */
  public async getLogoutUrl(idToken: string, postLogoutRedirectUri: string): Promise<string> {
    const { end_session_endpoint } = await this.getEndpoints();
    if (!end_session_endpoint)
      throw new LogoutError();

    const url = new URL(end_session_endpoint);
    url.searchParams.set('id_token_hint', idToken);
    url.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);

    return url.toString();
  }

  /**
   * Requests a new access token using a valid refresh token.
   *
   * Concurrent calls for the same refresh token share a single request: the identity
   * provider rotates refresh tokens and revokes the whole family when one is replayed, so
   * parallel refreshes would invalidate each other's session.
   *
   * The rotated token response is written back to storage when the SDK is already managing
   * the stored tokens, so the new refresh token is not lost.
   *
   * @param refreshToken The refresh token obtained from a previous token exchange.
   * @param options Set `persist` to force or suppress writing the result to storage.
   * @returns A promise that resolves to a new Token Response.
   * @throws {TokenRefreshError} If the token refresh fails.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   */
  public async refreshAccessToken(refreshToken: string, options: { persist?: boolean } = {}): Promise<TokenResponse> {
    if (!asString(refreshToken)) throw new NoTokenError('No refresh token was provided.');

    const inFlight = this.refreshInFlight.get(refreshToken);
    if (inFlight) return inFlight;

    const request = this.performRefresh(refreshToken, options)
      .finally(() => this.refreshInFlight.delete(refreshToken));

    this.refreshInFlight.set(refreshToken, request);
    return request;
  }

  private async performRefresh(refreshToken: string, options: { persist?: boolean }): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.config.clientId,
      refresh_token: refreshToken,
    });

    if (this.config.clientSecret) {
      params.append('client_secret', this.config.clientSecret);
    }

    const { token_endpoint } = await this.getEndpoints();
    const response = await fetch(token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
      credentials: 'include',
    });

    if (!response.ok) throw new TokenRefreshError(await this.readErrorBody(response));

    const tokens = await this.readTokenResponse(response, new TokenRefreshError('The token endpoint returned no access token.'));

    const persist = options.persist ?? (this.hasStorage() && this.readStorage(TOKEN_KEY) !== null);
    if (persist) this.saveTokens(tokens);

    return tokens;
  }

  /**
   * Verifies an ID token and returns the identity it asserts.
   *
   * This is the authorization path. In one pass it checks the RS256 signature against the
   * provider's JWKS (cached, `kid`-aware), that `iss` is the configured issuer, that `aud`
   * is this client - so an ID token minted for another application is rejected - that the
   * token has not expired, and that the `nonce` matches the authorization request.
   *
   * @param idToken The ID token to verify.
   * @param options The nonce to require, and an optional maximum authentication age.
   * @returns The verified user, safe to authorize on.
   * @throws {TokenVerificationError} If the signature, algorithm, issuer, audience or expiry fails.
   * @throws {NonceMismatchError} If the token is not bound to the supplied nonce.
   * @throws {ClaimValidationError} If a required claim is missing or the role is unrecognised.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   */
  public async verifyIdToken(idToken: string, options: VerifyIdTokenOptions = {}): Promise<AuthenticatedUser> {
    if (!asString(idToken)) throw new NoTokenError('No ID token was provided.');

    const { jwks_uri } = await this.getEndpoints();
    const claims = await verifyCompactJwt(this.keySet, idToken, {
      jwksUri: jwks_uri,
      issuer: await this.issuerCandidates(),
      audience: this.config.clientId,
      clockTolerance: this.clockTolerance(),
    }) as Record<string, unknown>;

    if (options.nonce !== undefined) {
      if (!timingSafeEqual(asString(claims.nonce) || '', options.nonce)) throw new NonceMismatchError();
    }

    if (options.maxAuthAgeSeconds !== undefined) {
      const authTime = asNumber(claims.auth_time);
      if (authTime === undefined) {
        throw new ClaimValidationError('The ID token has no `auth_time` claim, so its authentication age cannot be checked.');
      }
      if (nowSeconds() - authTime > options.maxAuthAgeSeconds + this.clockTolerance()) {
        throw new ClaimValidationError(`The user authenticated more than ${options.maxAuthAgeSeconds}s ago; re-authentication is required.`);
      }
    }

    return this.toAuthenticatedUser(claims);
  }

  /**
   * Verifies an access token presented to a resource server.
   *
   * The platform issues access tokens with a shared audience, so the accepted audience
   * must be pinned explicitly - either per call or via {@link AuthConfig.apiAudience}.
   * Verifying only the signature would let a token obtained by any client be replayed
   * against any resource server.
   *
   * Access tokens carry no `role`, `amr` or `session_version`; those live in the ID token.
   *
   * @param accessToken The bearer token to verify.
   * @param options The audience to accept and any scopes to require.
   * @returns The verified access token claims.
   * @throws {ClaimValidationError} If no audience was configured, or a required scope is missing.
   * @throws {TokenVerificationError} If the signature, algorithm, issuer, audience or expiry fails.
   */
  public async verifyAccessToken(accessToken: string, options: VerifyAccessTokenOptions = {}): Promise<AccessTokenClaims> {
    if (!asString(accessToken)) throw new NoTokenError('No access token was provided.');

    const audience = options.audience ?? this.config.apiAudience;
    if (!audience || (Array.isArray(audience) && audience.length === 0)) {
      throw new ClaimValidationError(
        'verifyAccessToken requires the audience this resource server accepts. ' +
        'Pass `{ audience }` or set `apiAudience` on AuthConfig - the provider issues access tokens with an ' +
        'audience shared across applications, so it cannot be defaulted safely.'
      );
    }

    const { jwks_uri } = await this.getEndpoints();
    const claims = await verifyCompactJwt(this.keySet, accessToken, {
      jwksUri: jwks_uri,
      issuer: await this.issuerCandidates(),
      audience,
      clockTolerance: this.clockTolerance(),
    }) as Record<string, unknown>;

    const subject = asString(claims.sub);
    if (!subject) throw new ClaimValidationError('The access token is missing the `sub` claim.');

    const expiresAt = asNumber(claims.exp);
    if (expiresAt === undefined) throw new ClaimValidationError('The access token is missing the `exp` claim.');

    const scopes = (asString(claims.scope) || '').split(/\s+/).filter(Boolean);
    const missing = (options.requiredScopes || []).filter(scope => !scopes.includes(scope));
    if (missing.length > 0) {
      throw new ClaimValidationError(`The access token is missing required scope(s): ${missing.join(', ')}.`);
    }

    const audienceClaim = typeof claims.aud === 'string' ? [claims.aud] : asStringArray(claims.aud);

    return {
      subject,
      clientId: asString(claims.client_id),
      scopes,
      issuer: asString(claims.iss) || '',
      audience: audienceClaim,
      issuedAt: asNumber(claims.iat),
      expiresAt,
      jwtId: asString(claims.jti),
      claims: Object.freeze({ ...claims }),
    };
  }

  /**
   * Decodes an ID token locally **without verifying it**.
   *
   * No signature, issuer, audience or expiry check is performed, so every field is
   * attacker-controlled: anyone can mint a JWT with `role: "admin"` and an empty signature.
   * Use it to render a name or avatar while a verification round-trip is in flight - never
   * to decide what a caller may do. Call {@link AuthClient.verifyIdToken} for that.
   *
   * @param idToken The ID token to decode.
   * @returns The unverified claims in the SDK's user shape.
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
   * @deprecated Since v2.0.0 - this method never verified the token's signature, issuer,
   * audience or expiry, and it was the only way to reach `role`, `amr` and
   * `session_version`. Any check built on its result can be bypassed by minting an
   * unsigned JWT. Use {@link AuthClient.verifyIdToken} for authorization, or
   * {@link AuthClient.decodeIdTokenUnsafe} when you knowingly want display-only claims.
   *
   * @param idToken The ID token obtained from a previous token exchange.
   * @returns The unverified claims in the SDK's user shape.
   * @throws {NoTokenError} If the ID token is invalid or cannot be parsed.
   */
  public parseIdToken(idToken: string): UnverifiedUser {
    warnOnce(
      'parseIdToken',
      'parseIdToken() does not verify the ID token - its signature, issuer, audience and expiry are all unchecked, ' +
      'so `role`, `authMethods` and `sessionVersion` from it are attacker-controlled. ' +
      'Use `await client.verifyIdToken(idToken)` for anything that gates access.'
    );
    return this.decodeIdTokenUnsafe(idToken);
  }

  /**
   * Validates that the state returned from the IdP matches the locally stored state.
   * This prevents CSRF attacks. The comparison is timing-safe.
   * @param returnedState The state returned from the IdP.
   * @param storedState The state stored in the application.
   * @throws {StateMismatchError} If either value is missing or they do not match.
   */
  public validateState(returnedState: string, storedState: string): void {
    if (!timingSafeEqual(returnedState || '', storedState || '')) throw new StateMismatchError();
  }

  /**
   * Reports whether a token is at or near its expiry, for refresh scheduling.
   *
   * This is a **hint**, not a gate: it reads an unverified payload. Expiry is enforced as
   * part of {@link AuthClient.verifyIdToken} / {@link AuthClient.verifyAccessToken}.
   *
   * Fails closed - a token that cannot be parsed, or that carries no `exp`, is reported as
   * expired rather than valid forever.
   *
   * @param token The JWT string.
   * @param offsetSeconds Buffer time (default 60s) to refresh before actual expiry.
   * @returns True when the token should be treated as expired.
   */
  public isTokenNearExpiry(token: string, offsetSeconds = 60): boolean {
    try {
      const payload = decodeTokenPayloadUnsafe(token);
      const exp = asNumber(payload.exp);
      if (exp === undefined) return true;

      return exp < (nowSeconds() + offsetSeconds);
    } catch {
      return true;
    }
  }

  /**
   * Checks if a JWT token is expired or about to expire.
   *
   * @deprecated Since v2.0.0 - renamed to {@link AuthClient.isTokenNearExpiry} because the
   * name read like a security check while parsing an unverified payload. Behaviour is
   * otherwise identical, except that a token with no `exp` claim is now reported as expired
   * instead of valid forever.
   *
   * @param token The JWT string.
   * @param offsetSeconds Buffer time (default 60s) to refresh before actual expiry.
   * @returns True when the token should be treated as expired.
   */
  public isTokenExpired(token: string, offsetSeconds = 60): boolean {
    warnOnce('isTokenExpired', 'isTokenExpired() is deprecated; use isTokenNearExpiry(). It is a refresh hint, not a security check - real expiry enforcement happens in verifyIdToken()/verifyAccessToken().');
    return this.isTokenNearExpiry(token, offsetSeconds);
  }

  /**
   * Resolves the verified user behind a token response, whichever way the platform is wired.
   *
   * Two shapes, in this order:
   *
   * 1. **The ID token is addressed to this client** - verify it directly. No network calls
   *    beyond the cached JWKS. This is the state right after your own code exchange.
   * 2. **It belongs to a sibling service, or is absent** - on a shared-cookie platform the
   *    session cookie holds whichever service completed the most recent exchange, so its `aud`
   *    is not yours and verifying it here would rightly fail. Fall back to the access token,
   *    which is addressed to the whole platform, via {@link AuthClient.verifyPlatformSession}.
   *
   * The audience check in step 1 is an unverified decode used purely to *route*; both branches
   * then verify properly, so a forged `aud` gains nothing.
   *
   * @param tokens The token response read from your session store.
   * @param options Platform-session cache behaviour, when that branch is taken.
   * @returns The verified user, safe to authorize on.
   * @throws {NoTokenError} If there is nothing usable to verify.
   * @throws {AuthError} If the cookie belongs to a sibling service but this client is not
   * configured for platform sessions.
   * @throws {TokenVerificationError} If verification fails.
   */
  public async resolveSession(
    tokens: Partial<Pick<TokenResponse, 'id_token' | 'access_token'>>,
    options: PlatformSessionOptions = {}
  ): Promise<AuthenticatedUser> {
    const idToken = asString(tokens?.id_token);
    const accessToken = asString(tokens?.access_token);

    if (idToken && this.isAddressedToThisClient(idToken)) return this.verifyIdToken(idToken);

    if (accessToken || idToken) {
      if (accessToken && asString(this.config.apiAudience)) return this.verifyPlatformSession(accessToken, options);

      throw new AuthError(
        'This session was established by another application, and this client is not configured for shared ' +
        'platform sessions. Set `apiAudience` (and `clientSecret`) to resolve them, or give this application ' +
        'its own session cookie.',
        'FOREIGN_SESSION'
      );
    }

    throw new NoTokenError('The session holds no tokens to verify.');
  }

  /**
   * Whether a token claims this client's audience. A routing hint, never a trust decision.
   * @private
   */
  private isAddressedToThisClient(token: string): boolean {
    try {
      const payload = decodeTokenPayloadUnsafe(token);
      const audience = typeof payload.aud === 'string' ? [payload.aud] : asStringArray(payload.aud);
      return audience.includes(this.config.clientId);
    } catch {
      return false;
    }
  }

  /**
   * Resolves a verified session from a **platform access token** - the token that rides in the
   * shared `.wilsoon.dev` session cookie and is addressed to the platform API audience rather
   * than to any one application.
   *
   * Use this when several first-party services share one login. Each service holds a different
   * `client_id`, so the ID token in the shared cookie belongs to whichever service last
   * completed a code exchange, and verifying it elsewhere would (correctly) fail on `aud`. The
   * access token, by contrast, is addressed to every service - so identity comes from it, and
   * the authorization claims come from introspection, which has the extra advantage of being
   * live: a role change or a "sign out everywhere" is honoured immediately instead of at token
   * expiry.
   *
   * Requires `apiAudience` and a `clientSecret` (introspection is for confidential clients).
   *
   * @param accessToken The access token from the shared session.
   * @param options Cache behaviour for this call.
   * @returns The verified user, safe to authorize on.
   * @throws {TokenVerificationError} If the token fails verification, or the session is no
   * longer active (revoked, or superseded by a newer one).
   * @throws {ClaimValidationError} If no audience is pinned, or a claim is unusable.
   * @throws {AuthError} If introspection is unavailable to this client.
   */
  public async verifyPlatformSession(accessToken: string, options: PlatformSessionOptions = {}): Promise<AuthenticatedUser> {
    if (!asString(accessToken)) throw new NoTokenError('No access token was provided.');

    const cacheSeconds = options.cacheSeconds ?? this.config.platformSessionCacheSeconds ?? 0;
    if (!options.force && cacheSeconds > 0) {
      const cached = this.readCachedSession(accessToken);
      if (cached) return cached;
    }

    const claims = await this.verifyAccessToken(accessToken);
    const introspection = await this.introspectToken(accessToken);

    if (!introspection.active) {
      throw new TokenVerificationError('The platform session is no longer active: it was revoked, or superseded by a newer session.');
    }
    if (introspection.sub && introspection.sub !== claims.subject) {
      throw new ClaimValidationError('The introspection response describes a different subject than the token.');
    }

    const user: AuthenticatedUser = {
      id: claims.subject,
      email: asString(introspection.email),
      emailVerified: typeof introspection.email_verified === 'boolean' ? introspection.email_verified : undefined,
      name: asString(introspection.name),
      picture: asString(introspection.picture),
      role: this.toRole(introspection.role),
      authMethods: asStringArray(introspection.amr),
      sessionVersion: asNumber(introspection.session_version),
      issuer: claims.issuer,
      audience: claims.audience[0] ?? '',
      source: 'access_token',
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
    // Never cache past the token's own expiry, and keep the map bounded.
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
   * Introspection answers the two questions a stateless JWT cannot: whether the token has
   * been revoked, and what the user's `role` and `session_version` are **right now**. It is
   * also how a resource server that only ever sees an access token learns the role, since
   * access tokens do not carry one.
   *
   * Requires a confidential client - the provider rejects introspection without a client
   * secret, so never call this from a browser.
   *
   * @param token An access token or ID token this client legitimately holds.
   * @returns The introspection response; `{ active: false }` for an unusable token.
   * @throws {AuthError} If the provider advertises no introspection endpoint, no client
   * secret is configured, or the request fails.
   */
  public async introspectToken(token: string): Promise<IntrospectionResponse> {
    if (!asString(token)) throw new NoTokenError('No token was provided to introspect.');

    if (!asString(this.config.clientSecret)) {
      throw new AuthError(
        'Token introspection requires a `clientSecret`. Public clients (browsers) cannot introspect - ' +
        'do this from your server.',
        'INTROSPECTION_UNAVAILABLE'
      );
    }

    const { introspection_endpoint } = await this.getEndpoints();
    if (!introspection_endpoint) {
      throw new AuthError('The identity provider does not advertise an `introspection_endpoint`.', 'INTROSPECTION_UNAVAILABLE');
    }

    const response = await fetch(introspection_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret as string,
      }),
    });

    if (!response.ok) {
      throw new AuthError(`Token introspection failed with status ${response.status}.`, 'INTROSPECTION_FAILED');
    }

    const body = await response.json().catch(() => null);
    if (!isRecord(body) || typeof body.active !== 'boolean') {
      throw new AuthError('The introspection endpoint returned an unexpected payload.', 'INTROSPECTION_FAILED');
    }

    return body as unknown as IntrospectionResponse;
  }

  /**
   * Checks a verified identity's `session_version` against the user's current version, so
   * that a "sign out everywhere" performed at the identity provider can be honoured before
   * the token's own expiry.
   *
   * Resolves the live version one of two ways:
   *
   * 1. {@link AuthConfig.resolveSessionVersion}, if configured - useful when your backend
   *    already knows the value, or when the client is public;
   * 2. otherwise, introspection - pass the token you verified as `options.token`. This needs
   *    a confidential client.
   *
   * Fails closed: it throws rather than assuming the session is still current.
   *
   * @param user A verified user carrying a `sessionVersion`.
   * @param options The token to introspect, when relying on introspection.
   * @returns True when the token's session version is the current one.
   * @throws {SessionCheckUnavailableError} If neither route is available, the token asserts
   * no version, or the live version cannot be determined.
   */
  public async isSessionCurrent(
    user: Pick<AuthenticatedUser, 'id' | 'sessionVersion'>,
    options: { token?: string } = {}
  ): Promise<boolean> {
    if (!user || !asString(user.id)) throw new SessionCheckUnavailableError('A verified user with an `id` is required to check the session version.');
    if (typeof user.sessionVersion !== 'number') {
      throw new SessionCheckUnavailableError('This token asserts no `session_version`, so revocation cannot be checked.');
    }

    const resolver = this.config.resolveSessionVersion;
    if (resolver) {
      const current = asNumber(await resolver(user.id));
      if (current === undefined) {
        throw new SessionCheckUnavailableError('`resolveSessionVersion` did not return the current session version.');
      }
      return user.sessionVersion === current;
    }

    if (options.token) {
      const introspection = await this.introspectToken(options.token);

      // The provider already refuses tokens from a superseded session.
      if (!introspection.active) return false;

      const current = asNumber(introspection.session_version);
      if (current === undefined) {
        throw new SessionCheckUnavailableError('The introspection response carried no `session_version`.');
      }
      return user.sessionVersion === current;
    }

    throw new SessionCheckUnavailableError();
  }

  /**
   * Rejects an ID token that was passed where an access token is required.
   *
   * Uses an unverified decode, which is safe here because the result is only ever used to
   * reject: an ID token carries this client's ID as its audience and no `scope` claim.
   * @private
   */
  private assertNotIdToken(token: string): void {
    let payload: Record<string, unknown>;
    try {
      payload = decodeTokenPayloadUnsafe(token);
    } catch {
      return; // Not a JWT we can inspect; let the provider reject it.
    }

    const audience = typeof payload.aud === 'string' ? [payload.aud] : asStringArray(payload.aud);
    if (audience.includes(this.config.clientId) && !asString(payload.scope)) {
      throw new ClaimValidationError(
        'An ID token was passed where an access token is required. ID tokens identify the user to this ' +
        'application; access tokens authorize API calls. Use `tokens.access_token` here, and ' +
        '`verifyIdToken(tokens.id_token)` to establish identity.'
      );
    }
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

export * from './types';
export * from './storage';
export * from './storage/CookieStorage';
export * from './errors';
export * from './utils';
export * from './amr';
export { ALLOWED_ALGORITHMS, decodeTokenHeaderUnsafe, decodeTokenPayloadUnsafe, splitJwt } from './jwt';

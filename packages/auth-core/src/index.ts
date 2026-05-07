import { AuthError, DiscoveryError, LogoutError, NoTokenError, StateMismatchError, TokenExchangeError, TokenRefreshError, UserInfoError } from "./errors";
import { AuthStorage, BrowserStorage } from "./storage";
import { AuthConfig, DiscoveryDocument, TokenResponse, User } from "./types";
import { generatePKCE, generateState } from "./utils";

/**
 * The core client for interacting with the Wilsoon Identity platform.
 * Provides methods for OIDC discovery, authorization URL generation,
 * token exchange, and user profile management.
 */

const TOKEN_KEY = 'wilsoon_id_tokens';

const decodeBase64 = (str: string) => {
  if (typeof atob === 'function') return atob(str);
  return Buffer.from(str, 'base64').toString('binary');
};

export class AuthClient {
  private discoveryCache: DiscoveryDocument | null = null;
  private storage: AuthStorage;

  /**
   * Initializes a new instance of the AuthClient.
   * @param config The configuration object containing client credentials and issuer details.
   * @param storage An optional custom storage implementation. Defaults to browser session storage.
   */
  constructor(private config: AuthConfig, storage?: AuthStorage) {
    this.storage = storage || (typeof window !== 'undefined' ? new BrowserStorage() : {} as AuthStorage);
  }

  /**
   * Persists the OIDC token response to the configured storage.
   * @param tokens The token response object to save.
   */
  public saveTokens(tokens: TokenResponse): void {
    this.storage.setItem(TOKEN_KEY, JSON.stringify(tokens));
  }

  /**
   * Retrieves the persisted OIDC token response from storage.
   * @returns The stored TokenResponse or null if none is found.
   */
  public getStoredTokens(): TokenResponse | null {
    const raw = this.storage.getItem(TOKEN_KEY);
    return raw ? JSON.parse(raw) : null;
  }

  /**
   * Clears all authentication-related data from the configured storage.
   * This includes tokens, security state, and PKCE verifiers.
   */
  public clearStorage(): void {
    this.storage.removeItem(TOKEN_KEY);
    this.storage.removeItem('wilsoon_auth_state');
    this.storage.removeItem('wilsoon_auth_verifier');
  }

  /**
   * Retrieves the OIDC discovery document from the identity provider.
   * Results are cached internally after the first successful request.
   * @returns A promise that resolves to the OIDC Discovery Document.
   * @throws {DiscoveryError} If the discovery document cannot be fetched.
   * @private
   */
  private async getEndpoints(): Promise<DiscoveryDocument> {
    if (this.discoveryCache) return this.discoveryCache;

    const discoveryUrl = `${this.config.issuer}/.well-known/openid-configuration`;
    const response = await fetch(discoveryUrl);

    if (!response.ok) {
      throw new DiscoveryError(discoveryUrl);
    }

    this.discoveryCache = await response.json();
    return this.discoveryCache!;
  }

  /**
   * Maps raw JSON claims from the identity provider to a standardized User object.
   * @param raw The raw payload received from the OIDC userinfo endpoint.
   * @returns A standardized User object for application use.
   * @private
   */
  private mapUser(raw: any): User {
    return {
      id: raw.oidc_fields.id,
      email: raw.email,
      name: raw.name,
      role: raw.oidc_fields.role,
      authMethods: raw.amr || [],
      sessionVersion: raw.oidc_fields.session_version
    };
  }

  /**
   * Generates a PKCE-compliant authorization URL to initiate the user login flow.
   * @returns A promise resolving to the authorization URL and security tokens (state/verifier).
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   */
  public async createAuthorizeUrl() {
    const { codeVerifier, codeChallenge } = await generatePKCE();
    const state = generateState();

    const { authorization_endpoint } = await this.getEndpoints();
    const url = new URL(authorization_endpoint);
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', (this.config.scope || ['openid', 'profile', 'email']).join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    return { url: url.toString(), state, codeVerifier };
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
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
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
    });

    if (!response.ok) throw new TokenExchangeError();

    return response.json();
  }

  /**
   * Fetches the user's profile information using an active access token.
   * @param accessToken A valid OIDC access token.
   * @returns A promise that resolves to the standardized User object.
   * @throws {UserInfoError} If the user information cannot be retrieved.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   */
  public async getUser(accessToken: string): Promise<User> {
    const { userinfo_endpoint } = await this.getEndpoints();
    const response = await fetch(userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) throw new UserInfoError();

    const raw = await response.json();
    return this.mapUser(raw);
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
   * @param refreshToken The refresh token obtained from a previous token exchange.
   * @returns A promise that resolves to a new Token Response.
   * @throws {TokenRefreshError} If the token refresh fails.
   * @throws {DiscoveryError} If the OIDC discovery process fails.
   */
  public async refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
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
    });

    if (!response.ok) throw new TokenRefreshError();

    return response.json();
  }

  /**
   * Decodes the ID token locally to get user data without a network call.
   * This is isomorphic and works in both Client and Server environments.
   * @param idToken The ID token obtained from a previous token exchange.
   * @returns The standardized User object.
   * @throws {NoTokenError} If the ID token is invalid or cannot be parsed.
   */
  public parseIdToken(idToken: string): User {
    try {
      const base64Url = idToken.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(decodeBase64(base64).split('').map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));

      const raw = JSON.parse(jsonPayload);
      return this.mapUser(raw);
    } catch (error) {
      throw new NoTokenError('Failed to parse ID token');
    }
  }

  /**
   * Validates that the state returned from the IdP matches the locally stored state.
   * This prevents CSRF attacks.
   * @param returnedState The state returned from the IdP.
   * @param storedState The state stored in the application.
   * @throws {StateMismatchError} If the states do not match, indicating a potential CSRF attack.
   */
  public validateState(returnedState: string, storedState: string): void {
    if (!returnedState || !storedState || returnedState !== storedState)
      throw new StateMismatchError();
  }

  /**
   * Checks if a JWT token is expired or about to expire.
   * @param token The JWT string.
   * @param offsetSeconds Buffer time (default 60s) to refresh before actual expiry.
   */
  public isTokenExpired(token: string, offsetSeconds = 60): boolean {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const payload = JSON.parse(decodeBase64(base64));

      if (!payload.exp) return false;

      const currentTime = Math.floor(Date.now() / 1000);
      return payload.exp < (currentTime + offsetSeconds);
    } catch {
      return true; // If we can't parse it, assume it's invalid/expired
    }
  }
}

export * from './types';
export * from './storage';
export * from './storage/CookieStorage';
export * from './errors';
export * from './utils';
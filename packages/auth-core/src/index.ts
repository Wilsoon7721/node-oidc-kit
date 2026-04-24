import { AuthConfig, TokenResponse, User } from "./types";
import { generatePKCE, generateState } from "./utils";

export class AuthClient {
  constructor(private config: AuthConfig) { }

  private mapUser(raw: any): User {
    return {
      id: raw.oidc_fields.id,
      email: raw.email,
      role: raw.oidc_fields.role,
      authMethods: raw.amr || [],
      sessionVersion: raw.oidc_fields.session_version
    };
  }

  public async createAuthorizeUrl() {
    const { codeVerifier, codeChallenge } = await generatePKCE();
    const state = generateState();

    const url = new URL(`${this.config.issuer}/authorize`);
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', (this.config.scope || ['openid', 'profile', 'email']).join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    return { url: url.toString(), state, codeVerifier };
  }

  public async exchangeCodeForToken(code: string, codeVerifier: string): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      code,
      code_verifier: codeVerifier,
    });

    const response = await fetch(`${this.config.issuer}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
    });

    if (!response.ok) throw new Error('Failed to exchange code for token');

    return response.json();
  }

  public async getUser(accessToken: string): Promise<User> {
    const response = await fetch(`${this.config.issuer}/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) throw new Error('Failed to fetch user info');

    const raw = await response.json();
    return this.mapUser(raw);
  }

  /**
   * Generates the standardized logout URL for the Wilsoon Identity platform.
   * @param idToken The user's ID Token (hint) from their session.
   * @param postLogoutRedirectUri Where the user should be sent after logout.
   */
  public getLogoutUrl(idToken: string, postLogoutRedirectUri: string): string {
    const url = new URL(`${this.config.issuer}/api/logout`);

    url.searchParams.set('id_token_hint', idToken);
    url.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);

    return url.toString();
  }
}
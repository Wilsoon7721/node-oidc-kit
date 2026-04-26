export interface AuthConfig {
    /** The client ID assigned to your application in the Wilsoon Identity portal. */
    clientId: string;
    /** The base URL of the identity provider (e.g., https://id.wilsoon.dev). */
    issuer: string;
    /** The URI where the user is redirected after successful authentication. */
    redirectUri: string;
    /* Optional list of scopes to request (defaults to ['openid', 'profile', 'email']). */
    scope?: string[];
    /** Optional domain for setting cookies across subdomains. */
    cookieDomain?: string;
}

/**
 * Standard OIDC Discovery Document containing server endpoints and metadata.
 */
export interface DiscoveryDocument {
    /** The issuer URL of the identity provider. */
    issuer: string;
    /** The URL of the server's authorization endpoint. */
    authorization_endpoint: string;
    /** The URL of the server's token endpoint. */
    token_endpoint: string;
    /** The URL of the server's userinfo endpoint. */
    userinfo_endpoint: string;
    /** The URL of the server's JSON Web Key Set (JWKS) endpoint. */
    jwks_uri: string;
    /** Optional URL of the server's logout endpoint (RP-Initiated Logout). */
    end_session_endpoint?: string;
    /** Optional URL of the server's token revocation endpoint. */
    revocation_endpoint?: string;
    /** Optional URL of the server's token introspection endpoint. */
    introspection_endpoint?: string;
}

/**
 * Response received from the token endpoint after a successful exchange or refresh.
 */
export interface TokenResponse {
    /** The access token for authorizing API requests. */
    access_token: string;
    /** The ID token containing user profile information (JWT). */
    id_token?: string;
    /** The refresh token used to obtain new access tokens. */
    refresh_token?: string;
    /** The number of seconds until the access token expires. */
    expires_in?: number;
    /** The type of token (usually "Bearer"). */
    token_type?: string;
    /** The actual scopes granted by the server. */
    scope?: string;
}

/**
 * Standardized user profile object derived from OIDC claims.
 */
export interface User {
    /** The unique identifier for the user. */
    id: string;
    /** The user's primary email address. */
    email: string;
    /** The user's role within the platform. */
    role: 'admin' | 'user';
    /** List of authentication methods used during the session. */
    authMethods: string[];
    /** The version number of the user's session, used for invalidation. */
    sessionVersion: number;
}
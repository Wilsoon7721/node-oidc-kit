/**
 * Base class for all Wilsoon ID authentication errors.
 */
export class AuthError extends Error {
    constructor(message: string, public code?: string) {
        super(message);
        this.name = 'AuthError';
        Object.setPrototypeOf(this, AuthError.prototype);
    }
}

/**
 * Thrown when the state returned from the OIDC provider does not match the locally stored state.
 * This is a critical security check to prevent CSRF attacks.
 */
export class StateMismatchError extends AuthError {
    constructor() {
        super('The state returned from the server does not match the local state.', 'STATE_MISMATCH');
        this.name = 'StateMismatchError';
    }
}

/**
 * Thrown when the OIDC discovery document cannot be retrieved from the issuer.
 */
export class DiscoveryError extends AuthError {
    constructor(issuer: string) {
        super(`Failed to fetch OIDC discovery document from: ${issuer}`, 'DISCOVERY_FAILED');
        this.name = 'DiscoveryError';
    }
}

/**
 * Thrown when the authorization code cannot be exchanged for tokens at the token endpoint.
 */
export class TokenExchangeError extends AuthError {
    constructor(public originalError?: any) {
        super('Failed to exchange the authorization code for tokens.', 'TOKEN_EXCHANGE_FAILED');
        this.name = 'TokenExchangeError';
    }
}

/**
 * Thrown when user information cannot be retrieved from the userinfo endpoint.
 */
export class UserInfoError extends AuthError {
    constructor() {
        super('Failed to fetch user info.', 'USER_INFO_FAILED');
        this.name = 'UserInfoError';
    }
}

/**
 * Thrown when a refresh token cannot be used to obtain new access tokens.
 */
export class TokenRefreshError extends AuthError {
    constructor() {
        super('Failed to refresh access token.', 'TOKEN_REFRESH_FAILED');
        this.name = 'TokenRefreshError';
    }
}

/**
 * Thrown when the logout URL cannot be generated, typically due to a missing end_session_endpoint.
 */
export class LogoutError extends AuthError {
    constructor() {
        super('Failed to generate logout URL.', 'LOGOUT_FAILED');
        this.name = 'LogoutError';
    }
}

/**
 * Thrown when an ID token is missing or cannot be parsed.
 */
export class NoTokenError extends AuthError {
    constructor(message: string) {
        super(message, 'NO_TOKEN');
        this.name = 'NoTokenError';
    }
}
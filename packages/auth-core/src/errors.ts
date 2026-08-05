/**
 * Base class for all Wilsoon ID authentication errors.
 */
export class AuthError extends Error {
    constructor(message: string, public code?: string, options?: { cause?: unknown }) {
        super(message);
        this.name = 'AuthError';
        if (options && 'cause' in options) (this as { cause?: unknown }).cause = options.cause;
        // `new.target`, not `AuthError.prototype`: pinning the base prototype here made
        // `error instanceof StateMismatchError` (and every other subclass check) false.
        Object.setPrototypeOf(this, new.target.prototype);
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
 * Thrown when an ID token's `nonce` claim does not match the nonce sent on the
 * authorization request. Without this binding an ID token can be replayed.
 */
export class NonceMismatchError extends AuthError {
    constructor() {
        super('The ID token nonce does not match the nonce from the authorization request.', 'NONCE_MISMATCH');
        this.name = 'NonceMismatchError';
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
 * Thrown when the issuer advertised by the discovery document does not match the issuer
 * the client was configured with. A mismatch means tokens would be validated against an
 * issuer the application did not choose.
 */
export class IssuerMismatchError extends AuthError {
    constructor(configured: string, advertised: string) {
        super(
            `The discovery document advertises issuer "${advertised}" but the client is configured for "${configured}". ` +
            'Set `expectedIssuer` if this difference is intentional.',
            'ISSUER_MISMATCH'
        );
        this.name = 'IssuerMismatchError';
    }
}

/**
 * Thrown when the authorization code cannot be exchanged for tokens at the token endpoint.
 */
export class TokenExchangeError extends AuthError {
    constructor(public originalError?: any) {
        super(
            `Failed to exchange the authorization code for tokens.${typeof originalError === 'string' ? ` ${originalError}` : ''}`,
            'TOKEN_EXCHANGE_FAILED'
        );
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
    constructor(public originalError?: any) {
        super(
            `Failed to refresh access token.${typeof originalError === 'string' ? ` ${originalError}` : ''}`,
            'TOKEN_REFRESH_FAILED'
        );
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

/**
 * Thrown when a token's signature, algorithm, issuer, audience or expiry fails
 * verification against the provider's published keys.
 */
export class TokenVerificationError extends AuthError {
    constructor(message: string, options?: { cause?: unknown }) {
        super(message, 'TOKEN_VERIFICATION_FAILED', options);
        this.name = 'TokenVerificationError';
    }
}

/**
 * Thrown when a token is cryptographically valid but carries a claim the SDK will not
 * accept - a missing `sub`, an unrecognised `role`, an insufficient `amr`, and so on.
 */
export class ClaimValidationError extends AuthError {
    constructor(message: string) {
        super(message, 'CLAIM_INVALID');
        this.name = 'ClaimValidationError';
    }
}

/**
 * Thrown when the identity provider returns an error on the authorization callback
 * (e.g. `?error=access_denied`).
 */
export class AuthorizationResponseError extends AuthError {
    constructor(public error: string, public description?: string) {
        super(`The identity provider returned an authorization error: ${error}${description ? ` (${description})` : ''}`, 'AUTHORIZATION_RESPONSE_ERROR');
        this.name = 'AuthorizationResponseError';
    }
}

/**
 * Thrown when an operation needs persistent storage but none is available - for example
 * constructing a client on the server without passing a storage implementation and then
 * asking it to persist the PKCE verifier.
 */
export class StorageUnavailableError extends AuthError {
    constructor(operation: string) {
        super(
            `${operation} requires a storage implementation. Pass one to the AuthClient constructor ` +
            '(e.g. `new AuthClient(config, new MemoryStorage())`, a cookie-backed store on the server, ' +
            'or `new BrowserStorage(window.sessionStorage)` in the browser).',
            'STORAGE_UNAVAILABLE'
        );
        this.name = 'StorageUnavailableError';
    }
}

/**
 * Thrown when a session-version check is requested but no way to resolve the user's
 * current version has been configured. The check fails closed rather than assuming the
 * session is still valid.
 */
export class SessionCheckUnavailableError extends AuthError {
    constructor(message = 'Cannot determine the current session version. Configure `resolveSessionVersion` on AuthConfig, or pass the token so it can be introspected (confidential clients only).') {
        super(message, 'SESSION_CHECK_UNAVAILABLE');
        this.name = 'SessionCheckUnavailableError';
    }
}

/**
 * Thrown when the runtime provides no Web Crypto implementation, which the SDK requires
 * for PKCE and for generating state/nonce values.
 */
export class CryptoUnavailableError extends AuthError {
    constructor() {
        super(
            'No Web Crypto implementation found on `globalThis.crypto`. @wilsoon/auth-core requires ' +
            'Node.js 18+, a modern browser, or an edge runtime with the Web Crypto API.',
            'CRYPTO_UNAVAILABLE'
        );
        this.name = 'CryptoUnavailableError';
    }
}

/**
 * Base class for every error this SDK throws.
 *
 * Catch `AuthError` to handle any authentication failure, or a subclass to handle one cause.
 * Each carries a `code` - the messages are user-friendly, and may change between releases.
 */
export class AuthError extends Error {
  constructor(
    message: string,
    public code?: string,
    options?: { cause?: unknown },
  ) {
    super(message);
    this.name = "AuthError";
    if (options && "cause" in options) (this as { cause?: unknown }).cause = options.cause;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when the callback's `state` does not match the value stored when the authorization request was created - the CSRF check on the login flow.
 *
 * In practice this is most often benign: a stale bookmark of a callback URL, a login finished in a different tab, or transient cookies dropped by `SameSite=Strict`.
 * It is still never safe to continue past it.
 */
export class StateMismatchError extends AuthError {
  constructor() {
    super("The state returned from the server does not match the local state.", "STATE_MISMATCH");
    this.name = "StateMismatchError";
  }
}

/**
 * Thrown when an ID token's `nonce` claim does not match the nonce sent on the authorization request. Without this binding an ID token can be replayed.
 */
export class NonceMismatchError extends AuthError {
  constructor() {
    super("The ID token nonce does not match the nonce from the authorization request.", "NONCE_MISMATCH");
    this.name = "NonceMismatchError";
  }
}

/**
 * Thrown when `/.well-known/openid-configuration` cannot be fetched, or is missing an endpoint the SDK requires (`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`).
 */
export class DiscoveryError extends AuthError {
  constructor(issuer: string) {
    super(`Failed to fetch OIDC discovery document from: ${issuer}`, "DISCOVERY_FAILED");
    this.name = "DiscoveryError";
  }
}

/**
 * Thrown when the issuer advertised by the discovery document does not match the issuer the client was configured with.
 * A mismatch means tokens would be validated against an issuer the application did not choose.
 */
export class IssuerMismatchError extends AuthError {
  constructor(configured: string, advertised: string) {
    super(`The discovery document advertises issuer "${advertised}" but the client is configured for "${configured}". ` + "Set `expectedIssuer` if this difference is intentional.", "ISSUER_MISMATCH");
    this.name = "IssuerMismatchError";
  }
}

/** Thrown when the token endpoint refuses the authorization code, or returns no access token. */
export class TokenExchangeError extends AuthError {
  constructor(public originalError?: any) {
    super(`Failed to exchange the authorization code for tokens.${typeof originalError === "string" ? ` ${originalError}` : ""}`, "TOKEN_EXCHANGE_FAILED");
    this.name = "TokenExchangeError";
  }
}

/** Thrown when the userinfo endpoint cannot be read. */
export class UserInfoError extends AuthError {
  constructor() {
    super("Failed to fetch user info.", "USER_INFO_FAILED");
    this.name = "UserInfoError";
  }
}

/**
 * Thrown when a refresh fails.
 * With rotating refresh tokens, the provider revokes the whole family when one is replayed, so the right response is to sign the user out rather than to try again.
 */
export class TokenRefreshError extends AuthError {
  constructor(public originalError?: any) {
    super(`Failed to refresh access token.${typeof originalError === "string" ? ` ${originalError}` : ""}`, "TOKEN_REFRESH_FAILED");
    this.name = "TokenRefreshError";
  }
}

/** Thrown when the provider advertises no `end_session_endpoint`, so RP-initiated logout is unavailable. */
export class LogoutError extends AuthError {
  constructor() {
    super("Failed to generate logout URL.", "LOGOUT_FAILED");
    this.name = "LogoutError";
  }
}

/** Thrown when a token that an operation requires is absent, empty, or not a compact JWS. */
export class NoTokenError extends AuthError {
  constructor(message: string) {
    super(message, "NO_TOKEN");
    this.name = "NoTokenError";
  }
}

/**
 * Thrown when a token's signature, algorithm, issuer, audience or expiry fails verification against the provider's published keys.
 */
export class TokenVerificationError extends AuthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, "TOKEN_VERIFICATION_FAILED", options);
    this.name = "TokenVerificationError";
  }
}

/**
 * Thrown when a token is cryptographically valid but carries a claim the SDK will not accept - a missing `sub`, an unrecognised `role`, an insufficient `amr`, etc.
 */
export class ClaimValidationError extends AuthError {
  constructor(message: string) {
    super(message, "CLAIM_INVALID");
    this.name = "ClaimValidationError";
  }
}

/**
 * Thrown when the identity provider returns an error on the authorization callback (e.g. `?error=access_denied`).
 */
export class AuthorizationResponseError extends AuthError {
  constructor(
    public error: string,
    public description?: string,
  ) {
    super(`The identity provider returned an authorization error: ${error}${description ? ` (${description})` : ""}`, "AUTHORIZATION_RESPONSE_ERROR");
    this.name = "AuthorizationResponseError";
  }
}

/**
 * Thrown when an operation needs persistent storage but none is available.
 * For example constructing a client on the server without passing a storage implementation and then asking it to persist the PKCE verifier.
 */
export class StorageUnavailableError extends AuthError {
  constructor(operation: string) {
    super(`${operation} requires a storage implementation. Pass one to the AuthClient constructor ` + "(e.g. `new AuthClient(config, new MemoryStorage())`, a cookie-backed store on the server, " + "or `new BrowserStorage(window.sessionStorage)` in the browser).", "STORAGE_UNAVAILABLE");
    this.name = "StorageUnavailableError";
  }
}

/**
 * Thrown when a session-version check is requested but no way to resolve the user's current version has been configured.
 * The check fails closed rather than assuming the session is still valid.
 */
export class SessionCheckUnavailableError extends AuthError {
  constructor(message = "Cannot determine the current session version. Configure `resolveSessionVersion` on AuthConfig, or pass the token so it can be introspected (confidential clients only).") {
    super(message, "SESSION_CHECK_UNAVAILABLE");
    this.name = "SessionCheckUnavailableError";
  }
}

/**
 * Thrown when the runtime provides no Web Crypto implementation, which the SDK requires for PKCE and for generating state/nonce values.
 */
export class CryptoUnavailableError extends AuthError {
  constructor() {
    super("No Web Crypto implementation found on `globalThis.crypto`. @wilsoon/auth-core requires " + "Node.js 18+, a modern browser, or an edge runtime with the Web Crypto API.", "CRYPTO_UNAVAILABLE");
    this.name = "CryptoUnavailableError";
  }
}

/**
 * Thrown when a `client_credentials` access token is presented where a user is required.
 * A machine token's `sub` is a `client_id`, not a user identifier. Accepting one on a user path would hand back a client pretending to be a person.
 * The SDK refuses this by default and makes acceptance opt-in via `allowMachineTokens`, or explicit via {@link AuthClient.verifyMachineToken}.
 */
export class MachineTokenNotAllowedError extends AuthError {
  constructor(
    message: string,
    public clientId?: string,
  ) {
    super(message, "MACHINE_TOKEN_NOT_ALLOWED");
    this.name = "MachineTokenNotAllowedError";
  }
}

/** Thrown when a user access token is presented where a machine token is required. */
export class NotAMachineTokenError extends AuthError {
  constructor(message = "This access token was issued to a user, not to a client acting as itself. Use `verifyAccessToken` for user tokens.") {
    super(message, "NOT_A_MACHINE_TOKEN");
    this.name = "NotAMachineTokenError";
  }
}

/**
 * Thrown when the user refused a step-up or a device authorization (`access_denied`).
 * The flow reached the user, and they said no. Distinguish it from {@link AuthorizationExpiredError}, where they never answered.
 */
export class AuthorizationDeniedError extends AuthError {
  constructor(
    message: string,
    public reason?: string,
  ) {
    super(message, "ACCESS_DENIED");
    this.name = "AuthorizationDeniedError";
  }
}

/**
 * Thrown when a polled request passed its deadline (`expired_token`).
 * Only ever raised on the provider's say-so. A client-side timer is a courtesy to the user and never the verdict - see `pollUntilResolved`.
 */
export class AuthorizationExpiredError extends AuthError {
  constructor(
    message: string,
    public expiresAt?: number,
  ) {
    super(message, "EXPIRED_TOKEN");
    this.name = "AuthorizationExpiredError";
  }
}

/**
 * Thrown when an escalation request fails for a reason that is neither a denial nor an expiry - a rejected signature, an unknown method, a subject mismatch, a transport error.
 */
export class EscalationError extends AuthError {
  constructor(
    message: string,
    public error?: string,
  ) {
    super(message, "ESCALATION_FAILED");
    this.name = "EscalationError";
  }
}

/**
 * Thrown when the device authorization grant fails outside the polled vocabulary - the client is not registered for the grant, the device code was already redeemed, etc.
 */
export class DeviceFlowError extends AuthError {
  constructor(
    message: string,
    public error?: string,
  ) {
    super(message, "DEVICE_FLOW_FAILED");
    this.name = "DeviceFlowError";
  }
}

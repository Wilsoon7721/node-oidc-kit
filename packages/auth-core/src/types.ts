import type { ClaimSelector } from "./claims";
import type { ProviderProfile } from "./profile";

/**
 * Everything the library needs to talk to one identity provider as one registered client.
 *
 * Only `clientId` and `issuer` are always required; the rest are needed per use case, and
 * each says below which. The same object is accepted by `@wilsoon/auth-next`'s
 * `getSession()`, `requireSession()` and `createAuthMiddleware()`, so an application
 * normally defines it once and imports it everywhere.
 */
export interface AuthConfig {
  /** The client identifier registered with the provider. */
  clientId: string;
  /**
   * The provider's base URL, e.g. `https://id.example.com`.
   *
   * Discovery appends `/.well-known/openid-configuration` to it, and the `issuer` the
   * document advertises must match this value or the client refuses to start - see
   * {@link AuthConfig.expectedIssuer} for the deliberate-mismatch case.
   */
  issuer: string;
  /**
   * The URI where the user is redirected after successful authentication.
   *
   * Required to start a login or exchange a code; optional for a client that only verifies
   * tokens (middleware, a resource server), which has no redirect of its own.
   */
  redirectUri?: string;
  /**
   * Scopes to request (default `['openid', 'profile', 'email']`).
   *
   * Add `offline_access` if you want a refresh token; without one, the session ends when
   * the access token expires.
   */
  scope?: string[];
  /**
   * Cookie domain, for adapters and middleware that write cookies. A leading-dot domain
   * (`.example.com`) shares the session across subdomains.
   *
   * @deprecated Since 3.0.0 - core writes no cookies. Set `cookieDomain` on the `@wilsoon/auth-next` middleware options or `ServerCookieStorage` instead.
   */
  cookieDomain?: string;
  /**
   * The client secret, for confidential clients. Server-side only - never ship this to a
   * browser.
   *
   * Required for {@link AuthClient.introspectToken}, and for anything a profile builds on it.
   */
  clientSecret?: string;
  /**
   * Optional override for the `iss` value that tokens are validated against.
   *
   * By default the library requires the discovery document's `issuer` to match
   * {@link AuthConfig.issuer} and validates tokens against it. Set this only when the
   * provider deliberately advertises an issuer that differs from the base URL you
   * connect to.
   */
  expectedIssuer?: string;
  /**
   * The audience that access tokens are expected to carry (the resource server
   * identifier, e.g. `https://api.example.com`).
   *
   * Required by {@link AuthClient.verifyAccessToken} unless the audience is passed per
   * call. There is deliberately no default: a provider may issue access tokens with an
   * audience shared across applications, so each resource server must pin what it accepts.
   */
  apiAudience?: string;
  /** Leeway, in seconds, applied to `exp`/`nbf` checks during verification (default 60). */
  clockToleranceSeconds?: number;
  /**
   * How long a resolved platform session may be reused before it is re-checked with the provider, in seconds (default 0).
   *
   * @deprecated Since 3.0.0 - pass `platformSessionCacheSeconds` to the WilsoonID profile, which still reads this as a fallback.
   */
  platformSessionCacheSeconds?: number;
  /** Tuning for the cached remote JSON Web Key Set. */
  jwks?: JwksOptions;
  /**
   * Decides whether verified access token claims describe a machine (`client_credentials`) caller rather than a user.
   *
   * Overrides the profile's `isMachineToken` and the built-in check, which recognises an RFC 9068 `sub` equal to `client_id`.
   * Set this for a provider that marks machine tokens some other way - returning `false` for a token that really is one lets a `client_id` reach code written for users.
   */
  detectMachineToken?: (claims: Readonly<Record<string, unknown>>) => boolean;
  /**
   * Base URL of the provider's method-escalation API (default `<issuer>/api/escalate`).
   *
   * @deprecated Since 3.0.0 - pass `escalationEndpoint` to the WilsoonID profile, which still reads this as a fallback.
   */
  escalationEndpoint?: string;
  /**
   * Resolves the user's current `session_version` from your backend.
   *
   * @deprecated Since 3.0.0 - pass `resolveSessionVersion` to the WilsoonID profile, which still reads this as a fallback.
   */
  resolveSessionVersion?: (userId: string) => Promise<number | null | undefined> | number | null | undefined;
  /**
   * Where verified tokens carry the user's roles, e.g. `"roles"` (Entra ID) or `"resource_access.my-app.roles"` (Keycloak).
   * Unset means {@link AuthenticatedUser.roles} is empty unless the profile fills it.
   */
  rolesClaim?: ClaimSelector;
  /**
   * Where verified tokens carry the user's permissions, e.g. `"permissions"` (Auth0, WilsoonID).
   * Unset means {@link AuthenticatedUser.permissions} is empty unless the profile fills it.
   */
  permissionsClaim?: ClaimSelector;
  /**
   * Prefix for the names the client stores its tokens and transient values under (default `"oidc_"`).
   * Changing it on a live app signs every user out, because their stored tokens sit under the old names.
   */
  storagePrefix?: string;
  /** The provider profile: claim mapping, storage names and provider-specific functions. See `createAuthClient`. */
  profile?: ProviderProfile<string, object>;
}

/** Tuning options for the remote JWKS used to verify token signatures. */
export interface JwksOptions {
  /** How long a fetched key set is reused before refetching, in ms (default 600000). */
  cacheMaxAgeMs?: number;
  /** Minimum interval between key-set refetches, in ms (default 30000). */
  cooldownMs?: number;
  /** Timeout for the key-set request, in ms (default 5000). */
  timeoutMs?: number;
}

/**
 * The subset of OIDC discovery metadata this library reads.
 *
 * The five non-optional fields are required: discovery fails if the provider omits any of
 * them. The optional ones each unlock a feature - no `end_session_endpoint` means no
 * RP-initiated logout, no `introspection_endpoint` means no live revocation checks.
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
  /** Optional URL of the server's RFC 8628 device authorization endpoint. */
  device_authorization_endpoint?: string;
  /** Grant types the provider advertises. */
  grant_types_supported?: string[];
  /** Authentication context class references the provider advertises. */
  acr_values_supported?: string[];
  /** Signing algorithms the provider advertises for ID tokens. */
  id_token_signing_alg_values_supported?: string[];
  /** Scopes the provider advertises. */
  scopes_supported?: string[];
  /** PKCE challenge methods the provider advertises. */
  code_challenge_methods_supported?: string[];
}

/** A successful token endpoint response, as returned by a code exchange or a refresh. */
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
 * The two legacy WilsoonID roles.
 *
 * @deprecated Since 3.0.0 - core no longer models a provider's role vocabulary. Read {@link AuthenticatedUser.roles} or {@link AuthenticatedUser.permissions} instead.
 */
export type UserRole = "admin" | "user";

/** @deprecated Since 3.0.0 - see {@link UserRole}. */
export const USER_ROLES: readonly UserRole[] = ["admin", "user"];

/**
 * Profile claims returned by the OIDC userinfo endpoint.
 *
 * These are display-level attributes only. The userinfo endpoint does **not** return
 * `role`, `amr` or `session_version`, so this type deliberately has no field that can be
 * used to make an authorization decision. Use {@link AuthClient.verifyIdToken} - which
 * returns an {@link AuthenticatedUser} - when you need to authorize.
 */
export interface ProfileUser {
  /** The unique identifier for the user (the `sub` claim). */
  id: string;
  /** The user's primary email address, when the `email` scope was granted. */
  email?: string;
  /** Whether the provider considers the email address verified. */
  emailVerified?: boolean;
  /** The user's name or friendly nickname, when the `profile` scope was granted. */
  name?: string;
  /** URL of the user's avatar, when the `profile` scope was granted. */
  picture?: string;
}

/**
 * A user identity derived from an ID token whose signature, issuer, audience and expiry
 * have all been verified against the provider's JWKS.
 *
 * This is the only type in the library that is safe to authorize on.
 */
export interface AuthenticatedUser extends ProfileUser {
  /** Roles read through {@link AuthConfig.rolesClaim} or the profile. Empty unless one of them is configured. */
  roles: string[];
  /**
   * Permissions read through {@link AuthConfig.permissionsClaim} or the profile. Empty unless one of them is configured.
   * When the session's access token verifies and was issued to this client, its permissions are merged in, since many providers carry them only there.
   */
  permissions: string[];
  /**
   * The legacy WilsoonID role, set only by the `wilsoon()` profile.
   *
   * @deprecated Since 3.0.0 - use {@link AuthenticatedUser.roles} or {@link AuthenticatedUser.permissions}.
   */
  role?: UserRole;
  /** Authentication methods used for this session (the `amr` claim). Empty if absent. */
  authMethods: string[];
  /** The provider session this identity belongs to (the `sid` claim), when present. */
  sid?: string;
  /**
   * The WilsoonID session version, set only by the `wilsoon()` profile.
   *
   * @deprecated Since 3.0.0 - provider-specific; use the profile's `isSessionCurrent`.
   */
  sessionVersion?: number;
  /** The verified `iss` claim. */
  issuer: string;
  /** The verified audience: this client's ID for an ID token, the API audience for a platform session. */
  audience: string;
  /**
   * Where the identity came from - a verified ID token, or a verified access token whose
   * authorization claims were resolved by introspection.
   */
  source?: "id_token" | "access_token";
  /** The `iat` claim, in seconds since the epoch. */
  issuedAt?: number;
  /** The verified `exp` claim, in seconds since the epoch. */
  expiresAt: number;
  /** The `auth_time` claim, in seconds since the epoch, when present. */
  authTime?: number;
  /** The `nonce` claim, when present. */
  nonce?: string;
  /** All verified claims, for provider-specific fields not modelled above. */
  claims: Readonly<Record<string, unknown>>;
}

/**
 * The shape returned by the unverified decode helpers.
 *
 * Only for display and debugging - never authorize on it. Authorize on {@link AuthenticatedUser}.
 */
export interface UnverifiedUser {
  /** The `id`/`sub` claim as it appeared in the token, if any. */
  id?: string;
  /** The `email` claim as it appeared in the token, if any. */
  email?: string;
  /** The `name` claim as it appeared in the token, if any. */
  name?: string;
  /** The `picture` claim as it appeared in the token, if any. */
  picture?: string;
  /** The raw `role` claim. Not validated, not verified - never authorize on this. */
  role?: string;
  /** The raw `amr` claim. Not validated, not verified. */
  authMethods: string[];
  /** The raw `session_version` claim. Not validated, not verified. */
  sessionVersion?: number;
}

/**
 * Who an access token represents.
 *
 * `'user'` is a token generated through a flow where somebody authenticated - the authorization code grant, a refresh, or the device grant.
 * `'client'` is a `client_credentials` token, where the caller is a server acting as itself and no user exists anywhere in the exchange.
 *
 * The distinction is load-bearing rather than descriptive: the two carry the same shape and the same signature, but a machine token's `sub` is a `client_id`.
 * Code that resolves `sub` to a person must know which it is holding.
 */
export type TokenUse = "user" | "client";

/**
 * A verified `client_credentials` access token: a client that authenticated as itself.
 *
 * Deliberately **not** assignable to {@link AuthenticatedUser}. It has no `id`, no `role` and no `authMethods`, because there is no user.
 * Where an application handles both, it should branch on the type.
 */
export interface MachineClient {
  /** The `client_id` the token was issued to (its `sub`, and its `client_id` claim). */
  clientId: string;
  /** Always `'client'`, so a discriminated union with a user session narrows cleanly. */
  tokenUse: "client";
  /** The verified `iss` claim. */
  issuer: string;
  /** The verified `aud` claim(s) - the API audience the token may be presented to. */
  audience: string[];
  /** The `iat` claim, in seconds since the epoch. */
  issuedAt?: number;
  /**
   * The verified `exp` claim, in seconds since the epoch.
   *
   * The provider takes the lifetime from the application's `auth_flow_duration` (15 minutes by default).
   * Note that an issued machine token **cannot be revoked** - the grant does not generate a refresh token for RFC 7009 to act on, so rotating the client secret stops new issuance without killing what is already out.
   * A short lifetime is the only real control, which makes this value worth respecting rather than caching past.
   */
  expiresAt: number;
  /** The `jti` claim, when present. */
  jwtId?: string;
  /** All verified claims. */
  claims: Readonly<Record<string, unknown>>;
}

/** Verified claims of an access token. */
export interface AccessTokenClaims {
  /**
   * The subject the token was issued for.
   *
   * For a user token this is the user's identifier. For a machine token
   * ({@link AccessTokenClaims.tokenUse} `=== 'client'`) it is the **`client_id`** - check
   * {@link AccessTokenClaims.tokenUse} before treating it as a person.
   */
  subject: string;
  /**
   * Who the token represents: a user who authenticated, or a client acting as itself through the `client_credentials` grant.
   * Decided by {@link AuthConfig.detectMachineToken}, then the profile's `isMachineToken`, then RFC 9068's `sub === client_id`; `'user'` otherwise.
   */
  tokenUse: TokenUse;
  /** The client the token was issued to, when the provider includes it. */
  clientId?: string;
  /** Granted scopes, split from the `scope` claim. */
  scopes: string[];
  /** Roles read through {@link AuthConfig.rolesClaim} or the profile. */
  roles: string[];
  /** Permissions read through {@link AuthConfig.permissionsClaim} or the profile. */
  permissions: string[];
  /** The provider session the token belongs to (the `sid` claim), when present. */
  sid?: string;
  /** The verified `iss` claim. */
  issuer: string;
  /** The verified `aud` claim(s). */
  audience: string[];
  /** The `iat` claim, in seconds since the epoch. */
  issuedAt?: number;
  /** The verified `exp` claim, in seconds since the epoch. */
  expiresAt: number;
  /** The `jti` claim, when present. */
  jwtId?: string;
  /** All verified claims. */
  claims: Readonly<Record<string, unknown>>;
}

/**
 * An RFC 7662 token introspection response.
 * Fields past the RFC's own (`role`, `session_version`, `permissions`, `sid`) are provider extensions and may be absent.
 */
export interface IntrospectionResponse {
  /** Whether the provider considers the token usable right now. */
  active: boolean;
  /** The subject the token was issued for. */
  sub?: string;
  /** The client the token was issued to. */
  client_id?: string;
  /** `Bearer` for an access token, `id_token` for an ID token. */
  token_type?: string;
  /** Space-delimited granted scopes. */
  scope?: string;
  /** The token's audience. */
  aud?: string | string[];
  /** The token's issuer. */
  iss?: string;
  /** Expiry, in seconds since the epoch. */
  exp?: number;
  /** Issued-at, in seconds since the epoch. */
  iat?: number;
  /** The token's unique identifier. */
  jti?: string;
  /** When the user authenticated, in seconds since the epoch. */
  auth_time?: number;
  /** Authentication methods used. */
  amr?: string[];
  /** The user's current role, read from their record rather than the token. */
  role?: string;
  /** The user's current session version. */
  session_version?: number;
  /** The session version asserted by the introspected token, when it carried one. */
  token_session_version?: number;
  /** `"client"` when the token came from the `client_credentials` grant; absent otherwise. */
  token_use?: string;
  /** What the user holds right now for the calling client, when the provider answers live. */
  permissions?: string[];
  /** The provider session the token belongs to. */
  sid?: string;
  /** Any additional fields the provider returns. */
  [claim: string]: unknown;
}

/** Options for {@link AuthClient.verifyIdToken}. */
export interface VerifyIdTokenOptions {
  /**
   * The nonce that was sent on the authorization request. When provided it must match the token's `nonce` claim, which is what binds the token to your request.
   */
  nonce?: string;
  /** Reject the token if `auth_time` is older than this many seconds (step-up checks). */
  maxAuthAgeSeconds?: number;
  /**
   * Require the token's `acr` claim to be one of these values.
   * Requesting `acr_values` is a demand the provider is free to ignore, and one that ignores it returns a perfectly valid token describing a weaker authentication. Checking here is what turns the request into a guarantee.
   */
  requiredAcr?: string | string[];
}

/** Options for {@link AuthClient.verifyAccessToken}. */
export interface VerifyAccessTokenOptions {
  /**
   * The audience this resource server accepts. Falls back to
   * {@link AuthConfig.apiAudience}; verification throws if neither is set.
   */
  audience?: string | string[];
  /** Scopes that must all be present on the token. */
  requiredScopes?: string[];
  /**
   * Accept a `client_credentials` machine token (default `false`).
   * A machine token is refused with {@link MachineTokenNotAllowedError}. This fails closed on purpose: a machine token's `sub` is a `client_id`, and an endpoint written for users would otherwise treat it as one.
   * Turn it on only where the caller genuinely handles both and separate it based on {@link AccessTokenClaims.tokenUse} when it does.
   */
  allowMachineTokens?: boolean;
}

/** Options for {@link AuthClient.verifyPlatformSession}. */
export interface PlatformSessionOptions {
  /** Overrides {@link AuthConfig.platformSessionCacheSeconds} for this call. */
  cacheSeconds?: number;
  /** Skip the cache and re-check with the provider. */
  force?: boolean;
}

/** Options for {@link AuthClient.createAuthorizeUrl}. */
export interface AuthorizeUrlOptions {
  /**
   * Persist `state`, `nonce` and the PKCE verifier through the configured storage so that {@link AuthClient.handleCallback} can validate the callback.
   *
   * Defaults to `true` when the client has usable storage, `false` otherwise (in which case the caller must persist the returned values itself).
   * Passing `true` without usable storage throws.
   */
  persist?: boolean;
  /** Overrides the configured scopes for this request. */
  scope?: string[];
  /** OIDC `prompt` value: `none`, `login`, `consent` or `select_account`. Prefer `silentAuthorize()` over `none`. */
  prompt?: string;
  /** OIDC `acr_values`, used to request a stronger authentication context. */
  acrValues?: string | string[];
  /**
   * OIDC `max_age`: the maximum age, in seconds, of the authentication the client will accept.
   *
   * `0` demands a fresh authentication outright. The provider must then return `auth_time` in the ID token, so pass the same number to {@link VerifyIdTokenOptions.maxAuthAgeSeconds} on the way back - the request is a demand, and only the check makes it a guarantee.
   */
  maxAge?: number;
  /** OIDC `login_hint`. */
  loginHint?: string;
  /** Additional authorization request parameters. */
  extraParams?: Record<string, string>;
}

/** The authorization request created by {@link AuthClient.createAuthorizeUrl}. */
export interface AuthorizeRequest {
  /** The URL to send the user agent to. */
  url: string;
  /** The CSRF `state` value; must be echoed back on the callback. */
  state: string;
  /** The `nonce` bound into the ID token; must be checked on verification. */
  nonce: string;
  /** The PKCE code verifier to present at the token endpoint. */
  codeVerifier: string;
}

/** Options for {@link AuthClient.handleCallback}. */
export interface HandleCallbackOptions {
  /**
   * Values captured at authorize time. Supply these when your app persists them itself (for example in a server-side cookie) instead of through the library's storage.
   */
  expected?: {
    state?: string | null;
    codeVerifier?: string | null;
    nonce?: string | null;
  };
  /** Persist the token response through {@link AuthClient.saveTokens} (default false). */
  persistTokens?: boolean;
  /** Remove the transient state/nonce/verifier entries afterwards (default true). */
  clearTransient?: boolean;
}

/** The result of a completed authorization code callback. */
export interface CallbackResult {
  /** The token response from the token endpoint. */
  tokens: TokenResponse;
  /** The verified identity from the ID token, or `null` for non-OIDC (no `id_token`) flows. */
  user: AuthenticatedUser | null;
  /** The validated `state` value. */
  state: string;
}

/** Options for {@link AuthClient.silentAuthorize}. */
export interface SilentAuthorizeOptions extends Omit<AuthorizeUrlOptions, "prompt" | "persist"> {
  /**
   * `"iframe"` (default) runs the request in a hidden iframe and resolves with the result; `"redirect"` navigates the page itself.
   * After a redirect, finish with `handleCallback()` and treat {@link isSilentAuthError} as "not signed in".
   */
  mode?: "iframe" | "redirect";
  /** How long the iframe may take before the attempt counts as "not signed in", in ms (default 10000). */
  timeoutMs?: number;
}

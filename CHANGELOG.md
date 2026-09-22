# Changelog

The three original packages (`@wilsoon/auth-core`, `@wilsoon/auth-react`,
`@wilsoon/auth-next`) are versioned together. `@wilsoon/auth-machine` has no dependency on
them and is versioned independently, starting at 0.x.

## 2.3.0

One fix, in the Next.js middleware: it was ending the sessions it was meant to be keeping.

### Fixed - `@wilsoon/auth-next`

- **`createAuthMiddleware()` no longer refreshes from every request in parallel.** A refresh
  token is single-use under rotation, so a page load putting ten requests through the
  middleware with one cookie sent ten refreshes, nine of them presenting a token that had just
  been rotated away. A provider that reads that as reuse revokes the whole family, which turned
  a fortnight-long session into a daily re-login. Refreshes now begin
  `refreshThresholdSeconds` before expiry (default 300) and only on navigations - one per page
  load. A token with nothing left still refreshes from any request, so an app that only sends
  fetches keeps renewing.
- **A failed refresh no longer ends a live session.** An unreachable provider, or a sibling
  request that rotated the same token a moment earlier, signed the user out. While the access
  token is still valid the request carries on and a later one retries; a spent token still signs
  out.

### Added - `@wilsoon/auth-next`

- `refreshThresholdSeconds` and `refreshOn` (`"navigation"` by default, or `"request"`) on
  `AuthMiddlewareOptions`.

## 2.2.0

Three flows past authorization-code-plus-PKCE, a new package for the last of them, and
step-up that works against a provider other than the reference one.

### Added - `@wilsoon/auth-core`

- `reauthorize(use, force, options)` - method escalation (step-up), with
  `createEscalation()`, `pollEscalation()` and `verifyEscalationToken()` underneath for
  callers that need to own the loop.
- `authorizeDevice(options)` - the RFC 8628 device authorization grant, with
  `requestDeviceCode()` and `pollDeviceToken()` underneath. Reads
  `device_authorization_endpoint` from discovery.
- `verifyMachineToken()` - verifies a `client_credentials` token and returns a
  `MachineClient`, which deliberately has no `id`, `role` or `authMethods`. Refuses user
  tokens, so the check runs in both directions.
- `tokenUse` on `AccessTokenClaims`, and `isMachineToken(claims)`.
- `pollUntilResolved()` and the polling types, shared by escalation and the device grant -
  the provider answers both with the same RFC 8628 vocabulary, so one state machine drives
  both.
- `escalationEndpoint` on `AuthConfig`, since escalation is not an OIDC endpoint and cannot
  be discovered.
- Errors: `MachineTokenNotAllowedError`, `NotAMachineTokenError`,
  `AuthorizationDeniedError`, `AuthorizationExpiredError`, `EscalationError`,
  `DeviceFlowError`.

### Changed - `@wilsoon/auth-core`

Both changes tighten what is accepted. Neither removes or renames anything.

- **`verifyAccessToken()` refuses `client_credentials` tokens by default.** A machine token
  verifies identically to a user token but its `sub` is a `client_id`, so an endpoint that
  resolves `sub` to a person would have accepted a client dressed as a user. Pass
  `allowMachineTokens: true` and branch on `tokenUse` to serve both.
  `verifyPlatformSession()`, `resolveSession()` and `isSessionCurrent()` refuse outright -
  there is no user to resolve a session for, and nothing to revoke against.
- **`verifyIdToken()` refuses any token carrying an `evt` claim.** An escalation token is
  RS256, from the same issuer, audienced to the same client; `evt` was the only thing
  separating a proof that one action was authorised from a proof that a user is signed in.
  Real ID tokens never carry `evt`.

### Added - step-up, the portable way (`auth-core`, `auth-react`)

`acr_values` alone was not enough to do step-up against a provider other than the reference
one, and the two additions below are what a stranger's provider actually supports.

- `maxAge` on `createAuthorizeUrl()`, sending OIDC Core's `max_age`. `0` demands a fresh
  authentication.
- `readAuthenticationChallenge()`, `buildAuthenticationChallenge()` and `isStepUpChallenge()` -
  RFC 9470's `WWW-Authenticate` challenge, both the parsing and the emitting half, so a
  resource server and a client can agree on one header.
- `createStepUpRequest(challenge)`, turning a challenge into the authorization request that
  answers it. Only `acr_values` and `max_age` cross over: a `scope` from the same header would
  let a resource server widen what the client requests on the user's behalf.
- `requiredAcr` on `verifyIdToken()`, rejecting a token whose `acr` is not one the caller
  accepts.
- `maxAge` on `@wilsoon/auth-react`'s `login()`, so a React app can ask how *recent* an
  authentication must be and not only how strong.

### Changed - machine token detection no longer fails open

`isMachineToken()` recognised only `token_use: "client"`, a vendor claim rather than a
registered one. Against a provider that does not emit it, every machine token read as a user
token - the exact confusion the check exists to prevent, failing in the unsafe direction and
silently.

It now also accepts an RFC 9068 `sub` equal to `client_id`, which holds on any provider
following that profile, and `AuthConfig.detectMachineToken` overrides both for a provider that
marks them some other way.

### Added - `@wilsoon/auth-machine` 0.1.0, fixed in 0.1.1

New package, server-only, zero dependencies. Obtains `client_credentials` tokens; the
grant is a form POST, and the package exists for what surrounds it - single-flight so
concurrent callers on a cold cache produce one token request, refresh-ahead at 75% of the
lifetime rather than at `exp`, and exactly one forced retry on a 401.

Verification stays in `@wilsoon/auth-core`: this package only obtains tokens.

## 2.0.0

The theme of this release: **you cannot authorize on a claim nobody verified.** In 1.x the
only way to reach `role`, `amr` and `session_version` was `parseIdToken()`, which decoded
the token without checking its signature - so those values were attacker-controlled. Anyone
could mint a JWT with `role: "admin"` and an empty signature. 2.0 makes the verified path
the easy path and the unverified path impossible to take by accident.

**Nothing was removed.** Every 1.x call still compiles and runs; the unsafe ones now warn
once per process. See [migrating](#migrating-from-1x) below.

### Added

- `verifyIdToken()` - signature (RS256 against the provider's JWKS), `iss`, `aud`, `exp`
  and `nonce` in one pass. The only method that returns authorization claims.
- `verifyAccessToken()` - for resource servers, with a pinned audience and required scopes.
- `verifyPlatformSession()` / `resolveSession()` - resolve a session from a domain-wide
  cookie whose ID token belongs to a sibling service, via the shared-audience access token
  plus RFC 7662 introspection.
- `handleCallback()` - validates `state`, exchanges the code with its PKCE verifier,
  verifies the ID token, clears transient state. Replaces four separate calls.
- `introspectToken()` and `isSessionCurrent()` - live revocation checks, so "sign out
  everywhere" takes effect before token expiry.
- `nonce` on every authorization request, generated, persisted and checked by the library.
- `satisfiesAmr()` / `assertAmr()` and the `AMR` constants, for step-up policies.
- `hydrateSession()` - restores browser session state when the token cookie is `HttpOnly`.
- `MemoryStorage`, `UnavailableStorage`, and `ServerCookieStorage` (`@wilsoon/auth-next`).
- `getSession()`, `requireSession()`, `createAuthMiddleware()` in `@wilsoon/auth-next`.
- Single-flight token refresh, so parallel refreshes cannot revoke each other's token
  family.
- A JWKS cache that self-invalidates once (rate-limited) on a signature failure, so a key
  rotation that reuses its `kid` costs one refetch instead of an outage.

### Changed

- `AuthenticatedUser`, `ProfileUser` and `UnverifiedUser` replace the single `User` type.
  `User` remains exported as an alias of `AuthenticatedUser`.
- `getUser()` / `hydrateSession()` return `ProfileUser`, which has no `role` field -
  authorizing on a userinfo response is now a compile error rather than a silent
  `undefined`.
- `role` is validated against `USER_ROLES` rather than asserted. An unrecognised value
  throws `ClaimValidationError`; an absent one falls back to `'user'`.
- `createAuthorizeUrl()` persists `state`, `nonce` and the PKCE verifier when storage is
  available, and returns all three. Pass `{ persist: false }` to manage them yourself.
- Signature verification is restricted to an `RS256` allowlist, so `alg: "none"` and HMAC
  confusion are rejected outright.
- The server-side storage default is `UnavailableStorage`, which throws a
  `StorageUnavailableError` naming the operation and the fix. It was `{} as AuthStorage`,
  which type-checked as valid and then died with `TypeError: setItem is not a function`.

### Fixed

- `error instanceof StateMismatchError` (and every other subclass check) returned `false`.
  The base class pinned `AuthError.prototype` instead of `new.target.prototype`.
- `isTokenExpired()` reported a token with no `exp` claim as valid forever. Renamed to
  `isTokenNearExpiry()`, and it now fails closed.
- Rotated refresh tokens were dropped rather than written back to storage.
- `require('crypto')` fallbacks threw `ReferenceError` in ESM and on Workers instead of
  degrading. A runtime without Web Crypto now fails with `CryptoUnavailableError`.

### Deprecated

Still functional, warns once per process:

| Deprecated         | Use instead                                                         |
| ------------------ | ------------------------------------------------------------------- |
| `parseIdToken()`   | `verifyIdToken()` to authorize, `decodeIdTokenUnsafe()` for display |
| `isTokenExpired()` | `isTokenNearExpiry()`                                               |
| `User`             | `AuthenticatedUser` / `ProfileUser` / `UnverifiedUser`              |
| `CookieStorage`    | `hydrateSession()`, or a server-side cookie adapter                 |

### Migrating from 1.x

1. **Authorize on `verifyIdToken()`.**

   ```diff
   - const user = client.parseIdToken(tokens.id_token);
   + const user = await client.verifyIdToken(tokens.id_token);
     if (user.role === 'admin') { /* ... */ }
   ```

2. **Collapse the callback into one call.**

   ```diff
   - client.validateState(returnedState, storedState);
   - const tokens = await client.exchangeCodeForToken(code, verifier);
   - const user = client.parseIdToken(tokens.id_token);
   + const { tokens, user } = await client.handleCallback(request.url);
   ```

3. **Stop reading `.role` off `getUser()` / `hydrateSession()`.** It is a compile error now.
   At runtime it was always `undefined`, because the userinfo endpoint never returned it -
   so any check built on it was already broken, and an inverted check
   (`if (user.role === 'user') restrict()`) was failing _open_.

4. **Pass storage to any client that persists.** `MemoryStorage`, a cookie adapter, or
   nothing at all if you never touch storage.

5. **Confirm your provider echoes `nonce`.** It is now sent on every authorization request
   and required on the ID token. A provider that ignores it will fail with
   `NonceMismatchError`.

## 1.x

Not documented here.

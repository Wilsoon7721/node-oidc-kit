# Changelog

All three packages (`@wilsoon/auth-core`, `@wilsoon/auth-react`, `@wilsoon/auth-next`) are
versioned together.

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
- `nonce` on every authorization request, generated, persisted and checked by the SDK.
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

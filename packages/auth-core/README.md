# @wilsoon/auth-core

The framework-agnostic core: an OpenID Connect **relying party** that runs unchanged in a
browser, in Node 18+, and on edge runtimes. Point it at any conforming issuer via discovery
and get back a verified user.

Part of the [Wilsoon Node OIDC Kit](https://github.com/Wilsoon7721/node-oidc-kit) - an OpenID Connect relying party for TypeScript.
Siblings: **`@wilsoon/auth-core`** · [`@wilsoon/auth-react`](https://www.npmjs.com/package/@wilsoon/auth-react) · [`@wilsoon/auth-next`](https://www.npmjs.com/package/@wilsoon/auth-next).

## Features

- **Isomorphic Architecture:** Runs seamlessly in the browser, Node.js 18+, and Edge environments.
- **Token verification:** RS256 signature verification against the provider's JWKS, with issuer, audience, expiry and nonce checks.
- **OIDC Discovery:** Automatically discovers authorization, token, userinfo and JWKS endpoints from the issuer.
- **PKCE + state + nonce:** Generated, persisted and validated by the SDK rather than by every consumer.
- **Token Management:** Handles token exchange, storage, and single-flight refresh with rotation support.

## Installation

```bash
npm install @wilsoon/auth-core
```

Wiring up a whole application? Start with the [integration guide](https://github.com/Wilsoon7721/node-oidc-kit/blob/main/INTEGRATION.md) - end-to-end recipes
for Next.js, React SPAs, other server frameworks and APIs, plus a troubleshooting table.

Using a framework with no package here (Astro, SvelteKit, Hono, Express)? Use this package
directly and supply one [storage adapter](https://github.com/Wilsoon7721/node-oidc-kit#storage-the-one-thing-to-understand). That is
the entire integration.

## Authorization in one call

`verifyIdToken()` is the only method that returns `role`, `authMethods` and `sessionVersion`, and it returns them **only after** verifying the token:

```typescript
import { AMR, AuthClient, MemoryStorage, satisfiesAmr } from "@wilsoon/auth-core";

const client = new AuthClient(
  {
    clientId: process.env.OIDC_CLIENT_ID!,
    issuer: "https://id.example.com",
    redirectUri: "https://app.example.com/callback",
  },
  new MemoryStorage(),
);

// Signature (JWKS/RS256) + iss + aud + exp are all checked here.
const user = await client.verifyIdToken(idToken);

if (user.role !== "admin") return deny();
if (!satisfiesAmr(user, [AMR.FIDO])) return stepUp();
return allow();
```

Nothing else in the SDK is a substitute for this. The userinfo endpoint returns display claims only, and the decode helpers verify nothing at all - see [Which method returns what](#which-method-returns-what).

## Several services, one login

When first-party services share one domain-wide session cookie (set on `.example.com`, say),
that cookie holds the tokens of whichever service most recently completed a code exchange. Each service is its own client, so
the ID token inside it is addressed to that service alone - the access token is the one addressed
to the whole platform.

`verifyPlatformSession()` resolves a session from it: verify the access token, then take
`role`/`amr`/`session_version` from introspection, which is live rather than as-minted.

```typescript
const user = await client.verifyPlatformSession(tokens.access_token);
user.source; // 'access_token'
```

Needs `apiAudience` and a `clientSecret`. Set `platformSessionCacheSeconds` to reuse a resolved
session briefly instead of introspecting on every request. `@wilsoon/auth-next`'s `getSession()`
picks this path automatically when the cookie's ID token belongs to a sibling service - see the
[integration guide](https://github.com/Wilsoon7721/node-oidc-kit/blob/main/INTEGRATION.md#two-session-models--pick-yours-first).

## The login flow

### 1. Start the authorization request

```typescript
const { url } = await client.createAuthorizeUrl();
// state, nonce and the PKCE verifier have been persisted through the client's storage.
redirect(url);
```

`state` (CSRF), `nonce` (ID token replay) and the PKCE verifier are generated and stored for you. If the client has no storage, they are returned for you to persist and the call warns rather than losing them silently.

### 2. Complete the callback

```typescript
const { tokens, user } = await client.handleCallback(request.url);
// state validated, code exchanged with the PKCE verifier,
// ID token verified and bound to this request's nonce.
```

One call, so there is no half-implemented version of it. If you persist the transient values yourself (a server-side cookie, for instance), pass them in:

```typescript
const { tokens, user } = await client.handleCallback(request.url, {
  expected: { state, nonce, codeVerifier },
});
```

### 3. Resource servers

Access tokens are issued with an audience shared across applications, so each resource server pins the audience it accepts:

```typescript
const claims = await client.verifyAccessToken(bearerToken, {
  audience: "https://api.example.com",
  requiredScopes: ["openid"],
});
```

## Which method returns what

| Method                                      | Verified?                                           | Returns                                                                | Safe to authorize on                 |
| ------------------------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------ |
| `verifyIdToken(idToken)`                    | signature, `iss`, `aud`, `exp`, `nonce`             | `AuthenticatedUser` - includes `role`, `authMethods`, `sessionVersion` | **Yes**                              |
| `verifyPlatformSession(accessToken)`        | signature, `iss`, `aud`, `exp` + live introspection | `AuthenticatedUser` with live `role`                                   | **Yes**                              |
| `verifyAccessToken(token, { audience })`    | signature, `iss`, `aud`, `exp`, scopes              | `AccessTokenClaims`                                                    | **Yes** (subject + scopes)           |
| `handleCallback(url)`                       | everything `verifyIdToken` checks, plus `state`     | `{ tokens, user }`                                                     | **Yes**                              |
| `getUser(accessToken)` / `hydrateSession()` | the provider validates the token                    | `ProfileUser` - `id`, `email`, `name`, `picture` only                  | No - carries no authorization claims |
| `decodeIdTokenUnsafe(idToken)`              | **nothing**                                         | `UnverifiedUser`                                                       | **No**                               |
| `parseIdToken(idToken)` _(deprecated)_      | **nothing**                                         | `UnverifiedUser`                                                       | **No**                               |
| `isTokenNearExpiry(token)`                  | **nothing**                                         | `boolean` refresh hint                                                 | No                                   |

`ProfileUser` has no `role` field at all, so authorizing on a userinfo result is a compile error rather than a silent `undefined`.

## Authentication methods (`amr`)

Which `amr` values a provider emits is up to that provider; `satisfiesAmr()` compares plain
strings, so any vocabulary works. The reference provider composes them like this:

| Login                       | `amr`                    |
| --------------------------- | ------------------------ |
| Federated / social provider | `["ext", "social"]`      |
| Passkey                     | `["mfa", "fido", "hw"]`  |
| TOTP challenge completed    | adds `"otp"` and `"mfa"` |

`mfa` therefore does **not** imply a hardware factor - require `AMR.FIDO`/`AMR.HARDWARE` explicitly when you mean phishing-resistant:

```typescript
satisfiesAmr(user, [AMR.MFA]); // passkey *or* TOTP
satisfiesAmr(user, [AMR.FIDO, AMR.HARDWARE]); // passkey only
satisfiesAmr(user, [AMR.OTP, AMR.FIDO], { mode: "any" });
assertAmr(user, [AMR.FIDO]); // throws ClaimValidationError
```

## Session revocation

A JWT stays valid until it expires, so "sign out everywhere" does not take effect on its own.
The reference provider bumps a per-user session version on revocation, and the ID token carries
the version it was minted with. Comparing the two is what makes revocation enforceable - supply
a resolver so the SDK can read the live value:

```typescript
const client = new AuthClient({
  ...config,
  resolveSessionVersion: (userId) => myApi.getSessionVersion(userId),
});

if (!(await client.isSessionCurrent(user))) return reauthenticate();
```

With a confidential client you can skip the resolver and let the provider answer, via RFC 7662
introspection:

```typescript
if (!(await client.isSessionCurrent(user, { token: idToken }))) return reauthenticate();

// Or directly - also the way an API learns the live `role`, which access tokens do not carry:
const info = await client.introspectToken(accessToken);
```

Without either route, `isSessionCurrent()` throws `SessionCheckUnavailableError` - it never assumes the session is current.

## Token refresh

```typescript
const tokens = await client.refreshAccessToken(refreshToken);
```

The provider rotates refresh tokens and revokes the whole family if one is replayed. Concurrent calls for the same token therefore share a single request, and the rotated response is written back automatically when the SDK is managing stored tokens (pass `{ persist: false }` to opt out, or `true` to force it).

## Storage

| Implementation        | Use                                                                                          |
| --------------------- | -------------------------------------------------------------------------------------------- |
| `BrowserStorage`      | Web Storage. Default in the browser; pass `window.sessionStorage` for transient login state. |
| `MemoryStorage`       | Tests, and server flows handled by one client instance. Not shared across processes.         |
| `ServerCookieStorage` | From `@wilsoon/auth-next` - HttpOnly cookies with hardened flags.                            |
| _(none)_              | Storage-backed calls throw `StorageUnavailableError` naming the operation and the fix.       |

## Errors

All errors extend `AuthError` and carry a stable `code`. `error instanceof StateMismatchError` now works (the base class used to overwrite subclass prototypes, making every specific check false).

`TokenVerificationError`, `ClaimValidationError`, `NonceMismatchError`, `StateMismatchError`, `IssuerMismatchError`, `AuthorizationResponseError`, `StorageUnavailableError`, `SessionCheckUnavailableError`, `CryptoUnavailableError`, `DiscoveryError`, `TokenExchangeError`, `TokenRefreshError`, `UserInfoError`, `LogoutError`, `NoTokenError`.

## Migrating from 1.x

Nothing was removed; the unsafe paths still work and now warn. The changes that need attention
(full notes in the [changelog](https://github.com/Wilsoon7721/node-oidc-kit/blob/main/CHANGELOG.md)):

1. **Authorize on `verifyIdToken()`.** `parseIdToken()` never checked a signature, so `role`/`authMethods` from it are attacker-controlled. It still decodes (for display), is `@deprecated`, warns once per process, and its return type is now `UnverifiedUser` with every security field optional.

   ```diff
   - const user = client.parseIdToken(tokens.id_token);
   - if (user.role === 'admin') { /* ... */ }
   + const user = await client.verifyIdToken(tokens.id_token);
   + if (user.role === 'admin') { /* ... */ }
   ```

2. **`getUser()` / `hydrateSession()` return `ProfileUser`.** Reading `.role`, `.authMethods` or `.sessionVersion` off them is now a compile error. At runtime those fields were always `undefined`/`[]`, because the userinfo endpoint never returned them - any check built on them was already broken, and inverted checks (`if (user.role === 'user') restrict()`) were failing open.

3. **`isTokenExpired()` no longer reports a token with no `exp` as valid.** It is renamed to `isTokenNearExpiry()`; the old name still works and warns.

4. **`createAuthorizeUrl()` persists `state`, `nonce` and the verifier** when storage is available, and returns `nonce` alongside `state` and `codeVerifier`. Pass `{ persist: false }` to keep managing them yourself.

5. **`AuthClient` needs storage for storage-backed calls.** Previously the server-side default was `{} as AuthStorage`, which type-checked and then threw `TypeError: this.storage.setItem is not a function`. Pass `MemoryStorage`, a cookie store, or nothing if you never touch storage.

6. **`User` is deprecated** in favour of `AuthenticatedUser` (verified), `ProfileUser` (userinfo) and `UnverifiedUser` (decoded). It remains exported as an alias of `AuthenticatedUser`.

7. **`role` is validated, not asserted.** An unrecognised value throws `ClaimValidationError`; an absent one falls back to the least-privileged `'user'`.

## Claim shapes

The token endpoint spreads identity claims flat onto the ID token (`role`, `amr`, `session_version`), while some documentation nests them under `oidc_fields`. Both shapes are read, with the nested one preferred when present. `sub` is always treated as the authoritative subject identifier.

## Roles

`UserRole` is `'admin' | 'user'`, and a `role` claim outside that set throws
`ClaimValidationError` rather than being asserted into the union - silently mapping an unknown
role onto a known one is how privilege escalations ship. A provider that issues other roles
needs `UserRole` and `USER_ROLES` in `types.ts` widened together. See
[the provider-specific list](https://github.com/Wilsoon7721/node-oidc-kit#things-that-are-still-specific-to-one-provider).

## Environments Supported

Node.js 18+, modern browsers, and edge runtimes - anything with the Web Crypto API on `globalThis.crypto` and `fetch`. The old `require('crypto')` fallbacks were removed: `require` does not exist in ESM or on Workers, so they threw `ReferenceError` instead of degrading. A runtime without Web Crypto now fails with `CryptoUnavailableError`.

Signature verification uses [`jose`](https://github.com/panva/jose), the package's only runtime dependency.

## License

[MIT](./LICENSE) - free use, forking and redistribution, with no warranty of any kind.

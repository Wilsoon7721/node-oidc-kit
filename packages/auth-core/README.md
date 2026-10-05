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
- **PKCE + state + nonce:** Generated, persisted and validated by the library rather than by every consumer.
- **Token Management:** Handles token exchange, storage, and single-flight refresh with rotation support.

## Installation

```bash
npm install @wilsoon/auth-core
```

Wiring up a whole application? Start with the [recipes](https://docs.wilsoon.dev/node-oidc-kit/recipes/nextjs) - end-to-end wiring
for Next.js, React SPAs, other server frameworks and APIs, plus a troubleshooting table.

Using a framework with no package here (Astro, SvelteKit, Hono, Express)? Use this package
directly and supply one [storage adapter](https://github.com/Wilsoon7721/node-oidc-kit#storage-the-one-thing-to-understand). That is
the entire integration.

## Authorization in one call

`verifyIdToken()` is the only method that returns `role`, `authMethods` and `sessionVersion`, and it returns them **only after** verifying the token:

```typescript
import { AMR, AuthClient, hasRole, MemoryStorage, satisfiesAmr } from "@wilsoon/auth-core";

const client = new AuthClient(
  {
    clientId: process.env.OIDC_CLIENT_ID!,
    issuer: "https://id.example.com",
    redirectUri: "https://app.example.com/callback",
    rolesClaim: "roles", // where your provider puts roles, if it does
  },
  new MemoryStorage(),
);

// Signature (JWKS/RS256) + iss + aud + exp are all checked here.
const user = await client.verifyIdToken(idToken);

if (!hasRole(user, "admin")) return deny();
if (!satisfiesAmr(user, [AMR.FIDO])) return stepUp();
return allow();
```

Nothing else in the library is a substitute for this. The userinfo endpoint returns display claims only, and the decode helpers verify nothing at all - see [Which method returns what](#which-method-returns-what).

## Several services, one login

When first-party services share one domain-wide session cookie (set on `.example.com`, say),
that cookie holds the tokens of whichever service most recently completed a code exchange. Each service is its own client, so
the ID token inside it is addressed to that service alone - the access token is the one addressed
to the whole platform.

How to resolve a session from that access token is up to the provider, so since 3.0 it is a
[provider profile](https://docs.wilsoon.dev/node-oidc-kit/core-concepts/your-own-provider)'s job.
`resolveSession()` hands a sibling service's session to the profile, and throws
`FOREIGN_SESSION` when there is none. The WilsoonID profile verifies the access token and takes
the current permissions from introspection, which is live rather than as-minted:

```typescript
import { createAuthClient } from "@wilsoon/auth-core";
import { wilsoon } from "@wilsoon/auth-provider-wilsoon";

const client = createAuthClient({ ...config, profile: wilsoon({ platformSessionCacheSeconds: 30 }) });
const user = await client.resolveSession(tokens);
```

Needs `apiAudience` and a `clientSecret`. `@wilsoon/auth-next`'s `getSession()` picks this path
automatically - see the [session models](https://docs.wilsoon.dev/node-oidc-kit/core-concepts/session-models).

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

| Method                                   | Verified?                                       | Returns                                                       | Safe to authorize on                 |
| ---------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------- | ------------------------------------ |
| `verifyIdToken(idToken)`                 | signature, `iss`, `aud`, `exp`, `nonce`         | `AuthenticatedUser` - `roles`, `permissions`, `authMethods`   | **Yes**                              |
| `verifyAccessToken(token, { audience })` | signature, `iss`, `aud`, `exp`, scopes          | `AccessTokenClaims` - `roles`, `permissions`, scopes          | **Yes**                              |
| `liveAccess(accessToken)`                | the provider, live (profile hook or RFC 7662)   | `LiveAccess` - `active`, plus current grants where available  | **Yes**                              |
| `handleCallback(url)`                    | everything `verifyIdToken` checks, plus `state` | `{ tokens, user }`                                            | **Yes**                              |
| `getUser(accessToken)`                   | the provider validates the token                | `ProfileUser` - `id`, `email`, `name`, `picture` only         | No - carries no authorization claims |
| `decodeIdTokenUnsafe(idToken)`           | **nothing**                                     | `UnverifiedUser`                                              | **No**                               |
| `isTokenNearExpiry(token)`               | **nothing**                                     | `boolean` refresh hint                                        | No                                   |

`ProfileUser` has no `roles` field at all, so authorizing on a userinfo result is a compile error rather than a silent empty list.

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
`liveAccess()` asks the provider whether a token is still good - through the profile's hook when
there is one, RFC 7662 introspection otherwise:

```typescript
const access = await client.liveAccess(tokens.access_token);
if (!access.active) return reauthenticate();
```

In Next.js, `enforce: "live"` on the middleware does this on every request. The WilsoonID
profile adds a `session_version` check, `client.wilsoon.isSessionCurrent(user)` - see the
[session models](https://docs.wilsoon.dev/node-oidc-kit/core-concepts/session-models).

## Token refresh

```typescript
const tokens = await client.refreshAccessToken(refreshToken);
```

The provider rotates refresh tokens and revokes the whole family if one is replayed. Concurrent calls for the same token therefore share a single request, and the rotated response is written back automatically when the library is managing stored tokens (pass `{ persist: false }` to opt out, or `true` to force it).

## Storage

| Implementation        | Use                                                                                          |
| --------------------- | -------------------------------------------------------------------------------------------- |
| `BrowserStorage`      | Web Storage. Default in the browser; pass `window.sessionStorage` for transient login state. |
| `MemoryStorage`       | Tests, and server flows handled by one client instance. Not shared across processes.         |
| `ServerCookieStorage` | From `@wilsoon/auth-next` - HttpOnly cookies with hardened flags.                            |
| _(none)_              | Storage-backed calls throw `StorageUnavailableError` naming the operation and the fix.       |

## Errors

All errors extend `AuthError` and carry a stable `code`. `error instanceof StateMismatchError` now works (the base class used to overwrite subclass prototypes, making every specific check false).

3.0 adds the codes `PROFILE_REQUIRED`, `FOREIGN_SESSION`, `SILENT_AUTH_UNAVAILABLE` and `INVALID_CONFIG`.

`TokenVerificationError`, `ClaimValidationError`, `NonceMismatchError`, `StateMismatchError`, `IssuerMismatchError`, `AuthorizationResponseError`, `StorageUnavailableError`, `SessionCheckUnavailableError`, `CryptoUnavailableError`, `DiscoveryError`, `TokenExchangeError`, `TokenRefreshError`, `UserInfoError`, `LogoutError`, `NoTokenError`.

## Migrating to 3.0

The core no longer assumes one provider. For WilsoonID, install `@wilsoon/auth-provider-wilsoon`
and pass `profile: wilsoon()`; escalation, platform sessions and `isSessionCurrent()` move to
`client.wilsoon.*`. `role` gives way to `roles`/`permissions` arrays. Step-by-step notes are in the
[changelog](https://github.com/Wilsoon7721/node-oidc-kit/blob/main/CHANGELOG.md).

## Migrating from 1.x

2.0 removed nothing; the unsafe paths kept working and warned until 3.0 removed them. The changes that need attention
(full notes in the [changelog](https://github.com/Wilsoon7721/node-oidc-kit/blob/main/CHANGELOG.md)):

1. **Authorize on `verifyIdToken()`.** `parseIdToken()` never checked a signature, so `role`/`authMethods` from it are attacker-controlled. It was removed in 3.0; use `decodeIdTokenUnsafe()` when you only need display claims.

   ```diff
   - const user = client.parseIdToken(tokens.id_token);
   - if (user.role === 'admin') { /* ... */ }
   + const user = await client.verifyIdToken(tokens.id_token);
   + if (hasRole(user, 'admin')) { /* ... */ } // 3.0; 2.x read user.role
   ```

2. **`getUser()` returns `ProfileUser`.** Reading `.role`, `.authMethods` or `.sessionVersion` off them is now a compile error. At runtime those fields were always `undefined`/`[]`, because the userinfo endpoint never returned them - any check built on them was already broken, and inverted checks (`if (user.role === 'user') restrict()`) were failing open.

3. **`isTokenExpired()` no longer reports a token with no `exp` as valid.** It is renamed to `isTokenNearExpiry()`; the old name was removed in 3.0.

4. **`createAuthorizeUrl()` persists `state`, `nonce` and the verifier** when storage is available, and returns `nonce` alongside `state` and `codeVerifier`. Pass `{ persist: false }` to keep managing them yourself.

5. **`AuthClient` needs storage for storage-backed calls.** Previously the server-side default was `{} as AuthStorage`, which type-checked and then threw `TypeError: this.storage.setItem is not a function`. Pass `MemoryStorage`, a cookie store, or nothing if you never touch storage.

6. **`User` is deprecated** in favour of `AuthenticatedUser` (verified), `ProfileUser` (userinfo) and `UnverifiedUser` (decoded). The alias was removed in 3.0.

7. **`role` is validated, not asserted.** In 2.x an unrecognised value threw `ClaimValidationError`. 3.0 replaces it with open `roles`/`permissions` lists - see [Roles and permissions](#roles-and-permissions).

## Claim shapes

`decodeIdTokenUnsafe()` reads identity claims both flat and nested under `oidc_fields`, with the nested one preferred when present. `sub` is always treated as the authoritative subject identifier.

## Roles and permissions

`roles` and `permissions` are plain string lists, filled from wherever your provider puts them:

```typescript
new AuthClient({ ...config, rolesClaim: "resource_access.my-app.roles", permissionsClaim: "permissions" });
```

Each selector is a dot path or a function of the claims. With none configured both lists are
empty, so every check fails closed. `hasRole()` passes on any of the given roles,
`hasPermission()` only on all of them, and `requireRole()` / `requirePermission()` throw instead.
A provider profile can fill both lists itself.

## Environments Supported

Node.js 18+, modern browsers, and edge runtimes - anything with the Web Crypto API on `globalThis.crypto` and `fetch`. The old `require('crypto')` fallbacks were removed: `require` does not exist in ESM or on Workers, so they threw `ReferenceError` instead of degrading. A runtime without Web Crypto now fails with `CryptoUnavailableError`.

Signature verification uses [`jose`](https://github.com/panva/jose), the package's only runtime dependency.

## License

[MIT](./LICENSE) - free use, forking and redistribution, with no warranty of any kind.

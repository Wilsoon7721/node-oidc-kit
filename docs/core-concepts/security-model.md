---
title: Security model
identifier: security-model
order: 2
---

One rule governs the whole SDK: **only three methods produce a value you may authorize on.**

| Method                                    | Verified?                                     | Gives you                                                              |
| ----------------------------------------- | --------------------------------------------- | ---------------------------------------------------------------------- |
| `verifyIdToken()`                         | Signature, `iss`, `aud`, `exp`, `nonce`       | `AuthenticatedUser` - `role`, `authMethods`, `sessionVersion`          |
| `verifyAccessToken()`                     | Signature, `iss`, pinned `aud`, `exp`, scopes | `AccessTokenClaims` - no role (access tokens don't carry one)          |
| `verifyPlatformSession()`                 | The above, plus live introspection            | `AuthenticatedUser` with **current** role and session version          |
| `getUser()` / `hydrateSession()`          | Transport only                                | `ProfileUser` - display claims, deliberately no `role` field to misuse |
| `decodeIdTokenUnsafe()`, `parseIdToken()` | **Nothing**                                   | `UnverifiedUser` - attacker-controlled by definition                   |

`isTokenNearExpiry()` is a refresh _hint_ read from an unverified payload, not a gate. It
fails closed: unparseable, or no `exp` claim, means "expired."

{% callout type="danger" title="Anyone can mint a token with role: admin" %}
`decodeIdTokenUnsafe()` and the deprecated `parseIdToken()` read a JWT's payload without
checking its signature. A JWT is just base64 - anyone can construct one with any claims and
an empty or garbage signature. Reading `role` off an unverified decode is the exact bug
this SDK's v1 → v2 migration exists to close.
{% /callout %}

## The type system enforces it, not just the docs

`ProfileUser` - what `getUser()` and `hydrateSession()` return - has no `role` field at
all. Authorizing on a userinfo response is a compile error, not a runtime `undefined` you
might not notice.

`@wilsoon/auth-react`'s `SessionUser` is a discriminated union on `verified`:

```ts
type SessionUser = ({ verified: true } & AuthenticatedUser) | ({ verified: false } & ProfileUser);
```

```tsx
const { user } = useAuth();

// Always available: display claims.
user?.name;
user?.email;

// Only after a verified callback exchange:
if (user?.verified && user.role === "admin") {
  return <AdminNav />;
}
```

TypeScript won't let you read `role` without narrowing on `verified` first, so a hydrated
session can't silently produce `undefined` where a role was expected.

{% callout type="warning" title="Client-side checks are for rendering" %}
A browser can be told anything. Whatever `AuthProvider` / `useAuth()` report is for
deciding what to _show_, never what to _allow_. Gate real access on the server -
`@wilsoon/auth-next`'s `getSession()` / `requireSession()`, or `verifyIdToken()` /
`verifyAccessToken()` directly in your API.
{% /callout %}

## Roles are validated, not asserted

A `role` claim is narrowed against a closed set (`'admin' | 'user'` by default) rather than
cast. An unrecognised value throws `ClaimValidationError` instead of being silently mapped
onto a known role - the failure mode a privilege-escalation bug usually takes. An absent
`role` falls back to the least-privileged `'user'`.

A provider that issues other roles needs that set widened at the source - see
[Pointing it at your own provider](/core-concepts/your-own-provider).

## Every unverified method is named `*Unsafe`

`decodeIdTokenUnsafe()`, `decodeTokenPayloadUnsafe()`, `decodeTokenHeaderUnsafe()` - the
naming isn't decoration. It's so a call site reads as a decision the moment you type it,
and so a `grep -r Unsafe` finds every place a token's claims are trusted without
verification.

## Next

[Session models](/core-concepts/session-models) - per-application sessions versus one
login shared across subdomains, and which verification path each one takes.

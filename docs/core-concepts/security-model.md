---
title: Security model
identifier: security-model
order: 2
---

One rule governs the whole library: **only five methods produce a value you may authorize on.**

| Method                                    | Verified?                                      | Gives you                                                              |
| ----------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------- |
| `verifyIdToken()`                         | Signature, `iss`, `aud`, `exp`, `nonce`, `evt` | `AuthenticatedUser` - `role`, `authMethods`, `sessionVersion`          |
| `verifyAccessToken()`                     | Signature, `iss`, pinned `aud`, `exp`, scopes  | `AccessTokenClaims` - no role, plus `tokenUse`                         |
| `verifyPlatformSession()`                 | The above, plus live introspection             | `AuthenticatedUser` with **current** role and session version          |
| `verifyMachineToken()`                    | The access token checks, plus `token_use`      | `MachineClient` - a `clientId`, and deliberately no user fields        |
| `verifyEscalationToken()`                 | Signature, `iss`, `aud`, `exp`, `evt`          | `VerifiedEscalation` - proof one step-up happened                      |
| `getUser()` / `hydrateSession()`          | Transport only                                 | `ProfileUser` - display claims, deliberately no `role` field to misuse |
| `decodeIdTokenUnsafe()`, `parseIdToken()` | **Nothing**                                    | `UnverifiedUser` - attacker-controlled by definition                   |

`isTokenNearExpiry()` is a refresh _hint_ read from an unverified payload, not a gate. It fails closed: unparseable, or no `exp` claim, means "expired."

{% callout type="danger" title="Anyone can mint a token with role: admin" %}
`decodeIdTokenUnsafe()` and the deprecated `parseIdToken()` read a JWT's payload without checking its signature. A JWT is just base64 - anyone can construct one with any claims and an empty or garbage signature. Reading `role` off an unverified decode is a key issue that v2.x closed.
{% /callout %}

## The request is not the guarantee

Three times over, the same shape of bug:
**a token that is completely valid and means less than the calling code assumes.**
Correct signature, correct issuer, correct audience, not expired. Nothing to catch, unless you check the one claim that carries the meaning.

| You asked for                           | The claim that answers               | If you skip it                                                                |
| --------------------------------------- | ------------------------------------ | ----------------------------------------------------------------------------- |
| `acr_values` / `max_age` on the request | `acr`, `auth_time`                   | A provider that ignored you produces a step-up that appears to have succeeded |
| A user, at a user-facing endpoint       | `token_use`, or `sub` vs `client_id` | A machine's `client_id` is read as a person                                   |
| Proof a user is signed in               | `evt`                                | A proof that one action was authorised passes as a login                      |

Each of these is checked for you, but only where the library can know what you meant.
`requiredAcr` and `maxAuthAgeSeconds` are options because only the caller knows what was demanded - the token cannot say what it should have been.

```ts
// Asking.
const { url } = await client.createAuthorizeUrl({ acrValues: "urn:wilsoon:acr:passkey", maxAge: 300 });

// Checking. Without this, the first line is a suggestion.
const user = await client.verifyIdToken(idToken, {
  requiredAcr: "urn:wilsoon:acr:passkey",
  maxAuthAgeSeconds: 300,
});
```

See [Step-up authentication](/flows/step-up) for the whole loop.

## Two tokens are not what they look like

Three token kinds share an issuer, an audience and an algorithm, and differ only by a claim.
Each check below exists because without it one would verify cleanly as another.

| Kind             | Marked by                | Refused where                              |
| ---------------- | ------------------------ | ------------------------------------------ |
| ID token         | no `evt`, no `token_use` | -                                          |
| Escalation proof | `evt: "escalation"`      | `verifyIdToken()` refuses any `evt` at all |
| Machine token    | `token_use: "client"`    | every user path, unless opted into         |

A **machine token**'s `sub` is a `client_id`, not a person, so `verifyAccessToken()` refuses one by default and `verifyMachineToken()` returns a type with no `id`, `role` or `authMethods` on it to misread.
Two signals identify one: the reference provider's `token_use: "client"`, and an RFC 9068 `sub` equal to `client_id`, which holds on any provider following that profile. Set `detectMachineToken` on `AuthConfig` for a provider that marks them some other way. `verifyPlatformSession()`, `resolveSession()` and `isSessionCurrent()` refuse outright, with no opt-in - there is no user to resolve a session for. See [Machine tokens](/flows/machine-tokens).

An **escalation token** asserts that one step-up happened, not that a user is signed in. The check runs both ways: `verifyEscalationToken()` requires `evt: "escalation"`, and `verifyIdToken()` refuses any token carrying an `evt`. See [Method escalation](/flows/escalation).

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

---
title: Security model
identifier: security-model
order: 2
---

One rule governs the whole library: **only a handful of methods produce a value you may authorize on.**

| Method                                    | Verified?                                      | Gives you                                                              |
| ----------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------- |
| `verifyIdToken()`                         | Signature, `iss`, `aud`, `exp`, `nonce`, `evt` | `AuthenticatedUser` - `roles`, `permissions`, `authMethods`            |
| `verifyAccessToken()`                     | Signature, `iss`, pinned `aud`, `exp`, scopes  | `AccessTokenClaims` - `roles`, `permissions`, `tokenUse`               |
| `wilsoon.verifyPlatformSession()`         | The above, plus live introspection             | `AuthenticatedUser` with **current** permissions (WilsoonID profile)   |
| `verifyMachineToken()`                    | The access token checks, plus machine detection | `MachineClient` - a `clientId`, and deliberately no user fields       |
| `wilsoon.verifyEscalationToken()`         | Signature, `iss`, `aud`, `exp`, `evt`          | `VerifiedEscalation` - proof one step-up happened (WilsoonID profile)  |
| `getUser()`, a profile's restore          | Transport only                                 | `ProfileUser` - display claims, deliberately no `roles` to misuse      |
| `decodeIdTokenUnsafe()`                   | **Nothing**                                    | `UnverifiedUser` - attacker-controlled by definition                   |

`isTokenNearExpiry()` is a refresh _hint_ read from an unverified payload, not a gate. It fails closed: unparseable, or no `exp` claim, means "expired."

{% callout type="danger" title="Anyone can mint a token with role: admin" %}
`decodeIdTokenUnsafe()` reads a JWT's payload without checking its signature. A JWT is just base64 - anyone can construct one with any claims and an empty or garbage signature. Reading `roles` or `permissions` off an unverified decode is exactly the bug the verified methods exist to prevent.
{% /callout %}

## The request is not the guarantee

Three times over, the same shape of bug:
**a token that is completely valid and means less than the calling code assumes.**
Correct signature, correct issuer, correct audience, not expired. Nothing to catch, unless you check the one claim that carries the meaning.

| You asked for                           | The claim that answers               | If you skip it                                                                |
| --------------------------------------- | ------------------------------------ | ----------------------------------------------------------------------------- |
| `acr_values` / `max_age` on the request | `acr`, `auth_time`                   | A provider that ignored you produces a step-up that appears to have succeeded |
| A user, at a user-facing endpoint       | `sub` vs `client_id`, or the profile's marker | A machine's `client_id` is read as a person                                   |
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
| ID token         | no `evt`, not a machine token | -                                     |
| Escalation proof | `evt: "escalation"`      | `verifyIdToken()` refuses any `evt` at all |
| Machine token    | `sub === client_id`, or a profile marker | every user path, unless opted into |

A **machine token**'s `sub` is a `client_id`, not a person, so `verifyAccessToken()` refuses one by default and `verifyMachineToken()` returns a type with no `id`, `roles` or `authMethods` on it to misread.
Without a profile, core recognises one by RFC 9068's `sub` equal to `client_id`, which holds on any provider following that profile. A provider profile can add its own marker (WilsoonID's is `token_use: "client"`), and `detectMachineToken` on `AuthConfig` overrides both. `resolveSession()` and a profile's session checks refuse outright, with no opt-in - there is no user to resolve a session for. See [Machine tokens](/flows/machine-tokens).

An **escalation token** asserts that one step-up happened, not that a user is signed in. The check runs both ways: the WilsoonID profile's `verifyEscalationToken()` requires `evt: "escalation"`, and `verifyIdToken()` refuses any token carrying an `evt`. See [Method escalation](/flows/escalation).

## The type system enforces it, not just the docs

`ProfileUser` - what `getUser()` and a profile's cookie restore return - has no `roles` or
`permissions` at all. Authorizing on a userinfo response is a compile error, not a runtime `undefined` you
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
if (user?.verified && hasRole(user, "admin")) {
  return <AdminNav />;
}
```

TypeScript won't let you read `roles` without narrowing on `verified` first, so a session
restored from a cookie can't silently produce an empty list where roles were expected.

{% callout type="warning" title="Client-side checks are for rendering" %}
A browser can be told anything. Whatever `AuthProvider` / `useAuth()` report is for
deciding what to _show_, never what to _allow_. Gate real access on the server -
`@wilsoon/auth-next`'s `getSession()` / `requireSession()`, or `verifyIdToken()` /
`verifyAccessToken()` directly in your API.
{% /callout %}

## Roles are data, not a type

`roles` and `permissions` are plain string arrays, read from verified claims through
`rolesClaim` / `permissionsClaim` or a provider profile. There is no closed set: an unknown
role lands in `roles` and matches only a `hasRole()` check that names it. Nothing is guessed
either - with no selector configured both lists are empty, so a check fails closed rather than
passing on a claim nobody mapped. See [Authorization](/recipes/authorization).

The deprecated `role` field, set only by the WilsoonID profile for 2.x apps, keeps its old
`'admin' | 'user'` narrowing: any other value leaves it unset rather than mapping onto a known
role.

## Every unverified method is named `*Unsafe`

`decodeIdTokenUnsafe()`, `decodeTokenPayloadUnsafe()`, `decodeTokenHeaderUnsafe()` - the
naming isn't decoration. It's so a call site reads as a decision the moment you type it,
and so a `grep -r Unsafe` finds every place a token's claims are trusted without
verification.

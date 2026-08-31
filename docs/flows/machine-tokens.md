---
title: Machine tokens
identifier: machine-tokens
order: 3
---

`client_credentials`: a server authenticating as _itself_, with no user anywhere in the exchange. One service calling another's API on a schedule, not on somebody's behalf.

This splits across two packages, on purpose. Obtaining a machine token is `@wilsoon/auth-machine`; **verifying** one is `@wilsoon/auth-core`, and the verifying half is not optional.

## The danger, stated once

A machine token verifies identically to a user token. Same issuer, same audience, same RS256 signature. The only difference is that its `sub` is a **`client_id`, not a user**.

So any resource server that resolves `sub` to a person will happily accept a machine as a user, and nothing about the token will look wrong. That is the entire reason this page exists.

{% callout type="danger" title="auth-core refuses machine tokens by default" %}
`verifyAccessToken()` throws `MachineTokenNotAllowedError` when handed one, unless you opt in:

```ts
const claims = await client.verifyAccessToken(token, { allowMachineTokens: true });
if (claims.tokenUse === "client") return serveMachine(claims.subject);
```

Failing closed is deliberate. An endpoint written for users keeps working exactly as before, and one that wants to serve both has to say so and branch.
{% /callout %}

## Verifying, in auth-core

| Method                 | Accepts                                                    | Returns                              |
| ---------------------- | ---------------------------------------------------------- | ------------------------------------ |
| `verifyAccessToken()`  | User tokens; machine tokens only with `allowMachineTokens` | `AccessTokenClaims`, with `tokenUse` |
| `verifyMachineToken()` | Machine tokens only - refuses user tokens                  | `MachineClient`                      |

```ts
const machine = await client.verifyMachineToken(token);
machine.clientId; // who called
machine.tokenUse; // "client"
```

`MachineClient` deliberately has no `id`, no `role` and no `authMethods`. There is no user, so there is nothing to read - a caller cannot accidentally pull a person out of it, because the type has no person-shaped fields. `verifyMachineToken()` refuses user tokens in turn, so the check runs in both directions.

Session paths refuse machine tokens outright, with no opt-in at all: `verifyPlatformSession()`, `resolveSession()` and `isSessionCurrent()` all throw. There is no user behind a `client_id` to resolve a session for, and nothing to revoke against.

`isMachineToken(claims)` is exported from both packages for a server that only needs the one check. Pass it **verified** claims - an unverified decode tells you what the bearer chose to claim, which is a different question.

## Obtaining, in auth-machine

```bash
npm install @wilsoon/auth-machine
```

```ts
import { createMachineClient } from "@wilsoon/auth-machine";

const machine = createMachineClient({
  issuer: "https://id.example.com",
  clientId: process.env.CLIENT_ID!,
  clientSecret: process.env.CLIENT_SECRET!,
});

const res = await machine.fetch("https://api.example.com/reports");
```

{% callout type="warning" title="Version 0.x" %}
`@wilsoon/auth-machine` is versioned independently of the other three packages and is currently **0.x**. It has zero dependencies to the other packages, and its API may still change. The other three remain on a shared 2.x line.
{% /callout %}

### Why a package for a form POST

The grant itself is one request returning one token. Everything of value is around it:

- **Single-flight.** Fifty concurrent callers on a cold cache produce one token request, not fifty. This is the easiest part to get wrong.
- **Refresh-ahead.** Renewal starts at 75% of the lifetime and the still-valid token is served while it runs, so only a cold or fully expired cache makes a caller wait. Renewing at `exp` hands out tokens that die in flight once skew and latency are counted.
- **One retry on 401.** A rotated secret gets exactly one forced refresh and one retry, never a loop.

| Option          | Default              |                                                 |
| --------------- | -------------------- | ----------------------------------------------- |
| `refreshAt`     | `0.75`               | Fraction of lifetime after which renewal starts |
| `skewSeconds`   | `30`                 | Treated as expired this close to `exp`          |
| `tokenEndpoint` | `<issuer>/api/token` | Override if mounted elsewhere                   |
| `fetch`         | `globalThis.fetch`   | Injectable, for tests and odd runtimes          |

`getToken()` returns the cached string; `reset()` drops it, which is what to call after rotating a secret.

### Failures worth telling apart

`MachineTokenError` carries `code`, `status` and `permanent`. `invalid_client`, `unauthorized_client`, `invalid_scope` and `unsupported_grant_type` are configuration rather than weather - they will fail identically on every retry, so `permanent: true` says to surface them instead of backing off forever.

## Three constraints from the grant itself

**No scope.** Every scope an OIDC provider defines - `openid`, `profile`, `email`, `offline_access` - describes a user, so requesting one returns `invalid_scope`. There is deliberately no `scope` option until per-client machine scopes exist.

**No refresh token.** RFC 6749 §4.4.3 says the grant issues none, so there is no refresh path to add.

**No revocation.** Revocation acts on refresh tokens, and this grant mints none. Rotating the client secret stops **new** issuance but leaves outstanding tokens valid until they expire - short lifetimes are the only real control, which is why the cache respects `expiresAt` rather than holding past it.

{% aside title="Server-only, and it checks" %}
`createMachineClient()` throws if it finds a `window`. A bundler that reached this package would already have put your client secret in a file someone can read.
{% /aside %}

## Where the cache lives

Process memory, on purpose. The token is short-lived and cheap to re-obtain; writing it to disk or Redis would create a credential at rest with none of the protections the secret itself has.

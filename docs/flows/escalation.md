---
title: Method escalation
identifier: escalation
order: 4
---

Step-up through a back channel: the client asks the provider to require a stronger method, puts
a URL in front of the user, and polls for the verdict.

{% callout type="warning" title="A provider extension, not a standard" %}
Escalation is specific to the reference provider. It is not part of OIDC or any RFC, it is not
discoverable, and pointing this at Okta, Auth0 or Keycloak will find no endpoint to talk to.

For step-up that works against any conforming provider, use
[step-up authentication](/flows/step-up) - `acr_values` and `max_age` on an ordinary
authorization request. Come back here when you need what that cannot do: a client with no
redirect URI demanding step-up, or asking without showing anything to a user who already
qualifies.
{% /callout %}

```ts
await client.reauthorize(["passkey", "fido"], true, {
  idTokenHint: tokens.id_token,
  openUrl: (url) => console.log(`Confirm at: ${url}`),
});
```

That one call creates the request, puts a URL in front of the user, polls until the provider
gives a verdict, and verifies the proof that comes back.

## What it does that the standard path cannot

An authorization request with `acr_values` restarts the login through a redirect. Escalation
keeps the session, and adds three things the standard path has no answer for.

- **No redirect URI needed.** A CLI can demand step-up, because the URL goes to the user
  rather than to a registered callback.
- **It can complete without asking.** With `force: false` a session that already qualifies is
  satisfied on the first poll, and the user sees nothing.
- **A narrow proof.** The `escalation_token` asserts that one action was authorised, which is
  a smaller claim than an ID token's "this person is signed in".

## The three calls

`reauthorize()` is the whole exchange. Underneath it are three steps you can drive yourself
when you need to own the loop:

| Call                        | Channel            | Does                                                  |
| --------------------------- | ------------------ | ----------------------------------------------------- |
| `createEscalation(options)` | Back channel       | Returns `escalationUrl`, `pollToken` and the deadline |
| open `escalationUrl`        | The user's browser | They satisfy it at the provider                       |
| `pollEscalation(request)`   | Back channel       | One poll: `pending`, or throws terminally             |

```ts
const request = await client.createEscalation({
  use: ["passkey"],
  force: true,
  idTokenHint: tokens.id_token,
});

// request.escalationUrl, request.expiresAt, request.interval
```

{% callout type="warning" title="Never build the escalation URL yourself" %}
It carries a server HMAC over the request's parameters. Editing `use=passkey` to
`use=google` in the address bar fails as `invalid_signature` and is audited at the provider,
rather than being quietly ignored.

The server signs it, not you - which is what lets a public client (a CLI, which cannot hold
a secret) hand out a tamper-proof URL too.
{% /callout %}

## Naming the subject

An escalation has to say _whose_ step-up it is, and how you may say so depends on what kind
of client you are.

- **`idTokenHint`** - an ID token this client was issued for that user. Always preferred, and
  the only option for a public client.
- **`subject`** - a bare subject identifier. Accepted from confidential clients only.

Either way the provider only lets a client demand step-up from a user it has already been
issued a token for. A different signed-in user gets `subject_mismatch` and is told nothing
else about the request.

## `force`, and the case where nothing happens

`force: false` completes immediately when the session already qualifies. `reauthorize()`
polls once _before_ calling `openUrl`, so that case shows the user nothing at all:

```ts
const result = await client.reauthorize(["passkey"], false, {
  idTokenHint: tokens.id_token,
  openUrl, // never called if the session already qualifies
});

if (result.alreadySatisfied) {
  // Nothing was asked of them. Probably don't render a "verified!" toast.
}
```

`force: true` requires a fresh assertion regardless. The provider checks that the session's
`auth_time` is newer than the escalation itself, so an assertion from an hour ago cannot be
re-presented.

## Methods and their aliases

`use` accepts strategy names or `amr` values, and aliases collapse at the provider:
`passkey`, `fido`, `hw` and `webauthn` are one verifier; `mfa` means passkey or TOTP. So a
relying party that read `amr: ["fido"]` off a token can ask for `fido` back and get what it
meant.

An unrecognised value is rejected with `invalid_use` rather than dropped - dropping it would
quietly weaken the request, which is the wrong direction to fail in.

## Who owns the deadline

The server sets the lifetime when the request is created and returns it as `expiresAt`. The
client, the browser page and the provider all count down from that one number.

This is why `reauthorize()` keeps polling until the provider reports `expired_token` instead
of stopping on its own clock. If a local timer and the server disagree - a user finishing at
299 seconds against a client that gave up at 298 - the server is right. `maxWaitSeconds` is
available to bound a hung process, but it is off by default on purpose.

```ts
await client.reauthorize(["passkey"], true, {
  idTokenHint,
  openUrl,
  onPending: ({ attempt, interval }) => console.log(`waiting… (${attempt})`),
  signal: controller.signal, // cancel
});
```

## What you get back

| Outcome         |                                                                                         |
| --------------- | --------------------------------------------------------------------------------------- |
| Success         | `EscalationResult` - `satisfiedBy`, `acr`, `authMethods`, `authTime`, `escalationToken` |
| User refused    | throws `AuthorizationDeniedError` (`reason` where the provider gave one)                |
| Deadline passed | throws `AuthorizationExpiredError`                                                      |
| Anything else   | throws `EscalationError` with the provider's `error` code                               |

A denial and an expiry are separate errors because they are different facts: in one the user
answered, in the other they never did.

## The escalation token

On success the provider returns a short-lived RS256 JWT audienced to your client, carrying
`amr`, `acr`, `auth_time`, `satisfied_by` and `already_satisfied`. `reauthorize()` verifies
it for you unless you pass `verifyToken: false`.

It exists so the outcome can be handed to a resource server that trusts the provider's JWKS
but not you. A boolean returned by your own code proves nothing to anybody else.

```ts
const proof = await client.verifyEscalationToken(result.escalationToken!);
// proof.satisfiedBy === "passkey"
```

{% callout type="danger" title="An escalation token is not a login" %}
Both are RS256, from the same issuer, audienced to the same client. The only thing separating
them is the `evt` claim, which is `"escalation"` on one and absent on the other.

The library checks this in **both** directions: `verifyEscalationToken()` refuses anything whose
`evt` isn't `escalation`, and `verifyIdToken()` refuses any token that carries an `evt` at
all. Without the second check, a proof that one action was authorised would verify as proof
that a user is signed in.
{% /callout %}

## Configuration

Escalation is not an OIDC endpoint, so discovery says nothing about it. The library assumes
`<issuer>/api/escalate`; override with `escalationEndpoint` if your provider mounts it
elsewhere. The poll endpoint is always `<escalationEndpoint>/poll`.

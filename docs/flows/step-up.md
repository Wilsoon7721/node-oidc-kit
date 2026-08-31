---
title: Step-up authentication
identifier: step-up
order: 1
---

Requiring stronger or fresher authentication for one action, using only what every OIDC
provider already supports. A passkey before changing a payout account; a login no older than
five minutes before deleting an account.

This is the portable path. It needs no endpoint beyond `/authorize`, so it works against
Okta, Auth0, Keycloak or your own provider without configuration.

## The loop

Three parties, and each does one thing.

```
resource server   401 + WWW-Authenticate: Bearer error="insufficient_user_authentication",
                      acr_values="...", max_age=...
        ↓
client            readAuthenticationChallenge()  →  createStepUpRequest()  →  redirect
        ↓
provider          re-authenticates, mints a token carrying acr and auth_time
        ↓
client            verifyIdToken(token, { requiredAcr, maxAuthAgeSeconds })
```

The last line is not optional. More on that below.

## The resource server's half

Answer with `401`, never `403`. The client is being told to go and fetch something, which is
a different statement from being refused.

```ts
import { buildAuthenticationChallenge } from "@wilsoon/auth-core";

if (!satisfiesAmr(user, [AMR.FIDO])) {
  res.setHeader(
    "WWW-Authenticate",
    buildAuthenticationChallenge({
      acrValues: "urn:wilsoon:acr:passkey",
      maxAge: 300,
      errorDescription: "A recent passkey assertion is required to change payout details.",
    })
  );
  return res.status(401).end();
}
```

That header is [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470). A client that has never
heard of your service can act on it.

## The client's half

```ts
import { readAuthenticationChallenge, isStepUpChallenge } from "@wilsoon/auth-core";

const res = await fetch("/api/payouts", { method: "POST", body });

if (res.status === 401) {
  const challenge = readAuthenticationChallenge(res.headers.get("www-authenticate"));

  if (isStepUpChallenge(challenge)) {
    const { url } = await client.createStepUpRequest(challenge);
    return redirect(url);
  }
  return redirect("/login");
}
```

`isStepUpChallenge()` earns its place: a `401` carrying `insufficient_user_authentication`
means the token is valid and the user *is* signed in, they simply have not proved enough.
Sending them through a plain login throws away a good session for no reason.

{% callout type="warning" title="Only acr_values and max_age cross over" %}
`createStepUpRequest()` carries those two and nothing else. A challenge arrives from a
resource server over the network, and those two can only ever ask for *stronger*
authentication - whereas a `scope` taken from the same header would let that server widen
what your client requests on the user's behalf.

The challenge's `scope` is still parsed onto `challenge.scope` if you want to read it. It is
just never applied for you.
{% /callout %}

Anything you pass in `options` wins over the challenge, so you can tighten what a resource
asked for but never silently accept less.

## max_age

Seconds. `max_age: 0` demands a fresh authentication outright.

```ts
await client.createAuthorizeUrl({ maxAge: 0 });   // authenticate again, now
await client.createAuthorizeUrl({ maxAge: 300 }); // within the last five minutes is fine
```

When you send `max_age`, the provider must return `auth_time` in the ID token - which is what
makes the check on the way back possible.

## The request is not the guarantee

An authorization server is free to ignore `acr_values` and `max_age`. One that does returns a
**completely valid token** - correct signature, correct issuer, correct audience, not expired
- describing a weaker authentication than you asked for. Nothing about it looks wrong.

So the demand and the check are two separate jobs, and only the second one protects you:

```ts
const user = await client.verifyIdToken(idToken, {
  requiredAcr: "urn:wilsoon:acr:passkey",
  maxAuthAgeSeconds: 300,
});
```

`requiredAcr` rejects a token whose `acr` is not one of the values you accept.
`maxAuthAgeSeconds` rejects one whose `auth_time` is older than you allow. Without them a
provider that quietly ignored your request produces a step-up that appears to have succeeded.

{% callout type="danger" title="This failure mode is silent by construction" %}
There is no error, no warning, and no malformed token. The only signal that the step-up did
not happen is the `acr` claim you did not read.
{% /callout %}

## What your provider needs

| Requirement | Effect if missing |
| --- | --- |
| Honours `acr_values` on `/authorize` | `requiredAcr` rejects the token; the user loops |
| Honours `max_age`, and returns `auth_time` | `maxAuthAgeSeconds` rejects the token |
| Advertises `acr_values_supported` | Nothing breaks; you have to know the values yourself |

The reference provider does all three, and refuses an unsatisfiable request with
`unmet_authentication_requirements` rather than issuing a code that would fail your check
anyway.

## When to reach for escalation instead

[Method escalation](/flows/escalation) solves the same problem through a back channel, and is
better in two specific cases - but it is a provider extension rather than a standard, so it
only works against the reference provider.

| | Step-up (this page) | [Escalation](/flows/escalation) |
| --- | --- | --- |
| Basis | OIDC Core + RFC 9470 | Provider extension |
| Works against | Any conforming provider | The reference provider only |
| Mechanism | Redirect through `/authorize` | Back channel, then poll |
| Suits a CLI | No - needs a redirect URI | Yes |
| "Already satisfied" without prompting | No | Yes |
| Proof for a third party | The ID token's `acr` | A dedicated escalation token |

Reach for step-up by default. Reach for escalation when you need a client with no redirect
URI to demand one, or when you want to ask without putting a screen in front of a user who
already qualifies.

## Next

[The device grant](/flows/device-grant) - signing in a client that has no browser at all.

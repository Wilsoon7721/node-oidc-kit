---
title: Session models
identifier: session-models
order: 3
---

Two shapes of session are supported, and which one you're in decides which methods you
call. A third case - a caller with no session at all - is covered in
[Machine tokens](/flows/machine-tokens).

## Per-application session - standard OIDC

Each application has its own cookie and its own ID token, addressed to that application's
`client_id` alone. This is the default, and it needs nothing exotic:

```ts
const user = await client.verifyIdToken(idToken);
// or, server-side per request:
const { user } = await getSession(authConfig);
```

## Platform session - one login across subdomains

Several first-party applications can share a single, domain-wide session cookie (set on
`.example.com`, say) instead of each running its own login. That cookie holds the tokens of
whichever application most recently completed a code exchange - so the **ID token** inside
it belongs to that one application, and verifying it from a sibling application correctly
fails on `aud`.

The **access token** is different: it's minted with an audience shared across every
application on the platform, so it verifies the same way everywhere.

Resolving that access token is not part of any standard, so it takes a provider profile
that knows how. The WilsoonID profile does it with introspection.

{% callout type="tip" title="resolveSession() routes it for you" %}

```ts
const user = await client.resolveSession(tokens);
```

Verifies the ID token when it's addressed to this client; otherwise hands the access token
to the profile's shared-session resolver (WilsoonID's `verifyPlatformSession()`: verify,
then introspect). Without such a profile it throws `FOREIGN_SESSION`. The routing decode is
unverified - it's used only to pick a branch, and both branches verify properly, so a
forged `aud` gains nothing.
{% /callout %}

Shared sessions need the profile, `apiAudience` and a `clientSecret` (introspection is for
confidential clients only - never call it from a browser). The WilsoonID profile's
`platformSessionCacheSeconds` reuses a resolved session briefly instead of introspecting
on every request; a revocation then takes up to that long to be noticed, and never longer
than the token's own expiry.

```ts
import { createAuthClient } from "@wilsoon/auth-core";
import { wilsoon } from "@wilsoon/auth-provider-wilsoon";

const client = createAuthClient({
  ...config,
  apiAudience: "https://api.example.com",
  clientSecret: process.env.OIDC_CLIENT_SECRET,
  profile: wilsoon({ platformSessionCacheSeconds: 10 }),
});
```

`@wilsoon/auth-next`'s `getSession()` picks this path automatically when the cookie's ID
token belongs to a sibling service - you don't call `client.wilsoon.verifyPlatformSession()`
yourself in the common case.

## No session at all

A `client_credentials` caller has no user, so none of this applies to it. Every method on
this page refuses a machine token rather than inventing a session for it: `resolveSession()`
and the WilsoonID profile's `verifyPlatformSession()` throw `MachineTokenNotAllowedError`, and
so does its `isSessionCurrent()`, because there is no user record for a revocation to act on.

Verify those callers with `verifyMachineToken()` instead.

## Session revocation

A JWT stays valid until it expires, so "sign out everywhere" doesn't take effect on its
own - the token is still cryptographically valid for as long as it says it is. The portable
fix is to ask the provider, with a confidential client:

```ts
const access = await client.liveAccess(tokens.access_token);
if (!access.active) return reauthenticate();
```

`liveAccess()` uses the profile's hook when there is one, and RFC 7662 introspection
otherwise. In Next.js, `enforce: "live"` on the middleware does this on every request.

{% callout type="note" title="On WilsoonID" %}
The provider also bumps a per-user `session_version` on "sign out everywhere". The profile
checks it without a confidential client when your backend knows the current value:

```ts
const client = createAuthClient({
  ...config,
  profile: wilsoon({ resolveSessionVersion: (userId) => myApi.getSessionVersion(userId) }),
});

if (!(await client.wilsoon.isSessionCurrent(user))) return reauthenticate();
```

Without a resolver it introspects `{ token }` instead, and with neither it throws
`SessionCheckUnavailableError` rather than assuming the session is still valid.
{% /callout %}

Machine tokens cannot be revoked at all - the grant issues no refresh token for revocation
to act on - so a short lifetime is the only control there.

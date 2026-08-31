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

{% callout type="tip" title="resolveSession() routes it for you" %}

```ts
const user = await client.resolveSession(tokens);
```

Verifies the ID token when it's addressed to this client; otherwise falls back to the
access token plus introspection via `verifyPlatformSession()`. The routing decode is
unverified - it's used only to pick a branch, and both branches verify properly, so a
forged `aud` gains nothing.
{% /callout %}

`verifyPlatformSession()` needs `apiAudience` and a `clientSecret` (introspection is for
confidential clients only - never call it from a browser). Set
`platformSessionCacheSeconds` to reuse a resolved session briefly instead of introspecting
on every request; a revocation then takes up to that long to be noticed, and never longer
than the token's own expiry.

```ts
const client = new AuthClient({
  ...config,
  apiAudience: "https://api.example.com",
  clientSecret: process.env.OIDC_CLIENT_SECRET,
  platformSessionCacheSeconds: 10,
});
```

`@wilsoon/auth-next`'s `getSession()` picks this path automatically when the cookie's ID
token belongs to a sibling service - you don't call `verifyPlatformSession()` yourself in
the common case.

## No session at all

A `client_credentials` caller has no user, so none of this applies to it. Every method on
this page refuses a machine token rather than inventing a session for it: `resolveSession()`
and `verifyPlatformSession()` throw `MachineTokenNotAllowedError`, and so does
`isSessionCurrent()`, because there is no user record for a revocation to act on.

Verify those callers with `verifyMachineToken()` instead.

## Session revocation

A JWT stays valid until it expires, so "sign out everywhere" doesn't take effect on its
own - the token is still cryptographically valid for as long as it says it is. Two routes
make revocation enforceable:

```ts
// 1. Your own backend already knows the current value.
const client = new AuthClient({
  ...config,
  resolveSessionVersion: (userId) => myApi.getSessionVersion(userId),
});

if (!(await client.isSessionCurrent(user))) return reauthenticate();
```

```ts
// 2. Or, with a confidential client, let the provider answer via introspection.
if (!(await client.isSessionCurrent(user, { token: idToken }))) return reauthenticate();
```

{% callout type="warning" title="Fails closed" %}
Without either route configured, `isSessionCurrent()` throws
`SessionCheckUnavailableError` rather than assuming the session is still valid.
{% /callout %}

Machine tokens cannot be revoked at all - the grant issues no refresh token for revocation
to act on - so a short lifetime is the only control there.

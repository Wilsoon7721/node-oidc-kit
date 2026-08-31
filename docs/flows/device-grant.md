---
title: The device grant
identifier: device-grant
order: 2
---

RFC 8628, for a client that can print a short string but cannot host a redirect URI - which
is to say, a CLI.

```ts
const { user, tokens } = await client.authorizeDevice({
  scope: ["openid", "profile", "email", "offline_access"],
  onUserCode: ({ userCode, verificationUri }) => console.log(`Go to ${verificationUri} and enter ${userCode}`),
});
```

## The exchange

```
POST <device_authorization_endpoint>   →  device_code, user_code, verification_uri,
  client_id, scope                          verification_uri_complete, expires_in, interval

  print the code, user approves in a browser

POST <token_endpoint>                  →  authorization_pending | slow_down |
  grant_type=…:device_code                  expired_token | access_denied | tokens
  device_code, client_id
```

`authorizeDevice()` is all of it. The two halves are also available separately - `requestDeviceCode()` and `pollDeviceToken()` - for a process that cannot block on a loop.

## Registration

The client must be registered for the device grant at the provider, or the first call is refused with `unauthorized_client`. A public client is expected and needs no secret. However, a client that registered a secret must still present it, and the library sends it automatically when `clientSecret` is configured.

The endpoint comes from discovery (`device_authorization_endpoint`). A provider that doesn't advertise one gets a `DeviceFlowError` saying so, rather than a 404 from a guessed URL.

## The two codes

`userCode` is the half meant for human eyes - eight characters, formatted `XXXX-XXXX`. `deviceCode` is the secret your client polls with and should never be displayed.

`verificationUriComplete` carries the code in the URL so a user who can click doesn't have to type. Show it _alongside_ `userCode` rather than replacing it: the approval page displays the code it resolved, so someone who followed a link can still check it against what the terminal printed.

{% callout type="fact" title="Why the alphabet looks odd" %}
No vowels, and no `0`, `O`, `1`, `I` or `L`. No vowels means no code can ever spell anything. The excluded glyphs are the ones that get misread between different screens.
{% /callout %}

## Polling

`interval` starts at whatever the provider advertises, and only ever goes up. A client that polls too fast gets `slow_down` - which is _not_ a failure - and the library adopts the raised interval rather than the one it started with.

As with [escalation](/flows/escalation), the server owns the deadline: the loop polls until the provider reports `expired_token` instead of timing out on its own clock.

```ts
await client.authorizeDevice({
  onUserCode,
  onPending: ({ attempt, interval, slowDown }) => {
    /* spinner */
  },
  signal: controller.signal,
});
```

{% callout type="warning" title="A redeemed device code is gone, not slow" %}
Device codes are single use, and the provider marks one spent _before_ it generates anything from it. A client that keeps polling after success gets `invalid_grant`, which the library surfaces as `DeviceFlowError` rather than folding into "keep waiting" - it means the code is finished, not that the user is taking their time.
{% /callout %}

## What the tokens say about authentication

The device never sees a browser session, so it asserts nothing about how the user authenticated. The provider captures `amr`, `acr` and `auth_time` from **the session that approved the request**, and generates from that snapshot.

So the `acr` on a CLI's token is the acr of the browser that approved it. A user who approved from a passkey session hands the CLI a passkey-level token; one who approved from a plain social session does not. Worth knowing if a resource server is going to check.

```ts
const { user } = await client.authorizeDevice({ onUserCode });
user?.authMethods; // from the approving session
user?.claims.acr;
```

Pass `verifyUser: false` to get the raw `TokenResponse` back with `user` null, if you intend to verify somewhere else.

## Errors

| Outcome                                 |                                                         |
| --------------------------------------- | ------------------------------------------------------- |
| Success                                 | `DeviceGrantResult` - `tokens`, `user`, `authorization` |
| User refused                            | throws `AuthorizationDeniedError`                       |
| Code expired                            | throws `AuthorizationExpiredError`                      |
| Not registered, code spent, no endpoint | throws `DeviceFlowError` with the provider's code       |

## Storing what comes back

Request `offline_access` if the CLI should keep working after the access token expires - which, for something a user signs into once, is usually the point. Without it the session ends at the first expiry and they authorize the device again.

---
title: Authorization
identifier: authorization
order: 5
---

Deciding what a verified user may do: roles, permissions and how they signed in.

## Roles and permissions

Providers put these in different places, so tell the client where to look:

| Provider  | Config                                                      |
| --------- | ----------------------------------------------------------- |
| Auth0     | `permissionsClaim: "permissions"`                           |
| Entra ID  | `rolesClaim: "roles"`                                       |
| Keycloak  | `rolesClaim: "resource_access.<client-id>.roles"`           |
| WilsoonID | `profile: wilsoon()`, which fills `permissions` and `roles` |

A selector is a dot path or a function of the claims. Once set, verified users and access
token claims carry `roles` and `permissions` as plain string arrays. Any value lands there:
there is no fixed set of roles.

```ts
import { hasPermission, hasRole, requirePermission } from "@wilsoon/auth-core";

const user = await client.verifyIdToken(idToken);

if (!hasRole(user, ["admin", "owner"])) return forbidden(); // any of
if (!hasPermission(user, ["billing.read", "billing.write"])) return forbidden(); // all of
requirePermission(user, "billing.write"); // throws ClaimValidationError
```

Many providers carry permissions only in the access token. `handleCallback()` and
`resolveSession()` merge them in from the session's own access token when it verifies, names
this client as `client_id` and has the same subject.

{% callout type="tip" title="On WilsoonID" %}
Permissions are `<slug>.<key>` nodes your app registers. Define them once and get typed checks:

```ts
import { definePermissionSet } from "@wilsoon/auth-provider-wilsoon";

export const permissions = definePermissionSet("games_portal", {
  "leaderboard.edit": "Edit the leaderboard",
  "rooms.create": "Create rooms",
});

await client.wilsoon.definePermissions(permissions); // at boot or in a deploy step; idempotent
permissions.require(user, "leaderboard.edit"); // a typo here fails to compile
```
{% /callout %}

## How the user signed in

`authMethods` holds the verified `amr` claim.

```ts
import { AMR, assertAmr, satisfiesAmr } from "@wilsoon/auth-core";

if (!satisfiesAmr(user, [AMR.FIDO])) return stepUp();
assertAmr(user, [AMR.MFA]); // throws ClaimValidationError
```

**`mfa` does not imply a hardware factor.** WilsoonID, for one, emits it for passkeys and for a
social login that cleared a TOTP challenge:

| Login                       | `amr` on WilsoonID       |
| --------------------------- | ------------------------ |
| Federated / social provider | `["ext", "social"]`      |
| Passkey                     | `["mfa", "fido", "hw"]`  |
| TOTP challenge completed    | adds `"otp"` and `"mfa"` |

Require `AMR.FIDO` or `AMR.HARDWARE` when you mean phishing-resistant.

To require a recent login, check `auth_time` on the way back:

```ts
await client.verifyIdToken(idToken, { maxAuthAgeSeconds: 300 });
```

To ask for a stronger or fresher login rather than just refusing a weak one, use
[Step-up authentication](/flows/step-up), which works against any provider. On WilsoonID,
[Escalation](/flows/escalation) proves one extra factor without a new login.

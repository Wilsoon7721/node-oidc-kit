---
title: Pointing it at your own provider
identifier: your-own-provider
order: 4
---

Since 3.0 the core is standards-only. Discovery means no endpoint URLs are hardcoded, `amr`
policies compare plain strings, and nothing in core assumes one provider's claims or cookie
names - see [Installation](/getting-started/installation) for the endpoints your provider
needs to offer. What's left is configuration, plus one constant.

## 1. Tell it where roles and permissions live

```ts
const client = new AuthClient({
  ...config,
  rolesClaim: "resource_access.my-app.roles", // a dot path, or (claims) => string[]
  permissionsClaim: "permissions",
});
```

Without these, `roles` and `permissions` are empty and every check on them fails closed. Any
value your provider issues is accepted; there is no fixed set. See
[Authorization](/recipes/authorization) for the common providers.

## 2. RS256 only

```ts
// @wilsoon/auth-core, jwt.ts
export const ALLOWED_ALGORITHMS = ["RS256"] as const;
```

An allowlist here is mandatory, not optional - without one a verifier can be talked into
accepting `alg: "none"`, or an HMAC-confusion token where the attacker supplies the key
that verifies it. The _contents_ of the list are a choice, though: a provider signing with
ES256 or EdDSA needs this widened. Keep it an allowlist; never derive it from the token's
own header.

## 3. Machine tokens

Core recognises a `client_credentials` token by RFC 9068's `sub` equal to `client_id`. A
provider that marks them some other way needs `detectMachineToken` on `AuthConfig`, or a
profile's `isMachineToken`. Returning `false` for a real machine token lets a `client_id`
reach code written for users. See [Machine tokens](/flows/machine-tokens).

## 4. Anything that isn't a standard: a provider profile

Some of what a real provider does is in no spec: escalation APIs, shared platform sessions,
a cookie-based session restore, legacy storage names. Those go in a **provider profile**,
which core calls through a fixed set of hooks and exposes under the profile's name.

```ts
import { createAuthClient, defineProfile } from "@wilsoon/auth-core";

const acme = defineProfile({
  name: "acme",
  storagePrefix: "acme_",
  mapUser: (claims) => ({ roles: (claims.groups as string[]) ?? [] }),
  isMachineToken: (claims) => claims.gty === "client-credentials",
  extend: (ctx) => ({
    // Your provider's own endpoints, with this client's credentials and discovery cache.
    revokeAllSessions: (userId: string) => ctx.clientFetch(`${ctx.config.issuer}/api/sessions/${userId}`, { method: "DELETE" }),
  }),
});

const client = createAuthClient({ ...config, profile: acme });
await client.acme.revokeAllSessions("user-1");
```

| Hook                   | What it does                                                                    |
| ---------------------- | ------------------------------------------------------------------------------- |
| `mapUser`              | Adds fields to a verified user. Identity fields cannot be overridden            |
| `isMachineToken`       | Recognises the provider's machine tokens                                        |
| `storagePrefix`, `storageKeys` | Storage names                                                           |
| `apiAudience`          | Default access token audience                                                   |
| `restoreSession`       | A non-standard session restore, such as reading a provider cookie               |
| `resolveSharedSession` | Resolves a session holding only another client's access token                   |
| `liveAccess`           | Live access for a token; core falls back to plain introspection                 |
| `extend`               | Functions exposed under `client.<name>`                                         |

The WilsoonID profile, `@wilsoon/auth-provider-wilsoon`, is a complete example: escalation,
shared platform sessions, `session_version` revocation and permission registration, all
built on these hooks.

## That's it!

If you hit something not covered here, it's worth a GitHub
issue: [github.com/Wilsoon7721/node-oidc-kit](https://github.com/Wilsoon7721/node-oidc-kit).

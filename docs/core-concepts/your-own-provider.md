---
title: Pointing it at your own provider
identifier: your-own-provider
order: 4
---

Discovery means no endpoint URLs are hardcoded, and `amr` policies compare plain strings -
see [Installation](/getting-started/installation) for the endpoints your provider needs to
offer. Past that, being honest about what's left: five things are still specific to one
reference provider, in order of how likely each is to matter to you.

## 1. Roles are a closed set

```ts
// @wilsoon/auth-core, types.ts
export type UserRole = "admin" | "user";
export const USER_ROLES: readonly UserRole[] = ["admin", "user"];
```

A `role` claim outside that set throws `ClaimValidationError` rather than being asserted
into the union. That's deliberate - silently mapping an unknown role onto a known one is
how privilege escalations ship - but the closed set itself is a compile-time constant. A
provider issuing `editor` or `owner` needs both declarations widened together.

{% callout type="note" %}
This is the one change most forks will need, and it's two lines. It isn't yet
configurable at runtime through `AuthConfig` - see the SDK's own contributing guide if
you'd like to change that.
{% /callout %}

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

## 3. Storage key names

`STORAGE_KEYS` uses names like `wilsoon_id_tokens` and `wilsoon_auth_state`. Purely
cosmetic, and remappable inside your own storage adapter without touching the SDK - see
[Storage](/core-concepts/storage).

## 4. One hardcoded logout fallback

`AuthProvider`'s `logout()` in `@wilsoon/auth-react` falls back to `${issuer}/api/logout`
when the session was hydrated from a cookie and there's no `id_token` available to use as
the `id_token_hint` that `getLogoutUrl()` needs. Every other logout path goes through OIDC
discovery. Against a different provider, handle that one fallback case in your own code.

## 5. `hydrateSession()` assumes a cookie-friendly userinfo endpoint

It calls the userinfo endpoint with `credentials: 'include'` and no `Authorization`
header, so the browser attaches the session cookie itself. That requires a provider that
accepts a cookie-authenticated userinfo request and sends CORS credentials headers for
your origin. A provider that only accepts bearer tokens won't support it - read the
session server-side instead.

## That's it!

If you hit something not covered here, it's worth a GitHub
issue: [github.com/Wilsoon7721/node-oidc-kit](https://github.com/Wilsoon7721/node-oidc-kit).

---
title: React SPA
identifier: react-spa
order: 2
---

A browser-only app with no server of its own.

```bash
npm install @wilsoon/auth-react
```

```tsx
import { AuthProvider } from "@wilsoon/auth-react";

<AuthProvider
  clientId={import.meta.env.VITE_OIDC_CLIENT_ID}
  issuer="https://id.example.com"
  redirectUri={`${window.location.origin}/callback`}
  rolesClaim="roles"
>
  <App />
</AuthProvider>;
```

```tsx
import { hasRole } from "@wilsoon/auth-core";

const { user, isLoading, error, login, logout } = useAuth();

if (isLoading) return <Spinner />;
if (!user) return <button onClick={login}>Sign in</button>;

return (
  <>
    {/* Display claims are always available: */}
    <span>{user.name}</span>

    {/* Authorization claims exist only on a verified session: */}
    {user.verified && hasRole(user, "admin") && <AdminNav />}
  </>
);
```

## Restoring the session on page load

`restore` decides what happens when the page loads without a callback in the URL.

| `restore`            | What it does                                                                                       |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `"silent"` (default) | `silentAuthorize()`: a `prompt=none` request in a hidden iframe, then the profile's restore if any |
| `"profile"`          | Only the profile's own restore, such as WilsoonID's cookie                                         |
| `"none"`             | No restore. The user is signed out until they click sign in                                        |

The silent path needs two things: the `redirectUri` page must allow being framed by its own
origin, and the provider must allow its authorization endpoint to be framed. When either is
missing the attempt finds nothing and falls through, rather than hanging.

`user` is a discriminated union:

| How the session started                    | `verified` | Has `roles` / `permissions` / `authMethods` |
| ------------------------------------------ | ---------- | ------------------------------------------- |
| The OIDC callback (`?code=...`)            | `true`     | yes, the ID token was verified              |
| A silent restore                           | `true`     | yes, the ID token was verified              |
| A profile restore (e.g. a provider cookie) | `false`    | no, only display claims                     |

TypeScript will not let you read authorization claims without narrowing on `verified`.

The provider handles the callback itself: it keeps `state`/`nonce`/verifier in
`sessionStorage`, calls `handleCallback()`, strips the query string and surfaces failures on
`error` (`STATE_MISMATCH`, `NONCE_MISMATCH`, `TOKEN_VERIFICATION_FAILED`,
`AUTHORIZATION_RESPONSE_ERROR`).

{% callout type="warning" title="Client-side checks are for rendering" %}
Anything the browser decides, a user can change. Gate data on your API with
[a resource server](/recipes/resource-server), and use `user.verified` only to decide what to
show.
{% /callout %}

With a `profile` prop, its extensions appear on `useAuth()` under its name, for example
`useAuth<typeof profile>().wilsoon.reauthorize(["passkey"])`.

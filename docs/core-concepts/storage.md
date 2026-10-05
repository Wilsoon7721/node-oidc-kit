---
title: Storage
identifier: storage
order: 1
---

The library persists exactly four values, and it will not guess where to put them.

| Key (default name)                | Lifetime           | Purpose                                        |
| --------------------------------- | ------------------ | ---------------------------------------------- |
| `tokens` (`oidc_tokens`)          | The session        | The token response blob                        |
| `state` (`oidc_state`)            | One login, minutes | CSRF binding between authorize and callback    |
| `nonce` (`oidc_nonce`)            | One login, minutes | Binds the ID token to _this_ authorize request |
| `codeVerifier` (`oidc_verifier`)  | One login, minutes | The PKCE secret                                |

`storagePrefix` changes the `oidc_` prefix, and a provider profile can set exact names (the
WilsoonID profile keeps its 2.x `wilsoon_id_tokens` and `wilsoon_auth_*`). `client.storageKeys`
reports the names a client actually uses.

The bottom three are the interesting ones. They're written when you build the authorize
URL and read after the provider redirects back - a _different request_, often to a
different process. Somewhere durable across that redirect has to hold them. That "where"
is the only thing that differs between a browser SPA, Next.js, Astro on Workers, and an
Express app, so it's the only thing the library asks you to provide:

```ts
interface AuthStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}
```

## Which one ships, and why each exists

| Implementation        | Where                | Why it exists                                                                                                                                                                                                                                                     |
| --------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BrowserStorage`      | `@wilsoon/auth-core` | Web Storage API. Pass `window.sessionStorage` for login flows - the transient three are single-use and tab-scoped, and `sessionStorage` expires them for free. This is what `AuthProvider` does.                                                                  |
| `MemoryStorage`       | `@wilsoon/auth-core` | Tests, and single-process flows where authorize and callback are handled by the same instance. Does not survive a restart or a second replica.                                                                                                                    |
| `UnavailableStorage`  | `@wilsoon/auth-core` | The server default when you pass nothing. Every method throws `StorageUnavailableError` naming the operation and the fix, instead of type-checking as valid storage and then failing later with `TypeError: setItem is not a function`.                           |
| `ServerCookieStorage` | `@wilsoon/auth-next` | The Next.js cookie store. Writes `HttpOnly` + `SameSite=Lax`, short-lived for the transient three, long-lived for the token blob. Throws a useful error in a Server Component, where Next.js forbids cookie writes.                                               |

## Writing your own

There's no Astro or Express adapter shipped in the library, and there shouldn't be - an
adapter belongs next to the framework it adapts. Here's an Astro-on-Cloudflare-Workers one,
in full, as a template:

```ts
import type { AuthStorage } from "@wilsoon/auth-core";
import type { AstroCookies } from "astro";

export class AstroServerStorage implements AuthStorage {
  constructor(
    private cookies: AstroCookies,
    private currentHostname: string,
  ) {}

  getItem(key: string): string | null {
    return this.cookies.get(key)?.value || null;
  }

  setItem(key: string, value: string): void {
    const isLocalhost = ["localhost", "127.0.0.1"].includes(this.hostname());

    this.cookies.set(key, value, {
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
      httpOnly: true,
      sameSite: "lax", // 'strict' would drop these on the redirect back
      secure: !isLocalhost, // localhost is http, so Secure would drop them there
      ...(isLocalhost ? {} : { domain: ".example.com" }),
    });
  }

  removeItem(key: string): void {
    const isLocalhost = ["localhost", "127.0.0.1"].includes(this.hostname());
    // Naming the same domain matters: a bare delete only clears a host-only cookie.
    this.cookies.delete(key, { path: "/", ...(isLocalhost ? {} : { domain: ".example.com" }) });
  }

  private hostname(): string {
    /* strip scheme and port */
  }
}
```

A fuller version, which keeps the transient three host-only and short-lived, is in
[Other server frameworks](/recipes/other-frameworks).

Then hand it to the client, and everything else works unchanged:

```ts
const client = new AuthClient(config, new AstroServerStorage(cookies, origin));
```

## The rules an adapter must follow

Most of these are things that have actually broken:

1. **Synchronous.** `AuthClient` calls these inline. An async store (Redis, Postgres) has
   to be loaded into a `MemoryStorage` first, then written back after.
2. **Round-trip values unchanged.** Token blobs are JSON. If you encode on write, decode on
   read. (`getStoredTokens()` tolerates URI-encoding specifically because providers that
   write the cookie themselves tend to do this.)
3. **`SameSite=Lax`, not `Strict`.** `Strict` drops cookies on the cross-site redirect back
   from the provider, so `state` is missing and _every_ login fails with
   `StateMismatchError`.

   {% callout type="danger" title="The one that costs people an afternoon" %}
   If logins fail with `StateMismatchError` on 100% of attempts, check `SameSite` first.
   {% /callout %}

4. **`Secure`, except on localhost** - where the page is `http` and `Secure` cookies are
   dropped.
5. **Match the domain when deleting.** A bare `delete()` clears a host-only cookie and
   leaves a domain-wide one in place, which reads back as a dead session forever - a
   redirect loop.
6. **A missing key returns `null`.** Not `undefined`, not a throw.
7. **A write that can't happen should throw**, not silently no-op - unless the no-op is
   deliberate, as in the Next.js middleware, where the _response_ owns cookie writes and
   the storage passed to the reading client is read-only by design.
8. **Don't share one instance across requests.** Storage is per-request state; the
   `AuthClient` is what you cache (see `getCachedClient` in `@wilsoon/auth-next`, which
   reuses the JWKS cache across requests).

{% aside title="Remapping the token cookie name" %}
Names come from `storagePrefix` or the profile, per client. To put the token blob under a
cookie name that follows neither, map it inside your adapter - that's what the Next.js
middleware's `cookieName` option does - rather than expecting the client to emit a different key.
{% /aside %}

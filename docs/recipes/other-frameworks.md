---
title: Other server frameworks
identifier: other-frameworks
order: 3
---

Astro, Express, Hono, SvelteKit or anything else with request cookies. Implement
[`AuthStorage`](/core-concepts/storage) over your framework's cookies once, and the core
client does the rest.

## The pattern

```ts
import type { AuthStorage } from "@wilsoon/auth-core";

// `cookies` here is whatever your framework gives you.
export const cookieStorage = (cookies: any, tokensKey: string): AuthStorage => ({
  getItem: (key) => cookies.get(key)?.value ?? null,
  setItem: (key, value) =>
    cookies.set(key, value, {
      httpOnly: true,
      secure: true,
      sameSite: "lax", // must survive the redirect back from the provider
      path: "/",
      maxAge: key === tokensKey ? 60 * 60 * 24 * 30 : 600, // tokens long-lived, login state 10 min
    }),
  removeItem: (key) => cookies.delete(key, { path: "/" }),
});
```

```ts
import { AuthClient, storageKeysFor } from "@wilsoon/auth-core";

const keys = storageKeysFor(); // the names the client uses: oidc_tokens, oidc_state, ...

// GET /login
const client = new AuthClient(authConfig, cookieStorage(cookies, keys.tokens));
const { url } = await client.createAuthorizeUrl();
return redirect(url);

// GET /callback
const client = new AuthClient(authConfig, cookieStorage(cookies, keys.tokens));
const { user } = await client.handleCallback(request.url, { persistTokens: true });

// Any later request
const user = await client.resolveSession(client.getStoredTokens() ?? {});
```

`storageKeysFor()` takes the same prefix as `storagePrefix`. With a profile that sets its own
names, read them from `client.storageKeys` or the profile's export (WilsoonID's is
`WILSOON_STORAGE_KEYS`).

If you would rather keep the transient values yourself:

```ts
const { url, state, nonce, codeVerifier } = await client.createAuthorizeUrl({ persist: false });
// ...store all three...
const { user } = await client.handleCallback(request.url, { expected: { state, nonce, codeVerifier } });
```

All three matter: without `state` there is no CSRF protection on the callback, without
`codeVerifier` the exchange cannot complete, and without `nonce` the ID token is not bound to
your request. `handleCallback()` refuses to run if it has neither storage nor `expected`, and
`createAuthorizeUrl()` warns once when it has no storage to persist to. Treat that warning as a
bug in your wiring.

## Worked example: Astro on Cloudflare Workers

Five files, written against a WilsoonID-style shared session on `.example.com`. Drop the
`sharedDomain` and the profile for a per-application session.

### `src/lib/auth/config.ts`

`process.env` does not exist on Workers. Secrets are runtime bindings, so thread them in from
`Astro.locals.runtime?.env` and fall back to `import.meta.env` for `astro dev`. Don't reach for
`require('cloudflare:workers')`; `require` is undefined in an ESM bundle.

```ts
import { wilsoon } from "@wilsoon/auth-provider-wilsoon";

export type EnvSource = Record<string, string | undefined> | undefined;

const read = (env: EnvSource, key: string): string | undefined => env?.[key] ?? (import.meta.env as unknown as Record<string, string | undefined>)[key];

// Module level, so the client cache and the profile are created once.
const profile = wilsoon({ platformSessionCacheSeconds: 10 });

export function authConfig(origin: string, env?: EnvSource) {
  const clientId = read(env, "OIDC_CLIENT_ID");
  if (!clientId) throw new Error("Missing OIDC_CLIENT_ID");

  return {
    clientId,
    // Safe here: Astro API routes, middleware and .astro frontmatter are all server-side.
    // Required for introspection, which is how a shared session resolves.
    clientSecret: read(env, "OIDC_CLIENT_SECRET"),
    issuer: read(env, "OIDC_ISSUER") ?? "https://id.example.com",
    redirectUri: `${origin}/api/callback`,
    scope: ["openid", "profile", "email", "offline_access"],
    profile,
  };
}
```

### `src/lib/auth/AstroCookieStorage.ts`

The two kinds of value need different scopes. `state`, `nonce` and the PKCE verifier belong to
**one login attempt on one host**. Scoping them to the shared domain means two services
mid-login overwrite each other, and the first callback back fails with `STATE_MISMATCH`.

```ts
import type { AuthStorage } from "@wilsoon/auth-core";
import type { AstroCookies } from "astro";

export class AstroCookieStorage implements AuthStorage {
  private readonly isLocal: boolean;

  constructor(
    private cookies: AstroCookies,
    origin: string,
    private tokensKey: string,
    private sharedDomain: string | null = ".example.com",
  ) {
    const hostname = new URL(origin).hostname;
    this.isLocal = hostname === "localhost" || hostname === "127.0.0.1";
  }

  private scope(key: string) {
    const long = key === this.tokensKey;
    const shared = long && !this.isLocal && this.sharedDomain;
    return { long, domain: shared ? this.sharedDomain : undefined };
  }

  getItem(key: string): string | null {
    return this.cookies.get(key)?.value ?? null;
  }

  setItem(key: string, value: string): void {
    const { long, domain } = this.scope(key);
    this.cookies.set(key, value, {
      path: "/",
      httpOnly: true,
      sameSite: "lax", // must survive the redirect back from the provider
      secure: !this.isLocal,
      maxAge: long ? 60 * 60 * 24 * 365 : 600,
      ...(domain ? { domain } : {}),
    });
  }

  removeItem(key: string): void {
    const { domain } = this.scope(key);
    // A domain-scoped cookie is only cleared when the same domain is named.
    this.cookies.delete(key, { path: "/", ...(domain ? { domain } : {}) });
  }
}
```

### `src/lib/auth/utils.ts`

```ts
import { AuthClient, type AuthenticatedUser } from "@wilsoon/auth-core";
import { WILSOON_STORAGE_KEYS } from "@wilsoon/auth-provider-wilsoon";
import type { AstroCookies } from "astro";
import { AstroCookieStorage } from "./AstroCookieStorage";
import { authConfig, type EnvSource } from "./config";

export function getAuthClient(cookies: AstroCookies, origin: string, env?: EnvSource): AuthClient {
  return new AuthClient(authConfig(origin, env), new AstroCookieStorage(cookies, origin, WILSOON_STORAGE_KEYS.tokens));
}

/** The verified user for this request, or null. Fails closed. */
export async function getAuthenticatedUser(cookies: AstroCookies, origin: string, env?: EnvSource): Promise<AuthenticatedUser | null> {
  const client = getAuthClient(cookies, origin, env);

  const tokens = client.getStoredTokens();
  if (!tokens) return null;

  let current = tokens;
  if (client.isTokenNearExpiry(tokens.access_token)) {
    if (!tokens.refresh_token) {
      client.clearStorage();
      return null;
    }
    try {
      // Refresh tokens rotate; the library stores the rotated response itself.
      current = await client.refreshAccessToken(tokens.refresh_token);
    } catch {
      client.clearStorage();
      return null;
    }
  }

  try {
    // This app's own ID token when the cookie is ours; the shared session otherwise.
    return await client.resolveSession(current);
  } catch {
    return null;
  }
}
```

`resolveSession()` is the framework-agnostic version of what `getSession()` does in Next.js.

### `src/pages/auth.ts` and `src/pages/api/callback.ts`

```ts
// src/pages/auth.ts - login
import type { APIRoute } from "astro";
import { getAuthClient } from "../lib/auth/utils";

const RETURN_TO_COOKIE = "auth_return_to";

export const GET: APIRoute = async ({ url, cookies, redirect, locals }) => {
  const next = url.searchParams.get("next") ?? "/";

  // Same-origin paths only, so `?next=` cannot become an open redirect.
  if (!next.startsWith("/") || next.startsWith("//")) return new Response("Invalid 'next' parameter", { status: 400 });

  const client = getAuthClient(cookies, url.origin, (locals as any).runtime?.env);
  const { url: authorizeUrl } = await client.createAuthorizeUrl();

  cookies.set(RETURN_TO_COOKIE, next, { path: "/", httpOnly: true, sameSite: "lax", secure: url.protocol === "https:", maxAge: 600 });
  return redirect(authorizeUrl);
};
```

```ts
// src/pages/api/callback.ts
import type { APIRoute } from "astro";
import { AuthError } from "@wilsoon/auth-core";
import { getAuthClient } from "../../lib/auth/utils";

const RETURN_TO_COOKIE = "auth_return_to";

export const GET: APIRoute = async ({ url, cookies, redirect, locals }) => {
  const client = getAuthClient(cookies, url.origin, (locals as any).runtime?.env);
  const returnTo = cookies.get(RETURN_TO_COOKIE)?.value || "/";
  cookies.delete(RETURN_TO_COOKIE, { path: "/" });

  try {
    await client.handleCallback(url.href, { persistTokens: true });
    return redirect(returnTo);
  } catch (error) {
    const code = error instanceof AuthError ? error.code : "AUTH_FAILED";
    const errorUrl = new URL(returnTo, url.origin);
    errorUrl.searchParams.set("auth_error", code.toLowerCase());
    return redirect(errorUrl.pathname + errorUrl.search);
  }
};
```

### `src/middleware.ts`

```ts
import { defineMiddleware } from "astro:middleware";
import { AMR, hasPermission, satisfiesAmr } from "@wilsoon/auth-core";
import { getAuthenticatedUser } from "./lib/auth/utils";

export const onRequest = defineMiddleware(async (context, next) => {
  if (!context.url.pathname.startsWith("/admin")) return next();

  const isApi = context.url.pathname.startsWith("/api/");
  const deny = (status: number, error: string) => new Response(JSON.stringify({ error }), { status });
  const user = await getAuthenticatedUser(context.cookies, context.url.origin, (context.locals as any).runtime?.env);

  if (!user) return isApi ? deny(401, "Unauthorized") : context.redirect(`/auth?next=${encodeURIComponent(context.url.pathname)}`);
  if (!hasPermission(user, "my_app.admin")) return deny(403, "Forbidden");

  // `mfa` alone is not phishing-resistant: WilsoonID emits it for TOTP too.
  // To ask for a passkey instead of refusing, see Step-up authentication.
  if (!satisfiesAmr(user, [AMR.FIDO])) return deny(403, "A passkey sign-in is required");

  context.locals.user = user;
  return next();
});
```

---
title: Next.js App Router
identifier: nextjs
order: 1
---

The full wiring for an App Router app: a shared config, login and callback route handlers,
middleware that gates and refreshes, and the server helpers that authorize.

```bash
npm install @wilsoon/auth-core @wilsoon/auth-next
```

## Config

One object, shared by every file below.

```ts
// lib/auth-config.ts
export const authConfig = {
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET, // server-side only
  issuer: "https://id.example.com",
  redirectUri: `${process.env.APP_URL}/api/auth/callback`,
  scope: ["openid", "profile", "email", "offline_access"], // offline_access only if you refresh

  // Where your provider puts roles and permissions, if it does. See Authorization.
  rolesClaim: "roles",
  permissionsClaim: "permissions",
};
```

`redirectUri` must exactly match one of the redirect URIs registered with the provider.

{% callout type="tip" title="On WilsoonID" %}
Pass the provider's profile instead of the claim selectors. It maps WilsoonID's claims, keeps
the 2.x cookie names and adds `client.wilsoon`:

```ts
import { wilsoon, WILSOON_ISSUER } from "@wilsoon/auth-provider-wilsoon";

export const authConfig = { clientId, clientSecret, issuer: WILSOON_ISSUER, redirectUri, profile: wilsoon() };
```
{% /callout %}

## Login and callback

```ts
// app/api/auth/login/route.ts
import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { AuthClient } from "@wilsoon/auth-core";
import { ServerCookieStorage } from "@wilsoon/auth-next";
import { authConfig } from "@/lib/auth-config";

export async function GET() {
  const client = new AuthClient(authConfig, new ServerCookieStorage(await cookies()));

  // Persists state, nonce and the PKCE verifier as HttpOnly cookies (10 min).
  // Next.js applies those cookie writes to whatever response this handler returns.
  const { url } = await client.createAuthorizeUrl();

  return NextResponse.redirect(url);
}
```

```ts
// app/api/auth/callback/route.ts
import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { AuthClient, AuthError } from "@wilsoon/auth-core";
import { ServerCookieStorage } from "@wilsoon/auth-next";
import { authConfig } from "@/lib/auth-config";

export async function GET(request: Request) {
  const client = new AuthClient(authConfig, new ServerCookieStorage(await cookies()));

  try {
    // Validates state, exchanges the code with its PKCE verifier, verifies the ID token
    // (signature, iss, aud, exp, nonce), clears the transient cookies and stores the tokens.
    await client.handleCallback(request.url, { persistTokens: true });
    return NextResponse.redirect(new URL("/dashboard", request.url));
  } catch (error) {
    const code = error instanceof AuthError ? error.code : "UNKNOWN";
    return NextResponse.redirect(new URL(`/auth?error=${code}`, request.url));
  }
}
```

The session cookie is named after the client's `storageKeys.tokens`: `oidc_tokens` by
default, or whatever `storagePrefix` or the profile sets.

## Middleware

```ts
// middleware.ts
import { createAuthMiddleware } from "@wilsoon/auth-next";
import { authConfig } from "./lib/auth-config";

export const middleware = createAuthMiddleware({
  ...authConfig,
  loginPath: "/api/auth/login", // default "/auth"
  unauthorizedPath: "/unauthorized",
  // roles: ["admin"],                    // any of
  // permissions: ["billing.read"],       // all of
  // amr: ["fido"],
  // enforce: "live",                     // ask the provider on every request
});

export const config = { matcher: ["/dashboard/:path*", "/admin/:path*"] };
```

Per request it reads the session cookie, refreshes an access token that is close to expiry
(on navigations only, one refresh per page load), verifies the session, and checks the policy.
A session that cannot be verified is cleared and redirected rather than looped.

`enforce: "live"` asks the provider on every request whether the session still stands, and
checks `permissions` against what the user holds right now. It needs a `clientSecret`. If the
provider cannot be reached it answers 503 and keeps the cookie, so an outage signs nobody out.

## Server Components and Route Handlers

```tsx
import { redirect } from "next/navigation";
import { hasPermission } from "@wilsoon/auth-core";
import { getSession, requireSession } from "@wilsoon/auth-next";
import { authConfig } from "@/lib/auth-config";

export default async function Page() {
  const { user } = await getSession(authConfig); // null unless verified
  if (!user) redirect("/api/auth/login");

  return (
    <p>
      Hello {user.name}
      {hasPermission(user, "billing.read") && <a href="/billing">Billing</a>}
    </p>
  );
}
```

```ts
// Guard-clause style: throws AuthError with code NO_SESSION or FORBIDDEN.
const user = await requireSession(authConfig, { permissions: ["billing.write"], amr: ["fido"] });
```

Verifying clients are cached per config, so the JWKS is fetched once per runtime instance, not
once per render. Define `authConfig` (and any profile in it) once at module level so the cache
can find it.

## Client Components

```tsx
"use client";
import { AuthProvider, useAuth } from "@wilsoon/auth-next"; // re-exported from auth-react
```

See [React SPA](/recipes/react-spa) for the provider API. Client state is for rendering; the
server helpers above are what gate access.

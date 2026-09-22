# @wilsoon/auth-next

OpenID Connect for the Next.js App Router: verified sessions in Server Components and Route
Handlers, plus route-protecting Edge Middleware that refreshes expiring tokens.

Part of the [Wilsoon Node OIDC Kit](https://github.com/Wilsoon7721/node-oidc-kit) - an OpenID Connect relying party for TypeScript.
Siblings: [`@wilsoon/auth-core`](https://www.npmjs.com/package/@wilsoon/auth-core) · [`@wilsoon/auth-react`](https://www.npmjs.com/package/@wilsoon/auth-react) · **`@wilsoon/auth-next`**.

## Features

- **Verified sessions:** `getSession()` verifies the ID token's signature, issuer, audience and expiry against the provider's JWKS on every request, so `user.role` and `user.authMethods` can gate access.
- **Edge Middleware:** Protect your routes, enforce role/`amr` policies, and refresh tokens at the Edge.
- **Server Components:** Access session data securely using `next/headers` without client-side waterfalls.
- **Client Components:** Re-exports `@wilsoon/auth-react` so you can use it client-side with `"use client"`.

## Installation

```bash
npm install @wilsoon/auth-next @wilsoon/auth-core @wilsoon/auth-react
```

Full end-to-end recipes, migration notes and a troubleshooting table live in the
[integration guide](https://github.com/Wilsoon7721/node-oidc-kit/blob/main/INTEGRATION.md).

## Basic Usage

Keep one config object and share it across middleware, server helpers and the provider.

```typescript
// lib/auth-config.ts
import type { AuthConfig } from "@wilsoon/auth-core";

export const authConfig: AuthConfig = {
  clientId: process.env.OIDC_CLIENT_ID!,
  issuer: "https://id.example.com",
  redirectUri: "https://app.example.com/callback",
};
```

### 1. Protecting Routes with Middleware

Create a `middleware.ts` file in the root or `src/` directory of your Next.js project.

```typescript
import { createAuthMiddleware } from "@wilsoon/auth-next";
import { authConfig } from "./lib/auth-config";

export const middleware = createAuthMiddleware({
  ...authConfig,
  loginPath: "/auth",
  // Verifies the ID token per request (default). Optional policy:
  roles: ["admin"],
  unauthorizedPath: "/unauthorized",
});

// Protect specific routes
export const config = {
  matcher: ["/dashboard/:path*", "/profile/:path*"],
};
```

The middleware verifies the session, refreshes an access token that is near expiry (writing the rotated tokens back to the cookie), and clears the cookie instead of looping when a session cannot be verified. Pass `verify: false` to get 1.x behaviour - presence-of-cookie routing only, which any client can fake.

A refresh token is single-use where the provider rotates it, so a page load that sends ten requests through the middleware with one cookie must not send ten refreshes: nine of them present a token that has just been rotated away, and a provider that reads that as theft revokes the session. Refreshes therefore start `refreshThresholdSeconds` before expiry (default 300) and only on navigations, which is one request per page load. Set `refreshOn: "request"` to refresh from any request instead. A token with nothing left refreshes whatever the setting, so an app that only ever sends fetches still renews, and a refresh that fails while the access token is still valid leaves the session alone for a later request to retry.

### 2. Accessing Session in Server Components

```tsx
import { getSession } from "@wilsoon/auth-next";
import { authConfig } from "@/lib/auth-config";

export default async function DashboardPage() {
  const { user } = await getSession(authConfig);

  if (!user) return <div>Access Denied</div>;

  return (
    <div>
      <h1>Welcome to your Dashboard, {user.email}!</h1>
      <p>Role: {user.role}</p>
    </div>
  );
}
```

`user` is `null` unless the ID token verified, so `user.role` is a verified claim rather than a decoded one. When a cookie was present but unusable, the reason is in `error`.

For a guard clause, `requireSession()` throws instead:

```tsx
import { requireSession } from "@wilsoon/auth-next";
import { AMR } from "@wilsoon/auth-core";

const user = await requireSession(authConfig, { roles: ["admin"], amr: [AMR.FIDO] });
```

Verifying clients are cached per configuration, so the provider's JWKS is fetched once per runtime instance rather than once per render.

### 3. Handling the callback in a Route Handler

```typescript
import { cookies } from "next/headers";
import { AuthClient } from "@wilsoon/auth-core";
import { ServerCookieStorage } from "@wilsoon/auth-next";
import { authConfig } from "@/lib/auth-config";

export async function GET(request: Request) {
  const client = new AuthClient(authConfig, new ServerCookieStorage(await cookies(), { domain: ".example.com" }));

  // Validates state, exchanges the code with its PKCE verifier, verifies the ID token.
  const { user } = await client.handleCallback(request.url, { persistTokens: true });

  return Response.redirect(new URL(`/dashboard?welcome=${encodeURIComponent(user?.name ?? "")}`, request.url));
}
```

Start the flow from a matching route with `client.createAuthorizeUrl()`, which persists `state`, `nonce` and the PKCE verifier into HttpOnly cookies through the same storage - the two halves are no longer the caller's problem.

### 4. Client-Side Usage

`@wilsoon/auth-next` seamlessly re-exports `@wilsoon/auth-react`. You can import the `AuthProvider` and `useAuth` hook directly from `@wilsoon/auth-next` for your Client Components.

```tsx
"use client";

import { useAuth, AuthProvider } from "@wilsoon/auth-next";

// ...
```

Client state is for rendering only - the server helpers above are what gate access.

## Environment

Designed specifically for Next.js 13+. `ServerCookieStorage` reads cookies anywhere `cookies()` works and writes them in Route Handlers, Server Actions and middleware; in a Server Component, where Next.js forbids writes, it throws `StorageUnavailableError` explaining where to move the call.

## License

[MIT](./LICENSE) - free use, forking and redistribution, with no warranty of any kind.

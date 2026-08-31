---
title: Quick start
identifier: quick-start
order: 3
---

This is the whole login flow with `@wilsoon/auth-core` directly - the same three calls used by every framework package.

```ts
import { AuthClient } from "@wilsoon/auth-core";

export const authConfig = {
  clientId: process.env.OIDC_CLIENT_ID,
  clientSecret: process.env.OIDC_CLIENT_SECRET, // server-side only
  issuer: "https://id.example.com",
  redirectUri: "https://app.example.com/api/callback",
  scope: ["openid", "profile", "email", "offline_access"],
};

// One client per request, holding this request's cookies.
// `storage` is your adapter - see Storage. In the browser you can omit it.
const client = new AuthClient(authConfig, storage);
```

```ts
// GET /api/login
const { url } = await client.createAuthorizeUrl();
return Response.redirect(url);
```

`createAuthorizeUrl()` generates `state` (CSRF), `nonce` (ID token replay protection) and a PKCE verifier, and persists all three through `storage` so the callback can complete without you wiring that up.

```ts
// GET /api/callback?code=...&state=...
const { tokens, user } = await client.handleCallback(request.url);
// `user` is an AuthenticatedUser: verified signature, issuer, audience, expiry and nonce.
client.saveTokens(tokens);
```

`handleCallback()` validates `state`, exchanges the code with its PKCE verifier, verifies the returned ID token against the provider's JWKS, checks the `nonce`, and clears the transient state - one call instead of four.

```ts
// On any later request
const user = await client.resolveSession(client.getStoredTokens());
if (user.role !== "admin") return forbidden();
```

{% callout type="warning" title="Only three methods are safe to authorize on" %}
`verifyIdToken()`, `verifyAccessToken()` and `verifyPlatformSession()` - everything else, including `handleCallback()`'s `user` and any method whose name ends in `Unsafe`, either wraps one of those three or returns something you may render but must never gate access with. See [Security model](/core-concepts/security-model).
{% /callout %}

## Using a framework package

`@wilsoon/auth-react` wraps this in `<AuthProvider>` / `useAuth()` for browser session state, and `@wilsoon/auth-next` wraps it in `getSession()` / `requireSession()` / `createAuthMiddleware()` for the Next.js App Router. Both call the same `AuthClient` underneath - nothing above changes, only who calls it.

For per-framework, copy-pasteable recipes (Next.js, a React SPA, Astro on Cloudflare Workers, a plain resource server), see the [integration guide](https://github.com/Wilsoon7721/node-oidc-kit/blob/main/INTEGRATION.md) on GitHub.

## Next

- [Storage](/core-concepts/storage) - what `storage` above actually is, and how to write one for a framework with no package here
- [Security model](/core-concepts/security-model) - the verified/unverified split in full
- [Session models](/core-concepts/session-models) - one login per app, or one shared across subdomains

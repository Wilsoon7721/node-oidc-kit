---
title: Checklist before you ship
identifier: checklist
order: 8
---

## Your application

- [ ] `clientSecret` is only ever read on the server.
- [ ] Every authorization decision goes through `verifyIdToken()`, `getSession()`,
      `requireSession()`, `resolveSession()` or `verifyAccessToken()`.
- [ ] `rolesClaim` / `permissionsClaim` or a profile is configured, if you authorize on roles or
      permissions.
- [ ] `redirectUri` and any `post_logout_redirect_uri` are registered with the provider.
- [ ] Transient login cookies are `HttpOnly`, `Secure`, `SameSite=Lax`, and host-only.
- [ ] `offline_access` is requested only if you actually refresh, and refreshed tokens are
      persisted. The library does it when it owns storage; providers that rotate refresh tokens
      revoke a replayed one.
- [ ] Privileged actions check `satisfiesAmr(...)` and, where it matters, the live answer
      (`enforce: "live"` or `liveAccess()`).
- [ ] If you share a session cookie across subdomains: a profile that resolves shared sessions,
      `apiAudience` and `clientSecret` are set, and you never authorize on an ID token whose
      `aud` is not yours.
- [ ] Logout clears your own cookies as well as redirecting to the provider.

## The identity provider

For whoever operates it.

- [ ] The issuer is the deployment's public URL. Tokens and the discovery document must agree,
      or every client rejects every token.
- [ ] The JWKS publishes the key that signs tokens, and each `kid` is stable.
- [ ] After a key rotation, the previous `kid` stays published until the longest session has
      expired.
- [ ] Introspection is reachable and only accepts confidential clients.
- [ ] For silent sign-in, the authorization endpoint may be framed by your first-party origins.

---
title: Introduction
identifier: introduction
order: 1
---

**node-oidc-kit** is a framework-agnostic OpenID Connect _relying party_ for TypeScript - the client half of OIDC, not the provider. Point it at any conforming issuer, get back a verified user, and stop hand-rolling PKCE.

```js
const client = new AuthClient({ clientId, issuer: "https://id.example.com", redirectUri });

const { url } = await client.createAuthorizeUrl(); // PKCE + state + nonce, persisted
// ...redirect, and on the way back:
const { user } = await client.handleCallback(request.url);
// signature, issuer, audience, expiry and nonce all checked. Safe to authorize on.
```

Four packages, one runtime dependency ([`jose`](https://github.com/panva/jose)), no Node-only imports - just `fetch` and Web Crypto. It runs in a browser, in Node 18+, and on edge runtimes like Cloudflare Workers.

{% callout type="note" title="Where this came from" %}
This grew out of running my own OIDC provider for several first-party apps. The generic OIDC clients handled the textbook authorization-code-plus-PKCE flow fine, and fell over on the parts that make up an actual platform: one login shared across subdomains, revocation that takes effect before a token's own expiry, and a type system that won't let you authorize on a claim nobody verified. Those problems aren't specific to my provider - if you run your own OIDC issuer, they're probably yours too.
{% /callout %}

## The packages

| Package                 | What it's for                                                                                                      | Depends on            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------- |
| `@wilsoon/auth-core`    | The client: discovery, PKCE, code exchange, token verification, introspection, `amr` policies. Framework-agnostic. | `jose`                |
| `@wilsoon/auth-react`   | `<AuthProvider>` and `useAuth()` for browser session state.                                                        | core, React ≥16       |
| `@wilsoon/auth-next`    | `getSession()`, `requireSession()`, `createAuthMiddleware()`, `ServerCookieStorage`.                               | core, react, Next ≥14 |
| `@wilsoon/auth-machine` | `client_credentials` tokens for server-to-server calls, with caching and single-flight. **0.x**, standalone.       | nothing               |

The first three are versioned together on a shared 2.x line. `auth-machine` has no dependency on the others and is versioned independently - see [Machine tokens](/flows/machine-tokens).

Using anything else - Astro, SvelteKit, Hono, Express? Use `@wilsoon/auth-core` directly and write one storage adapter. See [Storage](/core-concepts/storage) - that's the entire
integration.

## One rule, everywhere

Only five methods produce a value you may authorize on: `verifyIdToken()`, `verifyAccessToken()`, `verifyPlatformSession()`, `verifyMachineToken()` and `verifyEscalationToken()`. Every method whose name ends in `Unsafe`, plus the userinfo-backed `getUser()` / `hydrateSession()`, returns something you can render but never gate access with. [Security model](/core-concepts/security-model) covers why, and how the type system enforces it.

{% aside title="Not a provider" %}
This is the _client_ half of OIDC. It doesn't run an authorization server, issue tokens, or store users - it talks to one you (or someone else) already runs.
{% /aside %}

## Next

- [Installation](/getting-started/installation) - requirements and package choice
- [Quick start](/getting-started/quick-start) - a working login flow in a few lines
- [Flows](/flows/escalation) - step-up, the device grant, and machine-to-machine tokens

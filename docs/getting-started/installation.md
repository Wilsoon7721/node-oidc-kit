---
title: Installation
identifier: installation
order: 2
---

Install the package for your framework. Each one pulls in `@wilsoon/auth-core`
automatically.

```bash
# Framework-agnostic - Astro, SvelteKit, Hono, Express, a plain API...
npm install @wilsoon/auth-core

# React SPA
npm install @wilsoon/auth-react

# Next.js App Router
npm install @wilsoon/auth-next
```

## What your provider needs to offer

Discovery does the work: set `issuer` and the SDK reads
`/.well-known/openid-configuration` for every endpoint. There are no hardcoded URLs on the
hot path.

| Requirement                                                      | Why                                                              | If it's missing                                                              |
| ---------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `/.well-known/openid-configuration` with the four core endpoints | Every other endpoint is discovered from here                     | `DiscoveryError` at startup                                                  |
| `issuer` in that document matching your configured `issuer`      | Stops tokens being validated against an issuer you didn't choose | `IssuerMismatchError` - set `expectedIssuer` if the difference is deliberate |
| Authorization code flow with **PKCE (`S256`)**                   | The only flow implemented                                        | Nothing works                                                                |
| **RS256** ID token signatures                                    | The SDK's allowlist is RS256 only                                | `ERR_JOSE_ALG_NOT_ALLOWED`                                                   |
| `nonce` echoed into the ID token                                 | ID token replay protection, mandatory in the OIDC spec           | `NonceMismatchError` on every login                                          |

{% callout type="tip" %}
Everything below `nonce` - `end_session_endpoint` for logout, `introspection_endpoint` for
live revocation - is optional and degrades cleanly. You lose one feature, not the whole
login. See [Pointing it at your own provider](/core-concepts/your-own-provider) for the
full picture, including the handful of things that are still specific to one reference
provider.
{% /callout %}

## Requirements

Node.js 18+, any modern browser, or an edge runtime with `fetch` and the Web Crypto API
(`globalThis.crypto`). There are no Node-only imports anywhere in the dependency graph.

## Next

[Quick start](/getting-started/quick-start) - wire up a login flow.

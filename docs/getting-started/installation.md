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

Server-to-server calls with no user involved need a different package, installed on its own:

```bash
npm install @wilsoon/auth-machine
```

{% callout type="note" title="auth-machine is 0.x, and stands alone" %}
It has no dependency on `@wilsoon/auth-core`, so it is versioned independently of the other
three rather than sharing their 2.x line. `0.x` reflects that its API may still move before
it has seen production use. See [Machine tokens](/flows/machine-tokens).
{% /callout %}

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
Everything below `nonce` - `end_session_endpoint` for logout, `introspection_endpoint` for live revocation - is optional and degrades cleanly. You lose one feature, not the whole login. See [Pointing it at your own provider](/core-concepts/your-own-provider) for the full picture, including the handful of things that are still specific to one reference provider.
{% /callout %}

## Optional endpoints, and what they unlock

Two flows need an endpoint beyond the core four, and both degrade to a clear error rather than a broken login when the provider doesn't offer them.

| Flow                                | Needs                                                | Without it                              |
| ----------------------------------- | ---------------------------------------------------- | --------------------------------------- |
| [Device grant](/flows/device-grant) | `device_authorization_endpoint` in discovery         | `DeviceFlowError` naming the gap        |
| [Escalation](/flows/escalation)     | `<issuer>/api/escalate`, or `escalationEndpoint` set | Provider-specific; not an OIDC endpoint |

## Requirements

Node.js 18+, any modern browser, or an edge runtime with `fetch` and the Web Crypto API (`globalThis.crypto`). There are no Node-only imports anywhere in the dependency graph.

`@wilsoon/auth-machine` is server-only and throws if it finds a `window` - it holds a client secret, so it must never reach a browser bundle.

## Next

[Quick start](/getting-started/quick-start) - wire up a login flow.

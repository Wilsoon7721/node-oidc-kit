# Security Policy

This SDK verifies identity tokens and gates authorization decisions. A verification bug
here can mean a forged signature is accepted, a claim from the wrong audience is trusted,
or a revoked session keeps working - please report it privately rather than opening a
public issue.

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/Wilsoon7721/node-oidc-kit/security/advisories/new) for this repository (Security tab → "Report a vulnerability"). If you'd rather not use
GitHub, email **hello@wilsoon.dev** with as much of the following as you can:

- The package and version affected (`@wilsoon/auth-core`, `@wilsoon/auth-react`, or `@wilsoon/auth-next`)
- A description of the issue and its impact - what a forged or manipulated token, a malicious storage adapter, or a malicious provider response could achieve
- Steps to reproduce, or a minimal repro (see the [fake IdP test harness](packages/auth-core/test/fake-idp.ts) if you need a stand-in provider to demonstrate against)

You should get an initial response in a **maximum of 3 days**. I'll credit you in the
advisory and the changelog unless you'd rather stay anonymous.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 2.x     | ✅        |
| 1.x     | ❌        |

Only the latest major version receives security fixes. See [CHANGELOG.md](CHANGELOG.md#migrating-from-1x) for the 1.x → 2.x migration - it exists specifically because 1.x let unverified claims be used for authorization.

## Scope

In scope: `@wilsoon/auth-core`, `@wilsoon/auth-react`, `@wilsoon/auth-next`, and this
repository's own tooling (build config, CI).

Out of scope: the identity provider you point this SDK at. If your provider itself has a
vulnerability, report it to whoever runs it. A bug in this SDK's OIDC discovery,
verification or storage handling **is** in scope even if it only manifests against a
specific provider's behavior.

## What "verified" means here

Not every finding is a vulnerability. Before reporting, it's worth checking
[the security model in the docs](https://docs.wilsoon.dev/node-oidc-kit/core-concepts/security-model) -
only `verifyIdToken()`, `verifyAccessToken()` and `verifyPlatformSession()` are meant to be
authorized on. Anything from a method ending in `Unsafe`, or from `getUser()` /
`hydrateSession()`, is documented as unverified by design; a report that one of those can
be spoofed is expected behavior, not a bug. A report that spoofing one of the three
verified methods succeeds, or that verification can be bypassed entirely, is exactly what
this policy is for.

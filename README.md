# @wilsoon/auth-core / auth-react / auth-next / auth-machine

A small, framework-agnostic OpenID Connect **relying party** for TypeScript - the client
half of OIDC, not the provider. Point it at any conforming issuer, get back a verified
user, and stop hand-rolling PKCE.

```ts
const client = new AuthClient({ clientId, issuer: "https://id.example.com", redirectUri });

const { url } = await client.createAuthorizeUrl(); // PKCE + state + nonce, persisted
// ...redirect, and on the way back:
const { user } = await client.handleCallback(request.url);
//    ^ signature, issuer, audience, expiry and nonce all checked. Safe to authorize on.
```

Four packages, one runtime dependency
([`jose`](https://github.com/panva/jose)), and no Node-only imports - just `fetch` and Web
Crypto. It runs in a browser, in Node 18+, and on edge runtimes like Cloudflare Workers.

> This was originally a private repository. I've only decided to publicise it now in v2 as I originally built it to serve my own purposes at [id.wilsoon.dev](https://id.wilsoon.dev), but things have been patched to be more generic since then.  

Full documentation, with slightly more depth than this README, is at
**[docs.wilsoon.dev/node-oidc-kit](https://docs.wilsoon.dev/node-oidc-kit)**.

- [Why this exists](#why-this-exists)
- [Packages](#packages)
- [Quick start](#quick-start)
- [Beyond the login flow](#beyond-the-login-flow)
- [Pointing it at your own provider](#pointing-it-at-your-own-provider)
- [Storage: the one thing to understand](#storage-the-one-thing-to-understand)
- [The security model](#the-security-model)
- [Things that are still specific to one provider](#things-that-are-still-specific-to-one-provider)
- [Contributing](#contributing)
- [License](#license)

---

## Why this exists

After building my OIDC provider at `id.wilsoon.dev` and several first-party apps that sign in against it, I decided to build the OIDC library instead of relying on existing OIDC client libraries that were not very well-suited for my needs.

As such, I built this authentication library in order to plug my provider into all my web apps, regardless of the web framework.

## Packages

| Package                                      | What it's for                                                                                                      | Depends on            |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------- |
| [`@wilsoon/auth-core`](packages/auth-core)   | The client: discovery, PKCE, code exchange, token verification, introspection, `amr` policies. Framework-agnostic. | `jose`                |
| [`@wilsoon/auth-react`](packages/auth-react) | `<AuthProvider>` and `useAuth()` for browser session state.                                                        | core, React ≥16       |
| [`@wilsoon/auth-next`](packages/auth-next)   | `getSession()`, `requireSession()`, `createAuthMiddleware()`, `ServerCookieStorage`.                               | core, React, Next ≥14 |
| [`@wilsoon/auth-machine`](packages/auth-machine) | `client_credentials` tokens for server-to-server calls, with caching and single-flight. **0.x**, standalone.  | nothing               |

Using anything else - Astro, SvelteKit, Hono, Express? Use `auth-core` directly and write one [storage adapter](#storage-the-one-thing-to-understand). That's the whole integration.

The first three are versioned together on a shared 2.x line. `auth-machine` has no dependency on the others, so it is versioned independently and is currently 0.x.

For end-to-end recipes per framework, see **[INTEGRATION.md](INTEGRATION.md)**; for what
changed in 2.0 and how to migrate from 1.x, see **[CHANGELOG.md](CHANGELOG.md)**. This README
is about the design and about running the project; that one is about wiring an app up.

## Quick start

```bash
pnpm add @wilsoon/auth-core
```

```ts
import { AuthClient } from "@wilsoon/auth-core";

export const authConfig = {
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET, // server-side only
  issuer: "https://id.example.com",
  redirectUri: "https://app.example.com/api/callback",
  scope: ["openid", "profile", "email", "offline_access"],
};

// One client per request, holding this request's cookies.
// `storage` is your adapter - see below. In the browser you can omit it.
const client = new AuthClient(authConfig, storage);
```

```ts
// GET /api/login
const { url } = await client.createAuthorizeUrl();
return Response.redirect(url);
```

```ts
// GET /api/callback?code=...&state=...
const { tokens, user } = await client.handleCallback(request.url);
// `user` is an AuthenticatedUser: verified signature, issuer, audience, expiry and nonce.
client.saveTokens(tokens);
```

```ts
// On any later request
const user = await client.resolveSession(client.getStoredTokens()!);
if (user.role !== "admin") return forbidden();
```

`handleCallback()` validates `state`, exchanges the code with its PKCE verifier, verifies
the returned ID token against the provider's JWKS, checks the `nonce`, and clears the
transient state. If you find yourself calling `exchangeCodeForToken()` and
`validateState()` by hand, you're re-implementing it.

## Pointing it at your own provider

Discovery does the work: set `issuer` and the SDK reads `/.well-known/openid-configuration` for every endpoint. Apart from the issuer and the `/openid-configuration` path, there are no hardcoded URLs.

Your provider needs to offer:
| Requirement | Why | If it doesn't |
| -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `/.well-known/openid-configuration` with `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri` | Every other endpoint is discovered from here | `DiscoveryError` at startup |
| `issuer` in that document matching your configured `issuer` | Stops tokens being validated against an issuer you didn't choose | `IssuerMismatchError` - set `expectedIssuer` if the difference is deliberate |
| Authorization code flow with **PKCE (`S256`)** | The only implemented flow here, there is no implicit flow. | Nothing will work |
| **RS256** ID token signatures | See [algorithms](#2-rs256-only) | `ERR_JOSE_ALG_NOT_ALLOWED` |
| `nonce` added into the ID token | ID token replay protection (also mandatory in the OIDC spec) | `NonceMismatchError` on every login |
| `end_session_endpoint` | RP-initiated logout | `getLogoutUrl()` throws `LogoutError`, log out locally instead |
| `introspection_endpoint` (RFC 7662) | Live revocation, and roles for resource servers | `verifyPlatformSession()` and introspection-based `isSessionCurrent()` unavailable; plain `verifyIdToken()` is unaffected |

Everything below `nonce` is optional. If it doesn't exist, you lose a feature, but the core functionality remains.

Two session models are supported, and which one you're in decides which methods you use:

- **Per-application session** (standard OIDC). Each app has its own cookie and its own ID
  token. Use `verifyIdToken()` / `getSession()`.
- **Platform session** (one cookie across subdomains). Set `apiAudience` and
  `clientSecret`, and use `resolveSession()`, which falls back to `verifyPlatformSession()` when the cookie belongs to another app.

## Storage: the one thing to understand

The library persists 4 values:

| Key                         | Lifetime           | Purpose                                        |
| --------------------------- | ------------------ | ---------------------------------------------- |
| `STORAGE_KEYS.tokens`       | The session        | The token response blob                        |
| `STORAGE_KEYS.state`        | One login, minutes | CSRF binding between authorize and callback    |
| `STORAGE_KEYS.nonce`        | One login, minutes | Binds the ID token to _this_ authorize request |
| `STORAGE_KEYS.codeVerifier` | One login, minutes | The PKCE secret                                |

The `state`, `nonce`, and `codeVerifier` are written when you build the authorize URL and read after the provider redirects back - a _different request_, often to a different process. Somewhere durable across that redirect has to hold them. That "where" is the only thing that differs between a browser SPA, Next.js, Astro, and an Express app, so it's the only thing the library asks you to provide:

```ts
interface AuthStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}
```

### Which one ships, and why each exists

| Implementation        | Where       | Why it exists                                                                                                                                                                                                                                                                                          |
| --------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `BrowserStorage`      | `auth-core` | Web Storage API. Pass `window.sessionStorage` for login flows - the three values (state/nonce/codeVerifier) are single-use and tab-scoped, and `sessionStorage` will help to expire them. This is what `AuthProvider` does.                                                                            |
| `MemoryStorage`       | `auth-core` | Tests, and single-process flows where authorize and callback are handled by the same instance. Will not survive a restart.                                                                                                                                                                             |
| `UnavailableStorage`  | `auth-core` | The server default when you pass nothing. Every method throws `StorageUnavailableError` naming the operation and the fix. It exists because the old default (`{} as AuthStorage`) type-checked as valid storage and then died with `TypeError: setItem is not a function` far from the actual mistake. |
| `ServerCookieStorage` | `auth-next` | The Next.js cookie store. Writes `HttpOnly` + `SameSite=Lax`, with a short lifetime for the transient three and a long one for the token blob. Throws a useful error in a Server Component, where Next.js forbids cookie writes.                                                                       |
| `CookieStorage`       | `auth-core` | **Deprecated.** Used to be the default, but now the provider sets the token cookie `HttpOnly` which means no browser-side cookie adapter can ever see it again. Kept so existing calls still compile. Use `hydrateSession()` instead.                                                                  |

### Writing your own

There is no `AstroStorage` or `ExpressStorage` in this repo, and there shouldn't be -
adapters belong next to the framework they adapt. Here is the Astro-on-Cloudflare-Workers
one, in full, as a template:

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

Then hand it to the client, and everything else works unchanged:

```ts
const client = new AuthClient(config, new AstroServerStorage(cookies, origin));
```

**The rules an adapter must follow.** Most of these are things that have actually gone wrong:

1. **Synchronous** - `AuthClient` calls these inline. An async store (Redis, Postgres) has to be loaded into a `MemoryStorage` first, then written back after.
2. **Round-trip values unchanged** - Token blobs are JSON. If you encode on write, decode on read. (`getStoredTokens()` tolerates URI-encoding specifically because providers that write the cookie themselves tend to do this.)
3. **`SameSite=Lax`, not `Strict`.** `Strict` drops cookies on the cross-site redirect back from the provider, so `state` is missing and _every_ login fails with `StateMismatchError`.
4. **`Secure`, except on localhost** - where the page is `http` and `Secure` cookies are dropped.
5. **Match the domain when deleting** - A bare `delete()` clears a host-only cookie and leaves a domain-wide one in place, which reads back as a dead session forever. This becomes a redirect loop.
6. **Missing key returns `null`** - It does not return `undefined`, and will not throw an error.
7. **A write that fails should throw an error, not silently fail** - Unless the failure to write is deliberate, as in the Next.js middleware, where the _response_ owns cookie writes and the storage is read-only by design.
8. **Don't share one instance across requests** - Storage is per-request state, and the `AuthClient` is what you cache (see `getCachedClient` in `auth-next`, which reuses the JWKS cache across requests).

To put the token blob under a different cookie name, map it inside your adapter - that's what the Next.js middleware's `cookieName` option does. `STORAGE_KEYS` itself is fixed.

## The security model

**Only five methods** produce a value you may base authorization decisions on:

| Method                                    | Verified?                                      | Gives you                                                                   |
| ----------------------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------- |
| `verifyIdToken()`                         | Signature, `iss`, `aud`, `exp`, `nonce`, `evt` | `AuthenticatedUser` - `role`, `authMethods`, `sessionVersion`               |
| `verifyAccessToken()`                     | Signature, `iss`, pinned `aud`, `exp`, scopes  | `AccessTokenClaims` - no role, plus `tokenUse`                              |
| `verifyPlatformSession()`                 | The above + introspection                      | `AuthenticatedUser` with **current** role and session version               |
| `verifyMachineToken()`                    | The access token checks, plus `token_use`      | `MachineClient` - a `clientId`, and deliberately no user fields             |
| `verifyEscalationToken()`                 | Signature, `iss`, `aud`, `exp`, `evt`          | `VerifiedEscalation` - proof one step-up happened                           |
| `getUser()` / `hydrateSession()`          | Transport only                                 | `ProfileUser` - display claims, no `role` field to prevent potential misuse |
| `decodeIdTokenUnsafe()`, `parseIdToken()` | **Nothing**                                    | `UnverifiedUser` - may be attacker-controlled by definition                 |

`isTokenNearExpiry()` is a refresh _hint_ read from an unverified payload, not a gate. Unparseable or no `exp` field means expired.

Client-side checks are for rendering only. Every authorization decision should be made on the server, where `getSession()` / `requireSession()` verify per request.

Three token kinds share an issuer, an audience and an algorithm, and differ only by a claim. A **machine token**'s `sub` is a `client_id` rather than a person, so `verifyAccessToken()` refuses one unless you pass `allowMachineTokens`, and the session methods refuse it outright. An **escalation token** carries `evt: "escalation"`; `verifyIdToken()` refuses any token with an `evt` at all, so a step-up proof cannot verify as a login.

## Beyond the login flow

Three flows past authorization-code-plus-PKCE, documented in full at [docs.wilsoon.dev/node-oidc-kit](https://docs.wilsoon.dev/node-oidc-kit).

```ts
// Step-up: require a stronger method for one action.
await client.reauthorize(["passkey", "fido"], true, { idTokenHint, openUrl });

// Device grant (RFC 8628): sign in a CLI with no redirect URI.
const { user } = await client.authorizeDevice({ onUserCode });

// Machine tokens: a server calling an API as itself.
const machine = createMachineClient({ issuer, clientId, clientSecret });
await machine.fetch("https://api.example.com/reports");
```

Escalation and the device grant share one polling loop, because the provider answers both with RFC 8628's vocabulary. In both, **the server owns the deadline**: the loop polls until the provider reports `expired_token` rather than timing out on its own clock, since a client-side timer that fires first turns a server-authoritative answer into a guess.

## Things that are still specific to one provider

Being honest about what a fork would have to change. There are five, and only the first is likely to matter the most.

### 1. Roles are a closed set

```ts
// packages/auth-core/src/types.ts
export type UserRole = "admin" | "user";
export const USER_ROLES: readonly UserRole[] = ["admin", "user"];
```

Building `id.wilsoon.dev` meant that I only needed `admin` (myself) and `user`.<br />
This means that any `role` claim outside of that set will throw `ClaimValidationError` (to prevent potential privilege escalation issues), but it does mean a provider issuing `editor` or `owner` must widen both declarations together. **This is the one change most forks will need**.

(This is not yet configurable at runtime. Making it so - `roles?: readonly string[]` on
`AuthConfig` - could be a good first contribution if you would like to help, see [Contributing](#contributing).)

### 2. RS256 only

`ALLOWED_ALGORITHMS` in `jwt.ts` is `['RS256']`. <br />
An allowlist is mandatory - without one a verifier can be talked into `alg: "none"` or HMAC confusion - but the contents are a choice. A provider signing with ES256 or EdDSA needs that array widened. I suggest to keep it an allowlist and never derive it from the token header.

### 3. Storage key names

`STORAGE_KEYS` uses `wilsoon_id_tokens`, `wilsoon_auth_state`, and so on. Cosmetic, and remappable in your adapter without touching the core library.

### 4. One hardcoded logout path

`AuthProvider`'s `logout()` falls back to `${issuer}/api/logout` when the session was hydrated and there's no `id_token` to use as a hint. Everything else goes through discovery. Against another provider, you'll have to handle that case in your own code.

### 5. `hydrateSession()` assumes a cookie-friendly userinfo endpoint

It calls userinfo with `credentials: 'include'` and no `Authorization` header, so the provider must accept a cookie-authenticated request and send CORS credentials headers for your origin. Providers that only accept bearer tokens won't support it - use a server-side session read instead.

## Contributing

Contributions are welcome, including forks that take this somewhere I wouldn't. This uses an [MIT license](LICENSE), you don't need permission.

### Getting set up

```bash
pnpm install
pnpm build
pnpm test       # vitest - 145 tests across the three packages
pnpm lint
pnpm typecheck
```

Node 18+ and pnpm 9. The test suite runs against a fake in-process IdP (`packages/auth-core/test/fake-idp.ts`) that mints real RS256-signed tokens, so verification paths are tested for real rather than mocked - including the failure cases (wrong `aud`, wrong `iss`, `alg: none`, expired, replayed nonce). Add to it rather than mocking `jose`.

### Documentation

The prose at [docs.wilsoon.dev/node-oidc-kit](https://docs.wilsoon.dev/node-oidc-kit) lives in this repo, under `docs/`, as Markdoc files - one folder per chapter, one file per page.

```bash
npx docs check     # validates every page - run this before opening a PR that touches docs/
npx docs preview   # serves docs/ locally so you can see the rendered result
```

Both work with no setup. **Publishing does not**: `docs push` needs a `DOCS_SYNC_SECRET` that only I hold, so it will fail for you, on purpose - the same way you can't `npm publish` the packages themselves. Open a PR against `docs/`; I push it after merge. If `docs check` passes, your PR is complete.

### Layout

```
packages/
  auth-core/    index.ts (AuthClient) · jwt.ts (verification) · storage.ts · types.ts · errors.ts
                amr.ts · utils.ts (PKCE, crypto)
  auth-react/   AuthProvider, useAuth
  auth-next/    middleware · server (getSession/requireSession) · ServerCookieStorage
                resolve.ts (shared routing) · client-cache.ts (JWKS reuse)
```

### House Rules

These are what the existing code follows; matching them makes review quick.

- **Keep things fail closed** - When something can't be determined - a missing `exp`, an unreachable
  introspection endpoint, an unparseable token - the answer should be a hard **no**.
- **Anything unverified is named `*Unsafe`,** and its return type must not carry a field that looks authoritative.
- **Comment the why, not the what.** The codebase is light on JSDoc that restates a method name, and heavy on comments explaining a non-obvious decision: why `new.target` in the error base class, why the refresh is single-flight, why the JWKS cache self-invalidates once. If a future reader would ask "why is it like this?", you could answer it. Lint enforces this at the surface a reader meets first - every exported class and function needs a doc comment - and deliberately not on individual methods, so it never demands a comment that would only restate a name.
- **Don't remove public API.** Deprecate it: a `@deprecated` tag explaining the replacement,
  a one-time runtime warning via `warnOnce`, and the old behaviour intact. Real apps depend
  on these packages.
- **New provider-specific behaviour needs a config option,** not a hardcoded value - and an
  entry in [the list above](#things-that-are-still-specific-to-one-provider) if it can't be.

### Good first issues

- Make `UserRole` configurable (`roles?: readonly string[]` on `AuthConfig`), preserving the fail-closed narrowing.
- Make `ALLOWED_ALGORITHMS` configurable, still as an allowlist.
- Storage adapters for SvelteKit, Remix, Hono, Express - ideally as their own packages, with a link from here.
- Broaden `hydrateSession()` so a bearer-only provider can use it.

Open an issue before a large change so we can discuss a little first. For a suspected security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a public issue - it explains what's in scope and how to reach me privately.

## License

[MIT](LICENSE) - use it, fork it, ship it commercially, no attribution beyond the license
text, and no warranty of any kind.

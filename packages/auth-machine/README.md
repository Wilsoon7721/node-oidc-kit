# @wilsoon/auth-machine

Server-only OAuth 2.0 `client_credentials` tokens, with caching, single-flight and
refresh-ahead.

The grant itself is a form POST that returns a token. That is not what this package is for -
everything of value is around the token.

```bash
pnpm add @wilsoon/auth-machine
```

## Usage

```ts
import { createMachineClient } from "@wilsoon/auth-machine";

const machine = createMachineClient({
  issuer: "https://id.wilsoon.dev",
  clientId: process.env.WILSOON_CLIENT_ID!,
  clientSecret: process.env.WILSOON_CLIENT_SECRET!,
});

// A cached token, obtained once and reused.
const token = await machine.getToken();

// Or let it attach the bearer header and handle a 401 for you.
const res = await machine.fetch("https://api.wilsoon.dev/reports");
```

| Option                      | Default              |                                                  |
| --------------------------- | -------------------- | ------------------------------------------------ |
| `issuer`                    | -                    | Provider base URL.                               |
| `clientId` / `clientSecret` | -                    | Required. The grant is confidential-only.        |
| `refreshAt`                 | `0.75`               | Fraction of lifetime after which renewal starts. |
| `skewSeconds`               | `30`                 | Treated as expired this close to `exp`.          |
| `tokenEndpoint`             | `<issuer>/api/token` | Override if mounted elsewhere.                   |
| `fetch`                     | `globalThis.fetch`   | Injectable, for tests and odd runtimes.          |

## What it actually does

**Single-flight.** Fifty concurrent callers on a cold cache produce one token request, not fifty. This is the easiest thing here to get wrong and the most valuable to get right.

**Refresh-ahead.** Renewal starts at 75% of the lifetime rather than at `exp`, and the still-valid token is served while it runs. Only a cold or fully expired cache makes a caller wait.

**One retry on 401.** A rotated secret or a token rejected mid-flight gets exactly one forced refresh and one retry - never a loop.

**Permanent vs transient.** `invalid_client`, `unauthorized_client`, `invalid_scope` and `unsupported_grant_type` are configuration, not transient. They surface as `MachineTokenError` with `permanent: true`.

## Things worth knowing

**No scope.** Every scope the provider defines (`openid`, `profile`, `email`, `offline_access`) describes a user, so requesting one returns `invalid_scope`. There is deliberately no `scope` option until per-client machine scopes exist.

**No refresh token.** RFC 6749 §4.4.3 says the grant issues none, so there is no refresh path to add.

**An issued token cannot be revoked.** Revocation acts on refresh tokens, and this grant generates none - rotating the secret stops new issuance but leaves outstanding tokens valid until they expire. Short lifetimes are the only real control, which is why `expiresAt` is respected rather than cached past.

**The cache is process memory, on purpose.** The token is short-lived and cheap to re-obtain. Writing it to disk or Redis would create a credential at rest with none of the protections the secret has.

**This package only obtains tokens.** Verifying them belongs on the resource server - use `verifyMachineToken()` from `@wilsoon/auth-core`, which refuses user tokens and returns a type with no user fields on it. `isMachineToken(claims)` is exported here too, for a server that only needs the one check.

## License

MIT

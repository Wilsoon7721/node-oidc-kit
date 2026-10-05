---
title: API / resource server
identifier: resource-server
order: 4
---

An API that receives bearer tokens and decides what each caller may do.

Access tokens are usually minted with an audience shared by every API on the platform, so
verifying only the signature would let any client's token in. Pin the audience:

```ts
import { AuthClient, ClaimValidationError, TokenVerificationError } from "@wilsoon/auth-core";

// A verify-only client needs no redirectUri: it never starts a login.
const client = new AuthClient({
  clientId: process.env.OIDC_CLIENT_ID!,
  issuer: "https://id.example.com",
  clientSecret: process.env.OIDC_CLIENT_SECRET, // only for liveAccess() / introspection
  apiAudience: "https://api.example.com",
  permissionsClaim: "permissions",
});

export async function authenticate(request: Request) {
  const bearer = request.headers.get("authorization")?.replace(/^Bearer /i, "");
  if (!bearer) return unauthorized();

  try {
    const claims = await client.verifyAccessToken(bearer, { requiredScopes: ["openid"] });
    return { userId: claims.subject, scopes: claims.scopes, permissions: claims.permissions };
  } catch (error) {
    if (error instanceof TokenVerificationError || error instanceof ClaimValidationError) return unauthorized();
    throw error;
  }
}
```

`claims.roles` and `claims.permissions` are read through `rolesClaim` / `permissionsClaim` or
the profile, so they are empty until one of those is configured.

## What the user holds right now

A token's claims are what was true when it was minted. To check the current answer, ask the
provider (confidential clients only):

```ts
const access = await client.liveAccess(bearer);
if (!access.active) return unauthorized();
if (access.permissions && !access.permissions.includes("billing.write")) return forbidden();
```

`liveAccess()` uses the profile's hook when there is one, and plain RFC 7662 introspection
otherwise. An absent `permissions` means the provider did not say, not that nothing is held.
This costs a network call, so put it on privileged actions rather than every request.

## Callers with no user

A `client_credentials` token verifies like a user token, but its `sub` is a `client_id`, so
`verifyAccessToken()` refuses it unless you opt in. See
[Machine tokens](/flows/machine-tokens).

## Asking for a stronger login

Answer `401` with an RFC 9470 challenge and let the client act on it. See
[Step-up authentication](/flows/step-up).

# @wilsoon/auth-react

React components and hooks for the Wilsoon Identity platform. Provides a convenient context provider and hook to manage authentication state across your React application.

## Features

- **AuthProvider:** Wraps your application to manage global authentication state, the login redirect, and the verified callback exchange.
- **useAuth Hook:** Easily access the current user, tokens, loading state, and auth methods from any child component.
- **Next.js App Router Compatible:** Includes the `"use client"` directive, making it safe for Next.js 13+ App Router.

## Installation

```bash
npm install @wilsoon/auth-react @wilsoon/auth-core
```

Full end-to-end recipes, migration notes and a troubleshooting table live in the
[integration guide](../../INTEGRATION.md).

## Basic Usage

### 1. Wrap your application with `AuthProvider`

You must wrap your application (or the authenticated part of it) in the `AuthProvider`.

```tsx
import { AuthProvider } from "@wilsoon/auth-react";

function App({ children }) {
  return (
    <AuthProvider clientId="your-client-id" issuer="https://id.wilsoon.dev" redirectUri="http://localhost:3000/callback">
      {children}
    </AuthProvider>
  );
}
```

The provider persists `state`, `nonce` and the PKCE verifier in `sessionStorage`, and completes the callback with `handleCallback()` - which validates `state`, exchanges the code with its verifier, and verifies the ID token's signature, issuer, audience, expiry and nonce.

### 2. Use the `useAuth` hook in your components

```tsx
import { useAuth } from "@wilsoon/auth-react";

export function Profile() {
  const { user, isAuthenticated, isLoading, login, logout } = useAuth();

  if (isLoading) return <div>Loading...</div>;
  if (!isAuthenticated) return <button onClick={() => login()}>Log In</button>;

  return (
    <div>
      <h1>Welcome, {user!.email}!</h1>
      <button onClick={() => logout()}>Log Out</button>
    </div>
  );
}
```

### 3. `user.verified` - the two kinds of session

`user` is a discriminated union, because the two ways a browser session comes into being differ in what they can prove:

```tsx
const { user } = useAuth();

// Always available: display claims.
user?.name;
user?.email;

// Only after a verified callback exchange:
if (user?.verified && user.role === "admin") {
  return <AdminNav />;
}
```

| How the session was established                           | `verified` | Has `role` / `authMethods` / `sessionVersion`   |
| --------------------------------------------------------- | ---------- | ----------------------------------------------- |
| OIDC callback (`?code=...`) - ID token verified           | `true`     | Yes                                             |
| Page load, hydrated from the HttpOnly cookie via userinfo | `false`    | No - the userinfo endpoint does not return them |

TypeScript will not let you read `role` without narrowing on `verified` first, so a hydrated session cannot silently produce `undefined` where a role was expected.

**Client-side checks are for rendering.** A browser can be told anything. Gate real access on the server with `@wilsoon/auth-next`'s `getSession()` / `requireSession()`, or with `verifyIdToken()` / `verifyAccessToken()` in your API.

### 4. Step-up login

```tsx
login({ prompt: "reauthenticate", acrValues: ["mfa"] });
```

## Environment

This package is built for browser environments and React applications. It integrates natively with client-side session management tools.

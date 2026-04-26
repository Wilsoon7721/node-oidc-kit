# @wilsoon/auth-react

React components and hooks for the Wilsoon Identity platform. Provides a convenient context provider and hook to manage authentication state across your React application.

## Features

- **AuthProvider:** Wraps your application to manage global authentication state and auto-refresh mechanisms.
- **useAuth Hook:** Easily access the current user, tokens, loading state, and auth methods from any child component.
- **Next.js App Router Compatible:** Includes the `"use client"` directive, making it safe for Next.js 13+ App Router.

## Installation

```bash
npm install @wilsoon/auth-react @wilsoon/auth-core
```

## Basic Usage

### 1. Wrap your application with `AuthProvider`

You must wrap your application (or the authenticated part of it) in the `AuthProvider`.

```tsx
import { AuthProvider } from '@wilsoon/auth-react';

function App({ children }) {
  return (
    <AuthProvider
      clientId="your-client-id"
      issuer="https://auth.yourdomain.com"
      redirectUri="http://localhost:3000/callback"
    >
      {children}
    </AuthProvider>
  );
}
```

### 2. Use the `useAuth` hook in your components

```tsx
import { useAuth } from '@wilsoon/auth-react';

export function Profile() {
  const { user, isAuthenticated, isLoading, login, logout } = useAuth();

  if (isLoading) return <div>Loading...</div>;

  if (!isAuthenticated) {
    return <button onClick={login}>Log In</button>;
  }

  return (
    <div>
      <h1>Welcome, {user.email}!</h1>
      <button onClick={() => logout()}>Log Out</button>
    </div>
  );
}
```

## Environment
This package is built for browser environments and React applications. It integrates natively with client-side session management tools.

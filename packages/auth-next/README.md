# @wilsoon/auth-next

Next.js integration for the Wilsoon Identity platform. Provides seamless utilities for Server Components, Route Handlers, and Edge Middleware in Next.js 13+ App Router.

## Features

- **Edge Middleware:** Protect your routes and handle automatic token refresh right at the Edge.
- **Server Components:** Access session data securely using `next/headers` without client-side waterfalls.
- **Client Components:** Re-exports `@wilsoon/auth-react` so you can use it client-side with `"use client"`.

## Installation

```bash
npm install @wilsoon/auth-next @wilsoon/auth-core @wilsoon/auth-react
```

## Basic Usage

### 1. Protecting Routes with Middleware

Create a `middleware.ts` file in the root or `src/` directory of your Next.js project.

```typescript
import { createAuthMiddleware } from '@wilsoon/auth-next';

export const middleware = createAuthMiddleware({
  clientId: 'your-client-id',
  issuer: 'https://auth.yourdomain.com',
  redirectUri: 'http://localhost:3000/callback',
});

// Protect specific routes
export const config = {
  matcher: ['/dashboard/:path*', '/profile/:path*'],
};
```

### 2. Accessing Session in Server Components

You can retrieve the session and user data in your Server Components without relying on client-side state.

```tsx
import { getSession } from '@wilsoon/auth-next';

export default async function DashboardPage() {
  const { user } = await getSession({
    clientId: 'your-client-id',
    issuer: 'https://auth.yourdomain.com',
    redirectUri: 'http://localhost:3000/callback',
  });

  if (!user) {
    return <div>Access Denied</div>;
  }

  return (
    <div>
      <h1>Welcome to your Dashboard, {user.email}!</h1>
      <p>Role: {user.role}</p>
    </div>
  );
}
```

### 3. Client-Side Usage

`@wilsoon/auth-next` seamlessly re-exports `@wilsoon/auth-react`. You can import the `AuthProvider` and `useAuth` hook directly from `@wilsoon/auth-next` for your Client Components.

```tsx
"use client";

import { useAuth, AuthProvider } from '@wilsoon/auth-next';

// ...
```

## Environment
Designed specifically for Next.js 13+. It respects Server Components, Route Handlers, and Edge Middleware limitations (e.g. `ServerCookieStorage` prohibits modifying cookies in Server Components as mandated by Next.js architecture).

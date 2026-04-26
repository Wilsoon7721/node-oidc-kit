# @wilsoon/auth-core

The core logic library for the Wilsoon Identity platform. It provides the isomorphic building blocks to implement OIDC-compliant authentication flows in both browser and Node.js server environments.

## Features

- **Isomorphic Architecture:** Runs seamlessly in the browser, Node.js, and Edge environments.
- **OIDC Discovery:** Automatically discovers authorization, token, and userinfo endpoints from the issuer.
- **PKCE Support:** Built-in Proof Key for Code Exchange for secure public client authorization.
- **Token Management:** Handles token exchange, storage, parsing, and refreshing.

## Installation

```bash
npm install @wilsoon/auth-core
```

## Basic Usage

### Initializing the Client

```typescript
import { AuthClient, CookieStorage } from '@wilsoon/auth-core';

// You can use a custom storage or the default browser sessionStorage
const storage = new CookieStorage(); 

const client = new AuthClient({
  clientId: 'your-client-id',
  issuer: 'https://auth.yourdomain.com',
  redirectUri: 'http://localhost:3000/callback',
}, storage);
```

### Generating an Authorization URL

```typescript
// Generates a URL for the user to visit and log in
const { url, state, codeVerifier } = await client.createAuthorizeUrl();

// Save state and codeVerifier in your session/local storage
window.sessionStorage.setItem('state', state);
window.sessionStorage.setItem('codeVerifier', codeVerifier);

// Redirect user
window.location.href = url;
```

### Exchanging a Code for Tokens

```typescript
// On your callback page after successful login
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

const savedState = window.sessionStorage.getItem('state');
const savedVerifier = window.sessionStorage.getItem('codeVerifier');

// Validate state to prevent CSRF
client.validateState(state, savedState);

// Exchange code for tokens
const tokens = await client.exchangeCodeForToken(code, savedVerifier);

// Save tokens
client.saveTokens(tokens);
```

### Fetching User Info

```typescript
const tokens = client.getStoredTokens();

if (tokens) {
  // Option 1: Decode ID token locally (No network request)
  const user = client.parseIdToken(tokens.id_token);

  // Option 2: Fetch fresh profile from IdP
  const freshUser = await client.getUser(tokens.access_token);
}
```

## Environments Supported
This package gracefully falls back to Node's `crypto` and `Buffer` modules when Web APIs like `globalThis.crypto` and `btoa` are unavailable. It is fully isomorphic.

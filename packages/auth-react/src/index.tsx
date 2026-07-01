"use client";

import React, { createContext, useContext, useEffect, useState, useMemo, useRef } from 'react';
import { AuthClient, User, TokenResponse } from '@wilsoon/auth-core';
import { AuthState } from './types';

const AuthContext = createContext<AuthState | null>(null);

/**
 * Provider component that handles authentication state for the application.
 * It manages token exchange, session hydration via HttpOnly cookies, and logout.
 *
 * On page load, the provider hydrates authentication state by calling the
 * identity provider's userinfo endpoint with `credentials: 'include'`.
 * The browser automatically attaches the HttpOnly `wilsoon_id_tokens` cookie,
 * and the server validates the token and returns user info.
 * 
 * **Token Refresh Strategies:**
 * Because the `wilsoon_id_tokens` cookie is `HttpOnly`, this provider cannot proactively 
 * refresh tokens on the client side. You must implement one of the following:
 * 
 * 1. **Pure React SPA (Reactive Refresh):** Set up a global Axios Interceptor or `fetch` 
 *    wrapper that catches `401 Unauthorized` responses from your API, calls 
 *    `client.refreshAccessToken()`, and retries the failed request.
 * 2. **Next.js / SSR (Middleware):** Use `@wilsoon/auth-next` middleware to automatically 
 *    intercept and refresh tokens server-side before they reach the client.
 * 
 * @param props.clientId The OAuth2 client ID.
 * @param props.issuer The OIDC issuer URL.
 * @param props.redirectUri The callback URI after login.
 * @param props.cookieDomain Optional domain for the auth cookie.
 * @param props.children React children.
 */
export const AuthProvider: React.FC<{ clientId: string; issuer: string; redirectUri: string; cookieDomain?: string; children: React.ReactNode; }> = ({ clientId, issuer, redirectUri, cookieDomain, children }) => {
  const config = useMemo(() => ({ clientId, issuer, redirectUri, cookieDomain }), [clientId, issuer, redirectUri, cookieDomain]);

  const client = useMemo(() => new AuthClient(config), [config]);

  const [user, setUser] = useState<User | null>(null);
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const processingRef = useRef(false);

  useEffect(() => {
    const init = async () => {
      if (processingRef.current) return;
      processingRef.current = true;

      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      const state = params.get('state');

      try {
        if (code && state) {
          // OAuth callback: exchange code for tokens
          const savedState = window.sessionStorage.getItem('wilsoon_auth_state');
          const savedVerifier = window.sessionStorage.getItem('wilsoon_auth_verifier');

          client.validateState(state, savedState || '');

          // Code Exchange
          const tokenRes = await client.exchangeCodeForToken(code, savedVerifier || '');

          setTokens(tokenRes);
          if (tokenRes.id_token)
            setUser(client.parseIdToken(tokenRes.id_token));

          window.sessionStorage.removeItem('wilsoon_auth_state');
          window.sessionStorage.removeItem('wilsoon_auth_verifier');
          window.history.replaceState({}, document.title, window.location.pathname);
        } else {
          const hydratedUser = await client.hydrateSession();
          if (hydratedUser) {
            setUser(hydratedUser);
          }
        }
      } catch (err: any) {
        setError(err);
        setUser(null);
        setTokens(null);
      } finally {
        setIsLoading(false);
      }
    };

    init();
  }, [client]);

  const login = async () => {
    const { url, state, codeVerifier } = await client.createAuthorizeUrl();
    window.sessionStorage.setItem('wilsoon_auth_state', state);
    window.sessionStorage.setItem('wilsoon_auth_verifier', codeVerifier);
    window.location.href = url;
  };

  const logout = async (returnTo = window.location.origin) => {
    try {
      setIsLoading(true);

      if (tokens?.id_token) {
        // Build the logout URL with the id_token_hint so the server can
        // verify the session and clear the HttpOnly cookie.
        const logoutUrl = await client.getLogoutUrl(tokens.id_token, returnTo);
        setUser(null);
        setTokens(null);
        window.location.href = logoutUrl;
      } else {
        // No id_token available (e.g., hydrated session without token exchange).
        // Redirect to the logout endpoint without the hint — the server
        // will still clear the HttpOnly cookie via the session.
        const logoutUrl = `${config.issuer}/api/logout?post_logout_redirect_uri=${encodeURIComponent(returnTo)}`;
        setUser(null);
        setTokens(null);
        window.location.href = logoutUrl;
      }
    } catch (err) {
      console.error("Logout failed:", err);
      setUser(null);
      setTokens(null);
      window.location.href = returnTo;
    }
  };

  const value = { user, tokens, isAuthenticated: !!user, isLoading, error, login, logout };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

/**
 * Hook to access the current authentication state and actions.
 * @returns The authentication state (user, tokens, isAuthenticated, isLoading, error) and actions (login, logout).
 * @throws Error if used outside of an AuthProvider.
 */
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

"use client";

import React, { createContext, useContext, useEffect, useState, useMemo, useRef } from 'react';
import { AuthClient, BrowserStorage, TokenResponse } from '@wilsoon/auth-core';
import { AuthState, LoginOptions, SessionUser } from './types';

const AuthContext = createContext<AuthState | null>(null);

/**
 * Provider component that handles authentication state for the application.
 * It manages the login redirect, the callback exchange, session hydration via HttpOnly
 * cookies, and logout.
 *
 * On the OIDC callback the provider calls `AuthClient.handleCallback()`, which validates
 * `state`, exchanges the code with its PKCE verifier and **verifies the returned ID token**
 * against the identity provider's published keys. The resulting user is marked
 * `verified: true`, and only then does it carry `role`, `authMethods` and `sessionVersion`.
 *
 * On a normal page load the provider hydrates from the HttpOnly session cookie by calling
 * the userinfo endpoint with `credentials: 'include'`. That endpoint returns profile claims
 * only, so the hydrated user is marked `verified: false` and carries no authorization
 * fields. Check `user.verified` before reading them.
 * 
 * No refresh here. The session cookie is `HttpOnly`, so this provider cannot see the refresh token. 
 * Instead, SPAs should react reactively (on 401s) and Next.js can utilise a middleware instead. 
 */
export const AuthProvider: React.FC<{
  clientId: string;
  issuer: string;
  redirectUri: string;
  scope?: string[];
  cookieDomain?: string;
  children: React.ReactNode;
}> = ({ clientId, issuer, redirectUri, scope, cookieDomain, children }) => {
  const scopeKey = scope ? scope.join(' ') : '';
  const config = useMemo(
    () => ({ clientId, issuer, redirectUri, cookieDomain, scope: scopeKey ? scopeKey.split(' ') : undefined }),
    [clientId, issuer, redirectUri, cookieDomain, scopeKey]
  );

  // sessionStorage, not localStorage: `state`, `nonce` and the PKCE verifier are single-use
  // values scoped to one login attempt in one tab.
  const client = useMemo(
    () => new AuthClient(config, typeof window !== 'undefined' ? new BrowserStorage(window.sessionStorage) : undefined),
    [config]
  );

  const [user, setUser] = useState<SessionUser | null>(null);
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const processingRef = useRef(false);

  useEffect(() => {
    const init = async () => {
      if (processingRef.current) return;
      processingRef.current = true;

      const params = new URLSearchParams(window.location.search);
      const isCallback = params.has('code') || params.has('error');

      try {
        if (isCallback) {
          // Validates state, exchanges the code with PKCE, verifies the ID token's
          // signature/issuer/audience/expiry and nonce, then clears the transient values.
          const { tokens: exchanged, user: verified } = await client.handleCallback(window.location.href);

          setTokens(exchanged);
          if (verified) setUser({ verified: true, ...verified });

          window.history.replaceState({}, document.title, window.location.pathname);
        } else {
          const profile = await client.hydrateSession();
          if (profile) setUser({ verified: false, ...profile });
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

  const login = async (options?: LoginOptions | React.MouseEvent<HTMLElement>) => {
    // `login` is commonly passed straight to `onClick`, so an event argument is discarded
    // rather than read as options, and the options are picked field by field.
    const requested: LoginOptions = options && !('nativeEvent' in options) ? options : {};
    const { scope: loginScope, prompt, acrValues, loginHint } = requested;

    // createAuthorizeUrl persists state, nonce and the PKCE verifier through the client's
    // storage, so the callback cannot be completed without them.
    const { url } = await client.createAuthorizeUrl({ scope: loginScope, prompt, acrValues, loginHint });
    window.location.href = url;
  };

  const logout = async (returnTo = window.location.origin) => {
    try {
      setIsLoading(true);

      if (tokens?.id_token) {
        // The id_token_hint tells the provider which session to end, so it can clear the
        // HttpOnly cookie it set.
        const logoutUrl = await client.getLogoutUrl(tokens.id_token, returnTo);
        setUser(null);
        setTokens(null);
        window.location.href = logoutUrl;
      } else {
        // A hydrated session has no id_token to hint with, and discovery cannot help:
        // `end_session_endpoint` is what getLogoutUrl() needs the hint *for*. So fall back
        // to the reference provider's logout path.
        //
        // This is the one provider-specific URL in the SDK. Against a different provider,
        // handle logout in your own code rather than relying on this branch.
        const logoutUrl = `${config.issuer.replace(/\/+$/, '')}/api/logout?post_logout_redirect_uri=${encodeURIComponent(returnTo)}`;
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
 * Reads the session state and actions from the nearest {@link AuthProvider}.
 * @throws If called outside an {@link AuthProvider}.
 */
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export * from './types';

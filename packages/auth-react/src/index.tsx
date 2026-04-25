import React, { createContext, useContext, useEffect, useState, useMemo, useRef } from 'react';
import { AuthClient, User, TokenResponse, NoTokenError } from '@wilsoon/auth-core';
import { AuthState } from './types';

const AuthContext = createContext<AuthState | null>(null);

export const AuthProvider: React.FC<{ clientId: string; issuer: string; redirectUri: string; children: React.ReactNode; }> = ({ clientId, issuer, redirectUri, children }) => {
  const client = useMemo(() => new AuthClient({ clientId, issuer, redirectUri }), [clientId, issuer, redirectUri]);

  const [user, setUser] = useState<User | null>(null);
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const processingRef = useRef(false);

  const updateAuth = (newTokens: TokenResponse | null) => {
    if (newTokens) {
      client.saveTokens(newTokens);
      setTokens(newTokens);
      if (!newTokens.id_token) throw new NoTokenError('No ID token received from server.');
      setUser(client.parseIdToken(newTokens.id_token));
    } else {
      client.clearStorage();
      setTokens(null);
      setUser(null);
    }
  };

  useEffect(() => {
    const init = async () => {
      if (processingRef.current) return;
      processingRef.current = true;

      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      const state = params.get('state');

      try {
        if (code && state) {
          const savedState = window.sessionStorage.getItem('wilsoon_auth_state');
          const savedVerifier = window.sessionStorage.getItem('wilsoon_auth_verifier');

          client.validateState(state, savedState || '');
          const tokenRes = await client.exchangeCodeForToken(code, savedVerifier || '');

          updateAuth(tokenRes);

          window.sessionStorage.removeItem('wilsoon_auth_state');
          window.sessionStorage.removeItem('wilsoon_auth_verifier');
          window.history.replaceState({}, document.title, window.location.pathname);
        } else {
          const stored = client.getStoredTokens();
          if (stored) {
            if (client.isTokenExpired(stored.access_token)) {
              if (stored.refresh_token) {
                const refreshed = await client.refreshAccessToken(stored.refresh_token);
                updateAuth(refreshed);
              } else {
                updateAuth(null);
              }
            } else {
              updateAuth(stored);
            }
          }
        }
      } catch (err: any) {
        setError(err);
        updateAuth(null);
      } finally {
        setIsLoading(false);
      }
    };

    init();
  }, [client]);

  useEffect(() => {
    if (!tokens?.refresh_token) return;

    const interval = setInterval(async () => {
      if (client.isTokenExpired(tokens.access_token)) {
        if(!tokens?.refresh_token) return;
        try {
          const refreshed = await client.refreshAccessToken(tokens.refresh_token);
          updateAuth(refreshed);
        } catch (err) {
          console.error("Auto-refresh failed:", err);
          logout();
        }
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [tokens, client]);

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
        const logoutUrl = await client.getLogoutUrl(tokens.id_token, returnTo);
        updateAuth(null); 
        window.location.href = logoutUrl;
      } else {
        updateAuth(null);
        window.location.href = returnTo;
      }
    } catch (err) {
      console.error("Logout failed:", err);
      updateAuth(null);
      window.location.href = returnTo;
    }
  };

  const value = { user, tokens, isAuthenticated: !!user, isLoading, error, login, logout };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

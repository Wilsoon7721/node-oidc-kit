"use client";

import React, { createContext, useContext, useEffect, useState, useMemo, useRef } from "react";
import { AuthClient, AuthConfig, BrowserStorage, ProfileExtensions, ProviderProfile, TokenResponse } from "@wilsoon/auth-core";
import { AuthState, LoginOptions, SessionRestore, SessionUser } from "./types";

const AuthContext = createContext<AuthState | null>(null);

/** Props for {@link AuthProvider}. */
export interface AuthProviderProps {
  clientId: string;
  issuer: string;
  redirectUri: string;
  scope?: string[];
  /** @deprecated Since 3.0.0 - the provider writes no cookies; this prop is ignored. */
  cookieDomain?: string;
  /** The provider profile, e.g. `wilsoon()`. Its extensions are exposed on `useAuth()` under its name. */
  profile?: ProviderProfile<string, object>;
  /** Where roles live in the ID token, as on `AuthConfig`. */
  rolesClaim?: AuthConfig["rolesClaim"];
  /** Where permissions live in the ID token, as on `AuthConfig`. */
  permissionsClaim?: AuthConfig["permissionsClaim"];
  /** Storage name prefix, as on `AuthConfig`. */
  storagePrefix?: string;
  /** How a page load restores the session (default `"silent"`). */
  restore?: SessionRestore;
  /** How long the silent attempt may take, in ms (default 10000). */
  silentTimeoutMs?: number;
  children: React.ReactNode;
}

/**
 * Provider component that handles authentication state for the application: the login redirect, the callback exchange, session restore and logout.
 *
 * On the OIDC callback, and after a silent restore, the ID token has been verified, so the user is marked `verified: true`.
 * A profile's non-standard restore (such as a provider cookie) yields display claims only, marked `verified: false`.
 *
 * No refresh here: a silent restore on the next page load renews the session. Next.js apps should keep tokens server-side and use the middleware instead.
 */
export const AuthProvider: React.FC<AuthProviderProps> = ({ clientId, issuer, redirectUri, scope, profile, rolesClaim, permissionsClaim, storagePrefix, restore = "silent", silentTimeoutMs, children }) => {
  const scopeKey = scope ? scope.join(" ") : "";
  const config = useMemo<AuthConfig>(() => ({ clientId, issuer, redirectUri, scope: scopeKey ? scopeKey.split(" ") : undefined, profile, rolesClaim, permissionsClaim, storagePrefix }), [clientId, issuer, redirectUri, scopeKey, profile, rolesClaim, permissionsClaim, storagePrefix]);

  // sessionStorage, not localStorage: `state`, `nonce` and the PKCE verifier are single-use
  // values scoped to one login attempt in one tab.
  const client = useMemo(() => new AuthClient(config, typeof window !== "undefined" ? new BrowserStorage(window.sessionStorage) : undefined), [config]);

  const [user, setUser] = useState<SessionUser | null>(null);
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const processingRef = useRef(false);

  useEffect(() => {
    const init = async () => {
      if (processingRef.current) return;
      processingRef.current = true;

      // Inside the silent sign-in iframe this page is only a landing spot: the parent reads the URL and finishes the exchange.
      if (window.parent !== window) {
        setIsLoading(false);
        return;
      }

      const params = new URLSearchParams(window.location.search);
      const isCallback = params.has("code") || params.has("error");

      try {
        if (isCallback) {
          // Validates state, exchanges the code with PKCE, verifies the ID token's
          // signature/issuer/audience/expiry and nonce, then clears the transient values.
          const { tokens: exchanged, user: verified } = await client.handleCallback(window.location.href);

          setTokens(exchanged);
          if (verified) setUser({ verified: true, ...verified });

          window.history.replaceState({}, document.title, window.location.pathname);
        } else if (restore !== "none") {
          const silent = restore === "silent" ? await client.silentAuthorize({ timeoutMs: silentTimeoutMs }) : null;

          if (silent) {
            setTokens(silent.tokens);
            if (silent.user) setUser({ verified: true, ...silent.user });
          } else if (profile?.restoreSession) {
            const restored = await client.restoreSession();
            if (restored) setUser({ verified: false, ...restored });
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
  }, [client, restore, silentTimeoutMs, profile]);

  const login = async (options?: LoginOptions | React.MouseEvent<HTMLElement>) => {
    // `login` is commonly passed straight to `onClick`, so an event argument is discarded
    // rather than read as options, and the options are picked field by field.
    const requested: LoginOptions = options && !("nativeEvent" in options) ? options : {};
    const { scope: loginScope, prompt, acrValues, maxAge, loginHint } = requested;

    // createAuthorizeUrl persists state, nonce and the PKCE verifier through the client's
    // storage, so the callback cannot be completed without them.
    const { url } = await client.createAuthorizeUrl({ scope: loginScope, prompt, acrValues, maxAge, loginHint });
    window.location.href = url;
  };

  const logout = async (returnTo = window.location.origin) => {
    try {
      setIsLoading(true);

      // With an ID token the provider knows which session to end; without one it is sent `client_id` and may ask the user to confirm.
      const logoutUrl = await client.getLogoutUrl(tokens?.id_token, returnTo);
      setUser(null);
      setTokens(null);
      window.location.href = logoutUrl;
    } catch (err) {
      console.error("Logout failed:", err);
      setUser(null);
      setTokens(null);
      window.location.href = returnTo;
    }
  };

  const value = useMemo<AuthState>(() => {
    const state: AuthState = { user, tokens, isAuthenticated: !!user, isLoading, error, login, logout, client };
    // Namespaced, as on the client: `useAuth().wilsoon.reauthorize()`.
    const name = client.profileName;
    if (name) (state as unknown as Record<string, unknown>)[name] = (client as unknown as Record<string, unknown>)[name];
    return state;
  }, [user, tokens, isLoading, error, client]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

/**
 * Reads the session state and actions from the nearest {@link AuthProvider}.
 * Pass the profile's type to get its extensions typed: `useAuth<ReturnType<typeof wilsoon>>().wilsoon`.
 *
 * @throws If called outside an {@link AuthProvider}.
 */
export const useAuth = <P extends ProviderProfile<string, object> | undefined = undefined>(): AuthState & ProfileExtensions<P> => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context as AuthState & ProfileExtensions<P>;
};

export * from "./types";

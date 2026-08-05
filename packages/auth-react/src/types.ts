import type { MouseEvent } from 'react';
import { AuthenticatedUser, ProfileUser, TokenResponse } from '@wilsoon/auth-core';

/**
 * The user in the React session.
 *
 * A discriminated union, because the two ways a browser session comes into being differ in
 * what they can prove:
 *
 * - after the OIDC callback the ID token has been verified, so `role`, `authMethods` and
 *   `sessionVersion` are present and trustworthy;
 * - after hydrating from the HttpOnly cookie the app has only the userinfo profile, which
 *   carries no authorization claims at all.
 *
 * Narrow on `verified` before reading anything security-relevant:
 *
 * ```tsx
 * if (user?.verified && user.role === 'admin') showAdminNav();
 * ```
 *
 * Client-side checks are for rendering. Every real decision still belongs on the server.
 */
export type SessionUser =
    | ({ verified: true } & AuthenticatedUser)
    | ({ verified: false } & ProfileUser);

export interface AuthState {
    user: SessionUser | null;
    tokens: TokenResponse | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: Error | null;
    /**
     * Starts a login redirect.
     *
     * The union with `MouseEvent` keeps `<button onClick={login}>` compiling, which is how
     * most callers use it; an event argument is ignored rather than read as options.
     */
    login: (options?: LoginOptions | MouseEvent<HTMLElement>) => Promise<void>;
    logout: (returnTo?: string) => Promise<void>;
}

/** Options for starting a login. */
export interface LoginOptions {
    /** Overrides the configured scopes. */
    scope?: string[];
    /** OIDC `prompt` value. */
    prompt?: string;
    /** OIDC `acr_values`, to request a stronger authentication context. */
    acrValues?: string | string[];
    /** OIDC `login_hint`. */
    loginHint?: string;
}

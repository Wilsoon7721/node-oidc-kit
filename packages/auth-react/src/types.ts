import type { MouseEvent } from 'react';
import { AuthClient, AuthenticatedUser, ProfileUser, TokenResponse } from '@wilsoon/auth-core';

/**
 * The user in the React session.
 *
 * A discriminated union, because the ways a browser session comes into being differ in what they can prove:
 *
 * - after the OIDC callback or a silent restore the ID token has been verified, so `roles`, `permissions` and `authMethods` are present and trustworthy;
 * - after a profile's non-standard restore (such as a provider cookie) the app has only a userinfo profile, which carries no authorization claims at all.
 *
 * Narrow on `verified` before reading anything security-relevant:
 *
 * ```tsx
 * if (user?.verified && user.permissions.includes('games_portal.admin')) showAdminNav();
 * ```
 *
 * Client-side checks are for rendering. Every real decision still belongs on the server.
 */
export type SessionUser =
    | ({ verified: true } & AuthenticatedUser)
    | ({ verified: false } & ProfileUser);

/**
 * How a page load restores the session.
 *
 * - `"silent"`: a `prompt=none` request in a hidden iframe, falling back to the profile's `restoreSession` when that finds nothing.
 * - `"profile"`: only the profile's `restoreSession`, the 2.x behaviour.
 * - `"none"`: nothing; the user is signed out until they log in.
 */
export type SessionRestore = 'silent' | 'profile' | 'none';

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
    /** The underlying client, for standard methods the hook does not wrap. */
    client: AuthClient;
}

/** Options for starting a login. */
export interface LoginOptions {
    /** Overrides the configured scopes. */
    scope?: string[];
    /** OIDC `prompt` value: `login` forces re-authentication. */
    prompt?: string;
    /** OIDC `acr_values`, to request a stronger authentication context. */
    acrValues?: string | string[];
    /**
     * OIDC `max_age`: the maximum age, in seconds, of the authentication that will be accepted.
     * `0` demands a fresh one, which is the other half of a step-up request - `acrValues` asks how strong, this asks how recent.
     */
    maxAge?: number;
    /** OIDC `login_hint`. */
    loginHint?: string;
}

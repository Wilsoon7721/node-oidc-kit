import { cookies } from 'next/headers';
import {
    assertAmr,
    AuthClient,
    AuthConfig,
    AuthenticatedUser,
    AuthError,
    TokenResponse,
} from '@wilsoon/auth-core';
import { getCachedClient } from './client-cache';
import { resolveSessionUser } from './resolve';
import { ServerCookieStorage, ServerCookieStorageOptions } from './storage/ServerCookieStorage';

/** The result of resolving the current request's session. */
export interface Session {
    /**
     * The verified user, or `null` when there is no valid session.
     *
     * Populated only after the ID token's signature, issuer, audience and expiry have been
     * checked against the provider's JWKS, so `role` and `authMethods` on it can be used to
     * authorize.
     */
    user: AuthenticatedUser | null;
    /** The tokens from the session cookie, or `null`. */
    tokens: TokenResponse | null;
    /** Why verification failed, when a session cookie was present but not usable. */
    error?: AuthError;
}

/** Options for {@link getSession}. */
export interface GetSessionOptions {
    /** Cookie attributes, when the session needs writing (unused for reads). */
    cookies?: ServerCookieStorageOptions;
}

/**
 * Retrieves the current session from cookies in a Server Component or Route Handler.
 *
 * The ID token in the cookie is **verified** against the identity provider's published keys
 * before its claims are returned, so the `role` and `authMethods` on the result are safe to
 * gate access with:
 *
 * ```ts
 * const { user } = await getSession(authConfig);
 * if (!user || user.role !== 'admin') return notFound();
 * ```
 *
 * Fails closed: any verification failure yields `user: null` with the reason in `error`.
 *
 * @param config The authentication configuration.
 * @param options Cookie options for the underlying storage.
 * @returns A promise resolving to the verified user and the raw tokens.
 */
export async function getSession(config: AuthConfig, options: GetSessionOptions = {}): Promise<Session> {
    let tokens: TokenResponse | null = null;

    try {
        const cookieStore = await cookies();
        const reader = new AuthClient(config, new ServerCookieStorage(cookieStore, options.cookies));
        tokens = reader.getStoredTokens();
    } catch (error) {
        return { user: null, tokens: null, error: error instanceof AuthError ? error : undefined };
    }

    if (!tokens || (!tokens.id_token && !tokens.access_token)) return { user: null, tokens: null };

    const { user, error } = await resolveSessionUser(getCachedClient(config), tokens);
    return user ? { user, tokens } : { user: null, tokens: null, error };
}

/**
 * Resolves the session and throws unless it satisfies a policy - the one-call access check
 * for a Server Component or Route Handler.
 *
 * @param config The authentication configuration.
 * @param policy Roles and authentication methods the session must satisfy.
 * @returns The verified user.
 * @throws {AuthError} If there is no valid session, or it does not satisfy the policy.
 */
export async function requireSession(
    config: AuthConfig,
    policy: { roles?: AuthenticatedUser['role'][]; amr?: string[] } = {}
): Promise<AuthenticatedUser> {
    const { user, error } = await getSession(config);

    if (!user) throw error ?? new AuthError('No authenticated session.', 'NO_SESSION');

    if (policy.roles && !policy.roles.includes(user.role)) {
        throw new AuthError(`Role "${user.role}" is not permitted here.`, 'FORBIDDEN');
    }

    if (policy.amr) assertAmr(user, policy.amr);

    return user;
}

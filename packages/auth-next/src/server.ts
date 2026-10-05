import { cookies } from 'next/headers';
import {
    assertAmr,
    AuthClient,
    AuthConfig,
    AuthenticatedUser,
    AuthError,
    hasPermission,
    hasRole,
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
     * checked against the provider's JWKS, so `roles`, `permissions` and `authMethods` on it can be used to
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
 * before its claims are returned, so the `roles`, `permissions` and `authMethods` on the result are safe to
 * gate access with:
 *
 * ```ts
 * const { user } = await getSession(authConfig);
 * if (!user || !hasPermission(user, 'games_portal.admin')) return notFound();
 * ```
 *
 * Fails closed: any verification failure yields `user: null`, with the reason in `error`
 * rather than as a thrown exception, so a page can render a signed-out state and still log
 * why.
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
 * {@link getSession} that throws unless the session satisfies a policy - the one-call
 * access check for a Server Component or Route Handler.
 *
 * The thrown {@link AuthError} carries a `code` (`NO_SESSION`, `FORBIDDEN`, or the
 * underlying verification failure) so an error boundary can tell "sign in" apart from
 * "you may not see this".
 *
 * @param policy Roles (any of), permissions (all of) and authentication methods the session must satisfy.
 * @throws {AuthError} If there is no valid session, or it does not satisfy the policy.
 */
export async function requireSession(
    config: AuthConfig,
    policy: { roles?: string[]; permissions?: string[]; amr?: string[] } = {}
): Promise<AuthenticatedUser> {
    const { user, error } = await getSession(config);

    if (!user) throw error ?? new AuthError('No authenticated session.', 'NO_SESSION');

    if (policy.roles && !hasRole(user, policy.roles)) {
        throw new AuthError(`One of the roles [${policy.roles.join(', ')}] is required here.`, 'FORBIDDEN');
    }

    if (policy.permissions && !hasPermission(user, policy.permissions)) {
        throw new AuthError(`The permission(s) [${policy.permissions.join(', ')}] are required here.`, 'FORBIDDEN');
    }

    if (policy.amr) assertAmr(user, policy.amr);

    return user;
}

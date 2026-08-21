import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import {
    AuthClient,
    AuthConfig,
    AuthStorage,
    satisfiesAmr,
    STORAGE_KEYS,
    TokenResponse,
    UserRole,
} from '@wilsoon/auth-core';
import { getCachedClient } from './client-cache';
import { isAddressedTo, resolveSessionUser } from './resolve';

/** Options for {@link createAuthMiddleware}. */
export interface AuthMiddlewareOptions extends AuthConfig {
    /** Where unauthenticated users are sent (default `/auth`). */
    loginPath?: string;
    /** Where authenticated-but-unauthorized users are sent (default `loginPath`). */
    unauthorizedPath?: string;
    /**
     * Verify the ID token's signature, issuer, audience and expiry before letting the
     * request through (default true).
     *
     * With this off the middleware only checks that a cookie exists, which any client can
     * fabricate - treat that as convenience routing, not access control.
     */
    verify?: boolean;
    /** Restrict access to these roles. Requires verification. */
    roles?: UserRole[];
    /** Require these authentication methods (`amr`). Requires verification. */
    amr?: string[];
    /**
     * Name of the cookie holding the token response (default `STORAGE_KEYS.tokens`).
     *
     * Set this when the provider writes the session cookie under a name of its own. Only
     * the token blob is remapped; the transient `state`/`nonce`/verifier cookies keep their
     * SDK names, because the SDK is the only thing that ever writes them.
     */
    cookieName?: string;
    /** Lifetime of the refreshed cookie, in seconds (default 1 year). */
    cookieMaxAgeSeconds?: number;
}

/** Reads the request's cookies through the SDK's storage interface. */
class RequestCookieStorage implements AuthStorage {
    constructor(private request: NextRequest, private tokenCookieName: string) { }

    getItem(key: string): string | null {
        // The token blob may live under a custom cookie name; the transient keys do not.
        const name = key === STORAGE_KEYS.tokens ? this.tokenCookieName : key;
        return this.request.cookies.get(name)?.value ?? null;
    }

    setItem(): void { /* The response owns writes; see writeTokens(). */ }
    removeItem(): void { /* The response owns deletes. */ }
}

/**
 * Builds a Next.js middleware that gates routes on a verified session, refreshing tokens
 * that are about to expire.
 *
 * Per request, in order: read the session cookie; refresh if the access token is near
 * expiry (writing the rotated tokens back onto the response); then verify, and check the
 * `roles`/`amr` policy if one was given. Any failure redirects to `loginPath` and expires
 * the cookie, so a request never proceeds on a session that could not be verified.
 *
 * Scope it with a `config.matcher` as usual - it runs on every matched request, and
 * verification is not free even with the JWKS cached.
 *
 * ```ts
 * export default createAuthMiddleware({ ...authConfig, roles: ['admin'] });
 * export const config = { matcher: ['/admin/:path*'] };
 * ```
 */
export function createAuthMiddleware(options: AuthMiddlewareOptions) {
    const loginPath = options.loginPath ?? '/auth';
    const unauthorizedPath = options.unauthorizedPath ?? loginPath;
    const cookieName = options.cookieName ?? STORAGE_KEYS.tokens;
    const shouldVerify = options.verify !== false;

    // Cached per configuration: the JWKS is then fetched once per runtime instance, not once
    // per request.
    const sharedClient = getCachedClient(options);

    return async (request: NextRequest) => {
        const redirectTo = (pathname: string) => {
            const url = request.nextUrl.clone();
            url.pathname = pathname;
            url.search = '';
            url.searchParams.set('callbackUrl', request.nextUrl.pathname);
            return url;
        };

        const signOut = (pathname: string) => {
            const response = NextResponse.redirect(redirectTo(pathname));

            // Expiring a domain-scoped cookie requires naming the same domain. A bare
            // delete() only clears a host-only cookie, leaving the domain-wide one the
            // provider set in place - so the next request reads the same dead session and
            // the user loops. Set `cookieDomain` to whatever the provider writes.
            response.cookies.set(cookieName, '', {
                path: '/',
                maxAge: 0,
                domain: options.cookieDomain,
            });

            return response;
        };

        // Parsing goes through the SDK, which tolerates the URI-encoded form the identity
        // provider writes and returns null instead of throwing on a malformed cookie.
        const reader = new AuthClient(options, new RequestCookieStorage(request, cookieName));
        const tokens = reader.getStoredTokens();

        if (!tokens) {
            return request.cookies.has(cookieName) ? signOut(loginPath) : NextResponse.redirect(redirectTo(loginPath));
        }

        let response: NextResponse | null = null;
        let current: TokenResponse = tokens;

        if (sharedClient.isTokenNearExpiry(tokens.access_token)) {
            if (!tokens.refresh_token) return signOut(loginPath);

            try {
                current = await sharedClient.refreshAccessToken(tokens.refresh_token, { persist: false });
            } catch {
                return signOut(loginPath);
            }

            response = NextResponse.next();
            response.cookies.set(cookieName, JSON.stringify(current), {
                path: '/',
                maxAge: options.cookieMaxAgeSeconds ?? 31536000,
                sameSite: 'lax',
                secure: true,
                httpOnly: true,
                domain: options.cookieDomain,
            });
        }

        if (shouldVerify) {
            const needsClaims = !!(options.roles || options.amr);

            try {
                if (needsClaims) {
                    // Resolves through the ID token when it is ours, or the shared platform
                    // access token plus introspection when it belongs to a sibling service.
                    const { user, error } = await resolveSessionUser(sharedClient, current);
                    if (!user) throw error ?? new Error('no session');

                    if (options.roles && !options.roles.includes(user.role)) {
                        return NextResponse.redirect(redirectTo(unauthorizedPath));
                    }
                    if (options.amr && !satisfiesAmr(user, options.amr)) {
                        return NextResponse.redirect(redirectTo(unauthorizedPath));
                    }
                } else if (current.id_token && isAddressedTo(current.id_token, options.clientId)) {
                    await sharedClient.verifyIdToken(current.id_token);
                } else if (options.apiAudience) {
                    // No policy to enforce, so "is this a real session?" is enough - and that
                    // needs no introspection round trip.
                    await sharedClient.verifyAccessToken(current.access_token);
                } else {
                    throw new Error('cannot verify a sibling service session without `apiAudience`');
                }
            } catch {
                return signOut(loginPath);
            }
        }

        return response ?? NextResponse.next();
    };
}

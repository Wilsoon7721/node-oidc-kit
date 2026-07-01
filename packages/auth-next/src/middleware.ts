import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { AuthClient } from '@wilsoon/auth-core';

/**
 * Creates a Next.js middleware that protects routes and handles token refresh.
 * @param config The authentication configuration.
 * @returns A middleware function for Next.js.
 */
export function createAuthMiddleware(config: any) {
    return async (request: NextRequest) => {
        const token = request.cookies.get('wilsoon_id_tokens')?.value;

        if (!token) {
            const url = request.nextUrl.clone();
            url.pathname = '/auth';
            return NextResponse.redirect(url);
        }

        const client = new AuthClient(config);
        const parsed = JSON.parse(token);

        if (client.isTokenExpired(parsed.access_token)) {
            try {
                const newTokens = await client.refreshAccessToken(parsed.refresh_token);
                const response = NextResponse.next();

                response.cookies.set('wilsoon_id_tokens', JSON.stringify(newTokens), {
                    path: '/',
                    maxAge: 31536000,
                    sameSite: 'lax',
                    secure: true,
                    httpOnly: true,
                    domain: config.cookieDomain
                });

                return response;
            } catch (error) {
                const url = request.nextUrl.clone();
                url.pathname = '/auth';
                url.searchParams.set('callbackUrl', request.nextUrl.pathname);

                const response = NextResponse.redirect(url);
                response.cookies.delete('wilsoon_id_tokens');
                return response;
            }
        }

        return NextResponse.next();
    };
}
import { NextRequest } from 'next/server';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { STORAGE_KEYS, type AuthConfig } from '@wilsoon/auth-core';
import { createAuthMiddleware, type AuthMiddlewareOptions } from '../src/middleware';
import { API_AUDIENCE, CLIENT_ID, startFakeIdp, unsignedToken, type FakeIdp } from '../../auth-core/test/fake-idp';

let idp: FakeIdp;

const config = (): AuthConfig => ({
    clientId: CLIENT_ID,
    issuer: idp.issuer,
    redirectUri: 'http://localhost:3000/callback',
});

const middlewareFor = (overrides: Partial<AuthMiddlewareOptions> = {}) =>
    createAuthMiddleware({ ...config(), ...overrides } as AuthMiddlewareOptions);

const requestWith = (cookie?: unknown, path = '/dashboard') => {
    const request = new NextRequest(`http://localhost:3000${path}`);
    if (cookie !== undefined) {
        request.cookies.set(STORAGE_KEYS.tokens, typeof cookie === 'string' ? cookie : JSON.stringify(cookie));
    }
    return request;
};

const locationOf = (response: Response) => {
    const location = response.headers.get('location');
    return location ? new URL(location) : null;
};

beforeAll(async () => {
    idp = await startFakeIdp();
});

afterAll(async () => {
    await idp.close();
});

afterEach(() => {
    idp.setTokenHandler(null);
});

describe('createAuthMiddleware', () => {
    it('lets a verified session through', async () => {
        const response = await middlewareFor()(requestWith({
            access_token: await idp.mintAccessToken(),
            id_token: await idp.mintIdToken(),
        }));

        expect(response.headers.get('location')).toBeNull();
        expect(response.headers.get('x-middleware-next')).toBe('1');
    });

    it('redirects to the login path with no cookie', async () => {
        const response = await middlewareFor()(requestWith());

        expect(locationOf(response)?.pathname).toBe('/auth');
        expect(locationOf(response)?.searchParams.get('callbackUrl')).toBe('/dashboard');
    });

    it('redirects and clears the cookie when it cannot be parsed', async () => {
        // 1.x did `JSON.parse(cookie)` unguarded, so this threw a 500 on every request.
        const response = await middlewareFor()(requestWith('}{ not json'));

        expect(locationOf(response)?.pathname).toBe('/auth');
        expect(response.cookies.get(STORAGE_KEYS.tokens)?.value).toBe('');
    });

    it('rejects a forged ID token', async () => {
        const response = await middlewareFor()(requestWith({
            access_token: await idp.mintAccessToken(),
            id_token: unsignedToken({
                sub: 'attacker',
                role: 'admin',
                iss: idp.issuer,
                aud: CLIENT_ID,
                exp: Math.floor(Date.now() / 1000) + 3600,
            }),
        }));

        expect(locationOf(response)?.pathname).toBe('/auth');
    });

    it('refreshes an expiring access token and writes the rotated cookie', async () => {
        const rotatedAccess = await idp.mintAccessToken();
        const rotatedId = await idp.mintIdToken();
        idp.setTokenHandler(() => ({
            body: { access_token: rotatedAccess, id_token: rotatedId, refresh_token: 'rt-2', token_type: 'Bearer', expires_in: 3600 },
        }));

        const response = await middlewareFor()(requestWith({
            access_token: await idp.mintAccessToken({}, { expiresInSeconds: 5 }),
            id_token: await idp.mintIdToken(),
            refresh_token: 'rt-1',
        }));

        expect(response.headers.get('location')).toBeNull();

        const written = JSON.parse(response.cookies.get(STORAGE_KEYS.tokens)!.value);
        expect(written.refresh_token).toBe('rt-2');
        expect(written.access_token).toBe(rotatedAccess);
        expect(idp.tokenRequests.at(-1)?.get('grant_type')).toBe('refresh_token');
    });

    it('signs out when the access token is expiring and there is no refresh token', async () => {
        const response = await middlewareFor()(requestWith({
            access_token: await idp.mintAccessToken({}, { expiresInSeconds: -5 }),
            id_token: await idp.mintIdToken(),
        }));

        expect(locationOf(response)?.pathname).toBe('/auth');
        expect(response.cookies.get(STORAGE_KEYS.tokens)?.value).toBe('');
    });

    it('signs out when the refresh is rejected', async () => {
        idp.setTokenHandler(() => ({ status: 400, body: { error: 'invalid_grant' } }));

        const response = await middlewareFor()(requestWith({
            access_token: await idp.mintAccessToken({}, { expiresInSeconds: -5 }),
            id_token: await idp.mintIdToken(),
            refresh_token: 'rt-1',
        }));

        expect(locationOf(response)?.pathname).toBe('/auth');
    });

    it('enforces a role policy', async () => {
        const middleware = middlewareFor({ roles: ['admin'], unauthorizedPath: '/unauthorized' });

        const allowed = await middleware(requestWith({ access_token: await idp.mintAccessToken(), id_token: await idp.mintIdToken({ role: 'admin' }) }));
        expect(allowed.headers.get('location')).toBeNull();

        const denied = await middleware(requestWith({ access_token: await idp.mintAccessToken(), id_token: await idp.mintIdToken({ role: 'user' }) }));
        expect(locationOf(denied)?.pathname).toBe('/unauthorized');
    });

    it('enforces an amr policy', async () => {
        const middleware = middlewareFor({ amr: ['fido'], unauthorizedPath: '/step-up' });

        const denied = await middleware(requestWith({ access_token: await idp.mintAccessToken(), id_token: await idp.mintIdToken({ amr: ['ext', 'social'] }) }));
        expect(locationOf(denied)?.pathname).toBe('/step-up');
    });

    it('expires the cookie on the configured domain when signing out', async () => {
        const middleware = middlewareFor({ cookieDomain: '.wilsoon.dev' });

        const response = await middleware(requestWith('}{ not json'));
        const cleared = response.cookies.get(STORAGE_KEYS.tokens);

        // A bare delete() would only clear a host-only cookie and leave the shared one.
        expect(cleared?.value).toBe('');
        expect(cleared?.maxAge).toBe(0);
        expect(cleared?.domain).toBe('.wilsoon.dev');
    });

    it('treats an unparseable access token as expiring rather than valid', async () => {
        // No refresh token to fall back on, so the session is dropped instead of trusted.
        const response = await middlewareFor()(requestWith({ access_token: 'not-a-jwt', id_token: await idp.mintIdToken() }));

        expect(locationOf(response)?.pathname).toBe('/auth');
    });

    it('honours a custom login path and cookie name', async () => {
        const middleware = middlewareFor({ loginPath: '/sign-in', cookieName: 'my_session' });
        const request = new NextRequest('http://localhost:3000/dashboard');
        request.cookies.set('my_session', JSON.stringify({ access_token: await idp.mintAccessToken(), id_token: await idp.mintIdToken() }));

        const response = await middleware(request);
        expect(response.headers.get('location')).toBeNull();

        expect(locationOf(await middleware(new NextRequest('http://localhost:3000/dashboard')))?.pathname).toBe('/sign-in');
    });

    it('accepts a sibling service cookie without introspecting when no policy needs claims', async () => {
        const middleware = middlewareFor({ clientId: 'dash-service', apiAudience: API_AUDIENCE });
        const before = idp.introspectionRequests.length;

        const response = await middleware(requestWith({
            access_token: await idp.mintAccessToken({ client_id: 'go-service' }),
            id_token: await idp.mintIdToken({}, { audience: 'go-service' }),
        }));

        expect(response.headers.get('location')).toBeNull();
        expect(idp.introspectionRequests.length).toBe(before);
    });

    it('introspects a sibling service cookie when a role policy applies', async () => {
        idp.setIntrospection({ active: true, sub: 'user-1', role: 'user', session_version: 3 });
        const middleware = middlewareFor({
            clientId: 'dash-service',
            apiAudience: API_AUDIENCE,
            clientSecret: 'shh',
            roles: ['admin'],
            unauthorizedPath: '/unauthorized',
        });

        const denied = await middleware(requestWith({
            access_token: await idp.mintAccessToken({ client_id: 'go-service' }),
            id_token: await idp.mintIdToken({}, { audience: 'go-service' }),
        }));
        expect(locationOf(denied)?.pathname).toBe('/unauthorized');

        // The live role is what decides, not anything inside the token.
        idp.setIntrospection({ active: true, sub: 'user-1', role: 'admin', session_version: 3 });
        const allowed = await middleware(requestWith({
            access_token: await idp.mintAccessToken({ client_id: 'go-service' }),
            id_token: await idp.mintIdToken({}, { audience: 'go-service' }),
        }));
        expect(allowed.headers.get('location')).toBeNull();
    });

    it('signs out a sibling cookie when the app cannot verify platform sessions', async () => {
        const middleware = middlewareFor({ clientId: 'dash-service' });   // no apiAudience

        const response = await middleware(requestWith({
            access_token: await idp.mintAccessToken({ client_id: 'go-service' }),
            id_token: await idp.mintIdToken({}, { audience: 'go-service' }),
        }));

        expect(locationOf(response)?.pathname).toBe('/auth');
    });

    it('with verify:false, routes on cookie presence only', async () => {
        const middleware = middlewareFor({ verify: false });

        const response = await middleware(requestWith({
            access_token: await idp.mintAccessToken(),
            id_token: unsignedToken({ sub: 'attacker', role: 'admin' }),
        }));

        // Documented as convenience routing, not access control - hence the default of true.
        expect(response.headers.get('location')).toBeNull();
    });
});

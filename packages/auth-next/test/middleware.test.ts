import { NextRequest } from 'next/server';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_STORAGE_KEYS as STORAGE_KEYS, type AuthConfig } from '@wilsoon/auth-core';
import { sharedSessions } from './shared-profile';
import { createAuthMiddleware, type AuthMiddlewareOptions } from '../src/middleware';
import { API_AUDIENCE, CLIENT_ID, startFakeIdp, unsignedToken, type FakeIdp } from '../../auth-core/test/fake-idp';

let idp: FakeIdp;

const config = (): AuthConfig => ({
    clientId: CLIENT_ID,
    issuer: idp.issuer,
    redirectUri: 'http://localhost:3000/callback',
    rolesClaim: 'role',
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

let rotatedId: string;

beforeAll(async () => {
    idp = await startFakeIdp();
    rotatedId = await idp.mintIdToken();
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

    it('leaves a refresh to the navigation rather than the fetches beside it', async () => {
        /*
          Rotation is single-use. Ten parallel requests carrying one cookie used to send ten
          refreshes, nine of which looked like token theft to the provider - which revoked the
          family and ended the session. Only the navigation refreshes now.
        */
        const tokens = {
            access_token: await idp.mintAccessToken({}, { expiresInSeconds: 120 }),
            id_token: await idp.mintIdToken(),
            refresh_token: 'rt-1',
        };
        const before = idp.tokenRequests.length;

        const fetched = await middlewareFor()(requestWith(tokens));

        expect(fetched.headers.get('location')).toBeNull();
        expect(idp.tokenRequests.length).toBe(before);
        expect(fetched.cookies.get(STORAGE_KEYS.tokens)).toBeUndefined();

        const rotatedAccess = await idp.mintAccessToken();
        idp.setTokenHandler(() => ({
            body: { access_token: rotatedAccess, id_token: rotatedId, refresh_token: 'rt-2', token_type: 'Bearer', expires_in: 3600 },
        }));

        const navigation = requestWith(tokens);
        navigation.headers.set('sec-fetch-mode', 'navigate');
        const navigated = await middlewareFor()(navigation);

        expect(idp.tokenRequests.length).toBe(before + 1);
        expect(JSON.parse(navigated.cookies.get(STORAGE_KEYS.tokens)!.value).refresh_token).toBe('rt-2');
    });

    it('refreshes on any request once the token is spent', async () => {
        // Otherwise an app that only ever sends fetches would never renew anything.
        const rotatedAccess = await idp.mintAccessToken();
        idp.setTokenHandler(() => ({
            body: { access_token: rotatedAccess, id_token: rotatedId, refresh_token: 'rt-2', token_type: 'Bearer', expires_in: 3600 },
        }));

        const response = await middlewareFor()(requestWith({
            access_token: await idp.mintAccessToken({}, { expiresInSeconds: 5 }),
            id_token: await idp.mintIdToken(),
            refresh_token: 'rt-1',
        }));

        expect(response.headers.get('location')).toBeNull();
        expect(JSON.parse(response.cookies.get(STORAGE_KEYS.tokens)!.value).refresh_token).toBe('rt-2');
    });

    it('refreshes on every request when asked to', async () => {
        const rotatedAccess = await idp.mintAccessToken();
        idp.setTokenHandler(() => ({
            body: { access_token: rotatedAccess, id_token: rotatedId, refresh_token: 'rt-2', token_type: 'Bearer', expires_in: 3600 },
        }));

        const response = await middlewareFor({ refreshOn: 'request' })(requestWith({
            access_token: await idp.mintAccessToken({}, { expiresInSeconds: 120 }),
            id_token: await idp.mintIdToken(),
            refresh_token: 'rt-1',
        }));

        expect(JSON.parse(response.cookies.get(STORAGE_KEYS.tokens)!.value).refresh_token).toBe('rt-2');
    });

    it('keeps a session whose early refresh failed but whose token is still good', async () => {
        // A provider hiccup, or a sibling request that rotated this token a moment ago, is not
        // a reason to sign anybody out while the access token still has minutes left.
        idp.setTokenHandler(() => ({ status: 400, body: { error: 'invalid_grant' } }));

        const navigation = requestWith({
            access_token: await idp.mintAccessToken({}, { expiresInSeconds: 120 }),
            id_token: await idp.mintIdToken(),
            refresh_token: 'rt-1',
        });
        navigation.headers.set('sec-fetch-mode', 'navigate');

        const response = await middlewareFor()(navigation);

        expect(response.headers.get('location')).toBeNull();
        expect(response.cookies.get(STORAGE_KEYS.tokens)).toBeUndefined();
    });

    it('keeps a session with no refresh token until the access token is spent', async () => {
        const response = await middlewareFor()(requestWith({
            access_token: await idp.mintAccessToken({}, { expiresInSeconds: 120 }),
            id_token: await idp.mintIdToken(),
        }));

        expect(response.headers.get('location')).toBeNull();
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
            profile: sharedSessions,
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

    it('enforces a permission policy from the session access token', async () => {
        const middleware = middlewareFor({ apiAudience: API_AUDIENCE, permissionsClaim: 'permissions', permissions: ['games_portal.access'], unauthorizedPath: '/unauthorized' });

        const allowed = await middleware(requestWith({ access_token: await idp.mintAccessToken({ permissions: ['games_portal.access'] }), id_token: await idp.mintIdToken() }));
        expect(allowed.headers.get('location')).toBeNull();

        const denied = await middleware(requestWith({ access_token: await idp.mintAccessToken({ permissions: [] }), id_token: await idp.mintIdToken() }));
        expect(locationOf(denied)?.pathname).toBe('/unauthorized');
    });

    describe('enforce: "live"', () => {
        const live = (overrides: Partial<AuthMiddlewareOptions> = {}) => middlewareFor({ apiAudience: API_AUDIENCE, clientSecret: 'shh', permissionsClaim: 'permissions', enforce: 'live', unauthorizedPath: '/unauthorized', ...overrides });
        const session = async (permissions: string[] = ['games_portal.access']) => requestWith({ access_token: await idp.mintAccessToken({ permissions }), id_token: await idp.mintIdToken() });

        afterEach(() => idp.setIntrospection({ active: true, sub: 'user-1', role: 'admin', session_version: 3 }));

        it('lets a session through while the provider still honours it', async () => {
            idp.setIntrospection({ active: true, sub: 'user-1', permissions: ['games_portal.access'] });
            const before = idp.introspectionRequests.length;

            const response = await live()(await session());

            expect(response.headers.get('location')).toBeNull();
            expect(idp.introspectionRequests.length - before).toBe(1);
        });

        it('signs the user out at once when the provider says the session is gone', async () => {
            idp.setIntrospection({ active: false });

            const response = await live({ permissions: ['games_portal.access'] })(await session());

            expect(locationOf(response)?.pathname).toBe('/auth');
            expect(response.cookies.get(STORAGE_KEYS.tokens)?.value).toBe('');
        });

        it('guards on the live permissions, not the token snapshot', async () => {
            // The token still says `admin`; the provider says it was taken away a moment ago.
            idp.setIntrospection({ active: true, sub: 'user-1', permissions: ['games_portal.access'] });
            const revoked = await live({ permissions: ['games_portal.admin'] })(await session(['games_portal.access', 'games_portal.admin']));
            expect(locationOf(revoked)?.pathname).toBe('/unauthorized');

            // And the reverse: granted since the token was issued.
            idp.setIntrospection({ active: true, sub: 'user-1', permissions: ['games_portal.access', 'games_portal.admin'] });
            const granted = await live({ permissions: ['games_portal.admin'] })(await session(['games_portal.access']));
            expect(granted.headers.get('location')).toBeNull();
        });

        it('answers 503 without clearing the cookie when the provider cannot be asked', async () => {
            idp.setIntrospection({ error: 'server_error' }, { status: 500 });

            const response = await live({ permissions: ['games_portal.access'] })(await session());

            expect(response.status).toBe(503);
            expect(response.cookies.get(STORAGE_KEYS.tokens)).toBeUndefined();
        });

        it('refuses a configuration that cannot work', () => {
            expect(() => middlewareFor({ enforce: 'live' })).toThrow(/clientSecret/);
            expect(() => middlewareFor({ enforce: 'live', clientSecret: 'shh', verify: false })).toThrow(/verify: false/);
        });
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

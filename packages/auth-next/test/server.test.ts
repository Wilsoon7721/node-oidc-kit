import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { AuthError, DEFAULT_STORAGE_KEYS as STORAGE_KEYS, type AuthConfig } from '@wilsoon/auth-core';
import { sharedSessions } from './shared-profile';
import { API_AUDIENCE, CLIENT_ID, OTHER_CLIENT_ID, startFakeIdp, unsignedToken, type FakeIdp } from '../../auth-core/test/fake-idp';

/** A stand-in for the Next.js cookie store, shared with the mocked `next/headers`. */
const jar = vi.hoisted(() => ({
    cookies: new Map<string, string>(),
    readOnly: false,
}));

vi.mock('next/headers', () => ({
    cookies: async () => ({
        get: (name: string) => (jar.cookies.has(name) ? { name, value: jar.cookies.get(name) } : undefined),
        has: (name: string) => jar.cookies.has(name),
        set: (options: { name: string; value: string }) => {
            if (jar.readOnly) throw new Error('Cookies can only be modified in a Server Action or Route Handler.');
            jar.cookies.set(options.name, options.value);
        },
        delete: (name: string) => {
            if (jar.readOnly) throw new Error('Cookies can only be modified in a Server Action or Route Handler.');
            jar.cookies.delete(name);
        },
    }),
}));

const { getSession, requireSession } = await import('../src/server');

let idp: FakeIdp;
const config = (): AuthConfig => ({
    clientId: CLIENT_ID,
    issuer: idp.issuer,
    redirectUri: 'http://localhost:3000/callback',
    rolesClaim: 'role',
});

const setSessionCookie = (value: unknown, encode = false) => {
    const json = JSON.stringify(value);
    jar.cookies.set(STORAGE_KEYS.tokens, encode ? encodeURIComponent(json) : json);
};

beforeAll(async () => {
    idp = await startFakeIdp();
});

afterAll(async () => {
    await idp.close();
});

afterEach(() => {
    jar.cookies.clear();
    jar.readOnly = false;
});

describe('getSession', () => {
    it('verifies the ID token in the cookie and returns the user', async () => {
        setSessionCookie({ access_token: await idp.mintAccessToken(), id_token: await idp.mintIdToken() });

        const { user, tokens, error } = await getSession(config());

        expect(error).toBeUndefined();
        expect(tokens?.id_token).toBeTruthy();
        expect(user).toMatchObject({ id: 'user-1', roles: ['admin'], authMethods: ['mfa', 'fido', 'hw'] });
    });

    it('reads the URI-encoded cookie the identity provider actually writes', async () => {
        setSessionCookie({ access_token: await idp.mintAccessToken(), id_token: await idp.mintIdToken() }, true);

        const { user } = await getSession(config());

        expect(user?.roles).toEqual(['admin']);
    });

    it('returns no session when there is no cookie', async () => {
        const { user, tokens, error } = await getSession(config());

        expect(user).toBeNull();
        expect(tokens).toBeNull();
        expect(error).toBeUndefined();
    });

    it('fails closed on a forged ID token and reports why', async () => {
        setSessionCookie({
            access_token: 'anything',
            id_token: unsignedToken({
                sub: 'attacker',
                role: 'admin',
                amr: ['mfa'],
                session_version: 99,
                iss: idp.issuer,
                aud: CLIENT_ID,
                exp: Math.floor(Date.now() / 1000) + 3600,
            }),
        });

        const { user, tokens, error } = await getSession(config());

        expect(user).toBeNull();
        expect(tokens).toBeNull();
        expect(error).toBeInstanceOf(AuthError);
        expect(error?.code).toBe('TOKEN_VERIFICATION_FAILED');
    });

    it('fails closed on an expired token and on another application audience', async () => {
        setSessionCookie({ access_token: 'a', id_token: await idp.mintIdToken({}, { expiresInSeconds: -60 }) });
        expect((await getSession(config())).user).toBeNull();

        setSessionCookie({ access_token: 'a', id_token: await idp.mintIdToken({}, { audience: OTHER_CLIENT_ID }) });
        expect((await getSession(config())).user).toBeNull();
    });

    it('returns no session when the cookie holds junk', async () => {
        jar.cookies.set(STORAGE_KEYS.tokens, 'not-json-at-all');

        const { user, tokens } = await getSession(config());

        expect(user).toBeNull();
        expect(tokens).toBeNull();
    });

    it('returns no session when the cookie has no ID token to verify', async () => {
        setSessionCookie({ access_token: await idp.mintAccessToken() });

        expect((await getSession(config())).user).toBeNull();
    });

    it('works in a read-only Server Component context', async () => {
        jar.readOnly = true;
        setSessionCookie({ access_token: 'a', id_token: await idp.mintIdToken() });
        jar.cookies.set(STORAGE_KEYS.tokens, jar.cookies.get(STORAGE_KEYS.tokens)!);

        const { user } = await getSession(config());

        expect(user?.id).toBe('user-1');
    });

    it('fetches the JWKS once across requests', async () => {
        setSessionCookie({ access_token: 'a', id_token: await idp.mintIdToken() });
        const before = idp.jwksHits;

        await getSession(config());
        await getSession(config());
        await getSession(config());

        expect(idp.jwksHits - before).toBeLessThanOrEqual(1);
    });
});

describe('getSession on a shared platform cookie', () => {
    // dash and go are separate clients sharing one `.wilsoon.dev` session cookie, so the
    // cookie holds whichever service completed the most recent code exchange.
    const dashConfig = (): AuthConfig => ({
        clientId: 'dash-service',
        clientSecret: 'shh',
        issuer: idp.issuer,
        redirectUri: 'https://dash.wilsoon.dev/callback',
        apiAudience: API_AUDIENCE,
        rolesClaim: 'role',
        profile: sharedSessions,
    });

    const platformIntrospection = () => idp.setIntrospection({
        active: true,
        sub: 'user-1',
        role: 'admin',
        amr: ['mfa', 'fido', 'hw'],
        session_version: 3,
        name: 'Ada Lovelace',
        email: 'ada@example.com',
    });

    it('resolves a session from a sibling service cookie via the access token', async () => {
        platformIntrospection();
        setSessionCookie({
            access_token: await idp.mintAccessToken({ client_id: 'go-service' }),
            id_token: await idp.mintIdToken({}, { audience: 'go-service' }),
        });

        const { user, error } = await getSession(dashConfig());

        expect(error).toBeUndefined();
        expect(user).toMatchObject({ id: 'user-1', roles: ['admin'], source: 'access_token', name: 'Ada Lovelace' });
    });

    it('prefers its own ID token and skips introspection entirely', async () => {
        platformIntrospection();
        setSessionCookie({
            access_token: await idp.mintAccessToken({ client_id: 'dash-service' }),
            id_token: await idp.mintIdToken({}, { audience: 'dash-service' }),
        });
        const before = idp.introspectionRequests.length;

        const { user } = await getSession(dashConfig());

        expect(user?.source).toBe('id_token');
        expect(idp.introspectionRequests.length).toBe(before);
    });

    it('still fails closed when the sibling access token is forged or revoked', async () => {
        platformIntrospection();
        setSessionCookie({ access_token: await idp.mintAccessToken({}, { expiresInSeconds: -60 }) });
        expect((await getSession(dashConfig())).user).toBeNull();

        idp.setIntrospection({ active: false });
        setSessionCookie({ access_token: await idp.mintAccessToken({ client_id: 'go-service' }) });
        const { user, error } = await getSession(dashConfig());
        expect(user).toBeNull();
        expect(error?.message).toMatch(/no longer active/);
    });

    it('explains itself when the app is not configured for platform sessions', async () => {
        platformIntrospection();
        setSessionCookie({ access_token: await idp.mintAccessToken({ client_id: 'go-service' }) });

        const { error } = await getSession({ ...dashConfig(), apiAudience: undefined });
        expect(error?.code).toBe('FOREIGN_SESSION');
        expect(error?.message).toMatch(/another application/);

        // Shared sessions go through introspection, so without a secret core does not even try.
        const { error: secretless } = await getSession({ ...dashConfig(), clientSecret: undefined });
        expect(secretless?.code).toBe('FOREIGN_SESSION');

        const { error: profileless } = await getSession({ ...dashConfig(), profile: undefined });
        expect(profileless?.code).toBe('FOREIGN_SESSION');
    });
});

describe('requireSession', () => {
    it('returns the user when the policy is satisfied', async () => {
        setSessionCookie({ access_token: 'a', id_token: await idp.mintIdToken() });

        const user = await requireSession(config(), { roles: ['admin'], amr: ['mfa', 'fido'] });

        expect(user.id).toBe('user-1');
    });

    it('throws when there is no session', async () => {
        await expect(requireSession(config())).rejects.toThrow(AuthError);
    });

    it('throws when the role is not permitted', async () => {
        setSessionCookie({ access_token: 'a', id_token: await idp.mintIdToken({ role: 'user' }) });

        await expect(requireSession(config(), { roles: ['admin'] })).rejects.toThrow(/roles \[admin\] is required/);
    });

    it('requires every listed permission, read from the session access token', async () => {
        const configured = { ...config(), apiAudience: API_AUDIENCE, permissionsClaim: 'permissions' };
        setSessionCookie({ access_token: await idp.mintAccessToken({ permissions: ['games_portal.access'] }), id_token: await idp.mintIdToken() });

        await expect(requireSession(configured, { permissions: ['games_portal.access'] })).resolves.toMatchObject({ permissions: ['games_portal.access'] });
        await expect(requireSession(configured, { permissions: ['games_portal.access', 'games_portal.admin'] })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    });

    it('throws when the authentication methods are insufficient', async () => {
        setSessionCookie({ access_token: 'a', id_token: await idp.mintIdToken({ amr: ['ext', 'social'] }) });

        await expect(requireSession(config(), { amr: ['fido'] })).rejects.toThrow(/do not satisfy/);
    });

    it('surfaces the verification failure rather than a generic error', async () => {
        setSessionCookie({ access_token: 'a', id_token: await idp.mintIdToken({}, { expiresInSeconds: -60 }) });

        await expect(requireSession(config())).rejects.toThrow(/expired/i);
    });
});

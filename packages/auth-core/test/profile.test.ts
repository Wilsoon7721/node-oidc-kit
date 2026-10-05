import { afterAll, beforeAll, describe, expect, expectTypeOf, it, vi } from 'vitest';
import {
    AuthClient,
    ClaimValidationError,
    createAuthClient,
    DEFAULT_STORAGE_KEYS,
    defineProfile,
    hasPermission,
    hasRole,
    IssuerMismatchError,
    isSilentAuthError,
    AuthorizationResponseError,
    MachineTokenNotAllowedError,
    MemoryStorage,
    readClaimList,
    readClaimPath,
    requirePermission,
    requireRole,
    type AuthConfig,
    type ProfileContext,
} from '../src/index';
import { API_AUDIENCE, CLIENT_ID, startFakeIdp, type FakeIdp } from './fake-idp';

let idp: FakeIdp;

const config = (overrides: Partial<AuthConfig> = {}): AuthConfig => ({
    clientId: CLIENT_ID,
    issuer: idp.issuer,
    redirectUri: 'http://localhost:3000/callback',
    apiAudience: API_AUDIENCE,
    ...overrides,
});

beforeAll(async () => {
    idp = await startFakeIdp();
});

afterAll(async () => {
    await idp.close();
});

describe('claim paths and guards', () => {
    const claims = {
        permissions: ['read:reports', 'write:reports'],
        roles: 'admin  auditor',
        realm_access: { roles: ['offline_access'] },
        resource_access: { 'my-app': { roles: ['editor'] } },
    };

    it('reads dot paths, arrays and space-delimited strings', () => {
        expect(readClaimPath(claims, 'realm_access.roles')).toEqual(['offline_access']);
        expect(readClaimPath(claims, 'nope.deeper')).toBeUndefined();
        expect(readClaimList(claims, 'resource_access.my-app.roles')).toEqual(['editor']);
        expect(readClaimList(claims, 'roles')).toEqual(['admin', 'auditor']);
        expect(readClaimList(claims, 'realm_access')).toEqual([]);
        expect(readClaimList(claims, (c) => Object.keys(c))).toEqual(Object.keys(claims));
    });

    it('treats roles as any-of and permissions as all-of', () => {
        const user = { roles: ['editor'], permissions: ['a', 'b'] };

        expect(hasRole(user, ['admin', 'editor'])).toBe(true);
        expect(hasRole(user, 'admin')).toBe(false);
        expect(hasPermission(user, ['a', 'b'])).toBe(true);
        expect(hasPermission(user, ['a', 'c'])).toBe(false);
        // Asking for nothing grants nothing.
        expect(hasPermission(user, [])).toBe(false);
        expect(hasPermission(null, 'a')).toBe(false);

        expect(() => requireRole(user, 'admin')).toThrow(ClaimValidationError);
        expect(() => requirePermission(user, ['a', 'c'])).toThrow(/Missing required permission\(s\): c/);
    });

    it('maps Auth0-style permissions and Keycloak-style roles without any profile', async () => {
        const client = new AuthClient(config({ permissionsClaim: 'permissions', rolesClaim: 'resource_access.test-client.roles' }), new MemoryStorage());
        const user = await client.verifyIdToken(await idp.mintIdToken({ permissions: ['read:reports'], resource_access: { 'test-client': { roles: ['editor'] } } }));

        expect(user.permissions).toEqual(['read:reports']);
        expect(user.roles).toEqual(['editor']);

        const access = await client.verifyAccessToken(await idp.mintAccessToken({ permissions: ['read:reports'] }));
        expect(access.permissions).toEqual(['read:reports']);
    });

    it('merges permissions from the session access token issued to this client', async () => {
        const client = new AuthClient(config({ permissionsClaim: 'permissions' }), new MemoryStorage());
        const user = await client.resolveSession({
            id_token: await idp.mintIdToken(),
            access_token: await idp.mintAccessToken({ permissions: ['read:reports'] }),
        });

        expect(user.permissions).toEqual(['read:reports']);
    });
});

describe('storage names', () => {
    it('defaults to neutral oidc_ names', () => {
        expect(new AuthClient(config(), new MemoryStorage()).storageKeys).toEqual(DEFAULT_STORAGE_KEYS);
        expect(DEFAULT_STORAGE_KEYS).toEqual({ tokens: 'oidc_tokens', state: 'oidc_state', nonce: 'oidc_nonce', codeVerifier: 'oidc_verifier' });
    });

    it('honours storagePrefix', async () => {
        const storage = new MemoryStorage();
        const client = new AuthClient(config({ storagePrefix: 'app_' }), storage);
        const request = await client.createAuthorizeUrl();

        expect(storage.getItem('app_state')).toBe(request.state);
        client.saveTokens({ access_token: 'a' });
        expect(storage.getItem('app_tokens')).toBeTruthy();
    });
});

describe('provider profiles', () => {
    const acme = (spy = vi.fn()) => defineProfile({
        name: 'acme',
        storagePrefix: 'acme_',
        mapUser: (claims) => ({ permissions: ['acme.seen'], tier: claims.tier, id: 'hijacked', issuer: 'https://evil.example' }),
        isMachineToken: (claims) => claims.kind === 'robot',
        extend: (ctx: ProfileContext) => {
            spy(ctx);
            return { hello: () => `hi from ${ctx.config.clientId}`, endpoints: () => ctx.getEndpoints() };
        },
    });

    it('namespaces the extensions and types them from the profile', async () => {
        const spy = vi.fn();
        const client = createAuthClient({ ...config(), profile: acme(spy) }, new MemoryStorage());

        expectTypeOf(client.acme.hello).toEqualTypeOf<() => string>();
        expect(client.acme.hello()).toBe(`hi from ${CLIENT_ID}`);
        expect((await client.acme.endpoints()).issuer).toBe(idp.issuer);
        expect(spy).toHaveBeenCalledTimes(1);
        expect(client.storageKeys.tokens).toBe('acme_tokens');
    });

    it('lets mapUser add fields but never override identity', async () => {
        const client = new AuthClient(config({ profile: acme() }), new MemoryStorage());
        const user = await client.verifyIdToken(await idp.mintIdToken({ tier: 'gold' }));

        expect(user.id).toBe('user-1');
        expect(user.issuer).toBe(idp.issuer);
        expect(user.permissions).toEqual(['acme.seen']);
        expect((user as unknown as { tier: string }).tier).toBe('gold');
    });

    it('lets a configured claim path win over the profile', async () => {
        const client = new AuthClient(config({ profile: acme(), permissionsClaim: 'perms' }), new MemoryStorage());
        const user = await client.verifyIdToken(await idp.mintIdToken({ perms: ['x'] }));
        expect(user.permissions).toEqual(['x']);
    });

    it('uses the profile machine detector, and lets detectMachineToken override it', async () => {
        const robot = await idp.mintAccessToken({ kind: 'robot' });

        await expect(new AuthClient(config({ profile: acme() }), new MemoryStorage()).verifyAccessToken(robot)).rejects.toThrow(MachineTokenNotAllowedError);
        await expect(new AuthClient(config({ profile: acme(), detectMachineToken: () => false }), new MemoryStorage()).verifyAccessToken(robot)).resolves.toBeDefined();
    });

    it('refuses a profile name that would shadow a client member', () => {
        expect(() => new AuthClient(config({ profile: defineProfile({ name: 'verifyIdToken' }) }), new MemoryStorage())).toThrow(/collides/);
        expect(() => new AuthClient(config({ profile: defineProfile({ name: '' }) }), new MemoryStorage())).toThrow(/non-empty/);
    });

    it('explains that a moved 2.x method needs a profile', async () => {
        const client = new AuthClient(config(), new MemoryStorage());

        await expect(client.reauthorize(['passkey'])).rejects.toMatchObject({ code: 'PROFILE_REQUIRED' });
        await expect(client.verifyPlatformSession('x')).rejects.toMatchObject({ code: 'PROFILE_REQUIRED' });
        await expect(client.isSessionCurrent({ id: 'u', sessionVersion: 1 })).rejects.toMatchObject({ code: 'PROFILE_REQUIRED' });
    });

    it('resolves hydrateSession to null without a profile that restores sessions', async () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => { });
        await expect(new AuthClient(config(), new MemoryStorage()).hydrateSession()).resolves.toBeNull();
        warn.mockRestore();
    });

    it('falls back to plain introspection for liveAccess', async () => {
        idp.setIntrospection({ active: true, sub: 'user-1', permissions: ['a'], sid: 's1' });
        const client = new AuthClient(config({ clientSecret: 'shh' }), new MemoryStorage());

        await expect(client.liveAccess(await idp.mintAccessToken())).resolves.toEqual({ active: true, permissions: ['a'], sid: 's1' });

        idp.setIntrospection({ active: false });
        await expect(client.liveAccess(await idp.mintAccessToken())).resolves.toEqual({ active: false });
        idp.setIntrospection({ active: true, sub: 'user-1', role: 'admin', session_version: 3 });
    });
});

describe('authorization response issuer (RFC 9207)', () => {
    const start = async () => {
        const client = new AuthClient(config(), new MemoryStorage());
        const request = await client.createAuthorizeUrl();
        idp.setTokenHandler(async () => ({ body: { access_token: await idp.mintAccessToken(), id_token: await idp.mintIdToken({ nonce: request.nonce }) } }));
        return { client, request };
    };

    afterAll(() => idp.setTokenHandler(null));

    it('accepts the configured issuer', async () => {
        const { client, request } = await start();
        const result = await client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}&iss=${encodeURIComponent(idp.issuer)}`);
        expect(result.user?.id).toBe('user-1');
    });

    it('refuses a response from another issuer before exchanging the code', async () => {
        const { client, request } = await start();
        const before = idp.tokenHits;

        await expect(client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}&iss=${encodeURIComponent('https://evil.example')}`)).rejects.toThrow(IssuerMismatchError);
        expect(idp.tokenHits).toBe(before);
    });
});

describe('isSilentAuthError', () => {
    it('reads the prompt=none outcomes as "not signed in", and nothing else', () => {
        expect(isSilentAuthError(new AuthorizationResponseError('login_required'))).toBe(true);
        expect(isSilentAuthError(new AuthorizationResponseError('account_selection_required'))).toBe(true);
        expect(isSilentAuthError(new AuthorizationResponseError('access_denied'))).toBe(false);
        expect(isSilentAuthError(new Error('login_required'))).toBe(false);
    });
});

describe('silentAuthorize', () => {
    it('needs a browser', async () => {
        await expect(new AuthClient(config(), new MemoryStorage()).silentAuthorize()).rejects.toMatchObject({ code: 'SILENT_AUTH_UNAVAILABLE' });
    });
});

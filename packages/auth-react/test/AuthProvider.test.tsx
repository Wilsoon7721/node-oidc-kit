import React from 'react';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_STORAGE_KEYS as STORAGE_KEYS, defineProfile, type ProfileContext } from '@wilsoon/auth-core';
import { AuthProvider, useAuth, type AuthProviderProps } from '../src/index';
import { CLIENT_ID, OTHER_CLIENT_ID, startFakeIdp, unsignedToken, type FakeIdp } from '../../auth-core/test/fake-idp';

let idp: FakeIdp;

/** Renders the auth state as text so assertions read like what a user would see. */
const Probe = () => {
    const { user, isLoading, error, isAuthenticated, login } = useAuth();

    if (isLoading) return <div>loading</div>;

    return (
        <div>
            <div data-testid="authenticated">{String(isAuthenticated)}</div>
            <div data-testid="verified">{user ? String(user.verified) : 'none'}</div>
            <div data-testid="name">{user?.name ?? 'none'}</div>
            <div data-testid="role">{user && user.verified ? user.roles.join(',') || 'none' : 'none'}</div>
            <div data-testid="amr">{user && user.verified ? user.authMethods.join(',') : 'none'}</div>
            <div data-testid="error">{error ? (error as { code?: string }).code ?? error.message : 'none'}</div>
            <button onClick={login}>Log in</button>
            <button onClick={() => login({ acrValues: 'urn:wilsoon:acr:passkey', maxAge: 300 })}>Step up</button>
        </div>
    );
};

/** The 2.x cookie restore, as a profile: userinfo with credentials, answered from a provider cookie. */
const cookieProfile = defineProfile({
    name: 'cookie',
    restoreSession: async (ctx: ProfileContext) => {
        const response = await fetch((await ctx.getEndpoints()).userinfo_endpoint, { credentials: 'include' });
        if (!response.ok) return null;
        const body = await response.json();
        return { id: body.sub, name: body.name, email: body.email };
    },
    extend: () => ({ ping: () => 'pong' }),
});

const renderProvider = (props: Partial<AuthProviderProps> = {}, probe: React.ReactNode = <Probe />) => render(
    <AuthProvider clientId={CLIENT_ID} issuer={idp.issuer} redirectUri="http://localhost:3000/callback" rolesClaim="role" restore="none" {...props}>
        {probe}
    </AuthProvider>
);

const setLocation = (search: string) => {
    Object.defineProperty(window, 'location', {
        configurable: true,
        writable: true,
        value: {
            href: `http://localhost:3000/callback${search}`,
            search,
            pathname: '/callback',
            origin: 'http://localhost:3000',
            assign: vi.fn(),
        },
    });
};

const settled = () => waitFor(() => expect(screen.queryByText('loading')).toBeNull());

beforeAll(async () => {
    idp = await startFakeIdp();
});

afterAll(async () => {
    await idp.close();
});

beforeEach(() => {
    window.sessionStorage.clear();
    setLocation('');
});

afterEach(() => {
    // Explicit because `globals: false` means testing-library cannot auto-register cleanup.
    cleanup();
    idp.setTokenHandler(null);
    vi.restoreAllMocks();
});

describe('AuthProvider hydration', () => {
    it('hydrates an unverified profile from the session cookie', async () => {
        renderProvider({ profile: cookieProfile, restore: 'profile' });
        await settled();

        expect(screen.getByTestId('authenticated').textContent).toBe('true');
        expect(screen.getByTestId('verified').textContent).toBe('false');
        expect(screen.getByTestId('name').textContent).toBe('Ada Lovelace');
        // A hydrated session carries no authorization claims - that is the point of the union.
        expect(screen.getByTestId('role').textContent).toBe('none');
    });

    it('stays unauthenticated when there is no session', async () => {
        idp.setUserinfo({ error: 'invalid_token' }, 401);
        try {
            renderProvider({ profile: cookieProfile, restore: 'profile' });
            await settled();

            expect(screen.getByTestId('authenticated').textContent).toBe('false');
            expect(screen.getByTestId('error').textContent).toBe('none');
        } finally {
            idp.setUserinfo({ sub: 'user-1', name: 'Ada Lovelace', email: 'ada@example.com', email_verified: true }, 200);
        }
    });
});

describe('AuthProvider login', () => {
    it('persists state, nonce and the PKCE verifier, then redirects', async () => {
        renderProvider();
        await settled();

        screen.getByText('Log in').click();

        await waitFor(() => expect(window.sessionStorage.getItem(STORAGE_KEYS.state)).toBeTruthy());
        expect(window.sessionStorage.getItem(STORAGE_KEYS.nonce)).toBeTruthy();
        expect(window.sessionStorage.getItem(STORAGE_KEYS.codeVerifier)).toBeTruthy();

        const authorizeUrl = new URL(window.location.href);
        expect(authorizeUrl.pathname).toBe('/authorize');
        expect(authorizeUrl.searchParams.get('state')).toBe(window.sessionStorage.getItem(STORAGE_KEYS.state));
        expect(authorizeUrl.searchParams.get('nonce')).toBe(window.sessionStorage.getItem(STORAGE_KEYS.nonce));
        expect(authorizeUrl.searchParams.get('code_challenge_method')).toBe('S256');
    });

    it('carries acr_values and max_age through to the authorization request', async () => {
        renderProvider();
        await settled();

        screen.getByText('Step up').click();

        await waitFor(() => expect(new URL(window.location.href).pathname).toBe('/authorize'));

        const authorizeUrl = new URL(window.location.href);
        expect(authorizeUrl.searchParams.get('acr_values')).toBe('urn:wilsoon:acr:passkey');
        expect(authorizeUrl.searchParams.get('max_age')).toBe('300');
    });

    it('sends no max_age when the caller asked for none', async () => {
        renderProvider();
        await settled();

        screen.getByText('Log in').click();

        await waitFor(() => expect(new URL(window.location.href).pathname).toBe('/authorize'));
        expect(new URL(window.location.href).searchParams.get('max_age')).toBeNull();
    });
});

describe('AuthProvider callback', () => {
    /** Seeds the transient values a real authorize redirect would have stored. */
    const seedPendingRequest = () => {
        const state = 'state-from-authorize';
        const nonce = 'nonce-from-authorize';
        window.sessionStorage.setItem(STORAGE_KEYS.state, state);
        window.sessionStorage.setItem(STORAGE_KEYS.nonce, nonce);
        window.sessionStorage.setItem(STORAGE_KEYS.codeVerifier, 'verifier-from-authorize');
        return { state, nonce };
    };

    const respondWith = (idToken: () => Promise<string>) => {
        idp.setTokenHandler(async () => ({
            body: {
                access_token: await idp.mintAccessToken(),
                id_token: await idToken(),
                token_type: 'Bearer',
                expires_in: 3600,
            },
        }));
    };

    it('exchanges the code and exposes a verified user', async () => {
        const { state, nonce } = seedPendingRequest();
        setLocation(`?code=the-code&state=${state}`);
        respondWith(() => idp.mintIdToken({ nonce }));

        renderProvider();
        await settled();

        expect(screen.getByTestId('verified').textContent).toBe('true');
        expect(screen.getByTestId('role').textContent).toBe('admin');
        expect(screen.getByTestId('amr').textContent).toBe('mfa,fido,hw');
        expect(idp.tokenRequests.at(-1)?.get('code_verifier')).toBe('verifier-from-authorize');
    });

    it('clears the transient values so the callback cannot be replayed', async () => {
        const { state, nonce } = seedPendingRequest();
        setLocation(`?code=the-code&state=${state}`);
        respondWith(() => idp.mintIdToken({ nonce }));

        renderProvider();
        await settled();

        expect(window.sessionStorage.getItem(STORAGE_KEYS.state)).toBeNull();
        expect(window.sessionStorage.getItem(STORAGE_KEYS.nonce)).toBeNull();
        expect(window.sessionStorage.getItem(STORAGE_KEYS.codeVerifier)).toBeNull();
    });

    it('rejects a callback whose state does not match', async () => {
        seedPendingRequest();
        setLocation('?code=the-code&state=attacker-supplied');
        const before = idp.tokenHits;

        renderProvider();
        await settled();

        expect(screen.getByTestId('error').textContent).toBe('STATE_MISMATCH');
        expect(screen.getByTestId('authenticated').textContent).toBe('false');
        expect(idp.tokenHits).toBe(before);
    });

    it('rejects an ID token bound to a different request', async () => {
        const { state } = seedPendingRequest();
        setLocation(`?code=the-code&state=${state}`);
        respondWith(() => idp.mintIdToken({ nonce: 'someone-elses-nonce' }));

        renderProvider();
        await settled();

        expect(screen.getByTestId('error').textContent).toBe('NONCE_MISMATCH');
        expect(screen.getByTestId('authenticated').textContent).toBe('false');
    });

    it('rejects an ID token minted for another application', async () => {
        const { state, nonce } = seedPendingRequest();
        setLocation(`?code=the-code&state=${state}`);
        respondWith(() => idp.mintIdToken({ nonce }, { audience: OTHER_CLIENT_ID }));

        renderProvider();
        await settled();

        expect(screen.getByTestId('error').textContent).toBe('TOKEN_VERIFICATION_FAILED');
    });

    it('rejects a forged unsigned ID token', async () => {
        const { state, nonce } = seedPendingRequest();
        setLocation(`?code=the-code&state=${state}`);
        idp.setTokenHandler(async () => ({
            body: {
                access_token: await idp.mintAccessToken(),
                id_token: unsignedToken({
                    sub: 'attacker',
                    role: 'admin',
                    nonce,
                    iss: idp.issuer,
                    aud: CLIENT_ID,
                    exp: Math.floor(Date.now() / 1000) + 3600,
                }),
                token_type: 'Bearer',
            },
        }));

        renderProvider();
        await settled();

        expect(screen.getByTestId('error').textContent).toBe('TOKEN_VERIFICATION_FAILED');
        expect(screen.getByTestId('role').textContent).toBe('none');
    });

    it('surfaces a provider error response', async () => {
        seedPendingRequest();
        setLocation('?error=access_denied&error_description=User+declined');

        renderProvider();
        await settled();

        expect(screen.getByTestId('error').textContent).toBe('AUTHORIZATION_RESPONSE_ERROR');
        expect(screen.getByTestId('authenticated').textContent).toBe('false');
    });
});

describe('AuthProvider silent restore', () => {
    /**
     * jsdom does not navigate iframes, so this stands in for the provider: it reads the authorize URL off the frame and decides where the frame lands.
     * `"cross-origin"` makes the landing unreadable, which is what a provider page or a framing refusal looks like.
     */
    const landSilentFrame = (landing: (authorize: URL) => string) => {
        const original = document.body.appendChild.bind(document.body);
        const frames: URL[] = [];

        vi.spyOn(document.body, 'appendChild').mockImplementation(<T extends Node>(node: T): T => {
            if (!(node instanceof HTMLIFrameElement)) return original(node);

            const authorize = new URL(node.src);
            frames.push(authorize);
            const target = landing(authorize);
            Object.defineProperty(node, 'contentWindow', {
                configurable: true,
                get: () => ({
                    get location() {
                        if (target === 'cross-origin') throw new DOMException('Blocked a frame from accessing a cross-origin frame.', 'SecurityError');
                        return { href: target };
                    },
                }),
            });
            original(node);
            setTimeout(() => node.dispatchEvent(new Event('load')), 0);
            return node;
        });

        return frames;
    };

    it('restores a verified session through prompt=none without touching the login state', async () => {
        const frames = landSilentFrame((authorize) => {
            idp.setTokenHandler(async () => ({ body: { access_token: await idp.mintAccessToken(), id_token: await idp.mintIdToken({ nonce: authorize.searchParams.get('nonce') }) } }));
            return `http://localhost:3000/callback?code=silent-code&state=${authorize.searchParams.get('state')}`;
        });

        renderProvider({ restore: 'silent' });
        await settled();

        expect(screen.getByTestId('verified').textContent).toBe('true');
        expect(screen.getByTestId('role').textContent).toBe('admin');
        expect(frames[0].searchParams.get('prompt')).toBe('none');
        expect(idp.tokenRequests.at(-1)?.get('code')).toBe('silent-code');
        // The attempt kept its values in memory, so an interactive login in another tab is not clobbered.
        expect(window.sessionStorage.getItem(STORAGE_KEYS.state)).toBeNull();
        expect(document.querySelector('iframe')).toBeNull();
    });

    it('treats login_required as signed out, and falls back to the profile restore', async () => {
        landSilentFrame((authorize) => `http://localhost:3000/callback?error=login_required&state=${authorize.searchParams.get('state')}`);
        const before = idp.tokenHits;

        renderProvider({ restore: 'silent', profile: cookieProfile });
        await settled();

        expect(screen.getByTestId('error').textContent).toBe('none');
        expect(screen.getByTestId('verified').textContent).toBe('false');
        expect(screen.getByTestId('name').textContent).toBe('Ada Lovelace');
        expect(idp.tokenHits).toBe(before);
    });

    it('stays signed out without a fallback, and gives up at once on an unreadable frame', async () => {
        landSilentFrame(() => 'cross-origin');
        const started = Date.now();

        renderProvider({ restore: 'silent' });
        await settled();

        expect(screen.getByTestId('authenticated').textContent).toBe('false');
        expect(screen.getByTestId('error').textContent).toBe('none');
        expect(Date.now() - started).toBeLessThan(5000);
    });

    it('surfaces a real denial rather than reading it as signed out', async () => {
        landSilentFrame((authorize) => `http://localhost:3000/callback?error=access_denied&state=${authorize.searchParams.get('state')}`);

        renderProvider({ restore: 'silent' });
        await settled();

        expect(screen.getByTestId('error').textContent).toBe('AUTHORIZATION_RESPONSE_ERROR');
    });

    it('does nothing when it is itself the page inside the silent frame', async () => {
        const parent = Object.getOwnPropertyDescriptor(window, 'parent');
        Object.defineProperty(window, 'parent', { configurable: true, value: {} });
        try {
            setLocation('?code=meant-for-the-parent&state=whatever');
            const before = idp.tokenHits;

            renderProvider({ restore: 'silent' });
            await settled();

            expect(idp.tokenHits).toBe(before);
            expect(screen.getByTestId('error').textContent).toBe('none');
        } finally {
            if (parent) Object.defineProperty(window, 'parent', parent);
        }
    });
});

describe('useAuth', () => {
    it('exposes the profile extensions under its name, and the client', async () => {
        const Extensions = () => {
            const auth = useAuth<typeof cookieProfile>();
            return <div data-testid="ping">{auth.isLoading ? 'loading' : `${auth.cookie.ping()} ${auth.client.profileName}`}</div>;
        };

        renderProvider({ profile: cookieProfile }, <Extensions />);

        await waitFor(() => expect(screen.getByTestId('ping').textContent).toBe('pong cookie'));
    });

    it('throws outside a provider', () => {
        const consoleError = vi.spyOn(console, 'error').mockImplementation(() => { });

        expect(() => render(<Probe />)).toThrow(/must be used within an AuthProvider/);

        consoleError.mockRestore();
    });
});

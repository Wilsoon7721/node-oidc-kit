import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMachineClient, isMachineToken, MachineTokenError } from '../src/index';

const ISSUER = 'https://id.wilsoon.dev';
const TOKEN_URL = `${ISSUER}/api/token`;

interface Call {
    url: string;
    init: RequestInit;
}

/** A scripted `fetch`: records every call, and answers the token endpoint from a queue. */
function fakeFetch(script: Array<{ status?: number; body: unknown }>) {
    const calls: Call[] = [];
    let cursor = 0;

    const impl = vi.fn(async (url: string, init: RequestInit = {}) => {
        calls.push({ url, init });
        const scripted = script[Math.min(cursor, script.length - 1)];
        cursor += 1;

        return {
            ok: (scripted.status ?? 200) < 400,
            status: scripted.status ?? 200,
            json: async () => scripted.body,
        } as Response;
    });

    return {
        impl: impl as unknown as (url: string, init?: RequestInit) => Promise<Response>,
        calls,
        get tokenCalls() { return calls.filter(c => c.url === TOKEN_URL); },
    };
}

const token = (access_token: string, expires_in = 900) => ({ body: { access_token, token_type: 'Bearer', expires_in } });

const client = (fetchImpl: (url: string, init?: RequestInit) => Promise<Response>, overrides = {}) =>
    createMachineClient({
        issuer: ISSUER,
        clientId: 'svc-reporting',
        clientSecret: 'shh',
        fetch: fetchImpl,
        ...overrides,
    });

/** Lets queued microtasks (a background renewal) run before assertions. */
const flush = () => new Promise<void>(resolve => setImmediate(resolve));

/** Moves the clock forward. Only `Date` is faked, so `setImmediate` stays real and `flush` still works. */
const advance = (ms: number) => vi.setSystemTime(new Date(Date.now() + ms));

beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-08-31T00:00:00Z'));
});

afterEach(() => {
    vi.useRealTimers();
});

describe('construction', () => {
    it('refuses to run in a browser, where the secret would be readable', () => {
        (globalThis as unknown as { window?: unknown }).window = {};
        try {
            expect(() => client(fakeFetch([token('t')]).impl)).toThrow(/server-only/);
        } finally {
            delete (globalThis as unknown as { window?: unknown }).window;
        }
    });

    it('requires every credential up front rather than failing at the first request', () => {
        const { impl } = fakeFetch([token('t')]);

        expect(() => createMachineClient({ issuer: '', clientId: 'a', clientSecret: 'b', fetch: impl })).toThrow(/requires/);
        expect(() => createMachineClient({ issuer: ISSUER, clientId: '', clientSecret: 'b', fetch: impl })).toThrow(/requires/);
        expect(() => createMachineClient({ issuer: ISSUER, clientId: 'a', clientSecret: '', fetch: impl })).toThrow(/requires/);
    });
});

describe('the request itself', () => {
    it('authenticates with Basic and sends no scope', async () => {
        const fetch = fakeFetch([token('t')]);

        await client(fetch.impl).getToken();

        const { init } = fetch.tokenCalls[0];
        const headers = init.headers as Record<string, string>;
        expect(headers.Authorization).toBe(`Basic ${Buffer.from('svc-reporting:shh').toString('base64')}`);
        expect(init.body).toBe('grant_type=client_credentials');
        expect(String(init.body)).not.toContain('scope');
    });

    it('URI-encodes both halves, so a secret containing + or % survives', async () => {
        const fetch = fakeFetch([token('t')]);

        await client(fetch.impl, { clientSecret: 'a+b%c' }).getToken();

        const headers = fetch.tokenCalls[0].init.headers as Record<string, string>;
        const decoded = Buffer.from(headers.Authorization.replace('Basic ', ''), 'base64').toString('utf8');
        expect(decoded).toBe('svc-reporting:a%2Bb%25c');
        expect(decodeURIComponent(decoded.split(':')[1])).toBe('a+b%c');
    });

    it('posts to <issuer>/api/token, and honours an override', async () => {
        const fetch = fakeFetch([token('t')]);
        await client(fetch.impl).getToken();
        expect(fetch.calls[0].url).toBe(TOKEN_URL);

        const other = fakeFetch([token('t')]);
        await client(other.impl, { tokenEndpoint: 'https://id.example.com/oauth/token' }).getToken();
        expect(other.calls[0].url).toBe('https://id.example.com/oauth/token');
    });
});

describe('caching and single-flight', () => {
    it('collapses 50 concurrent cold callers onto one token request', async () => {
        const fetch = fakeFetch([token('t-1')]);
        const machine = client(fetch.impl);

        const results = await Promise.all(Array.from({ length: 50 }, () => machine.getToken()));

        expect(fetch.tokenCalls).toHaveLength(1);
        expect(new Set(results)).toEqual(new Set(['t-1']));
    });

    it('serves a warm cache without touching the network', async () => {
        const fetch = fakeFetch([token('t-1')]);
        const machine = client(fetch.impl);

        await machine.getToken();
        await machine.getToken();
        await machine.getToken();

        expect(fetch.tokenCalls).toHaveLength(1);
    });

    it('serves the still-valid token during refresh-ahead instead of blocking on the renewal', async () => {
        const fetch = fakeFetch([token('t-1', 900), token('t-2', 900)]);
        const machine = client(fetch.impl);

        expect(await machine.getToken()).toBe('t-1');

        // Past 75% of the lifetime, but the token is still good for another ~200s.
        advance(700_000);
        expect(await machine.getToken()).toBe('t-1');

        await flush();
        expect(fetch.tokenCalls).toHaveLength(2);
        expect(await machine.getToken()).toBe('t-2');
    });

    it('renews only once even if several callers arrive inside the refresh-ahead window', async () => {
        const fetch = fakeFetch([token('t-1', 900), token('t-2', 900)]);
        const machine = client(fetch.impl);

        await machine.getToken();
        advance(700_000);
        await Promise.all([machine.getToken(), machine.getToken(), machine.getToken()]);
        await flush();

        expect(fetch.tokenCalls).toHaveLength(2);
    });

    it('makes the caller wait when the cache is fully expired', async () => {
        const fetch = fakeFetch([token('t-1', 900), token('t-2', 900)]);
        const machine = client(fetch.impl);

        await machine.getToken();
        advance(900_000);

        expect(await machine.getToken()).toBe('t-2');
        expect(fetch.tokenCalls).toHaveLength(2);
    });

    it('treats the skew window as already expired', async () => {
        const fetch = fakeFetch([token('t-1', 900), token('t-2', 900)]);
        const machine = client(fetch.impl, { skewSeconds: 120, refreshAt: 0.99 });

        await machine.getToken();
        // 800s in: inside the raw lifetime, but past 900 - 120 once skew is counted.
        advance(800_000);

        expect(await machine.getToken()).toBe('t-2');
    });

    it('drops the cache on reset(), as after a secret rotation', async () => {
        const fetch = fakeFetch([token('t-1'), token('t-2')]);
        const machine = client(fetch.impl);

        await machine.getToken();
        machine.reset();

        expect(await machine.getToken()).toBe('t-2');
        expect(fetch.tokenCalls).toHaveLength(2);
    });

    it('obtains a new token on force, without joining the request in flight', async () => {
        const fetch = fakeFetch([token('t-1'), token('t-2')]);
        const machine = client(fetch.impl);

        await machine.getToken();
        expect(await machine.getToken({ force: true })).toBe('t-2');
        expect(fetch.tokenCalls).toHaveLength(2);
    });
});

describe('failures', () => {
    it('surfaces a permanent misconfiguration with its code, rather than backing off', async () => {
        const fetch = fakeFetch([{ status: 401, body: { error: 'invalid_client', error_description: 'Invalid client credentials.' } }]);

        await client(fetch.impl).getToken().catch((error: MachineTokenError) => {
            expect(error).toBeInstanceOf(MachineTokenError);
            expect(error.code).toBe('invalid_client');
            expect(error.status).toBe(401);
            expect(error.permanent).toBe(true);
        });
        expect.assertions(4);
    });

    it('marks a transient failure as not permanent', async () => {
        const fetch = fakeFetch([{ status: 503, body: { error: 'server_error' } }]);

        await client(fetch.impl).getToken().catch((error: MachineTokenError) => {
            expect(error.permanent).toBe(false);
        });
        expect.assertions(1);
    });

    it('does not wedge the single-flight guard on a rejected request', async () => {
        const fetch = fakeFetch([
            { status: 503, body: { error: 'server_error' } },
            token('t-1'),
        ]);
        const machine = client(fetch.impl);

        await expect(machine.getToken()).rejects.toThrow(MachineTokenError);

        // The failure cleared the guard, so this is a fresh attempt rather than the old rejection.
        expect(await machine.getToken()).toBe('t-1');
    });

    it('rejects a 200 that carries no access token', async () => {
        const fetch = fakeFetch([{ body: { token_type: 'Bearer' } }]);

        await expect(client(fetch.impl).getToken()).rejects.toThrow(/no access token/);
    });
});

describe('fetch()', () => {
    it('attaches the token and preserves the caller headers', async () => {
        const fetch = fakeFetch([token('t-1'), { body: { ok: true } }]);
        const machine = client(fetch.impl);

        await machine.fetch('https://api.wilsoon.dev/reports', { method: 'POST', headers: { 'X-Trace': 'abc' } });

        const call = fetch.calls[1];
        const headers = call.init.headers as Record<string, string>;
        expect(headers.Authorization).toBe('Bearer t-1');
        expect(headers['X-Trace']).toBe('abc');
        expect(call.init.method).toBe('POST');
    });

    it('recovers a 401 with exactly one forced refresh and one retry', async () => {
        const fetch = fakeFetch([
            token('t-1'),
            { status: 401, body: {} },
            token('t-2'),
            { body: { ok: true } },
        ]);
        const machine = client(fetch.impl);

        const response = await machine.fetch('https://api.wilsoon.dev/reports');

        expect(response.status).toBe(200);
        expect(fetch.tokenCalls).toHaveLength(2);
        // token, 401, token, retry - four calls total, and no loop past that.
        expect(fetch.calls).toHaveLength(4);
    });

    it('returns a second 401 rather than retrying forever', async () => {
        const fetch = fakeFetch([
            token('t-1'),
            { status: 401, body: {} },
            token('t-2'),
            { status: 401, body: {} },
        ]);
        const machine = client(fetch.impl);

        const response = await machine.fetch('https://api.wilsoon.dev/reports');

        expect(response.status).toBe(401);
        expect(fetch.calls).toHaveLength(4);
    });

    it('does not retry a non-401 failure', async () => {
        const fetch = fakeFetch([token('t-1'), { status: 500, body: {} }]);
        const machine = client(fetch.impl);

        const response = await machine.fetch('https://api.wilsoon.dev/reports');

        expect(response.status).toBe(500);
        expect(fetch.calls).toHaveLength(2);
    });
});

describe('isMachineToken', () => {
    it('reads token_use, and treats everything else as a user', () => {
        expect(isMachineToken({ token_use: 'client' })).toBe(true);
        expect(isMachineToken({ token_use: 'user' })).toBe(false);
        expect(isMachineToken({})).toBe(false);
        expect(isMachineToken(null)).toBe(false);
        expect(isMachineToken(undefined)).toBe(false);
    });
});

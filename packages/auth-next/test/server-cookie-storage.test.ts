import { describe, expect, it, vi } from 'vitest';
import { STORAGE_KEYS, StorageUnavailableError } from '@wilsoon/auth-core';
import { ServerCookieStorage } from '../src/storage/ServerCookieStorage';

const writableStore = () => {
    const cookies = new Map<string, any>();
    return {
        cookies,
        set: vi.fn((options: any) => cookies.set(options.name, options)),
        get: vi.fn((name: string) => cookies.get(name)),
        delete: vi.fn((name: string) => cookies.delete(name)),
    };
};

const readOnlyStore = () => ({
    get: vi.fn(() => undefined),
    set: vi.fn(() => { throw new Error('Cookies can only be modified in a Server Action or Route Handler.'); }),
    delete: vi.fn(() => { throw new Error('Cookies can only be modified in a Server Action or Route Handler.'); }),
});

describe('ServerCookieStorage', () => {
    it('hardens the cookies it writes', () => {
        const store = writableStore();
        new ServerCookieStorage(store, { domain: '.example.com' }).setItem(STORAGE_KEYS.state, 'abc');

        expect(store.set).toHaveBeenCalledWith(expect.objectContaining({
            name: STORAGE_KEYS.state,
            value: 'abc',
            httpOnly: true,
            sameSite: 'lax',
            path: '/',
            domain: '.example.com',
        }));
    });

    it('gives transient login state a short lifetime and tokens a long one', () => {
        const store = writableStore();
        const storage = new ServerCookieStorage(store);

        for (const key of [STORAGE_KEYS.state, STORAGE_KEYS.nonce, STORAGE_KEYS.codeVerifier]) {
            storage.setItem(key, 'x');
            expect(store.cookies.get(key).maxAge).toBe(600);
        }

        storage.setItem(STORAGE_KEYS.tokens, 'y');
        expect(store.cookies.get(STORAGE_KEYS.tokens).maxAge).toBe(31536000);
    });

    it('allows the flags to be overridden', () => {
        const store = writableStore();
        new ServerCookieStorage(store, { secure: false, sameSite: 'strict', path: '/app', transientMaxAgeSeconds: 120 })
            .setItem(STORAGE_KEYS.nonce, 'n');

        expect(store.cookies.get(STORAGE_KEYS.nonce)).toMatchObject({ secure: false, sameSite: 'strict', path: '/app', maxAge: 120 });
    });

    it('reads and deletes', () => {
        const store = writableStore();
        const storage = new ServerCookieStorage(store);

        storage.setItem(STORAGE_KEYS.state, 'abc');
        expect(storage.getItem(STORAGE_KEYS.state)).toBe('abc');

        storage.removeItem(STORAGE_KEYS.state);
        expect(storage.getItem(STORAGE_KEYS.state)).toBeNull();
        expect(storage.getItem('never-set')).toBeNull();
    });

    it('explains where to move the call when the context is read-only', () => {
        const storage = new ServerCookieStorage(readOnlyStore());

        expect(() => storage.setItem(STORAGE_KEYS.state, 'abc')).toThrow(StorageUnavailableError);
        expect(() => storage.setItem(STORAGE_KEYS.state, 'abc')).toThrow(/Route Handler, Server Action or middleware/);
        expect(() => storage.removeItem(STORAGE_KEYS.state)).toThrow(StorageUnavailableError);
    });

    it('tolerates a missing cookie store on reads', () => {
        expect(new ServerCookieStorage(undefined).getItem('anything')).toBeNull();
    });
});

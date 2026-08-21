import { StorageUnavailableError } from './errors';

/**
 * The SDK's only persistence dependency: three synchronous string operations.
 *
 * Everything the SDK persists - the token response, plus the single-use `state`, `nonce`
 * and PKCE verifier - is read and written through this interface under the
 * `STORAGE_KEYS` names. Supporting a new framework therefore means writing one adapter,
 * not touching `AuthClient`. Implementations ship for the browser
 * ({@link BrowserStorage}), for tests and single-process flows ({@link MemoryStorage}),
 * and for the Next.js cookie store (`ServerCookieStorage` in `@wilsoon/auth-next`).
 *
 * The contract an implementation must honour:
 *
 * - **Synchronous.** `AuthClient` calls these inline, so an async store (Redis, a
 *   database) has to be loaded into memory first - see {@link MemoryStorage}.
 * - **Round-trips values unchanged.** Token blobs are JSON; a store that encodes on write
 *   must decode on read.
 * - **A missing key returns `null`,** never `undefined`, and never throws.
 * - **A write that cannot happen should throw** rather than silently no-op, unless the
 *   no-op is deliberate (as in the Next.js middleware, where the response owns writes).
 *
 * A cookie-backed adapter should also set `HttpOnly`, `Secure` and `SameSite=Lax`. `Lax`
 * is specifically what lets the `state`/`nonce`/verifier cookies survive the redirect back
 * from the identity provider; `Strict` drops them and every login fails on state mismatch.
 */
export interface AuthStorage {
    /** Returns the stored value, or `null` when the key is absent. */
    getItem(key: string): string | null;

    /** Persists `value` under `key`, overwriting any existing value. */
    setItem(key: string, value: string): void;

    /** Removes `key`. Absent keys are not an error. */
    removeItem(key: string): void;
}

/**
 * Web Storage API adapter, defaulting to `localStorage`.
 *
 * Pass `window.sessionStorage` for the transient login values - `state`, `nonce` and the
 * PKCE verifier are single-use and scoped to one login attempt in one tab, so
 * `sessionStorage` expires them for free when the tab closes. This is what
 * `@wilsoon/auth-react`'s `AuthProvider` does.
 *
 * Anything kept here is readable by any script on the page, so it is not a safe home for
 * tokens on a site that renders untrusted content.
 */
export class BrowserStorage implements AuthStorage {
    constructor(private storage: Storage = window.localStorage) { }

    getItem(key: string): string | null {
        return this.storage.getItem(key);
    }

    setItem(key: string, value: string): void {
        this.storage.setItem(key, value);
    }

    removeItem(key: string): void {
        this.storage.removeItem(key);
    }
}

/**
 * An in-process storage implementation.
 *
 * Useful for tests and for single-request server flows where the authorize call and the
 * callback are handled by the same client instance. It does **not** survive a process
 * restart and is not shared between instances or server processes, so it cannot carry
 * `state`/PKCE across a redirect in a multi-instance deployment - use a cookie-backed
 * store for that.
 */
export class MemoryStorage implements AuthStorage {
    private store = new Map<string, string>();

    getItem(key: string): string | null {
        const value = this.store.get(key);
        return value === undefined ? null : value;
    }

    setItem(key: string, value: string): void {
        this.store.set(key, value);
    }

    removeItem(key: string): void {
        this.store.delete(key);
    }
}

/**
 * The storage used when no implementation was supplied and none can be inferred (i.e. on
 * the server with no `window`).
 *
 * Every operation throws {@link StorageUnavailableError} naming the operation and the fix.
 * The previous behaviour - `{} as AuthStorage` - type-checked as valid storage and then
 * failed with `TypeError: this.storage.setItem is not a function` far from the mistake.
 *
 * @internal
 */
export class UnavailableStorage implements AuthStorage {
    getItem(key: string): string | null {
        throw new StorageUnavailableError(`Reading "${key}" from storage`);
    }

    setItem(key: string): void {
        throw new StorageUnavailableError(`Writing "${key}" to storage`);
    }

    removeItem(key: string): void {
        throw new StorageUnavailableError(`Removing "${key}" from storage`);
    }
}

/** Whether reads and writes against this storage will actually be attempted. */
export function isUsableStorage(storage: AuthStorage | undefined | null): boolean {
    return !!storage
        && !(storage instanceof UnavailableStorage)
        && typeof storage.getItem === 'function'
        && typeof storage.setItem === 'function'
        && typeof storage.removeItem === 'function';
}

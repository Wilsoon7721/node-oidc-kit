import { StorageUnavailableError } from './errors';

/**
 * Defines the contract for storage implementations used by the Auth SDK.
 * This abstraction allows for different persistence strategies (e.g., localStorage, sessionStorage, or custom memory storage).
 */
export interface AuthStorage {
    /**
     * Retrieves a value from storage by its key.
     * @param key The unique identifier for the stored item.
     * @returns The string value if found, or null if the key does not exist.
     */
    getItem(key: string): string | null;

    /**
     * Persists a value in storage under the specified key.
     * @param key The unique identifier for the item.
     * @param value The string value to store.
     */
    setItem(key: string, value: string): void;

    /**
     * Removes an item from storage by its key.
     * @param key The unique identifier for the item to remove.
     */
    removeItem(key: string): void;
}

/**
 * A standard browser-based storage implementation using the Web Storage API.
 * Defaults to localStorage but can be configured to use sessionStorage.
 */
export class BrowserStorage implements AuthStorage {
    /**
     * Initializes a new instance of BrowserStorage.
     * @param storage The browser Storage object to use (defaults to window.localStorage).
     */
    constructor(private storage: Storage = window.localStorage) { }

    /**
     * Retrieves a value from the underlying browser storage.
     * @param key The key to look up.
     * @returns The value associated with the key, or null.
     */
    getItem(key: string): string | null {
        return this.storage.getItem(key);
    }

    /**
     * Saves a value to the underlying browser storage.
     * @param key The key to save under.
     * @param value The value to save.
     */
    setItem(key: string, value: string): void {
        this.storage.setItem(key, value);
    }

    /**
     * Removes a value from the underlying browser storage.
     * @param key The key to remove.
     */
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

    /**
     * Retrieves a value from the in-memory map.
     * @param key The key to look up.
     * @returns The value associated with the key, or null.
     */
    getItem(key: string): string | null {
        const value = this.store.get(key);
        return value === undefined ? null : value;
    }

    /**
     * Saves a value in the in-memory map.
     * @param key The key to save under.
     * @param value The value to save.
     */
    setItem(key: string, value: string): void {
        this.store.set(key, value);
    }

    /**
     * Removes a value from the in-memory map.
     * @param key The key to remove.
     */
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
    /** @throws {StorageUnavailableError} Always. */
    getItem(key: string): string | null {
        throw new StorageUnavailableError(`Reading "${key}" from storage`);
    }

    /** @throws {StorageUnavailableError} Always. */
    setItem(key: string): void {
        throw new StorageUnavailableError(`Writing "${key}" to storage`);
    }

    /** @throws {StorageUnavailableError} Always. */
    removeItem(key: string): void {
        throw new StorageUnavailableError(`Removing "${key}" from storage`);
    }
}

/**
 * Reports whether a storage implementation can actually be used.
 * @param storage The storage instance to check.
 * @returns True when reads and writes will be attempted for real.
 */
export function isUsableStorage(storage: AuthStorage | undefined | null): boolean {
    return !!storage
        && !(storage instanceof UnavailableStorage)
        && typeof storage.getItem === 'function'
        && typeof storage.setItem === 'function'
        && typeof storage.removeItem === 'function';
}

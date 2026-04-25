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
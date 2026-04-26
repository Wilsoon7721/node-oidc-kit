import { AuthStorage } from '@wilsoon/auth-core';

/**
 * Implementation of AuthStorage for Next.js Server Components.
 * Note: setItem and removeItem are not supported in Server Components.
 */
export class ServerCookieStorage implements AuthStorage {
    constructor(private cookieStore: any) { }

    /**
     * Gets a cookie value by key from the Next.js cookie store.
     * @param key The cookie name.
     * @returns The cookie value or null.
     */
    getItem(key: string): string | null {
        return this.cookieStore.get(key)?.value || null;
    }

    setItem(): void { throw new Error("Cannot set cookies in Server Components."); }
    removeItem(): void { throw new Error("Cannot remove cookies in Server Components."); }
}
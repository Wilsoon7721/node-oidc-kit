import { AuthStorage } from '../storage';

/**
 * Implementation of AuthStorage using browser cookies.
 */
export class CookieStorage implements AuthStorage {
    constructor(private domain?: string) { }

    /**
     * Gets a cookie value by key.
     * @param key The cookie name.
     * @returns The cookie value or null if not found or if running on server.
     */
    getItem(key: string): string | null {
        if (typeof window === 'undefined') return null;
        const name = key + "=";
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i].trim();
            if (c.indexOf(name) === 0) return c.substring(name.length, c.length);
        }
        return null;
    }

    /**
     * Sets a cookie with a 1-year expiration.
     * @param key The cookie name.
     * @param value The cookie value.
     */
    setItem(key: string, value: string): void {
        if (typeof window === 'undefined') return;

        let cookieString = `${key}=${value}; path=/; max-age=31536000; SameSite=Lax; Secure`;

        if (this.domain)
            cookieString += `; domain=${this.domain}`;

        document.cookie = cookieString;
    }

    /**
     * Removes a cookie by setting its expiration to the past.
     * @param key The cookie name.
     */
    removeItem(key: string): void {
        if (typeof window === 'undefined') return;
        let cookieString = `${key}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        if (this.domain) cookieString += `; domain=${this.domain}`;
        document.cookie = cookieString;
    }
}
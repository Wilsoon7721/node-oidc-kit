import { AuthStorage } from '../storage';

export class CookieStorage implements AuthStorage {
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

    setItem(key: string, value: string): void {
        if (typeof window === 'undefined') return;
        document.cookie = `${key}=${value}; path=/; max-age=31536000; SameSite=Lax; Secure`;
    }

    removeItem(key: string): void {
        if (typeof window === 'undefined') return;
        document.cookie = `${key}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
    }
}
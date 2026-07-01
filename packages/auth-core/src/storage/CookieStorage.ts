import { AuthStorage } from '../storage';

/**
 * @deprecated Since v1.2.0 — CookieStorage is deprecated.
 *
 * The `wilsoon_id_tokens` cookie is now set as `HttpOnly` by the server,
 * making it invisible to `document.cookie`. All client-side read/write/remove
 * operations are no-ops.
 *
 * **Migration**: Use `AuthClient.hydrateSession()` to load authentication state
 * on page load. The server reads the HttpOnly cookie automatically when
 * `credentials: 'include'` is set on fetch requests.
 *
 * For non-HttpOnly use cases (e.g., localStorage), use `BrowserStorage` instead.
 */
export class CookieStorage implements AuthStorage {
    private static _deprecationWarned = false;

    constructor(private domain?: string) {
        if (!CookieStorage._deprecationWarned) {
            console.warn(
                '[WilsoonID] CookieStorage is deprecated. ' +
                'The auth cookie is now HttpOnly and managed server-side. ' +
                'Use AuthClient.hydrateSession() to load session state on page load.'
            );
            CookieStorage._deprecationWarned = true;
        }
    }

    /**
     * @deprecated No-op. HttpOnly cookies cannot be read via `document.cookie`.
     * Use `AuthClient.hydrateSession()` instead.
     * @param _key The cookie name (unused).
     * @returns Always returns null.
     */
    getItem(_key: string): string | null {
        return null;
    }

    /**
     * @deprecated No-op. The auth cookie is set server-side by `/api/token` with the HttpOnly flag.
     * @param _key The cookie name (unused).
     * @param _value The cookie value (unused).
     */
    setItem(_key: string, _value: string): void {
        // No-op: cookie is set server-side by /api/token with HttpOnly flag.
    }

    /**
     * @deprecated No-op. The auth cookie is cleared server-side during logout via `/api/logout`.
     * @param _key The cookie name (unused).
     */
    removeItem(_key: string): void {
        // No-op: cookie is cleared server-side during logout.
    }
}
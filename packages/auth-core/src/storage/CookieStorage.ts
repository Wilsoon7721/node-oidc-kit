import { AuthStorage } from '../storage';

/**
 * @deprecated Since v1.2.0. Every method is a no-op; the class is kept only so existing
 * `new CookieStorage()` calls keep compiling.
 *
 * It was written when the token cookie was readable from `document.cookie`. The provider
 * now sets that cookie `HttpOnly`, which is the correct thing for it to do and also means
 * no browser-side cookie adapter can ever see it again.
 *
 * **Instead:** call `AuthClient.hydrateSession()` on page load - the browser attaches the
 * HttpOnly cookie itself on a `credentials: 'include'` request, so the provider can answer
 * from it. Use {@link BrowserStorage} when you genuinely want JS-visible client storage,
 * and a server-side cookie adapter (`ServerCookieStorage`, or your own - see
 * {@link AuthStorage}) when you want to own the cookie yourself.
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

    /** @deprecated Always `null`: an HttpOnly cookie is not visible to `document.cookie`. */
    getItem(_key: string): string | null {
        return null;
    }

    /** @deprecated No-op: the provider sets the token cookie at its token endpoint. */
    setItem(_key: string, _value: string): void { }

    /** @deprecated No-op: the provider clears the token cookie at its logout endpoint. */
    removeItem(_key: string): void { }
}
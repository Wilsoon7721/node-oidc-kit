import { AuthStorage, STORAGE_KEYS, StorageUnavailableError } from '@wilsoon/auth-core';

/** Cookie attributes used when this storage writes. */
export interface ServerCookieStorageOptions {
    /** Cookie domain. Set a leading-dot domain (`.example.com`) to share the session across subdomains. */
    domain?: string;
    /** Marks cookies `Secure`. Defaults to true outside `NODE_ENV=development`. */
    secure?: boolean;
    /** `SameSite` attribute (default `lax`, which survives the OIDC redirect). */
    sameSite?: 'lax' | 'strict' | 'none';
    /** Cookie path (default `/`). */
    path?: string;
    /** Lifetime of the short-lived `state`/`nonce`/PKCE cookies (default 600s). */
    transientMaxAgeSeconds?: number;
    /** Lifetime of the token cookie (default 1 year, matching the identity provider). */
    tokenMaxAgeSeconds?: number;
}

const TRANSIENT_KEYS: string[] = [STORAGE_KEYS.state, STORAGE_KEYS.nonce, STORAGE_KEYS.codeVerifier];

/**
 * An {@link AuthStorage} backed by the Next.js cookie store.
 *
 * Reads work anywhere `cookies()` is available. Writes work in Route Handlers, Server
 * Actions and middleware - the contexts where Next.js permits setting cookies - and throw
 * a {@link StorageUnavailableError} naming the fix in a Server Component, where they
 * cannot.
 *
 * Writes are always `HttpOnly` with `SameSite=Lax`, so the `state`, `nonce` and PKCE
 * verifier are unreadable from JavaScript and still survive the redirect back from the
 * identity provider. The two lifetimes differ deliberately: those three values are
 * single-use and expire in minutes, the token blob lives as long as the session.
 */
export class ServerCookieStorage implements AuthStorage {
    constructor(private cookieStore: any, private options: ServerCookieStorageOptions = {}) { }

    getItem(key: string): string | null {
        return this.cookieStore?.get(key)?.value ?? null;
    }

    /** @throws {StorageUnavailableError} If this context cannot set cookies. */
    setItem(key: string, value: string): void {
        const isTransient = TRANSIENT_KEYS.includes(key);

        try {
            this.cookieStore.set({
                name: key,
                value,
                httpOnly: true,
                secure: this.options.secure ?? process.env.NODE_ENV !== 'development',
                sameSite: this.options.sameSite ?? 'lax',
                path: this.options.path ?? '/',
                domain: this.options.domain,
                maxAge: isTransient
                    ? this.options.transientMaxAgeSeconds ?? 600
                    : this.options.tokenMaxAgeSeconds ?? 60 * 60 * 24 * 365,
            });
        } catch (error) {
            throw new StorageUnavailableError(
                `Writing the "${key}" cookie (Server Components cannot set cookies - do this in a Route Handler, Server Action or middleware)`
            );
        }
    }

    /** @throws {StorageUnavailableError} If this context cannot modify cookies. */
    removeItem(key: string): void {
        try {
            this.cookieStore.delete(key);
        } catch (error) {
            throw new StorageUnavailableError(
                `Deleting the "${key}" cookie (Server Components cannot modify cookies - do this in a Route Handler, Server Action or middleware)`
            );
        }
    }
}

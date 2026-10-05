import { StorageUnavailableError } from "./errors";

/**
 * The library's only persistence dependency: three synchronous string operations.
 *
 * Everything the library persists - the token response, plus the single-use `state`, `nonce` and PKCE verifier - is read and written through this interface under the `STORAGE_KEYS` names.
 * The contract an implementation must honour:
 * - **Synchronous.** `AuthClient` calls these inline, so an async store (Redis, a
 *   database) has to be loaded into memory first - see {@link MemoryStorage}.
 * - **Round-trips values unchanged.** Token blobs are JSON; a store that encodes on write must decode on read.
 * - **A missing key returns `null`,** never `undefined`, and never throws.
 * - **A write that cannot happen should throw** rather than silently no-op, unless the no-op is deliberate (as in the Next.js middleware, where the response owns writes).
 *
 * A cookie-backed adapter should also set `HttpOnly`, `Secure` and `SameSite=Lax`.
 * `Lax` lets the `state`/`nonce`/verifier cookies survive the redirect back from the identity provider, while `Strict` drops them and every login fails on state mismatch.
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
 * Pass `window.sessionStorage` for the transient login values - `state`, `nonce` and the PKCE verifier are single-use and scoped to one login attempt in one tab.
 * `sessionStorage` expires them for free when the tab closes. This is what `@wilsoon/auth-react`'s `AuthProvider` does.
 *
 * Anything kept here is readable by any script on the page, so it is not a safe home for tokens on a site that renders untrusted content.
 */
export class BrowserStorage implements AuthStorage {
  constructor(private storage: Storage = window.localStorage) {}

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
 * Useful for tests and for single-request server flows where the authorize call and the callback are handled by the same client instance.
 * Doesn't survive restarts.
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
 * The storage used when no implementation was supplied and none can be inferred (e.g. on the server with no `window`).
 * Every operation throws {@link StorageUnavailableError} naming the operation and the fix.
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
  return !!storage && !(storage instanceof UnavailableStorage) && typeof storage.getItem === "function" && typeof storage.setItem === "function" && typeof storage.removeItem === "function";
}

/** The names the library reads and writes through {@link AuthStorage}. */
export interface StorageKeys {
  /** The persisted token response. Long-lived. */
  tokens: string;
  /** The pending authorization request's CSRF state. Single-use. */
  state: string;
  /** The pending authorization request's ID token nonce. Single-use. */
  nonce: string;
  /** The pending authorization request's PKCE code verifier. Single-use. */
  codeVerifier: string;
}

/** The storage prefix to use without any config or profile overriding. */
export const DEFAULT_STORAGE_PREFIX = "oidc_";

/** Builds the four storage names from a prefix: `<prefix>tokens`, `<prefix>state`, `<prefix>nonce` and `<prefix>verifier`. */
export function storageKeysFor(prefix: string = DEFAULT_STORAGE_PREFIX): StorageKeys {
  return { tokens: `${prefix}tokens`, state: `${prefix}state`, nonce: `${prefix}nonce`, codeVerifier: `${prefix}verifier` };
}

/** The storage names a client uses by default (`oidc_tokens`, `oidc_state`, `oidc_nonce`, `oidc_verifier`). */
export const DEFAULT_STORAGE_KEYS: Readonly<StorageKeys> = Object.freeze(storageKeysFor());

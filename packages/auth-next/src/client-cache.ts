import { AuthClient, AuthConfig } from '@wilsoon/auth-core';

/** Bounded so a caller that builds a varying config per request cannot grow this forever. */
const MAX_CACHED_CLIENTS = 100;

const clients = new Map<string, AuthClient>();

/** FNV-1a. Not cryptographic - it only has to distinguish configurations. */
const fingerprint = (value: string): string => {
    let hash = 0x811c9dc5;
    for (let i = 0; i < value.length; i++) {
        hash ^= value.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193);
    }
    return (hash >>> 0).toString(36);
};

/** Functions and profiles cannot be serialised, so each distinct object gets a stable id instead. */
const identities = new WeakMap<object, number>();
let nextIdentity = 1;
const identityOf = (value: unknown): string | number => {
    if ((typeof value !== 'object' && typeof value !== 'function') || value === null) return typeof value === 'string' ? value : '';
    let id = identities.get(value);
    if (id === undefined) {
        id = nextIdentity++;
        identities.set(value, id);
    }
    return `#${id}`;
};

/**
 * Returns a client for this configuration, reused across requests.
 *
 * Verification fetches the provider's JWKS and caches the keys *inside* the client, so a fresh client per request would refetch the key set on every render.
 * The key covers every field that changes behaviour, including a fingerprint of the client secret and the identity of the profile and claim selectors; `resolveSessionVersion` is excluded because it never affects verification.
 *
 * @param config The application's authentication configuration.
 * @returns A client for that exact configuration, with the profile's extensions attached.
 */
export function getCachedClient(config: AuthConfig): AuthClient {
    const key = fingerprint(JSON.stringify([
        config.issuer,
        config.clientId,
        config.clientSecret ?? '',
        config.expectedIssuer ?? '',
        config.apiAudience ?? '',
        config.redirectUri ?? '',
        config.scope?.join(' ') ?? '',
        config.clockToleranceSeconds ?? '',
        config.platformSessionCacheSeconds ?? '',
        config.jwks ?? '',
        config.storagePrefix ?? '',
        identityOf(config.profile),
        identityOf(config.rolesClaim),
        identityOf(config.permissionsClaim),
        identityOf(config.detectMachineToken),
    ]));

    const existing = clients.get(key);
    if (existing) return existing;

    if (clients.size >= MAX_CACHED_CLIENTS) {
        const oldest = clients.keys().next();
        if (!oldest.done) clients.delete(oldest.value);
    }

    const client = new AuthClient(config);
    clients.set(key, client);
    return client;
}

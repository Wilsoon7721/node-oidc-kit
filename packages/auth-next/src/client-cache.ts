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

/**
 * Returns a client for this configuration, reused across requests.
 *
 * Verification fetches the provider's JWKS and caches the keys *inside* the client, so a fresh
 * client per request would refetch the key set on every render. Platform-session results are
 * cached in there too.
 *
 * The key covers every field that changes behaviour, **including a fingerprint of the client
 * secret**: keying on a subset means two configurations that differ only in an uncovered field
 * silently share a client, and the second caller gets one configured for someone else.
 * `resolveSessionVersion` is excluded because a function cannot be fingerprinted; it affects
 * only `isSessionCurrent`, never verification.
 *
 * @param config The application's authentication configuration.
 * @returns A client for that exact configuration.
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

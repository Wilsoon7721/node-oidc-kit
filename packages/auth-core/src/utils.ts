import { CryptoUnavailableError } from './errors';

const toHex = (buf: Uint8Array) => Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');

const toBinaryString = (buf: Uint8Array) => {
    // Chunked rather than `String.fromCharCode(...buf)`: spreading a large buffer into
    // arguments overflows the call stack.
    let binary = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < buf.length; i += CHUNK) {
        binary += String.fromCharCode.apply(null, Array.from(buf.subarray(i, i + CHUNK)));
    }
    return binary;
};

const toBase64Url = (buf: Uint8Array) => {
    const binary = toBinaryString(buf);
    const base64 = typeof btoa === 'function'
        ? btoa(binary)
        : Buffer.from(binary, 'binary').toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

/**
 * Returns the runtime's Web Crypto implementation.
 *
 * Node.js 18+, browsers and edge runtimes all expose `globalThis.crypto`. There is
 * deliberately no `require('crypto')` fallback: `require` does not exist in ESM or on
 * Workers, so the "fallback" threw a confusing `ReferenceError` instead of degrading.
 * @throws {CryptoUnavailableError} If the runtime has no Web Crypto API.
 */
export function getWebCrypto(): Crypto {
    const webCrypto = globalThis.crypto;
    if (!webCrypto || typeof webCrypto.getRandomValues !== 'function') throw new CryptoUnavailableError();
    return webCrypto;
}

/**
 * Generates a high-entropy random string for security purposes.
 * Uses the Web Crypto API to ensure cryptographic strength.
 * @param length The desired length of the returned hex string.
 * @returns A cryptographically secure random string.
 * @throws {CryptoUnavailableError} If the runtime has no Web Crypto API.
 */
export function generateRandomString(length: number): string {
    const array = new Uint8Array(Math.ceil(length / 2));
    getWebCrypto().getRandomValues(array);
    return toHex(array).slice(0, length);
}

/**
 * Generates a random state string to prevent CSRF attacks in OIDC flows.
 * @returns A 32-character random string.
 */
export function generateState(): string {
    return generateRandomString(32);
}

/**
 * Generates a random nonce, which binds an ID token to the authorization request that
 * asked for it and is the OIDC-mandated protection against ID token replay.
 * @returns A 32-character random string.
 */
export function generateNonce(): string {
    return generateRandomString(32);
}

/**
 * Generates a PKCE code verifier string.
 * 96 random bytes base64url-encode to exactly 128 characters, the maximum length
 * RFC 7636 allows.
 * @returns A base64url-encoded random string.
 */
export function generateCodeVerifier(): string {
    const array = new Uint8Array(96);
    getWebCrypto().getRandomValues(array);
    return toBase64Url(array);
}

/**
 * Generates a PKCE code challenge by hashing the verifier with SHA-256.
 * @param codeVerifier The original verifier string to hash.
 * @returns A promise resolving to the base64url-encoded SHA-256 hash.
 * @throws {CryptoUnavailableError} If the runtime has no Web Crypto subtle API.
 */
export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
    const webCrypto = getWebCrypto();
    if (!webCrypto.subtle) throw new CryptoUnavailableError();

    const data = new TextEncoder().encode(codeVerifier);
    const hashBuffer = await webCrypto.subtle.digest('SHA-256', data);
    return toBase64Url(new Uint8Array(hashBuffer));
}

/**
 * Helper to generate both the PKCE verifier and its corresponding challenge.
 * @returns A promise resolving to an object containing both the verifier and challenge.
 */
export async function generatePKCE() {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    return { codeVerifier, codeChallenge };
}

/**
 * Compares two strings in constant time relative to their length, so that a mismatched
 * `state` or `nonce` cannot be discovered by timing the comparison.
 * @param a First value.
 * @param b Second value.
 * @returns True when both values are non-empty and equal.
 */
export function timingSafeEqual(a: string, b: string): boolean {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length === 0 || b.length === 0) return false;

    // Length is not secret for these values, but keep the loop input-independent anyway.
    let mismatch = a.length ^ b.length;
    const max = Math.max(a.length, b.length);
    for (let i = 0; i < max; i++) {
        mismatch |= (a.charCodeAt(i % a.length) ^ b.charCodeAt(i % b.length));
    }
    return mismatch === 0;
}

/** Strips a single trailing slash so issuer comparisons are not defeated by formatting. */
export function normalizeIssuer(issuer: string): string {
    return issuer.replace(/\/+$/, '');
}

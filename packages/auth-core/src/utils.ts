const toHex = (buf: Uint8Array) => Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');

const toBase64Url = (buf: Uint8Array) => {
    const binary = String.fromCharCode(...buf);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

/**
 * Generates a high-entropy random string for security purposes.
 * Uses the Web Crypto API to ensure cryptographic strength.
 * @param length The desired length of the returned hex string.
 * @returns A cryptographically secure random string.
 */
export function generateRandomString(length: number): string {
    const array = new Uint8Array(Math.ceil(length / 2));
    globalThis.crypto.getRandomValues(array);
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
 * Generates a PKCE code verifier string.
 * A high-entropy cryptographic random string with a length between 43 and 128 characters.
 * @returns A base64url-encoded random string.
 */
export function generateCodeVerifier(): string {
    const array = new Uint8Array(96);
    globalThis.crypto.getRandomValues(array);
    return toBase64Url(array).slice(0, 128);
}

/**
 * Generates a PKCE code challenge by hashing the verifier with SHA-256.
 * @param codeVerifier The original verifier string to hash.
 * @returns A promise resolving to the base64url-encoded SHA-256 hash.
 */
export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data);

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
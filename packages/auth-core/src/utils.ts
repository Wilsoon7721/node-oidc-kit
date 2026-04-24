const toHex = (buf: Uint8Array) => Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');

const toBase64Url = (buf: Uint8Array) => {
    const binary = String.fromCharCode(...buf);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

/**
 * Generates a random string using the Web Crypto API.
 */
export function generateRandomString(length: number): string {
    const array = new Uint8Array(Math.ceil(length / 2));
    globalThis.crypto.getRandomValues(array);
    return toHex(array).slice(0, length);
}

export function generateState(): string {
    return generateRandomString(32);
}

/**
 * PKCE Verifier: A high-entropy cryptographic random string.
 */
export function generateCodeVerifier(): string {
    const array = new Uint8Array(96);
    globalThis.crypto.getRandomValues(array);
    return toBase64Url(array).slice(0, 128);
}

/**
 * PKCE Code Challenge: SHA256 hash of the verifier.
 * NOTE: This is now ASYNC because subtle.digest returns a Promise.
 */
export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data);

    return toBase64Url(new Uint8Array(hashBuffer));
}

export async function generatePKCE() {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    return { codeVerifier, codeChallenge };
}
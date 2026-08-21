import { AuthClient, AuthenticatedUser, AuthError, decodeTokenPayloadUnsafe, TokenResponse } from '@wilsoon/auth-core';

/**
 * Establishes the verified user behind a token response, returning the failure rather than
 * throwing so callers can fail closed and still report why.
 *
 * The routing itself lives in `AuthClient.resolveSession()` so every framework - not just
 * Next.js - gets the same behaviour.
 *
 * @returns The verified user, or the error explaining why there is no session.
 */
export async function resolveSessionUser(client: AuthClient, tokens: TokenResponse): Promise<{ user: AuthenticatedUser | null; error?: AuthError }> {
    try {
        return { user: await client.resolveSession(tokens) };
    } catch (error) {
        return { user: null, error: error instanceof AuthError ? error : undefined };
    }
}

/**
 * Whether a token *claims* the given audience.
 *
 * A routing hint only - never a trust decision. Whichever branch it selects, the token is
 * then verified properly, so a forged `aud` buys nothing.
 */
export function isAddressedTo(token: string, clientId: string): boolean {
    try {
        const claims = decodeTokenPayloadUnsafe(token);
        const audience = typeof claims.aud === 'string' ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud : [];
        return audience.includes(clientId);
    } catch {
        return false;
    }
}

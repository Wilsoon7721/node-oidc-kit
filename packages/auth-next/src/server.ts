import { cookies } from 'next/headers';
import { AuthClient } from '@wilsoon/auth-core';
import { ServerCookieStorage } from './storage/ServerCookieStorage';

/**
 * Retrieves the current session from cookies in a Server Component or Route Handler.
 * @param config The authentication configuration.
 * @returns A promise that resolves to an object containing the user and tokens, or nulls if not authenticated.
 */
export async function getSession(config: any) {
    const cookieStore = await cookies();
    const tokenData = cookieStore.get('wilsoon_id_tokens')?.value;

    if (!tokenData) return { user: null, tokens: null };

    try {
        const serverStorage = new ServerCookieStorage(cookieStore);
        const client = new AuthClient(config, serverStorage);
        const tokens = client.getStoredTokens();
        if (!tokens || !tokens.id_token) return { user: null, tokens: null };

        try {
            const user = client.parseIdToken(tokens.id_token);
            return { user, tokens };
        } catch {
            return { user: null, tokens: null };
        }
    } catch {
        return { user: null, tokens: null };
    }
} 
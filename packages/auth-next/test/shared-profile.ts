import { defineProfile, TokenVerificationError } from '@wilsoon/auth-core';

/**
 * A minimal profile that resolves shared platform sessions the way WilsoonID's does: verify the sibling's access token, then take the live claims from introspection.
 * The real one lives in a separate package that these tests do not depend on.
 */
export const sharedSessions = defineProfile({
    name: 'platform',
    resolveSharedSession: async (ctx, accessToken) => {
        const claims = await ctx.client.verifyAccessToken(accessToken);
        const live = await ctx.introspect(accessToken);
        if (!live.active) throw new TokenVerificationError('The platform session is no longer active.');

        const { active: _active, ...fields } = live;
        return ctx.toUser({ ...claims.claims, ...fields }, { source: 'access_token', audience: claims.audience[0] ?? '' });
    },
});

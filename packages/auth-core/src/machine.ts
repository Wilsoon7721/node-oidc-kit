import { TokenUse } from "./types";

/**
 * The claim the provider stamps on a `client_credentials` access token, and the value it carries.
 */
export const TOKEN_USE_CLAIM = "token_use";

/** The `token_use` value that marks a machine token. */
export const MACHINE_TOKEN_USE = "client";

/**
 * Whether a set of token claims describes a machine (`client_credentials`) token.
 *
 * Answers one question - is this `sub` a `client_id` rather than a user? - and answers it from claims that have **already been verified**.
 * Passing an unverified decode here tells you what the bearer of the token claimed, which is not the same thing and is not a basis for an authorization decision.
 *
 * ```ts
 * const claims = await client.verifyAccessToken(token, { allowMachineTokens: true });
 * if (isMachineToken(claims.claims)) return serveMachine(claims.subject);
 * ```
 */
export function isMachineToken(claims: Record<string, unknown> | null | undefined): boolean {
  return claims?.[TOKEN_USE_CLAIM] === MACHINE_TOKEN_USE;
}

/**
 * Reads `token_use` off verified claims, defaulting to `'user'`.
 *
 * The default matters: the provider stamps `token_use` only on machine tokens, so an absent claim means a user flow (or a token minted before the grant existed) rather than an unknown one.
 * Anything that is not exactly `"client"` is treated as a user token, which keeps an unrecognised future value from silently reading as machine.
 */
export function tokenUseOf(claims: Record<string, unknown> | null | undefined): TokenUse {
  return isMachineToken(claims) ? "client" : "user";
}

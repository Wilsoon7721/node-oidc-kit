import { TokenUse } from "./types";

/**
 * The claim the reference provider stamps on a `client_credentials` access token, and the value it carries.
 * This is more of a vendor convention rather than a registered claim, which is why {@link isMachineToken} does not rely on it alone.
 */
export const TOKEN_USE_CLAIM = "token_use";

/** The `token_use` value that marks a machine token. */
export const MACHINE_TOKEN_USE = "client";

/**
 * Whether a set of token claims describes a machine (`client_credentials`) token.
 * Two signals:
 * 1. `token_use: "client"`, which the reference provider stamps.
 * 2. `sub` equal to the `client_id` claim. RFC 9068 says a `client_credentials` access token's `sub` should be the client's identifier, so this holds on any provider following that profile even when it emits no `token_use`.
 *
 * A provider that emits no `token_use` would have had every machine token read as a user token. Where neither signal applies, set {@link AuthConfig.detectMachineToken}.
 *
 * ```ts
 * const claims = await client.verifyAccessToken(token, { allowMachineTokens: true });
 * if (isMachineToken(claims.claims)) return serveMachine(claims.subject);
 * ```
 */
export function isMachineToken(claims: Record<string, unknown> | null | undefined): boolean {
  if (!claims) return false;
  if (claims[TOKEN_USE_CLAIM] === MACHINE_TOKEN_USE) return true;

  // A user's `sub` and a `client_id` come from different namespaces, so an accidental collision
  // would mean the provider had already lost the ability to tell the two apart itself.
  const subject = claims.sub;
  const clientId = claims.client_id;
  return typeof subject === "string" && subject.length > 0 && subject === clientId;
}

/**
 * Reads which kind of caller a set of verified claims describes.
 * Anything that is not recognised as a machine is treated as a user, so an unfamiliar future value cannot silently read as machine.
 */
export function tokenUseOf(claims: Record<string, unknown> | null | undefined): TokenUse {
  return isMachineToken(claims) ? "client" : "user";
}

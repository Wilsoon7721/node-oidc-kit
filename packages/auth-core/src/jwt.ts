import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyOptions } from "jose";
import { NoTokenError, TokenVerificationError } from "./errors";
import type { JwksOptions } from "./types";

/**
 * The only signature algorithms this library will accept.
 *
 * An allowlist is not optional: without one, a verifier can be talked into accepting
 * `alg: "none"`, or an HMAC-confusion token where the attacker supplies the key that
 * verifies it.
 *
 * RS256 only, because that is what the reference provider signs with and advertises in
 * `id_token_signing_alg_values_supported`. A provider that signs with ES256 or EdDSA needs
 * this list widened - see the algorithm note in the repository README first.
 */
export const ALLOWED_ALGORITHMS = ["RS256"] as const;

const DEFAULT_JWKS_CACHE_MAX_AGE_MS = 600_000;
const DEFAULT_JWKS_COOLDOWN_MS = 30_000;
const DEFAULT_JWKS_TIMEOUT_MS = 5_000;

/**
 * Minimum interval between key-set drops triggered by a signature failure.
 *
 * Bounds the extra load an attacker can push onto the provider's JWKS endpoint by replaying garbage signatures.
 */
const ROTATION_RETRY_COOLDOWN_MS = 60_000;

const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;

const base64UrlToBytes = (segment: string): Uint8Array => {
  if (!BASE64URL_SEGMENT.test(segment)) throw new Error("Segment is not valid base64url.");

  const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  if (typeof atob === "function") {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  return new Uint8Array(Buffer.from(padded, "base64"));
};

/** @throws {NoTokenError} If the value is not a three-part compact JWS. */
export function splitJwt(token: string): { header: string; payload: string; signature: string } {
  if (typeof token !== "string" || token.length === 0) throw new NoTokenError("No token was provided.");

  const parts = token.split(".");
  if (parts.length !== 3 || parts[0].length === 0 || parts[1].length === 0) throw new NoTokenError("Token is not a compact JWS (expected three dot-separated segments).");

  return { header: parts[0], payload: parts[1], signature: parts[2] };
}

/** Decodes one base64url JWT segment's JSON. Verifies nothing. */
function decodeSegmentUnsafe(segment: string): Record<string, unknown> {
  const json = new TextDecoder().decode(base64UrlToBytes(segment));
  const parsed = JSON.parse(json);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Segment is not a JSON object.");
  return parsed as Record<string, unknown>;
}

/**
 * Decodes a JWT's payload **without verifying its signature, issuer, audience or expiry**.
 *
 * The result is attacker-controlled: anyone can mint a JWT with any payload and an empty
 * signature. Use it for display, diagnostics and scheduling hints only, and never to
 * decide what a caller is allowed to do.
 *
 * @throws {NoTokenError} If the token cannot be decoded.
 */
export function decodeTokenPayloadUnsafe(token: string): Record<string, unknown> {
  const { payload } = splitJwt(token);
  try {
    return decodeSegmentUnsafe(payload);
  } catch (error) {
    throw new NoTokenError("Failed to decode the token payload.");
  }
}

/**
 * Decodes a JWT's protected header **without verifying anything**. For diagnostics - in
 * particular, reading `kid` and `alg` when a verification failure needs explaining.
 *
 * @throws {NoTokenError} If the header cannot be decoded.
 */
export function decodeTokenHeaderUnsafe(token: string): Record<string, unknown> {
  const { header } = splitJwt(token);
  try {
    return decodeSegmentUnsafe(header);
  } catch (error) {
    throw new NoTokenError("Failed to decode the token header.");
  }
}

/**
 * A cached remote JSON Web Key Set.
 *
 * `createRemoteJWKSet` already handles `kid` selection and caching. This wrapper adds one
 * thing on top: recovery from a provider that rotates its signing key **without** changing
 * the `kid` - which the reference provider does, since it serves a fixed `kid`.
 *
 * Normally a rotation is invisible: the new key arrives under a new `kid` and jose refetches
 * on the miss. With a fixed `kid` the cached key simply stops verifying, and every request
 * fails until the cache ages out. So on a signature failure the key set is dropped once - at
 * most every {@link ROTATION_RETRY_COOLDOWN_MS} - and verification retried, making a rotation
 * cost one extra fetch instead of ten minutes of outage. The cooldown is what stops replayed
 * garbage signatures from turning into a fetch storm against the provider's JWKS endpoint.
 */
export class RemoteKeySet {
  private keySet?: ReturnType<typeof createRemoteJWKSet>;
  private keySetUri?: string;
  private lastInvalidatedAt = 0;

  constructor(private options: JwksOptions = {}) {}

  /** The resolver for this JWKS URI, created on first use and reused after. */
  resolver(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
    if (!this.keySet || this.keySetUri !== jwksUri) {
      this.keySetUri = jwksUri;
      this.keySet = createRemoteJWKSet(new URL(jwksUri), {
        cacheMaxAge: this.options.cacheMaxAgeMs ?? DEFAULT_JWKS_CACHE_MAX_AGE_MS,
        cooldownDuration: this.options.cooldownMs ?? DEFAULT_JWKS_COOLDOWN_MS,
        timeoutDuration: this.options.timeoutMs ?? DEFAULT_JWKS_TIMEOUT_MS,
      });
    }
    return this.keySet;
  }

  /**
   * Drops the cached key set so the next verification refetches it.
   * @returns False when the cooldown is still active and nothing was dropped.
   */
  invalidate(): boolean {
    const now = Date.now();
    if (now - this.lastInvalidatedAt < ROTATION_RETRY_COOLDOWN_MS) return false;

    this.lastInvalidatedAt = now;
    this.keySet = undefined;
    return true;
  }
}

const errorCode = (error: unknown): string | undefined => (typeof error === "object" && error !== null && "code" in error ? String((error as { code: unknown }).code) : undefined);

const isSignatureFailure = (error: unknown): boolean => {
  const code = errorCode(error);
  return code === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED" || code === "ERR_JWKS_NO_MATCHING_KEY";
};

const describe = (error: unknown): string => {
  switch (errorCode(error)) {
    case "ERR_JWS_SIGNATURE_VERIFICATION_FAILED":
      return "Token signature verification failed.";
    case "ERR_JWKS_NO_MATCHING_KEY":
      return "No key in the provider JWKS matches this token.";
    case "ERR_JWKS_MULTIPLE_MATCHING_KEYS":
      return "The provider JWKS contains multiple candidate keys for this token.";
    case "ERR_JOSE_ALG_NOT_ALLOWED":
      return `Token algorithm is not allowed. Only ${ALLOWED_ALGORITHMS.join(", ")} is accepted.`;
    case "ERR_JWT_EXPIRED":
      return "Token has expired.";
    case "ERR_JWT_CLAIM_VALIDATION_FAILED":
      return `Token claim validation failed: ${error instanceof Error ? error.message : "unknown claim"}.`;
    case "ERR_JWKS_TIMEOUT":
      return "Timed out fetching the provider JWKS.";
    case "ERR_JWS_INVALID":
    case "ERR_JWT_INVALID":
      return "Token is malformed.";
    default:
      return `Token verification failed: ${error instanceof Error ? error.message : String(error)}`;
  }
};

/** Parameters for {@link verifyCompactJwt}. */
export interface VerifyJwtParams {
  /** The provider's `jwks_uri`. */
  jwksUri: string;
  /** The exact `iss` value(s) accepted. */
  issuer: string | string[];
  /** The audience value(s) required. */
  audience: string | string[];
  /** Leeway in seconds for time-based claims. */
  clockTolerance: number;
  /** The `typ` header to require, when set. */
  typ?: string;
}

/**
 * Verifies a compact JWT against the provider's JWKS.
 *
 * Checks, in one pass: the signature, that the algorithm is one of
 * {@link ALLOWED_ALGORITHMS}, the `iss`, the `aud`, and `exp`/`nbf` (with leeway).
 *
 * @returns The verified claims.
 * @throws {NoTokenError} If the token is not a compact JWS.
 * @throws {TokenVerificationError} If any check fails.
 */
export async function verifyCompactJwt(keySet: RemoteKeySet, token: string, params: VerifyJwtParams): Promise<JWTPayload> {
  splitJwt(token);

  const options: JWTVerifyOptions = {
    issuer: params.issuer,
    audience: params.audience,
    algorithms: [...ALLOWED_ALGORITHMS],
    clockTolerance: params.clockTolerance,
    requiredClaims: ["exp"],
    ...(params.typ ? { typ: params.typ } : {}),
  };

  try {
    const { payload } = await jwtVerify(token, keySet.resolver(params.jwksUri), options);
    return payload;
  } catch (error) {
    // A signature that does not verify against a cached key can also mean the provider rotated its key without changing the `kid`. Refetch once and retry.
    if (isSignatureFailure(error) && keySet.invalidate()) {
      try {
        const { payload } = await jwtVerify(token, keySet.resolver(params.jwksUri), options);
        return payload;
      } catch (retryError) {
        throw new TokenVerificationError(describe(retryError), { cause: retryError });
      }
    }
    throw new TokenVerificationError(describe(error), { cause: error });
  }
}

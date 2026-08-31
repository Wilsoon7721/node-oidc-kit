import { PollOptions } from "./polling";

/**
 * The `evt` claim value that marks an escalation token.
 */
export const ESCALATION_TOKEN_TYPE = "escalation";

/** Options for {@link AuthClient.createEscalation}. */
export interface CreateEscalationOptions {
  /**
   * The methods that would satisfy the request, as strategy names or `amr` values.
   *
   * Aliases collapse at the provider - `passkey`, `fido`, `hw` and `webauthn` are one verifier, and `mfa` means passkey or TOTP.
   * A relying party that reads `amr: ["fido"]` off a token can ask for `fido` back and get what it meant.
   * An unrecognised value is rejected outright rather than dropped, because dropping it would quietly weaken the request.
   */
  use: string | string[];
  /**
   * Require a fresh assertion even if the session already used an accepted method (default `false`).
   *
   * With `force: false` a qualifying session completes immediately and the result carries {@link EscalationResult.alreadySatisfied}.
   * With `force: true` the provider checks that the session's `auth_time` is newer than the escalation itself, so an assertion from an hour ago cannot be re-presented.
   */
  force?: boolean;
  /**
   * An ID token this client was issued for the user being asked to step up.
   *
   * This is how the provider knows *whose* step-up is being demanded, and it is the only way a **public client may name a subject at all**.
   * Prefer it always: it binds the request to a user this client has already been issued a token for, so a client cannot demand step-up from someone it has never seen.
   */
  idTokenHint?: string;
  /**
   * The subject identifier, for confidential clients that have no ID token to hand.
   * Refused from a public client - use {@link CreateEscalationOptions.idTokenHint} there.
   */
  subject?: string;
  /**
   * Requested lifetime in seconds. The provider clamps it to 60-900 and defaults to 300.
   * Whatever it decides comes back as {@link EscalationRequest.expiresAt} and that value is what everything counts down from.
   */
  expiresInSeconds?: number;
}

/** A created escalation request: the URL to put in front of the user, and what is needed to poll for the outcome. */
export interface EscalationRequest {
  /** The provider's identifier for this request. */
  escalationId: string;
  /**
   * The URL to open in a browser.
   *
   * **Do not construct or edit this** as it carries a server HMAC over the request's parameters. Changing `use=passkey` to `use=google` in the address bar fails as `invalid_signature` and is audited.
   * The server signs it so that a public client, which cannot hold a secret, still gets a tamper-proof URL.
   */
  escalationUrl: string;
  /** The methods the provider resolved {@link CreateEscalationOptions.use} to. */
  strategies: string[];
  /** Whether a fresh assertion was demanded. */
  force: boolean;
  /** The secret that authorizes polling for this one request. Single-use once collected. */
  pollToken: string;
  /** Seconds until the deadline, as the provider computed it. */
  expiresIn: number;
  /** The deadline, in seconds since the epoch. The one number everything counts down from. */
  expiresAt: number;
  /** Seconds to wait between polls. */
  interval: number;
}

/** A completed escalation. */
export interface EscalationResult {
  /** The request this answers. */
  escalationId: string;
  /**
   * True when the session already met the requirement and the user was asked for nothing.
   * Only ever true for `force: false`. It is the clue for whether to show the user "verified" or nothing at all - nothing happened on their screen.
   */
  alreadySatisfied: boolean;
  /** The method that satisfied the request, e.g. `passkey`. */
  satisfiedBy?: string;
  /** The `amr` of the session at the moment it was satisfied. */
  authMethods: string[];
  /** The resulting authentication context class, e.g. `urn:wilsoon:acr:passkey`. */
  acr?: string;
  /** When the satisfying authentication happened, in seconds since the epoch. */
  authTime?: number;
  /**
   * A short-lived JWT asserting the outcome, signed by the provider and audienced to this client. This verifies against the provider's JWKS.
   * Verify it with {@link AuthClient.verifyEscalationToken} before trusting it.
   */
  escalationToken?: string;
}

/** The verified claims of an escalation token. */
export interface VerifiedEscalation {
  /** The user who completed the step-up. */
  subject: string;
  /** The method that satisfied it. */
  satisfiedBy?: string;
  /** Whether the session already qualified and the user was asked for nothing. */
  alreadySatisfied: boolean;
  /** The `amr` recorded at the moment of satisfaction. */
  authMethods: string[];
  /** The resulting authentication context class. */
  acr?: string;
  /** When the satisfying authentication happened, in seconds since the epoch. */
  authTime?: number;
  /** The verified `iss` claim. */
  issuer: string;
  /** The verified `aud` claim - this client. */
  audience: string;
  /** The verified `exp` claim, in seconds since the epoch. */
  expiresAt: number;
  /** All verified claims. */
  claims: Readonly<Record<string, unknown>>;
}

/** Options for {@link AuthClient.reauthorize}. */
export interface ReauthorizeOptions extends CreateEscalationOptions, PollOptions {
  /**
   * Puts {@link EscalationRequest.escalationUrl} in front of the user.
   *
   * Called once, as soon as the request exists and before the first poll.
   * What it should do depends entirely on where the code runs - open a browser tab, print the URL to a terminal, render a link - which is why this package cannot guess and asks for it.
   * Skipped entirely when the provider satisfies the request immediately, so a `force: false` step-up against a qualifying session shows the user nothing.
   */
  openUrl?: (url: string, request: EscalationRequest) => void | Promise<void>;
  /**
   * Verify the returned escalation token against the provider's JWKS before resolving (default `true`).
   * Leave it on. The token is the only part of the result that can be shown to a third party, and an unverified one is nothing but a string.
   */
  verifyToken?: boolean;
}

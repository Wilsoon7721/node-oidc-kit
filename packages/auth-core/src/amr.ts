import { ClaimValidationError } from './errors';

/**
 * Authentication Method Reference values the Wilsoon identity provider emits, and helpers for checking them.
 *
 * The provider composes `amr` as follows:
 * | Login                        | `amr`                     |
 * |------------------------------|---------------------------|
 * | Federated / social provider  | `["ext", "social"]`       |
 * | Passkey                      | `["mfa", "fido", "hw"]`   |
 * | + TOTP challenge completed   | adds `"otp"` and `"mfa"`  |
 *
 * The important consequence: **`mfa` does not imply a hardware factor.** It is present both for passkeys and for a password/social login that cleared a TOTP challenge. 
 * Require {@link AMR.FIDO} or {@link AMR.HARDWARE} explicitly when you mean "phishing-resistant".
 */
export const AMR = {
    /** A second factor was used - either a passkey or a completed TOTP challenge. */
    MFA: 'mfa',
    /** A WebAuthn/FIDO credential was used. */
    FIDO: 'fido',
    /** A hardware-backed credential was used. */
    HARDWARE: 'hw',
    /** A time-based one-time password was verified. */
    OTP: 'otp',
    /** Authentication was delegated to an external identity provider. */
    EXTERNAL: 'ext',
    /** The external identity provider was a social login. */
    SOCIAL: 'social',
} as const;

/** A known `amr` value. Providers may emit others; comparisons accept any string. */
export type AmrValue = typeof AMR[keyof typeof AMR];

/** Anything carrying verified authentication methods. */
export interface AmrCarrier {
    authMethods?: string[] | null;
}

/** Options for {@link satisfiesAmr}. */
export interface SatisfiesAmrOptions {
    /**
     * `'all'` (default) requires every listed method to be present`'any'` requires at least one. 
     * `'all'` is the default because step-up policies are conjunctions.
     */
    mode?: 'all' | 'any';
}

const methodsOf = (source: string[] | AmrCarrier | null | undefined): string[] => {
    if (!source) return [];
    const methods = Array.isArray(source) ? source : source.authMethods;
    return Array.isArray(methods) ? methods.filter((m): m is string => typeof m === 'string') : [];
};

/**
 * Checks a verified identity's authentication methods against a policy.
 *
 * Fails closed: an empty or missing `amr` satisfies nothing (unless nothing is required),
 * and unknown values are simply absent rather than treated as wildcards.
 *
 * ```ts
 * const user = await client.verifyIdToken(idToken);
 * if (!satisfiesAmr(user, [AMR.FIDO])) return stepUp();
 * ```
 *
 * @param source A verified user (or a raw `amr` array).
 * @param required The methods the caller requires. An empty list is trivially satisfied.
 * @param options Whether all or any of the required methods must be present.
 * @returns True when the policy is satisfied.
 */
export function satisfiesAmr(source: string[] | AmrCarrier | null | undefined, required: string[], options: SatisfiesAmrOptions = {}): boolean {
    if (!Array.isArray(required) || required.length === 0) return true;

    const present = new Set(methodsOf(source));
    return options.mode === 'any'
        ? required.some(method => present.has(method))
        : required.every(method => present.has(method));
}

/**
 * Asserts a policy over authentication methods, for use in guard clauses.
 * @param source A verified user (or a raw `amr` array).
 * @param required The methods the caller requires.
 * @param options Whether all or any of the required methods must be present.
 * @throws {ClaimValidationError} If the policy is not satisfied.
 */
export function assertAmr(source: string[] | AmrCarrier | null | undefined, required: string[], options: SatisfiesAmrOptions = {}): void {
    if (satisfiesAmr(source, required, options)) return;

    throw new ClaimValidationError(`Authentication methods [${methodsOf(source).join(', ') || 'none'}] do not satisfy ` + `${options.mode === 'any' ? 'any of' : 'all of'} [${required.join(', ')}].`);
}

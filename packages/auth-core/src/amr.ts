import { ClaimValidationError } from './errors';

/**
 * Authentication Method Reference (`amr`) values, and helpers for checking them.
 *
 * `amr` is how a token says *how* the user proved who they are, which is what step-up
 * policies are written against. RFC 8176 registers the names; which of them a provider
 * emits, and in what combinations, is the provider's choice. The reference provider
 * composes them like this:
 *
 * | Login                        | `amr`                     |
 * |------------------------------|---------------------------|
 * | Federated / social provider  | `["ext", "social"]`       |
 * | Passkey                      | `["mfa", "fido", "hw"]`   |
 * | + TOTP challenge completed   | adds `"otp"` and `"mfa"`  |
 *
 * The consequence worth internalising: **`mfa` does not imply a hardware factor.** It
 * appears both for a passkey and for a password or social login that cleared a TOTP
 * challenge, and TOTP is phishable. Require {@link AMR.FIDO} or {@link AMR.HARDWARE}
 * explicitly when you mean phishing-resistant.
 *
 * The constants are a convenience, not a constraint: {@link satisfiesAmr} compares plain
 * strings, so a provider that emits values outside this table works without changes here.
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
     * `'all'` (default) requires every listed method; `'any'` requires at least one.
     *
     * `'all'` is the default because step-up policies are conjunctions - "a hardware key
     * *and* a recent authentication", not either one.
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
 * @param required The methods the caller requires. An empty list is trivially satisfied.
 */
export function satisfiesAmr(source: string[] | AmrCarrier | null | undefined, required: string[], options: SatisfiesAmrOptions = {}): boolean {
    if (!Array.isArray(required) || required.length === 0) return true;

    const present = new Set(methodsOf(source));
    return options.mode === 'any'
        ? required.some(method => present.has(method))
        : required.every(method => present.has(method));
}

/**
 * {@link satisfiesAmr} as a guard clause: throws instead of returning false, with the
 * present and required methods named in the message.
 *
 * @throws {ClaimValidationError} If the policy is not satisfied.
 */
export function assertAmr(source: string[] | AmrCarrier | null | undefined, required: string[], options: SatisfiesAmrOptions = {}): void {
    if (satisfiesAmr(source, required, options)) return;

    throw new ClaimValidationError(`Authentication methods [${methodsOf(source).join(', ') || 'none'}] do not satisfy ` + `${options.mode === 'any' ? 'any of' : 'all of'} [${required.join(', ')}].`);
}

/**
 * Thrown when the token endpoint refuses a `client_credentials` request.
 * Branch on {@link MachineTokenError.permanent} to decide whether retrying could ever help.
 */
export class MachineTokenError extends Error {
  constructor(
    message: string,
    /** The OAuth error code, e.g. `invalid_client`, or `unknown_error` when the body carried none. */
    public code: string,
    /** The HTTP status the token endpoint returned. */
    public status: number,
    /**
     * Whether this failure is configuration or transient,
     */
    public permanent: boolean,
  ) {
    super(message);
    this.name = "MachineTokenError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Error codes that describe a misconfigured client rather than a transient fault.
 * Retrying any of these produces the same answer, so they are worth failing loudly on.
 */
export const PERMANENT_ERROR_CODES: readonly string[] = ["invalid_client", "unauthorized_client", "invalid_scope", "unsupported_grant_type"];

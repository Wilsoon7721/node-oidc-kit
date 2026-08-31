import { PollOptions } from "./polling";
import { AuthenticatedUser, TokenResponse } from "./types";

export const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

/** Options for {@link AuthClient.requestDeviceCode}. */
export interface DeviceAuthorizationOptions {
  // Scopes to request. Falls back to {@link AuthConfig.scope}, then to the provider's own default.
  scope?: string[];
}

export interface DeviceAuthorization {
  /**
   * The secret this client polls with, which should never be displayed. {@link DeviceAuthorization.userCode} should be displayed instead.
   */
  deviceCode: string;
  /**
   * The short code to display, formatted `XXXX-XXXX`.
   */
  userCode: string;
  /** Where the user should go to enter the code. */
  verificationUri: string;
  /**
   * The same destination with the code already filled in, when the provider offers it.
   *
   * Show it alongside {@link DeviceAuthorization.userCode} rather than instead of it.
   * The approval page shows the resolved code, so the user can check it against what was displayed on terminal.
   */
  verificationUriComplete?: string;
  /** Seconds until the code expires, as the provider computed */
  expiresIn: number;
  /** The deadline, in seconds since epoch */
  expiresAt: number;
  /** Seconds to wait between polls. The provider raises an error if polled too fast. */
  interval: number;
}

/** Options for {@link AuthClient.authorizeDevice}. */
export interface AuthorizeDeviceOptions extends DeviceAuthorizationOptions, PollOptions {
  /**
   * Shows the user the code and where to enter it.
   *
   * Called once, before the first poll. A CLI usually prints both the code and {@link DeviceAuthorization.verificationUri}.
   * There is no default because this package has no idea what it is running inside.
   */
  onUserCode?: (authorization: DeviceAuthorization) => void | Promise<void>;
  /**
   * Verify the returned ID token and resolve the user (default `true`).
   * Turning it off gives back the raw token response and leaves `user` null, which should only be done if you are storing the tokens to verify somewhere else.
   */
  verifyUser?: boolean;
}

/** The outcome of a completed device authorization. */
export interface DeviceGrantResult {
  /** The tokens generated for the device. */
  tokens: TokenResponse;
  /**
   * The verified user, or `null` when `verifyUser: false` or no ID token was issued.
   *
   * Worth knowing what the `acr` on these tokens means: the provider captures `amr`, `acr` and `auth_time` from the **browser session that approved the request**, because the device never sees a session and cannot assert anything about the authentication.
   * A user who approved from a passkey session hands the device a passkey-level token, and one who approved from a plain social session does not.
   */
  user: AuthenticatedUser | null;
  /** The authorization this completes, including the code that was displayed. */
  authorization: DeviceAuthorization;
}

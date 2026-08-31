/**
 * RFC 9470 - OAuth 2.0 Step Up Authentication Challenge Protocol
 */

/** The `error` code RFC 9470 defines for "authenticated, but not strongly enough". */
export const INSUFFICIENT_USER_AUTHENTICATION = "insufficient_user_authentication";

/**
 * The OIDC Core error an authorization server returns when it cannot satisfy the requested `acr_values`.
 * Worth recognising by name: it means the demand was understood and refused, not that the request was malformed.
 */
export const UNMET_AUTHENTICATION_REQUIREMENTS = "unmet_authentication_requirements";

/** A parsed `WWW-Authenticate` challenge. */
export interface AuthenticationChallenge {
  /** The auth scheme, normalised to lower case (`bearer` for anything RFC 9470 describes). */
  scheme: string;
  /** The `error` parameter, when present. */
  error?: string;
  /** The `error_description` parameter, when present. */
  errorDescription?: string;
  /** `acr_values`, split on whitespace. Empty when the challenge names none. */
  acrValues: string[];
  /** `max_age` in seconds, when present and numeric. */
  maxAge?: number;
  /** `scope`, split on whitespace. Empty when the challenge names none. */
  scope: string[];
  /** The `realm` parameter, when present. */
  realm?: string;
  /** Every parameter as it was received, for anything not modelled above. */
  parameters: Readonly<Record<string, string>>;
}

/** Options for {@link buildAuthenticationChallenge}. */
export interface BuildChallengeOptions {
  /** Authentication context classes that would satisfy this resource. */
  acrValues?: string | string[];
  /** Maximum age, in seconds, of the authentication the resource will accept. */
  maxAge?: number;
  /** Human-readable explanation. Never put a token or a user identifier in here. */
  errorDescription?: string;
  /** The protection space, when the resource server uses one. */
  realm?: string;
  /** Scopes the resource requires, if the challenge is also about scope. */
  scope?: string | string[];
  /** Overrides the default `insufficient_user_authentication`. */
  error?: string;
}

const TOKEN_CHARS = /[A-Za-z0-9!#$%&'*+\-.^_`|~]/;

const asList = (value: string | undefined): string[] => (value ? value.split(/\s+/).filter(Boolean) : []);

/**
 * Parses a WWW-Authenticate header.
 * Returns null for an absent or unparsable header, and returns only the first challenge if multiple are present.
 */
export function readAuthenticationChallenge(header: string | null | undefined): AuthenticationChallenge | null {
  if (typeof header !== "string") return null;

  const input = header.trim();
  if (!input) return null;

  let i = 0;

  const readToken = (): string => {
    const start = i;
    while (i < input.length && TOKEN_CHARS.test(input[i])) i += 1;
    return input.slice(start, i);
  };

  const skipSpace = (): void => {
    while (i < input.length && (input[i] === " " || input[i] === "\t")) i += 1;
  };

  const scheme = readToken();
  if (!scheme) return null;

  const parameters: Record<string, string> = {};
  skipSpace();

  while (i < input.length) {
    const name = readToken();
    if (!name) break;

    skipSpace();
    if (input[i] !== "=") break;

    i += 1;
    skipSpace();

    let value = "";
    if (input[i] === '"') {
      i += 1;
      while (i < input.length && input[i] !== '"') {
        if (input[i] === "\\" && i + 1 < input.length) i += 1;
        value += input[i];
        i += 1;
      }
      i += 1;
    } else {
      value = readToken();
    }

    parameters[name.toLowerCase()] = value;

    skipSpace();
    if (input[i] === ",") {
      i += 1;
      skipSpace();
    }
  }

  const maxAge = Number(parameters.max_age);

  return {
    scheme: scheme.toLowerCase(),
    error: parameters.error || undefined,
    errorDescription: parameters.error_description || undefined,
    acrValues: asList(parameters.acr_values),
    maxAge: parameters.max_age !== undefined && Number.isFinite(maxAge) && maxAge >= 0 ? maxAge : undefined,
    scope: asList(parameters.scope),
    realm: parameters.realm || undefined,
    parameters: Object.freeze({ ...parameters }),
  };
}

/** Whether a challenge is RFC 9470's step-up demand. */
export function isStepUpChallenge(challenge: AuthenticationChallenge | null | undefined): boolean {
  return challenge?.error === INSUFFICIENT_USER_AUTHENTICATION;
}

/**
 * Builds the `WWW-Authenticate` value a resource server returns with `401` to demand stronger authentication.
 * ```ts
 * res.setHeader("WWW-Authenticate", buildAuthenticationChallenge({ acrValues: "urn:example:acr:passkey", maxAge: 300 }));
 * res.status(401).end();
 * ```
 */
export function buildAuthenticationChallenge(options: BuildChallengeOptions = {}): string {
  const parts: string[] = [];

  const quote = (value: string) => `"${String(value).replace(/(["\\])/g, "\\$1")}"`;
  const push = (name: string, value: string | undefined) => {
    if (value) parts.push(`${name}=${quote(value)}`);
  };

  push("realm", options.realm);
  push("error", options.error ?? INSUFFICIENT_USER_AUTHENTICATION);
  push("error_description", options.errorDescription);
  push("scope", Array.isArray(options.scope) ? options.scope.join(" ") : options.scope);
  push("acr_values", Array.isArray(options.acrValues) ? options.acrValues.join(" ") : options.acrValues);

  if (typeof options.maxAge === "number" && Number.isFinite(options.maxAge) && options.maxAge >= 0) {
    parts.push(`max_age=${quote(String(Math.floor(options.maxAge)))}`);
  }

  return `Bearer ${parts.join(", ")}`;
}

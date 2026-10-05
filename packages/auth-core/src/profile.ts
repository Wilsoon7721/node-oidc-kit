import type { AuthClient } from "./index";
import type { AuthStorage, StorageKeys } from "./storage";
import type { AuthConfig, AuthenticatedUser, DiscoveryDocument, IntrospectionResponse, PlatformSessionOptions, ProfileUser, TokenUse } from "./types";

/** What a profile's {@link ProviderProfile.mapUser} may add to a verified user, on top of the standard claims core maps itself. */
export type ProfileUserFields = Partial<Pick<AuthenticatedUser, "roles" | "permissions" | "role" | "sessionVersion" | "sid">> & Record<string, unknown>;

/** The live answer to "may this token still be used, and with what", from {@link ProviderProfile.liveAccess} or plain introspection. */
export interface LiveAccess {
  /** Whether the provider still honours the token. */
  active: boolean;
  /** What the user holds right now for this client, when the provider says. Absent means the provider did not answer, not that nothing is held. */
  permissions?: string[];
  /** The provider session the token belongs to, when known. */
  sid?: string;
}

/** Options for {@link ProfileContext.verifyJwt}. */
export interface ProfileVerifyJwtOptions {
  /** The audience to require (default: this client's ID). */
  audience?: string | string[];
  /** The `typ` header to require, e.g. `"logout+jwt"`. Unchecked when omitted. */
  typ?: string;
}

/**
 * What core hands a profile so its extensions can talk to the provider as this client.
 * Everything here goes through the same discovery cache, key set and credentials as the client's own standard methods.
 */
export interface ProfileContext {
  /** The client's configuration. */
  readonly config: Readonly<AuthConfig>;
  /** The core client, for calling standard methods. */
  readonly client: AuthClient;
  /** The client's storage adapter. */
  readonly storage: AuthStorage;
  /** The names the client stores its tokens and transient values under. */
  readonly storageKeys: Readonly<StorageKeys>;
  /** The provider's discovery document, cached for the life of the client. */
  getEndpoints(): Promise<DiscoveryDocument>;
  /** Fetch with this client's credentials as HTTP Basic auth. A public client sends no `Authorization` header. */
  clientFetch(url: string, init?: RequestInit): Promise<Response>;
  /** Verifies a JWT's signature, issuer, audience and expiry against the provider's JWKS, returning its claims. */
  verifyJwt(token: string, options?: ProfileVerifyJwtOptions): Promise<Record<string, unknown>>;
  /** RFC 7662 introspection with this client's credentials. */
  introspect(token: string): Promise<IntrospectionResponse>;
  /** Maps verified claims onto an {@link AuthenticatedUser} exactly as `verifyIdToken` does, profile `mapUser` included. */
  toUser(claims: Record<string, unknown>, details: { source: "id_token" | "access_token"; audience: string }): AuthenticatedUser;
  /** Whether verified claims describe a machine caller, honouring `detectMachineToken` and the profile's `isMachineToken`. */
  classifyTokenUse(claims: Record<string, unknown>): TokenUse;
  /** Logs a warning once per key, under the library's prefix. */
  warnOnce(key: string, message: string): void;
}

/**
 * Adapts the standards-only core to one identity provider: claim mapping, storage names, and extra functions that are in no spec.
 * The functions returned by {@link ProviderProfile.extend} are exposed under the profile's {@link ProviderProfile.name} on a client made with `createAuthClient`.
 */
export interface ProviderProfile<Name extends string = string, Ext extends object = object> {
  /** The namespace the extensions are exposed under, e.g. `"wilsoon"` gives `client.wilsoon.reauthorize()`. */
  readonly name: Name;
  /** Prefix for the storage names, used when the config sets no `storagePrefix`. */
  readonly storagePrefix?: string;
  /** Exact storage names, for a provider whose legacy names do not follow `<prefix><key>`. Wins over any prefix. */
  readonly storageKeys?: Partial<StorageKeys>;
  /** Default access token audience, used when the config sets no `apiAudience`. */
  readonly apiAudience?: string;
  /** Adds provider-specific fields to a verified user. Identity fields (`id`, `issuer`, `audience`, `expiresAt`, `claims`, `source`) cannot be overridden. */
  mapUser?(claims: Readonly<Record<string, unknown>>): ProfileUserFields;
  /** Recognises the provider's machine tokens. A config `detectMachineToken` wins over this. */
  isMachineToken?(claims: Readonly<Record<string, unknown>>): boolean;
  /** A non-standard session restore, such as reading a provider cookie. Never throws; `null` means no session. */
  restoreSession?(ctx: ProfileContext): Promise<ProfileUser | null>;
  /** Resolves a session that holds only an access token issued to another client, such as a shared platform cookie. */
  resolveSharedSession?(ctx: ProfileContext, accessToken: string, options: PlatformSessionOptions): Promise<AuthenticatedUser>;
  /** Live access for a token. Without it, core falls back to plain introspection, which answers `active` only. */
  liveAccess?(ctx: ProfileContext, token: string): Promise<LiveAccess>;
  /** The injected functions. Called once per client. */
  extend?(ctx: ProfileContext): Ext;
}

/** The namespaced extensions a profile adds to a client: `{ [name]: ReturnType<extend> }`, or nothing for an untyped or absent profile. */
export type ProfileExtensions<P> = P extends ProviderProfile<infer Name, infer Ext> ? (string extends Name ? unknown : { readonly [K in Name]: Ext }) : unknown;

/** Identity helper that keeps a profile's `name` as a string literal, so `createAuthClient` can type `client.<name>`. */
export function defineProfile<const Name extends string, Ext extends object = object>(profile: ProviderProfile<Name, Ext>): ProviderProfile<Name, Ext> {
  return profile;
}

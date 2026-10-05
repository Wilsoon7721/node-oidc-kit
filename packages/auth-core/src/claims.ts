import { ClaimValidationError } from "./errors";

/**
 * A dot path into a token's claims, e.g. `"permissions"`, `"realm_access.roles"` or `"resource_access.my-app.roles"`.
 * Each segment is one property name, so a path cannot address a key that itself contains a dot.
 */
export type ClaimPath = string;

/** Where to read a list of strings from: a {@link ClaimPath}, or a function over the verified claims. */
export type ClaimSelector = ClaimPath | ((claims: Readonly<Record<string, unknown>>) => readonly string[] | null | undefined);

/** Anything carrying roles, such as an `AuthenticatedUser` or `AccessTokenClaims`. */
export interface RoleCarrier {
  roles?: readonly string[];
}

/** Anything carrying permissions, such as an `AuthenticatedUser` or `AccessTokenClaims`. */
export interface PermissionCarrier {
  permissions?: readonly string[];
}

/** Reads the value at a dot path, or `undefined` when any segment is missing. */
export function readClaimPath(claims: Readonly<Record<string, unknown>> | null | undefined, path: ClaimPath): unknown {
  let current: unknown = claims;
  for (const segment of path.split(".")) {
    if (typeof current !== "object" || current === null || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

/**
 * Reads a list of strings through a {@link ClaimSelector}.
 * An array keeps its string entries, a string is split on whitespace (the `scope` convention), and anything else is an empty list.
 */
export function readClaimList(claims: Readonly<Record<string, unknown>>, selector: ClaimSelector): string[] {
  const value = typeof selector === "function" ? selector(claims) : readClaimPath(claims, selector);
  if (typeof value === "string") return value.split(/\s+/).filter(Boolean);
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0);
  return [];
}

const listOf = <T extends string>(value: T | readonly T[]): readonly T[] => (typeof value === "string" ? [value] : value);

/** Whether the subject holds **any** of the given roles. */
export function hasRole(subject: RoleCarrier | null | undefined, role: string | readonly string[]): boolean {
  const held = subject?.roles ?? [];
  return listOf(role).some((entry) => held.includes(entry));
}

/** Whether the subject holds **every** one of the given permissions. */
export function hasPermission<P extends string = string>(subject: PermissionCarrier | null | undefined, permission: P | readonly P[]): boolean {
  const held = subject?.permissions ?? [];
  const required = listOf(permission);
  return required.length > 0 && required.every((entry) => held.includes(entry));
}

/** {@link hasRole} that throws instead of returning `false`. @throws {ClaimValidationError} If no listed role is held. */
export function requireRole(subject: RoleCarrier | null | undefined, role: string | readonly string[]): void {
  if (!hasRole(subject, role)) throw new ClaimValidationError(`One of the roles [${listOf(role).join(", ")}] is required.`);
}

/** {@link hasPermission} that throws instead of returning `false`. @throws {ClaimValidationError} If any listed permission is missing. */
export function requirePermission<P extends string = string>(subject: PermissionCarrier | null | undefined, permission: P | readonly P[]): void {
  if (hasPermission(subject, permission)) return;
  const held = subject?.permissions ?? [];
  const missing = listOf(permission).filter((entry) => !held.includes(entry));
  throw new ClaimValidationError(`Missing required permission(s): ${missing.join(", ") || "(none requested)"}.`);
}

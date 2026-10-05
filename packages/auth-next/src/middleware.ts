import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { AuthClient, AuthConfig, AuthError, AuthStorage, hasPermission, hasRole, LiveAccess, satisfiesAmr, TokenResponse } from "@wilsoon/auth-core";
import { getCachedClient } from "./client-cache";
import { isAddressedTo, resolveSessionUser } from "./resolve";

/** Options for {@link createAuthMiddleware}. */
export interface AuthMiddlewareOptions extends AuthConfig {
  /** Where unauthenticated users are sent (default `/auth`). */
  loginPath?: string;
  /** Where authenticated-but-unauthorized users are sent (default `loginPath`). */
  unauthorizedPath?: string;
  /**
   * Verify the ID token's signature, issuer, audience and expiry before letting the
   * request through (default true).
   */
  verify?: boolean;
  /** Let through only users holding **any** of these roles. Requires verification. */
  roles?: string[];
  /** Let through only users holding **every** one of these permissions, e.g. `["games_portal.access"]`. Requires verification. */
  permissions?: string[];
  /**
   * `"live"` asks the provider on every request whether the session still stands, signing the user out when it does not and guarding `permissions` on what the user holds now (default `"token"`).
   * Without it, a revoked permission lands at the next refresh. Needs a `clientSecret`, since it uses introspection.
   */
  enforce?: "token" | "live";
  /**
   * Domain of the session cookie. A leading-dot domain (`.example.com`) shares the session across subdomains.
   * It must match the domain the cookie was set with, or signing out silently fails and the user loops.
   */
  cookieDomain?: string;
  /** Require these authentication methods (`amr`). Requires verification. */
  amr?: string[];
  /**
   * Name of the cookie holding the token response (default: the client's `storageKeys.tokens`, `oidc_tokens` unless a prefix or profile says otherwise).
   *
   * Set this when the provider writes the session cookie under a name of its own. Only
   * the token blob is remapped; the transient `state`/`nonce`/verifier cookies keep their
   * library names, because the library is the only thing that ever writes them.
   */
  cookieName?: string;
  /** Lifetime of the refreshed cookie, in seconds (default 1 year). */
  cookieMaxAgeSeconds?: number;
  /**
   * How long before the access token expires a refresh is attempted, in seconds
   * (default 300).
   *
   * Refreshing early is what lets the refresh happen on a navigation, where it is one
   * request, rather than on whichever fetch happens to be first past the post.
   */
  refreshThresholdSeconds?: number;
  /**
   * Which requests may refresh (default `"navigation"`).
   */
  refreshOn?: "navigation" | "request";
}

/**
 * How close to expiry a token has to be for any request, navigation or not, to refresh it.
 * Past this there is nothing left to ride on, so waiting for a navigation would just fail.
 */
const REFRESH_FLOOR_SECONDS = 30;

/** Reads the request's cookies through the library's storage interface. */
class RequestCookieStorage implements AuthStorage {
  constructor(
    private request: NextRequest,
    private tokenKey: string,
    private tokenCookieName: string,
  ) {}

  getItem(key: string): string | null {
    // The token blob may live under a custom cookie name; the transient keys do not.
    const name = key === this.tokenKey ? this.tokenCookieName : key;
    return this.request.cookies.get(name)?.value ?? null;
  }

  setItem(): void {
    /* The response owns writes; see writeTokens(). */
  }
  removeItem(): void {
    /* The response owns deletes. */
  }
}

/**
 * Builds a Next.js middleware that gates routes on a verified session, refreshing tokens
 * that are about to expire.
 *
 * Per request, in order: read the session cookie, refresh if the access token is near expiry (writing the rotated tokens back onto the response)
 * then verify, with `enforce: "live"` ask the provider whether the session still stands, and check the `roles`/`permissions`/`amr` policy if one was given. A session that cannot be verified redirects to `loginPath` and expires the cookie, so a request never proceeds on one.
 *
 * Refreshes are attempted `refreshThresholdSeconds` before expiry and, by default, only on navigations - one per page load rather than one per parallel fetch, all of them presenting the same single-use refresh token.
 * A refresh that fails while the access token is still valid is ignored.
 *
 * Scope it with a `config.matcher` as usual - it runs on every matched request, and verification is not free even with the JWKS cached.
 *
 * ```ts
 * export default createAuthMiddleware({ ...authConfig, permissions: ['games_portal.admin'], enforce: 'live' });
 * export const config = { matcher: ['/admin/:path*'] };
 * ```
 */
export function createAuthMiddleware(options: AuthMiddlewareOptions) {
  const loginPath = options.loginPath ?? "/auth";
  const unauthorizedPath = options.unauthorizedPath ?? loginPath;
  const shouldVerify = options.verify !== false;
  const refreshThreshold = options.refreshThresholdSeconds ?? 300;
  const refreshOn = options.refreshOn ?? "navigation";
  const live = options.enforce === "live";

  if (live && !shouldVerify) throw new AuthError('`enforce: "live"` needs verification; it cannot be combined with `verify: false`.', "INVALID_CONFIG");
  if (live && !options.clientSecret) throw new AuthError('`enforce: "live"` asks the provider through introspection, which needs a `clientSecret`.', "INVALID_CONFIG");

  // Cached per configuration: the JWKS is then fetched once per runtime instance, not once
  // per request.
  const sharedClient = getCachedClient(options);
  const tokenKey = sharedClient.storageKeys.tokens;
  const cookieName = options.cookieName ?? tokenKey;

  return async (request: NextRequest) => {
    const redirectTo = (pathname: string) => {
      const url = request.nextUrl.clone();
      url.pathname = pathname;
      url.search = "";
      url.searchParams.set("callbackUrl", request.nextUrl.pathname);
      return url;
    };

    // The provider could not be asked. Failing closed without clearing the cookie keeps an outage from signing everyone out.
    const unavailable = () => new NextResponse("Could not confirm access with the identity provider.", { status: 503, headers: { "Retry-After": "5" } });

    /** `enforce: "live"`: the provider's answer, or a response to return when there is none to go on. */
    const askLive = async (): Promise<LiveAccess | NextResponse> => {
      let access: LiveAccess;
      try {
        access = await sharedClient.liveAccess(current.access_token);
      } catch {
        return unavailable();
      }
      return access.active ? access : signOut(loginPath);
    };

    const signOut = (pathname: string) => {
      const response = NextResponse.redirect(redirectTo(pathname));

      // Expiring a domain-scoped cookie requires naming the same domain. A bare
      // delete() only clears a host-only cookie, leaving the domain-wide one the
      // provider set in place - so the next request reads the same dead session and
      // the user loops. Set `cookieDomain` to whatever the provider writes.
      response.cookies.set(cookieName, "", {
        path: "/",
        maxAge: 0,
        domain: options.cookieDomain,
      });

      return response;
    };

    // Parsing goes through the library, which tolerates the URI-encoded form the identity
    // provider writes and returns null instead of throwing on a malformed cookie.
    const reader = new AuthClient(options, new RequestCookieStorage(request, tokenKey, cookieName));
    const tokens = reader.getStoredTokens();

    if (!tokens) {
      return request.cookies.has(cookieName) ? signOut(loginPath) : NextResponse.redirect(redirectTo(loginPath));
    }

    let response: NextResponse | null = null;
    let current: TokenResponse = tokens;

    const spent = sharedClient.isTokenNearExpiry(tokens.access_token, Math.min(refreshThreshold, REFRESH_FLOOR_SECONDS));
    const nearExpiry = spent || sharedClient.isTokenNearExpiry(tokens.access_token, refreshThreshold);
    const isNavigation = request.headers.get("sec-fetch-mode") === "navigate" || (request.headers.get("accept") ?? "").includes("text/html");

    if (nearExpiry && (spent || refreshOn === "request" || isNavigation)) {
      if (!tokens.refresh_token) {
        // Nothing to renew with. Sitting on a still-valid token is fine, a spent one is not.
        if (spent) return signOut(loginPath);
      } else {
        let rotated: TokenResponse | null = null;

        try {
          rotated = await sharedClient.refreshAccessToken(tokens.refresh_token, { persist: false });
        } catch {
          if (spent) return signOut(loginPath);
        }

        if (rotated) {
          current = rotated;

          response = NextResponse.next();
          response.cookies.set(cookieName, JSON.stringify(current), {
            path: "/",
            maxAge: options.cookieMaxAgeSeconds ?? 31536000,
            sameSite: "lax",
            secure: true,
            httpOnly: true,
            domain: options.cookieDomain,
          });
        }
      }
    }

    if (shouldVerify) {
      const needsClaims = !!(options.roles || options.permissions || options.amr);
      let access: LiveAccess | null = null;

      try {
        if (needsClaims) {
          // Resolves through the ID token when it is ours, or through the profile when the session belongs to a sibling service.
          const { user, error } = await resolveSessionUser(sharedClient, current);
          if (!user) throw error ?? new Error("no session");

          if (live) {
            const answer = await askLive();
            if (answer instanceof NextResponse) return answer;
            access = answer;
          }

          if (options.roles && !hasRole(user, options.roles)) {
            return NextResponse.redirect(redirectTo(unauthorizedPath));
          }
          // The live answer replaces the token's snapshot when the provider gave one.
          if (options.permissions && !hasPermission({ permissions: access?.permissions ?? user.permissions }, options.permissions)) {
            return NextResponse.redirect(redirectTo(unauthorizedPath));
          }
          if (options.amr && !satisfiesAmr(user, options.amr)) {
            return NextResponse.redirect(redirectTo(unauthorizedPath));
          }
        } else if (current.id_token && isAddressedTo(current.id_token, options.clientId)) {
          await sharedClient.verifyIdToken(current.id_token);
        } else if (options.apiAudience) {
          // No policy to enforce, so just verify
          await sharedClient.verifyAccessToken(current.access_token);
        } else {
          throw new Error("cannot verify a sibling service session without `apiAudience`");
        }
      } catch {
        return signOut(loginPath);
      }

      if (live && !needsClaims) {
        const answer = await askLive();
        if (answer instanceof NextResponse) return answer;
      }
    }

    return response ?? NextResponse.next();
  };
}

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AMR, assertAmr, AuthClient, AuthError, AuthorizationResponseError, ClaimValidationError, MemoryStorage, NonceMismatchError, NoTokenError, satisfiesAmr, StateMismatchError, DEFAULT_STORAGE_KEYS, StorageUnavailableError, TokenRefreshError, TokenVerificationError, UserInfoError, generateCodeChallenge, type AuthConfig } from "../src/index";
import { API_AUDIENCE, CLIENT_ID, OTHER_CLIENT_ID, attackerKeys, startFakeIdp, unsignedToken, type FakeIdp } from "./fake-idp";

let idp: FakeIdp;

const config = (overrides: Partial<AuthConfig> = {}): AuthConfig => ({
  clientId: CLIENT_ID,
  issuer: idp.issuer,
  redirectUri: "http://localhost:3000/callback",
  apiAudience: API_AUDIENCE,
  ...overrides,
});

const withStorage = (overrides: Partial<AuthConfig> = {}) => {
  const storage = new MemoryStorage();
  return { storage, client: new AuthClient(config(overrides), storage) };
};

beforeAll(async () => {
  idp = await startFakeIdp();
});

afterAll(async () => {
  await idp.close();
});

afterEach(() => {
  idp.setTokenHandler(null);
});

describe("createAuthorizeUrl", () => {
  it("binds state, nonce and a correct S256 PKCE challenge to the request", async () => {
    const { client } = withStorage();
    const request = await client.createAuthorizeUrl();
    const params = new URL(request.url).searchParams;

    expect(params.get("client_id")).toBe(CLIENT_ID);
    expect(params.get("redirect_uri")).toBe("http://localhost:3000/callback");
    expect(params.get("response_type")).toBe("code");
    expect(params.get("scope")).toBe("openid profile email");
    expect(params.get("state")).toBe(request.state);
    expect(params.get("nonce")).toBe(request.nonce);
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("code_challenge")).toBe(await generateCodeChallenge(request.codeVerifier));
    expect(request.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(request.codeVerifier.length).toBeLessThanOrEqual(128);
  });

  it("persists state, nonce and verifier so the callback can be validated", async () => {
    const { client, storage } = withStorage();
    const request = await client.createAuthorizeUrl();

    expect(storage.getItem(DEFAULT_STORAGE_KEYS.state)).toBe(request.state);
    expect(storage.getItem(DEFAULT_STORAGE_KEYS.nonce)).toBe(request.nonce);
    expect(storage.getItem(DEFAULT_STORAGE_KEYS.codeVerifier)).toBe(request.codeVerifier);
  });

  it("passes through prompt, acr_values and login_hint", async () => {
    const { client } = withStorage();
    const request = await client.createAuthorizeUrl({
      prompt: "consent",
      acrValues: ["mfa", "hw"],
      loginHint: "ada@example.com",
      scope: ["openid"],
    });
    const params = new URL(request.url).searchParams;

    expect(params.get("prompt")).toBe("consent");
    expect(params.get("acr_values")).toBe("mfa hw");
    expect(params.get("login_hint")).toBe("ada@example.com");
    expect(params.get("scope")).toBe("openid");
  });

  it("refuses to let extraParams override the security parameters", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { client } = withStorage();

    const request = await client.createAuthorizeUrl({
      extraParams: { state: "attacker-state", code_challenge: "attacker-challenge", ui_locales: "en" },
    });
    const params = new URL(request.url).searchParams;

    expect(params.get("state")).toBe(request.state);
    expect(params.get("code_challenge")).not.toBe("attacker-challenge");
    expect(params.get("ui_locales")).toBe("en");
    warn.mockRestore();
  });

  it("warns instead of silently losing state when no storage is configured", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = new AuthClient(config());

    const request = await client.createAuthorizeUrl();

    expect(request.state).toBeTruthy();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("did not persist"));
    await expect(client.createAuthorizeUrl({ persist: true })).rejects.toThrow(StorageUnavailableError);
    warn.mockRestore();
  });
});

describe("handleCallback", () => {
  const startFlow = async (overrides: Partial<AuthConfig> = {}) => {
    const { client, storage } = withStorage(overrides);
    const request = await client.createAuthorizeUrl();
    return { client, storage, request };
  };

  const respondWith = (idToken: () => Promise<string>) => {
    idp.setTokenHandler(async () => ({
      body: {
        access_token: await idp.mintAccessToken(),
        id_token: await idToken(),
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile email",
        refresh_token: "rotated-refresh-token",
      },
    }));
  };

  it("validates state, exchanges the code with PKCE and returns a verified user", async () => {
    const { client, storage, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    const result = await client.handleCallback(`http://localhost:3000/callback?code=the-code&state=${request.state}`);

    expect(result.user?.id).toBe("user-1");
    expect(result.user?.roles).toEqual([]);
    expect(result.user?.authMethods).toContain(AMR.FIDO);
    expect(result.state).toBe(request.state);
    expect(result.tokens.access_token).toBeTruthy();

    const sent = idp.tokenRequests.at(-1)!;
    expect(sent.get("grant_type")).toBe("authorization_code");
    expect(sent.get("code")).toBe("the-code");
    expect(sent.get("code_verifier")).toBe(request.codeVerifier);

    // Single-use values are cleared so the callback cannot be replayed.
    expect(storage.getItem(DEFAULT_STORAGE_KEYS.state)).toBeNull();
    expect(storage.getItem(DEFAULT_STORAGE_KEYS.nonce)).toBeNull();
    expect(storage.getItem(DEFAULT_STORAGE_KEYS.codeVerifier)).toBeNull();
  });

  it("rejects a mismatched state without touching the token endpoint", async () => {
    const { client } = await startFlow();
    const before = idp.tokenHits;

    await expect(client.handleCallback("http://localhost:3000/callback?code=c&state=not-the-state")).rejects.toThrow(StateMismatchError);
    expect(idp.tokenHits).toBe(before);
  });

  it("rejects a callback with no state at all", async () => {
    const { client } = await startFlow();

    await expect(client.handleCallback("http://localhost:3000/callback?code=c")).rejects.toThrow(StateMismatchError);
  });

  it("cannot be replayed once the transient state is consumed", async () => {
    const { client, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    const callbackUrl = `http://localhost:3000/callback?code=the-code&state=${request.state}`;
    await client.handleCallback(callbackUrl);

    await expect(client.handleCallback(callbackUrl)).rejects.toThrow(StateMismatchError);
  });

  it("surfaces a provider error response", async () => {
    const { client, storage, request } = await startFlow();

    await expect(client.handleCallback(`http://localhost:3000/callback?error=access_denied&error_description=User+said+no&state=${request.state}`)).rejects.toThrow(AuthorizationResponseError);
    expect(storage.getItem(DEFAULT_STORAGE_KEYS.state)).toBeNull();
  });

  it("requires an authorization code", async () => {
    const { client, request } = await startFlow();

    await expect(client.handleCallback(`http://localhost:3000/callback?state=${request.state}`)).rejects.toThrow(AuthError);
  });

  it("rejects an ID token bound to a different authorization request", async () => {
    const { client, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: "someone-elses-nonce" }));

    await expect(client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`)).rejects.toThrow(NonceMismatchError);
  });

  it("rejects an ID token minted for another application", async () => {
    const { client, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }, { audience: OTHER_CLIENT_ID }));

    await expect(client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`)).rejects.toThrow(TokenVerificationError);
  });

  it("fails when the provider returns no ID token for an OpenID request", async () => {
    const { client, request } = await startFlow();
    idp.setTokenHandler(async () => ({ body: { access_token: await idp.mintAccessToken(), token_type: "Bearer" } }));

    await expect(client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`)).rejects.toThrow(NoTokenError);
  });

  it("accepts caller-managed state for server-side flows", async () => {
    const client = new AuthClient(config());
    const request = await client.createAuthorizeUrl({ persist: false });
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    const result = await client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`, {
      expected: { state: request.state, nonce: request.nonce, codeVerifier: request.codeVerifier },
    });

    expect(result.user?.id).toBe("user-1");
  });

  it("refuses to run blind when there is neither storage nor supplied expectations", async () => {
    const client = new AuthClient(config());

    await expect(client.handleCallback("http://localhost:3000/callback?code=c&state=s")).rejects.toThrow(StorageUnavailableError);
  });

  it("optionally persists the token response", async () => {
    const { client, storage, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    await client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`, { persistTokens: true });

    expect(client.getStoredTokens()?.refresh_token).toBe("rotated-refresh-token");
    expect(storage.getItem(DEFAULT_STORAGE_KEYS.tokens)).toBeTruthy();
  });

  it("accepts URLSearchParams as well as a URL", async () => {
    const { client, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    const params = new URLSearchParams({ code: "c", state: request.state });
    await expect(client.handleCallback(params)).resolves.toMatchObject({ state: request.state });
  });
});

describe("refreshAccessToken", () => {
  it("collapses concurrent refreshes into a single request", async () => {
    const { client } = withStorage();
    idp.setTokenHandler(async () => ({
      body: { access_token: await idp.mintAccessToken(), refresh_token: "next-refresh", token_type: "Bearer", expires_in: 3600 },
    }));
    const before = idp.tokenHits;

    const [a, b, c] = await Promise.all([client.refreshAccessToken("rt-1"), client.refreshAccessToken("rt-1"), client.refreshAccessToken("rt-1")]);

    expect(idp.tokenHits - before).toBe(1);
    expect(a.access_token).toBe(b.access_token);
    expect(b.access_token).toBe(c.access_token);
  });

  it("writes the rotated tokens back when the library is managing storage", async () => {
    const { client } = withStorage();
    client.saveTokens({ access_token: "old-access", refresh_token: "rt-1" });
    idp.setTokenHandler(async () => ({
      body: { access_token: await idp.mintAccessToken(), refresh_token: "rt-2", token_type: "Bearer", expires_in: 3600 },
    }));

    await client.refreshAccessToken("rt-1");

    expect(client.getStoredTokens()?.refresh_token).toBe("rt-2");
  });

  it("leaves storage alone when the caller manages tokens itself", async () => {
    const { client, storage } = withStorage();
    idp.setTokenHandler(async () => ({
      body: { access_token: await idp.mintAccessToken(), refresh_token: "rt-2", token_type: "Bearer" },
    }));

    await client.refreshAccessToken("rt-1");

    expect(storage.getItem(DEFAULT_STORAGE_KEYS.tokens)).toBeNull();
  });

  it("reports refresh failures and requires a token", async () => {
    const { client } = withStorage();
    idp.setTokenHandler(() => ({ status: 400, body: { error: "invalid_grant" } }));

    await expect(client.refreshAccessToken("rt-1")).rejects.toThrow(TokenRefreshError);
    await expect(client.refreshAccessToken("")).rejects.toThrow(NoTokenError);
  });

  it("does not reuse a settled in-flight request", async () => {
    const { client } = withStorage();
    idp.setTokenHandler(async () => ({ body: { access_token: await idp.mintAccessToken(), token_type: "Bearer" } }));
    const before = idp.tokenHits;

    await client.refreshAccessToken("rt-1");
    await client.refreshAccessToken("rt-1");

    expect(idp.tokenHits - before).toBe(2);
  });
});

describe("expiry hints", () => {
  it("treats a token with no exp claim as expired rather than valid forever", async () => {
    const { client } = withStorage();

    const eternal = unsignedToken({ sub: "user-1", role: "admin" });
    expect(client.isTokenNearExpiry(eternal)).toBe(true);
  });

  it("treats an unparseable token as expired", () => {
    const { client } = withStorage();

    expect(client.isTokenNearExpiry("garbage")).toBe(true);
    expect(client.isTokenNearExpiry("")).toBe(true);
  });

  it("reports live and near-expiry tokens correctly", async () => {
    const { client } = withStorage();

    expect(client.isTokenNearExpiry(await idp.mintAccessToken())).toBe(false);
    expect(client.isTokenNearExpiry(await idp.mintAccessToken({}, { expiresInSeconds: -1 }))).toBe(true);
    expect(client.isTokenNearExpiry(await idp.mintAccessToken({}, { expiresInSeconds: 30 }), 60)).toBe(true);
    expect(client.isTokenNearExpiry(await idp.mintAccessToken({}, { expiresInSeconds: 30 }), 10)).toBe(false);
  });
});

describe("storage handling", () => {
  it("fails with a descriptive error instead of a TypeError when no storage exists", () => {
    const client = new AuthClient(config());

    expect(client.hasStorage()).toBe(false);
    expect(() => client.saveTokens({ access_token: "a" })).toThrow(StorageUnavailableError);
    expect(() => client.saveTokens({ access_token: "a" })).toThrow(/requires a storage implementation/);
    expect(client.getStoredTokens()).toBeNull();
    expect(() => client.clearStorage()).not.toThrow();
  });

  it("round-trips tokens and clears them", () => {
    const { client, storage } = withStorage();

    client.saveTokens({ access_token: "a", refresh_token: "r" });
    expect(client.getStoredTokens()).toEqual({ access_token: "a", refresh_token: "r" });

    client.clearStorage();
    expect(storage.getItem(DEFAULT_STORAGE_KEYS.tokens)).toBeNull();
  });

  it("reads the URI-encoded cookie form the identity provider writes", () => {
    const { client, storage } = withStorage();
    storage.setItem(DEFAULT_STORAGE_KEYS.tokens, encodeURIComponent(JSON.stringify({ access_token: "a", id_token: "b" })));

    expect(client.getStoredTokens()).toEqual({ access_token: "a", id_token: "b" });
  });

  it("returns null for junk in storage rather than throwing", () => {
    const { client, storage } = withStorage();

    storage.setItem(DEFAULT_STORAGE_KEYS.tokens, "not json");
    expect(client.getStoredTokens()).toBeNull();

    storage.setItem(DEFAULT_STORAGE_KEYS.tokens, JSON.stringify({ nothing: true }));
    expect(client.getStoredTokens()).toBeNull();
  });
});

describe("profile fetching", () => {
  it("returns display claims only from userinfo", async () => {
    const { client } = withStorage();

    const profile = await client.getUser(await idp.mintAccessToken());

    expect(profile).toEqual({ id: "user-1", name: "Ada Lovelace", email: "ada@example.com", emailVerified: true, picture: undefined });
    expect("role" in profile).toBe(false);
    expect("authMethods" in profile).toBe(false);
    expect("sessionVersion" in profile).toBe(false);
  });

  it("reports userinfo failures and requires a token", async () => {
    const { client } = withStorage();
    idp.setUserinfo({ error: "invalid_token" }, 401);

    await expect(client.getUser(await idp.mintAccessToken())).rejects.toThrow(UserInfoError);
    await expect(client.hydrateSession()).resolves.toBeNull();
    await expect(client.getUser("")).rejects.toThrow(NoTokenError);

    idp.setUserinfo({ sub: "user-1", name: "Ada Lovelace", email: "ada@example.com", email_verified: true }, 200);
  });

  it("rejects a userinfo payload with no subject", async () => {
    const { client } = withStorage();
    idp.setUserinfo({ name: "nobody" }, 200);

    await expect(client.getUser(await idp.mintAccessToken())).rejects.toThrow(ClaimValidationError);

    idp.setUserinfo({ sub: "user-1", name: "Ada Lovelace", email: "ada@example.com", email_verified: true }, 200);
  });
});

describe("introspection", () => {
  const confidential = () => {
    const storage = new MemoryStorage();
    return new AuthClient(config({ clientSecret: "shh" }), storage);
  };

  it("posts the token with client credentials and returns the response", async () => {
    idp.setIntrospection({ active: true, sub: "user-1", role: "admin", session_version: 3 });
    const client = confidential();

    const result = await client.introspectToken(await idp.mintAccessToken());

    expect(result.active).toBe(true);
    expect(result.session_version).toBe(3);

    const sent = idp.introspectionRequests.at(-1)!;
    expect(sent.get("client_id")).toBe(CLIENT_ID);
    expect(sent.get("client_secret")).toBe("shh");
    expect(sent.get("token")).toBeTruthy();
  });

  it("refuses to introspect from a public client", async () => {
    const { client } = withStorage();

    await expect(client.introspectToken(await idp.mintAccessToken())).rejects.toThrow(/requires a `clientSecret`/);
  });

  it("reports a provider that advertises no introspection endpoint", async () => {
    idp.setIntrospection({ active: true }, { advertise: false });
    try {
      await expect(confidential().introspectToken(await idp.mintAccessToken())).rejects.toThrow(/introspection_endpoint/);
    } finally {
      idp.setIntrospection({ active: true, sub: "user-1", role: "admin", session_version: 3 });
    }
  });

  it("rejects a failed or malformed introspection response", async () => {
    idp.setIntrospection({ error: "invalid_client" }, { status: 401 });
    await expect(confidential().introspectToken(await idp.mintAccessToken())).rejects.toThrow(/status 401/);

    idp.setIntrospection({ not: "an introspection response" });
    await expect(confidential().introspectToken(await idp.mintAccessToken())).rejects.toThrow(/unexpected payload/);

    idp.setIntrospection({ active: true, sub: "user-1", role: "admin", session_version: 3 });
  });
});

describe("resolveSession (framework-agnostic routing)", () => {
  const dash = (overrides: Partial<AuthConfig> = {}) => new AuthClient(config({ clientId: "dash-service", clientSecret: "shh", ...overrides }), new MemoryStorage());

  beforeEach(() => {
    idp.setIntrospection({ active: true, sub: "user-1", role: "admin", amr: ["mfa", "fido", "hw"], session_version: 3 });
  });

  it("verifies our own ID token without introspecting", async () => {
    const before = idp.introspectionRequests.length;

    const user = await dash().resolveSession({
      id_token: await idp.mintIdToken({}, { audience: "dash-service" }),
      access_token: await idp.mintAccessToken(),
    });

    expect(user.source).toBe("id_token");
    expect(idp.introspectionRequests.length).toBe(before);
  });

  it("explains a foreign session when no profile can resolve shared sessions", async () => {
    // Standards-only core has no shared-session mechanism, so even a confidential, pinned client refuses.
    const notConfigured = dash();

    await expect(
      notConfigured.resolveSession({
        id_token: await idp.mintIdToken({}, { audience: "go-service" }),
        access_token: await idp.mintAccessToken(),
      }),
    ).rejects.toMatchObject({ code: "FOREIGN_SESSION" });
  });

  it("requires something to verify", async () => {
    await expect(dash().resolveSession({})).rejects.toThrow(NoTokenError);
  });

  it("does not let a forged audience skip verification", async () => {
    // Claims to be ours, so routing picks the ID token path - where it fails properly.
    const forged = unsignedToken({
      sub: "attacker",
      role: "admin",
      aud: "dash-service",
      iss: idp.issuer,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    await expect(dash().resolveSession({ id_token: forged, access_token: await idp.mintAccessToken() })).rejects.toThrow(TokenVerificationError);
  });
});

describe("amr helpers", () => {
  it("requires every listed method by default", () => {
    const user = { authMethods: ["mfa", "fido", "hw"] };

    expect(satisfiesAmr(user, [AMR.MFA, AMR.FIDO])).toBe(true);
    expect(satisfiesAmr(user, [AMR.OTP])).toBe(false);
    expect(satisfiesAmr(user, [AMR.MFA, AMR.OTP])).toBe(false);
    expect(satisfiesAmr(user, [AMR.MFA, AMR.OTP], { mode: "any" })).toBe(true);
  });

  it("does not treat a social login as multi-factor", () => {
    const social = { authMethods: ["ext", "social"] };

    expect(satisfiesAmr(social, [AMR.MFA])).toBe(false);
    expect(satisfiesAmr(social, [AMR.HARDWARE])).toBe(false);
  });

  it("fails closed on missing or empty methods", () => {
    expect(satisfiesAmr(undefined, [AMR.MFA])).toBe(false);
    expect(satisfiesAmr({ authMethods: [] }, [AMR.MFA])).toBe(false);
    expect(satisfiesAmr({}, [AMR.MFA])).toBe(false);
    expect(satisfiesAmr(undefined, [])).toBe(true);
  });

  it("asserts with a descriptive error", () => {
    expect(() => assertAmr({ authMethods: ["ext", "social"] }, [AMR.FIDO])).toThrow(ClaimValidationError);
    expect(() => assertAmr({ authMethods: ["mfa"] }, [AMR.MFA])).not.toThrow();
  });
});

describe("configuration validation", () => {
  it("rejects incomplete configuration at construction", () => {
    expect(() => new AuthClient({ issuer: "https://id.wilsoon.dev", redirectUri: "x" } as unknown as AuthConfig)).toThrow(AuthError);
    expect(() => new AuthClient({ clientId: "c", redirectUri: "x" } as unknown as AuthConfig)).toThrow(AuthError);
    expect(() => new AuthClient({ clientId: "c", issuer: "not-a-url", redirectUri: "x" })).toThrow(/absolute URL/);
  });

  it("lets a verify-only client omit the redirectUri", async () => {
    const verifier = new AuthClient({ clientId: CLIENT_ID, issuer: idp.issuer, apiAudience: API_AUDIENCE });

    await expect(verifier.verifyIdToken(await idp.mintIdToken())).resolves.toMatchObject({ id: "user-1" });
    await expect(verifier.verifyAccessToken(await idp.mintAccessToken())).resolves.toMatchObject({ subject: "user-1" });

    // ...but it cannot start a login.
    await expect(verifier.createAuthorizeUrl()).rejects.toThrow(/redirectUri/);
    await expect(verifier.exchangeCodeForToken("c", "v")).rejects.toThrow(/redirectUri/);
  });

  it("warns when the issuer is not HTTPS", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    new AuthClient({ clientId: "c", issuer: "http://id.example.com", redirectUri: "http://localhost/cb" });

    expect(warn).toHaveBeenCalledWith(expect.stringContaining("not HTTPS"));
    warn.mockRestore();
  });
});

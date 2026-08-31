import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuthClient, AuthError, buildAuthenticationChallenge, ClaimValidationError, INSUFFICIENT_USER_AUTHENTICATION, isStepUpChallenge, MemoryStorage, readAuthenticationChallenge } from "../src/index";
import { API_AUDIENCE, CLIENT_ID, startFakeIdp, type FakeIdp } from "./fake-idp";

let idp: FakeIdp;

const client = () =>
  new AuthClient(
    {
      clientId: CLIENT_ID,
      issuer: idp.issuer,
      redirectUri: "http://localhost:3000/callback",
      apiAudience: API_AUDIENCE,
    },
    new MemoryStorage(),
  );

beforeAll(async () => {
  idp = await startFakeIdp();
});

afterAll(async () => {
  await idp.close();
});

describe("readAuthenticationChallenge", () => {
  it("parses the challenge RFC 9470 describes", () => {
    const challenge = readAuthenticationChallenge('Bearer realm="api", error="insufficient_user_authentication", ' + 'error_description="A passkey is required.", acr_values="urn:wilsoon:acr:passkey", max_age=300');

    expect(challenge?.scheme).toBe("bearer");
    expect(challenge?.error).toBe(INSUFFICIENT_USER_AUTHENTICATION);
    expect(challenge?.acrValues).toEqual(["urn:wilsoon:acr:passkey"]);
    expect(challenge?.maxAge).toBe(300);
    expect(challenge?.realm).toBe("api");
    expect(isStepUpChallenge(challenge)).toBe(true);
  });

  it("splits multiple acr values and scopes on whitespace", () => {
    const challenge = readAuthenticationChallenge('Bearer acr_values="a b c", scope="read write"');

    expect(challenge?.acrValues).toEqual(["a", "b", "c"]);
    expect(challenge?.scope).toEqual(["read", "write"]);
  });

  it("accepts unquoted parameter values", () => {
    const challenge = readAuthenticationChallenge("Bearer error=insufficient_user_authentication, max_age=0");

    expect(challenge?.error).toBe(INSUFFICIENT_USER_AUTHENTICATION);
    expect(challenge?.maxAge).toBe(0);
  });

  it("handles an escaped quote inside a description", () => {
    const challenge = readAuthenticationChallenge('Bearer error_description="the \\"strong\\" method", max_age=60');

    expect(challenge?.errorDescription).toBe('the "strong" method');
    expect(challenge?.maxAge).toBe(60);
  });

  it("stops at the second challenge rather than merging two schemes", () => {
    const challenge = readAuthenticationChallenge('Bearer error="invalid_token", Basic realm="other"');

    expect(challenge?.scheme).toBe("bearer");
    expect(challenge?.realm).toBeUndefined();
  });

  it("returns null for nothing usable, since a 401 need not be about step-up", () => {
    expect(readAuthenticationChallenge(null)).toBeNull();
    expect(readAuthenticationChallenge(undefined)).toBeNull();
    expect(readAuthenticationChallenge("")).toBeNull();
    expect(readAuthenticationChallenge("   ")).toBeNull();
  });

  it("distinguishes a step-up demand from an ordinary rejection", () => {
    expect(isStepUpChallenge(readAuthenticationChallenge('Bearer error="invalid_token"'))).toBe(false);
    expect(isStepUpChallenge(readAuthenticationChallenge('Bearer realm="api"'))).toBe(false);
    expect(isStepUpChallenge(null)).toBe(false);
  });

  it("ignores a non-numeric max_age instead of producing NaN", () => {
    expect(readAuthenticationChallenge('Bearer max_age="soon"')?.maxAge).toBeUndefined();
  });
});

describe("buildAuthenticationChallenge", () => {
  it("produces a header the parser reads back identically", () => {
    const header = buildAuthenticationChallenge({
      acrValues: ["urn:wilsoon:acr:passkey"],
      maxAge: 300,
      errorDescription: "A passkey is required for this action.",
      realm: "api",
    });

    const round = readAuthenticationChallenge(header);
    expect(round?.error).toBe(INSUFFICIENT_USER_AUTHENTICATION);
    expect(round?.acrValues).toEqual(["urn:wilsoon:acr:passkey"]);
    expect(round?.maxAge).toBe(300);
    expect(round?.realm).toBe("api");
  });

  it("defaults to the step-up error code", () => {
    expect(buildAuthenticationChallenge({ acrValues: "x" })).toContain(`error="${INSUFFICIENT_USER_AUTHENTICATION}"`);
  });

  it("escapes a quote in the description rather than breaking the header", () => {
    const header = buildAuthenticationChallenge({ errorDescription: 'needs "passkey"', acrValues: "x" });

    expect(readAuthenticationChallenge(header)?.errorDescription).toBe('needs "passkey"');
  });

  it("emits max_age: 0, which demands a fresh authentication", () => {
    expect(readAuthenticationChallenge(buildAuthenticationChallenge({ maxAge: 0 }))?.maxAge).toBe(0);
  });
});

describe("createAuthorizeUrl with max_age", () => {
  it("sends max_age when asked, and omits it otherwise", async () => {
    const withAge = await client().createAuthorizeUrl({ maxAge: 300 });
    expect(new URL(withAge.url).searchParams.get("max_age")).toBe("300");

    const without = await client().createAuthorizeUrl();
    expect(new URL(without.url).searchParams.get("max_age")).toBeNull();
  });

  it("sends max_age=0, which is a demand rather than an absent value", async () => {
    const { url } = await client().createAuthorizeUrl({ maxAge: 0 });
    expect(new URL(url).searchParams.get("max_age")).toBe("0");
  });
});

describe("createStepUpRequest", () => {
  it("carries the challenge straight into the authorization request", async () => {
    const header = buildAuthenticationChallenge({ acrValues: "urn:wilsoon:acr:passkey", maxAge: 120 });

    const { url } = await client().createStepUpRequest(header);
    const params = new URL(url).searchParams;

    expect(params.get("acr_values")).toBe("urn:wilsoon:acr:passkey");
    expect(params.get("max_age")).toBe("120");
    expect(params.get("code_challenge_method")).toBe("S256");
  });

  it("does not carry a scope from the challenge into the request", async () => {
    // A challenge arrives over the network. acr_values and max_age can only ask for stronger
    // authentication, but a scope taken from the same header would let a resource server
    // widen what this client requests on the user's behalf.
    const header = 'Bearer error="insufficient_user_authentication", acr_values="urn:a", scope="admin:write"';

    const { url } = await client().createStepUpRequest(header);
    expect(new URL(url).searchParams.get("scope")).not.toContain("admin:write");
    expect(readAuthenticationChallenge(header)?.scope).toEqual(["admin:write"]);
  });

  it("accepts an already-parsed challenge", async () => {
    const challenge = readAuthenticationChallenge('Bearer acr_values="a b", max_age=60')!;

    const { url } = await client().createStepUpRequest(challenge);
    expect(new URL(url).searchParams.get("acr_values")).toBe("a b");
  });

  it("lets the caller tighten what the resource asked for", async () => {
    const header = buildAuthenticationChallenge({ acrValues: "urn:wilsoon:acr:mfa", maxAge: 900 });

    const { url } = await client().createStepUpRequest(header, {
      acrValues: "urn:wilsoon:acr:passkey",
      maxAge: 60,
    });
    const params = new URL(url).searchParams;

    expect(params.get("acr_values")).toBe("urn:wilsoon:acr:passkey");
    expect(params.get("max_age")).toBe("60");
  });

  it("refuses a challenge with nothing to step up to", async () => {
    await expect(client().createStepUpRequest('Bearer error="invalid_token"')).rejects.toThrow(/nothing to step up to/);
  });

  it("refuses an unparseable header", async () => {
    await expect(client().createStepUpRequest("")).rejects.toThrow(AuthError);
  });
});

describe("requiredAcr on verifyIdToken", () => {
  it("accepts a token whose acr is one of the accepted values", async () => {
    const token = await idp.mintIdToken({ acr: "urn:wilsoon:acr:passkey" });

    const user = await client().verifyIdToken(token, {
      requiredAcr: ["urn:wilsoon:acr:passkey", "urn:wilsoon:acr:mfa"],
    });
    expect(user.claims.acr).toBe("urn:wilsoon:acr:passkey");
  });

  it("rejects a weaker acr than was demanded", async () => {
    // The provider ignored acr_values and returned a valid token describing a weaker login.
    // Without this check the client would have accepted it as a successful step-up.
    const token = await idp.mintIdToken({ acr: "urn:wilsoon:acr:social" });

    await expect(client().verifyIdToken(token, { requiredAcr: "urn:wilsoon:acr:passkey" })).rejects.toThrow(ClaimValidationError);
  });

  it("rejects a token carrying no acr at all", async () => {
    await expect(client().verifyIdToken(await idp.mintIdToken(), { requiredAcr: "urn:wilsoon:acr:passkey" })).rejects.toThrow(/does not satisfy/);
  });

  it("accepts a single string as well as a list", async () => {
    const token = await idp.mintIdToken({ acr: "urn:wilsoon:acr:mfa" });

    const user = await client().verifyIdToken(token, { requiredAcr: "urn:wilsoon:acr:mfa" });
    expect(user.id).toBe("user-1");
  });

  it("leaves acr unchecked when nothing was required", async () => {
    const user = await client().verifyIdToken(await idp.mintIdToken({ acr: "anything" }));
    expect(user.claims.acr).toBe("anything");
  });
});

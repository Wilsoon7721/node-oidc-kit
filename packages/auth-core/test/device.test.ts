import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
    AuthClient,
    AuthorizationDeniedError,
    AuthorizationExpiredError,
    DeviceFlowError,
    DEVICE_GRANT_TYPE,
    MemoryStorage,
} from '../src/index';
import { API_AUDIENCE, CLIENT_ID, startFakeIdp, type FakeIdp } from './fake-idp';

let idp: FakeIdp;

const client = (overrides: Record<string, unknown> = {}) => new AuthClient({
    clientId: CLIENT_ID,
    issuer: idp.issuer,
    apiAudience: API_AUDIENCE,
    ...overrides,
}, new MemoryStorage());

/** A device authorization with a 0s interval, so the poll loop does not actually wait. */
const instantAuthorization = { deviceCode: 'dev-code-1', interval: 0 };

beforeAll(async () => {
    idp = await startFakeIdp();
});

afterEach(() => {
    idp.setTokenHandler(null);
    idp.setDeviceCode(null);
});

afterAll(async () => {
    await idp.close();
});

describe('requestDeviceCode', () => {
    it('returns the code to show and the code to poll with, kept separate', async () => {
        const authorization = await client().requestDeviceCode();

        expect(authorization.userCode).toBe('BCDF-GHJK');
        expect(authorization.deviceCode).toBe('dev-code-1');
        expect(authorization.verificationUri).toContain('/device');
        expect(authorization.verificationUriComplete).toContain('user_code=BCDF-GHJK');
        expect(authorization.interval).toBe(1);
    });

    it('turns the provider expires_in into an absolute deadline', async () => {
        const before = Math.floor(Date.now() / 1000);
        const authorization = await client().requestDeviceCode();

        expect(authorization.expiresIn).toBe(600);
        expect(authorization.expiresAt).toBeGreaterThanOrEqual(before + 600);
    });

    it('requests the configured scopes, and the caller can override them', async () => {
        const before = idp.deviceCodeRequests.length;

        await client({ scope: ['openid', 'email'] }).requestDeviceCode();
        expect(idp.deviceCodeRequests[before].get('scope')).toBe('openid email');

        await client().requestDeviceCode({ scope: ['openid', 'offline_access'] });
        expect(idp.deviceCodeRequests[before + 1].get('scope')).toBe('openid offline_access');
    });

    it('sends no client secret for a public client, which is the expected case here', async () => {
        const before = idp.deviceCodeRequests.length;

        await client().requestDeviceCode();

        expect(idp.deviceCodeRequests[before].get('client_id')).toBe(CLIENT_ID);
        expect(idp.deviceCodeRequests[before].get('client_secret')).toBeNull();
    });

    it('still sends the secret when the client registered one', async () => {
        const before = idp.deviceCodeRequests.length;

        await client({ clientSecret: 'shh' }).requestDeviceCode();

        expect(idp.deviceCodeRequests[before].get('client_secret')).toBe('shh');
    });

    it('surfaces unauthorized_client when the app is not registered for the grant', async () => {
        idp.setDeviceCode({ error: 'unauthorized_client', error_description: 'Not registered for the device grant.' }, { status: 400 });

        await client().requestDeviceCode().catch((error: DeviceFlowError) => {
            expect(error).toBeInstanceOf(DeviceFlowError);
            expect(error.error).toBe('unauthorized_client');
        });
        expect.assertions(2);
    });

    it('refuses to start when the provider advertises no device endpoint', async () => {
        idp.setDeviceCode(null, { advertise: false });

        // A fresh client, so the cached discovery document is re-read.
        await expect(client().requestDeviceCode()).rejects.toThrow(/does not support the device grant/);

        idp.setDeviceCode(null, { advertise: true });
    });
});

describe('pollDeviceToken', () => {
    it('presents the RFC 8628 grant type and the device code', async () => {
        idp.setTokenHandler(() => ({ body: { access_token: 'at', token_type: 'Bearer' } }));
        const before = idp.tokenRequests.length;

        await client().pollDeviceToken(instantAuthorization);

        const sent = idp.tokenRequests[before];
        expect(sent.get('grant_type')).toBe(DEVICE_GRANT_TYPE);
        expect(sent.get('device_code')).toBe('dev-code-1');
        expect(sent.get('client_id')).toBe(CLIENT_ID);
    });

    it('reports authorization_pending as pending rather than as a failure', async () => {
        idp.setTokenHandler(() => ({ status: 400, body: { error: 'authorization_pending', interval: 3 } }));

        const step = await client().pollDeviceToken(instantAuthorization);

        expect(step.state).toBe('pending');
        if (step.state === 'pending') expect(step.interval).toBe(3);
    });

    it('adopts the raised interval on slow_down instead of failing the request', async () => {
        idp.setTokenHandler(() => ({ status: 400, body: { error: 'slow_down', interval: 9 } }));

        const step = await client().pollDeviceToken(instantAuthorization);

        expect(step.state).toBe('pending');
        if (step.state === 'pending') {
            expect(step.slowDown).toBe(true);
            expect(step.interval).toBe(9);
        }
    });

    it('throws a denial and an expiry as distinct errors', async () => {
        idp.setTokenHandler(() => ({ status: 400, body: { error: 'access_denied', error_description: 'Refused.' } }));
        await expect(client().pollDeviceToken(instantAuthorization)).rejects.toThrow(AuthorizationDeniedError);

        idp.setTokenHandler(() => ({ status: 400, body: { error: 'expired_token', error_description: 'Too late.' } }));
        await expect(client().pollDeviceToken(instantAuthorization)).rejects.toThrow(AuthorizationExpiredError);
    });

    it('treats a redeemed device code as a flow error, not as "keep polling"', async () => {
        // Device codes are single use: the provider marks one spent before minting from it,
        // so polling after success lands here rather than yielding a second token family.
        idp.setTokenHandler(() => ({ status: 400, body: { error: 'invalid_grant', error_description: 'Device code already used.' } }));

        await client().pollDeviceToken(instantAuthorization).catch((error: DeviceFlowError) => {
            expect(error).toBeInstanceOf(DeviceFlowError);
            expect(error.error).toBe('invalid_grant');
        });
        expect.assertions(2);
    });
});

describe('authorizeDevice', () => {
    it('shows the code once, polls past pending rounds, and verifies the user', async () => {
        let calls = 0;
        idp.setTokenHandler(async () => {
            calls += 1;
            if (calls < 3) return { status: 400, body: { error: 'authorization_pending', interval: 1 } };
            return {
                body: {
                    access_token: await idp.mintAccessToken(),
                    id_token: await idp.mintIdToken(),
                    token_type: 'Bearer',
                    expires_in: 3600,
                },
            };
        });
        const onUserCode = vi.fn();

        const result = await client().authorizeDevice({ onUserCode });

        expect(onUserCode).toHaveBeenCalledTimes(1);
        expect(onUserCode.mock.calls[0][0].userCode).toBe('BCDF-GHJK');
        expect(calls).toBe(3);
        expect(result.user?.id).toBe('user-1');
        expect(result.tokens.access_token).toBeTruthy();
        expect(result.authorization.userCode).toBe('BCDF-GHJK');
    }, 20000);

    it('carries the approving session\'s acr through to the device token', async () => {
        // The device never sees a session, so its acr is the acr of the browser that
        // approved it - a passkey approval hands the CLI a passkey-level token.
        idp.setTokenHandler(async () => ({
            body: {
                access_token: await idp.mintAccessToken(),
                id_token: await idp.mintIdToken({ acr: 'urn:wilsoon:acr:passkey' }),
                token_type: 'Bearer',
            },
        }));

        const result = await client().authorizeDevice();

        expect(result.user?.claims.acr).toBe('urn:wilsoon:acr:passkey');
        expect(result.user?.authMethods).toContain('fido');
    });

    it('returns the raw tokens without a user when verification is turned off', async () => {
        idp.setTokenHandler(async () => ({
            body: { access_token: await idp.mintAccessToken(), id_token: await idp.mintIdToken(), token_type: 'Bearer' },
        }));

        const result = await client().authorizeDevice({ verifyUser: false });

        expect(result.user).toBeNull();
        expect(result.tokens.id_token).toBeTruthy();
    });

    it('propagates a denial instead of waiting for a deadline that will never come', async () => {
        idp.setTokenHandler(() => ({ status: 400, body: { error: 'access_denied', error_description: 'Refused.' } }));

        await expect(client().authorizeDevice()).rejects.toThrow(AuthorizationDeniedError);
    });

    it('can be cancelled with an abort signal', async () => {
        const controller = new AbortController();
        idp.setTokenHandler(() => {
            controller.abort(new Error('ctrl-c'));
            return { status: 400, body: { error: 'authorization_pending', interval: 1 } };
        });

        await expect(client().authorizeDevice({ signal: controller.signal })).rejects.toThrow('ctrl-c');
    });
});

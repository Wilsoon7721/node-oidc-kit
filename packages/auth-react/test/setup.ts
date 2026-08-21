import { webcrypto } from 'node:crypto';
import { TextDecoder, TextEncoder } from 'node:util';
import { URLSearchParams as NodeURLSearchParams } from 'node:url';

/**
 * Environment repairs for jsdom. None of this reflects product behaviour.
 *
 * jsdom installs typed-array builtins from its own realm, so `globalThis.Uint8Array` is not
 * the constructor `TextEncoder`/`Buffer` actually produce - `Buffer.from('x') instanceof
 * Uint8Array` is `false` under vitest's jsdom environment. `jose` guards its inputs with
 * `instanceof Uint8Array`, so signing a token inside a test would fail on the realm boundary
 * rather than on anything real. Pinning the builtins to Node's realm makes them agree.
 *
 * jsdom does the same to `URLSearchParams`: `exchangeCodeForToken()` builds the token
 * request body with `new URLSearchParams(...)`, which under jsdom constructs jsdom's class,
 * not Node's. Node's own `fetch()` passes that straight through - but whether its `Request`
 * constructor accepts a foreign `URLSearchParams` as a body depends on the undici version
 * bundled with the Node major running the test, so this passed locally and failed in CI on
 * an older Node before it was pinned here.
 *
 * jsdom also ships no `crypto.subtle`, which PKCE needs.
 */
const sample = new TextEncoder().encode('');

Object.assign(globalThis, {
    TextEncoder,
    TextDecoder,
    Uint8Array: sample.constructor,
    ArrayBuffer: sample.buffer.constructor,
    URLSearchParams: NodeURLSearchParams,
});

if (!globalThis.crypto?.subtle) {
    Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true, writable: true });
}

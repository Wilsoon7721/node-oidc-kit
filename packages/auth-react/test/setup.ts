import { webcrypto } from 'node:crypto';
import { TextDecoder, TextEncoder } from 'node:util';

/**
 * Environment repairs for jsdom. None of this reflects product behaviour.
 *
 * jsdom installs typed-array builtins from its own realm, so `globalThis.Uint8Array` is not
 * the constructor `TextEncoder`/`Buffer` actually produce - `Buffer.from('x') instanceof
 * Uint8Array` is `false` under vitest's jsdom environment. `jose` guards its inputs with
 * `instanceof Uint8Array`, so signing a token inside a test would fail on the realm boundary
 * rather than on anything real. Pinning the builtins to Node's realm makes them agree.
 *
 * jsdom also ships no `crypto.subtle`, which PKCE needs.
 */
const sample = new TextEncoder().encode('');

Object.assign(globalThis, {
    TextEncoder,
    TextDecoder,
    Uint8Array: sample.constructor,
    ArrayBuffer: sample.buffer.constructor,
});

if (!globalThis.crypto?.subtle) {
    Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true, writable: true });
}

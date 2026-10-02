/**
 * @module PrfKeys
 * @description
 * One read of the passkey's PRF output, and the keys an application derives
 * from it.
 *
 * The PRF output is the secret every key here starts from. The same passkey
 * answers the same PRF input with the same bytes on every device that holds
 * it — a synced passkey, or a security key carried from one machine to the
 * next — and nothing without the passkey can produce them. An application
 * derives what it needs from that answer with HKDF under its own `info`
 * string: a database key, a database name, a key that seals something. The
 * identity provider derives the OrbitDB signing key from it under its own.
 * HKDF with different `info` strings yields independent keys, so one answer
 * serves all of them without one revealing another.
 *
 * Read it once and derive everything from that one answer. Each read is an
 * assertion, and an assertion is a touch: `ensureDerivedSigningKey` takes the
 * same answer as `seed`, so an application that unlocks its data and signs as
 * the identity asks the passkey once.
 */
import { CRYPTO_ALGORITHMS } from '../constants.js';
import { PrfUnavailableError } from '../errors.js';
import { buildCredentialRequestOptions } from '../webauthn/config.js';
import { prfInputForRelyingParty } from '../webauthn/prf-input.js';

const MIN_PRF_BYTES = 32;
const HKDF_MAX_BYTES = 255 * 32;
const encoder = new TextEncoder();

/** @param {unknown} value @returns {Uint8Array|undefined} */
function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (Array.isArray(value)) return Uint8Array.from(value);
  return undefined;
}

/**
 * HKDF-SHA-256 with an empty salt.
 *
 * The salt is empty because the input is already uniformly random — a PRF
 * output — so the extract step needs none. An empty salt and a salt of 32 zero
 * bytes give the same result (HMAC pads either to the same block), which is
 * why this function reproduces every HKDF that applications wrote for
 * themselves before it existed, including one that passed 32 zero bytes.
 *
 * Shared with `derived-signing-key.js`, which keeps its own, more lenient
 * input checks.
 *
 * @param {Uint8Array} secret
 * @param {string} info
 * @param {number} length in bytes
 * @returns {Promise<Uint8Array>}
 */
export async function hkdfSha256(secret, info, length) {
  const base = await crypto.subtle.importKey(
    'raw',
    secret,
    CRYPTO_ALGORITHMS.HKDF,
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: CRYPTO_ALGORITHMS.HKDF,
      hash: CRYPTO_ALGORITHMS.SHA_256,
      salt: new Uint8Array(0),
      info: encoder.encode(info),
    },
    base,
    length * 8
  );
  return new Uint8Array(bits);
}

/** @param {unknown} prfOutput @param {string} caller */
function assertPrfOutput(prfOutput, caller) {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < MIN_PRF_BYTES) {
    throw new TypeError(
      `${caller} needs a PRF output of at least ${MIN_PRF_BYTES} bytes`
    );
  }
}

/** @param {unknown} info @param {string} caller */
function assertInfo(info, caller) {
  if (typeof info !== 'string' || info.length === 0) {
    throw new TypeError(`${caller} needs a non-empty info string`);
  }
}

/**
 * Ask the authenticator for the credential's PRF output: one assertion, one
 * touch.
 *
 * Always with a fixed PRF input — `prfInput` if given, else the one the
 * credential carries, else the one every device can compute for the relying
 * party (`prfInputForRelyingParty`). A random input would give different bytes
 * on every read, and every key derived from them would be lost the moment the
 * page closes; this function never draws one.
 *
 * A refused prompt is not caught: it stays the `NotAllowedError` the browser
 * raised, so a caller can tell "the user said no" from "this authenticator has
 * no PRF", which is `PrfUnavailableError`.
 *
 * @param {Object} credential - The stored credential: `rawCredentialId`
 *   (bytes), and `prfInput` when it was registered with one.
 * @param {Object} [options]
 * @param {string} [options.rpId] - Relying party id; defaults to this page's
 *   hostname.
 * @param {Uint8Array} [options.prfInput] - Overrides the credential's input.
 * @returns {Promise<Uint8Array>} The PRF output, 32 bytes.
 * @throws {PrfUnavailableError} When the authenticator answers without one.
 */
export async function readPrfOutput(credential, { rpId, prfInput } = {}) {
  if (!credential || typeof credential !== 'object') {
    throw new TypeError('readPrfOutput needs a credential object');
  }
  const rawCredentialId = toBytes(credential.rawCredentialId);
  if (!rawCredentialId || rawCredentialId.length === 0) {
    throw new TypeError('readPrfOutput needs the credential’s rawCredentialId');
  }
  const relyingParty = rpId ?? globalThis.location?.hostname;
  const input =
    toBytes(prfInput) ??
    toBytes(credential.prfInput) ??
    (await prfInputForRelyingParty(relyingParty));

  const assertion = await navigator.credentials.get(
    buildCredentialRequestOptions({
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      credentialId: rawCredentialId,
      rpId: relyingParty,
      userVerification: 'required',
      extensions: { prf: { eval: { first: input } } },
    })
  );

  const first = assertion?.getClientExtensionResults?.()?.prf?.results?.first;
  if (!first) {
    throw new PrfUnavailableError(
      'The authenticator answered without a PRF output'
    );
  }
  return new Uint8Array(first);
}

/**
 * Derive key material from a PRF output with HKDF-SHA-256.
 *
 * `info` is part of the data format: the same PRF output and the same `info`
 * always give the same bytes, and changing `info` gives unrelated ones. Name it
 * after the application and the purpose, and put a version in it
 * (`invoice/db-key/v1`) — bumping that version is how a key is rotated, and it
 * makes everything sealed under the old key unreadable.
 *
 * @param {Uint8Array} prfOutput - From `readPrfOutput`, at least 32 bytes.
 * @param {string} info - Domain separation, non-empty.
 * @param {Object} [options]
 * @param {number} [options.length=32] - Bytes to derive, 1 to 8160.
 * @returns {Promise<Uint8Array>}
 */
export async function deriveSubkey(prfOutput, info, { length = 32 } = {}) {
  assertPrfOutput(prfOutput, 'deriveSubkey');
  assertInfo(info, 'deriveSubkey');
  if (!Number.isInteger(length) || length < 1 || length > HKDF_MAX_BYTES) {
    throw new RangeError(
      `deriveSubkey length must be an integer from 1 to ${HKDF_MAX_BYTES}`
    );
  }
  return hkdfSha256(prfOutput, info, length);
}

/**
 * Derive an AES-GCM-256 key from a PRF output, for sealing what an
 * application keeps.
 *
 * The key is not extractable: it encrypts and decrypts, and no script can read
 * its bytes. Its material is exactly `deriveSubkey(prfOutput, info)`.
 *
 * @param {Uint8Array} prfOutput - From `readPrfOutput`, at least 32 bytes.
 * @param {string} info - Domain separation, non-empty.
 * @returns {Promise<CryptoKey>}
 */
export async function deriveAesKey(prfOutput, info) {
  assertPrfOutput(prfOutput, 'deriveAesKey');
  assertInfo(info, 'deriveAesKey');
  const base = await crypto.subtle.importKey(
    'raw',
    prfOutput,
    CRYPTO_ALGORITHMS.HKDF,
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: CRYPTO_ALGORITHMS.HKDF,
      hash: CRYPTO_ALGORITHMS.SHA_256,
      salt: new Uint8Array(0),
      info: encoder.encode(info),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

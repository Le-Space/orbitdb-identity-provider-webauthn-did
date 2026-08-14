/**
 * Byte and challenge helpers for varsig signing.
 */
import { concat, varintEncode } from 'iso-webauthn-varsig';

const encoder = new TextEncoder();

/**
 * Convert a Uint8Array view to ArrayBuffer slice.
 * @param {Uint8Array} bytes - Source bytes.
 * @returns {ArrayBuffer} ArrayBuffer slice.
 */
function toArrayBuffer(bytes) {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
}

/**
 * Convert string to bytes, or return bytes as-is.
 * @param {string|Uint8Array} data - Input data.
 * @returns {Uint8Array} Byte representation.
 */
function toBytes(data) {
  return typeof data === 'string' ? encoder.encode(data) : data;
}

/**
 * Frame a payload with the context it is signed for.
 *
 * The same credential signs three different things — an identity, a public key
 * and an oplog entry — and a signature over one must not be reusable as a
 * signature over another. The separation has to live inside the bytes that get
 * hashed: the WebAuthn signature covers `authenticatorData ‖ SHA-256(clientDataJSON)`
 * and nothing else, so a context field carried alongside the varsig would not
 * be bound to the signature at all.
 *
 * It used to be mixed into the challenge preimage instead
 * (`SHA-256(label ‖ payload)`), which separated the domains but meant the
 * challenge was no longer the hash of the payload — so verifiers following the
 * varsig spec could never reproduce it.
 *
 * @param {string} context - Domain label, e.g. 'orbitdb-entry:'.
 * @param {Uint8Array} payloadBytes - Payload bytes.
 * @returns {Uint8Array} The bytes that are signed over.
 */
function bindContext(context, payloadBytes) {
  const contextBytes = encoder.encode(context);
  // Length-prefixed so the frame is unambiguous: without it, a context of
  // 'a' with payload 'bc' and a context of 'ab' with payload 'c' would
  // produce identical bytes.
  return concat([
    varintEncode(contextBytes.length),
    contextBytes,
    payloadBytes,
  ]);
}

/**
 * Build a WebAuthn challenge as a multihash of the payload.
 *
 * Per the varsig WebAuthn draft the challenge carries the payload hash as a
 * multihash, so a verifier can re-hash the payload and compare. `0x12 0x20` is
 * the SHA-256 prefix and its 32-byte length.
 *
 * @param {Uint8Array} payloadBytes - The bytes being signed, context included.
 * @returns {Promise<Uint8Array>} Multihash of the payload.
 */
async function buildChallengeBytes(payloadBytes) {
  const hash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', payloadBytes)
  );
  return concat([new Uint8Array([0x12, 0x20]), hash]);
}

export { encoder, toArrayBuffer, toBytes, bindContext, buildChallengeBytes };

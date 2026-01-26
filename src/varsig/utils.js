/**
 * Byte and challenge helpers for varsig signing.
 */
import { concat } from 'iso-webauthn-varsig';

const encoder = new TextEncoder();

/**
 * Convert a Uint8Array view to ArrayBuffer slice.
 * @param {Uint8Array} bytes - Source bytes.
 * @returns {ArrayBuffer} ArrayBuffer slice.
 */
function toArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
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
 * Build a WebAuthn challenge from a domain label and payload.
 * @param {string} domainLabel - Domain label prefix.
 * @param {Uint8Array} payloadBytes - Payload bytes.
 * @returns {Promise<Uint8Array>} SHA-256 digest.
 */
async function buildChallengeBytes(domainLabel, payloadBytes) {
  const domain = encoder.encode(domainLabel);
  const hash = await crypto.subtle.digest('SHA-256', concat([domain, payloadBytes]));
  return new Uint8Array(hash);
}

export {
  encoder,
  toArrayBuffer,
  toBytes,
  buildChallengeBytes
};

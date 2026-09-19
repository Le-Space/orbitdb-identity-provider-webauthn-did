/**
 * @module PrfInput
 * @description
 * The PRF input an authenticator is asked to evaluate.
 *
 * It was drawn at random per credential and stored with the credential's
 * metadata, which makes the derived signing key — and with it the identity —
 * reachable only from the device that kept that metadata. A second device
 * holding the same passkey asks the same authenticator and gets a different
 * answer, because it asks a different question.
 *
 * Fixing the input per relying party removes the question: both devices ask
 * the same thing, and the authenticator answers the same thing. The input is
 * not a secret — the *output* is, and it never leaves the authenticator's
 * answer — so nothing is lost by making it derivable. See issue #61.
 */
import { CRYPTO_ALGORITHMS } from '../constants.js';

/**
 * Bumping this rotates every PRF output, and with it every derived signing
 * key, so treat it as a breaking change.
 */
export const PRF_INPUT_INFO = 'orbitdb-identity-provider-webauthn-did:prf:v2';

/**
 * The fixed PRF input for a relying party.
 *
 * @param {string} rpId - Relying party id, e.g. `example.org`. The current
 *   host is used when it is omitted and there is one.
 * @returns {Promise<Uint8Array>} 32 bytes, the same on every device.
 */
export async function prfInputForRelyingParty(rpId) {
  const party =
    rpId ??
    (typeof globalThis.location === 'object'
      ? globalThis.location.hostname
      : undefined);
  if (typeof party !== 'string' || party.length === 0) {
    throw new TypeError('prfInputForRelyingParty needs a relying party id');
  }
  const digest = await crypto.subtle.digest(
    CRYPTO_ALGORITHMS.SHA_256,
    new TextEncoder().encode(`${PRF_INPUT_INFO}:${party}`)
  );
  return new Uint8Array(digest);
}

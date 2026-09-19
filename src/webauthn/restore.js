/**
 * @module Restore
 * @description
 * Restore an identity on a device that has stored nothing (#61).
 *
 * Two touches of the same passkey are all it takes. The first is asked with
 * user verification and with the PRF input every device can compute
 * (`prf-input.js`), so the authenticator returns the same secret it returns on
 * the device the identity was made on. The second signs another challenge, and
 * the two signatures together give back the credential's public key
 * (`recovery.js`) — which an assertion does not carry, and which nothing here
 * had a way to learn without largeBlob or a copy in storage.
 *
 * From those two: the DID, and the signing key derived from the PRF output
 * with the DID mixed in — the same pair the original device holds.
 *
 * Nothing stands in for a missing PRF. A device whose authenticator cannot
 * evaluate it gets a refusal, because the alternative is an identity that
 * silently differs from the one the database knows.
 */
import { logger } from '@libp2p/logger';

import {
  ERROR_CODES,
  PrfUnavailableError,
  WebAuthnIdentityError,
} from '../errors.js';
import { deriveSigningKeyBytes } from '../keystore/derived-signing-key.js';
import { KEY_TYPES } from '../constants.js';
import { buildCredentialRequestOptions } from './config.js';
import { prfInputForRelyingParty } from './prf-input.js';
import { WebAuthnDIDProvider } from './provider.js';
import { recoverPublicKey } from './recovery.js';

const log = logger('orbitdb-identity-provider-webauthn-did:restore');

/**
 * Ask the authenticator in front of this device who it is.
 *
 * @param {Object} [options]
 * @param {string} [options.rpId] - Relying party id; the current host by default.
 * @param {number} [options.timeout=120000] - Per touch, in ms. Generous on
 *   purpose: an NFC key has to be found, held and read.
 * @param {string} [options.signingKeyType='secp256k1'] - As the keystore wants it.
 * @param {(step: {touch: number, of: number}) => void} [options.onTouch] -
 *   Called before each ceremony, so an application can say which touch this is.
 * @returns {Promise<{did: string, publicKey: {x: Uint8Array, y: Uint8Array},
 *   credentialId: Uint8Array, signingKey: Uint8Array, prfInput: Uint8Array}>}
 */
export async function restoreIdentityFromAuthenticator({
  rpId,
  timeout = 120_000,
  signingKeyType = KEY_TYPES.SECP256K1,
  onTouch,
} = {}) {
  if (typeof navigator === 'undefined' || !navigator.credentials?.get) {
    throw new WebAuthnIdentityError('WebAuthn is not available here', {
      code: ERROR_CODES.WEBAUTHN_NOT_SUPPORTED,
    });
  }

  const party = rpId ?? globalThis.location?.hostname;
  const prfInput = await prfInputForRelyingParty(party);

  // Touch one: discoverable, so the device does not have to know which
  // credential to ask for — it has nothing stored, that is the premise.
  onTouch?.({ touch: 1, of: 2 });
  const first = await navigator.credentials.get(
    buildCredentialRequestOptions({
      rpId: party,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: 'required',
      timeout,
      extensions: { prf: { eval: { first: prfInput } } },
    })
  );
  if (!first) {
    throw new WebAuthnIdentityError('no credential was offered', {
      code: ERROR_CODES.WEBAUTHN_AUTHENTICATION_FAILED,
    });
  }

  const prfOutput = first.getClientExtensionResults?.()?.prf?.results?.first;
  if (!prfOutput) {
    // No fallback: an identity derived from anything else is not this one.
    throw new PrfUnavailableError(
      'the authenticator returned no PRF output, so the signing key cannot be derived'
    );
  }

  // Touch two: the same credential, another challenge. Only the signature
  // matters, so this asks for no more verification than the key insists on.
  onTouch?.({ touch: 2, of: 2 });
  const second = await navigator.credentials.get(
    buildCredentialRequestOptions({
      rpId: party,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: 'preferred',
      timeout,
      credentialId: first.rawId,
      discoverableCredentials: false,
    })
  );

  const publicKey = await recoverPublicKey(first, second);
  const did = await WebAuthnDIDProvider.createDID({ publicKey });
  const signingKey = await deriveSigningKeyBytes(
    new Uint8Array(prfOutput),
    did,
    signingKeyType
  );
  log('restored %s from the authenticator alone', did);

  return {
    did,
    publicKey,
    credentialId: new Uint8Array(first.rawId),
    signingKey,
    prfInput,
  };
}

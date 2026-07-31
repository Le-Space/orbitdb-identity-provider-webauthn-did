/**
 * @module DerivedSigningKey
 * @description
 * Derives the OrbitDB signing key deterministically from the passkey's PRF
 * output instead of letting the keystore generate a random one.
 *
 * `Identities.createIdentity` in `@orbitdb/core` does:
 *
 *     const privateKey = await keystore.getKey(id) || await keystore.createKey(id)
 *     const publicKey  = keystore.getPublic(privateKey)
 *     const idSignature = await signMessage(privateKey, id)
 *
 * `createKey` generates a random secp256k1 key, so `publicKey` and
 * `signatures.id` differ on every device even for the same passkey — one
 * identity document per device. Seeding the keystore with a PRF-derived key
 * before OrbitDB asks for it makes all of that reproducible: the same passkey
 * yields the same document everywhere, so there is exactly one block to keep
 * retrievable and a device that loses its keystore reconstructs the identity
 * rather than minting another one.
 *
 * Needs no change to `@orbitdb/core` — it only has to happen before
 * `getKey(id)` is called, which `getId()` is.
 *
 * See issue #18, option 1.
 */
import { logger } from '@libp2p/logger';
import { privateKeyFromRaw } from '@libp2p/crypto/keys';

import { CRYPTO_ALGORITHMS } from '../constants.js';
import { buildCredentialRequestOptions } from '../webauthn/config.js';

const log = logger('orbitdb-identity-provider-webauthn-did:derived-key');

// Bumping this rotates every derived key, so treat it as a breaking change.
const DERIVATION_INFO = 'orbitdb-identity-provider-webauthn-did:signing-key:v1';

const SECP256K1_KEY_BYTES = 32;

/**
 * HKDF-SHA256 a 32-byte candidate from the PRF seed.
 * @param {Uint8Array} seed - PRF output.
 * @param {string} info - Domain separation string.
 * @returns {Promise<Uint8Array>} 32 bytes.
 */
async function hkdf(seed, info) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    seed,
    CRYPTO_ALGORITHMS.HKDF,
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: CRYPTO_ALGORITHMS.HKDF,
      hash: CRYPTO_ALGORITHMS.SHA_256,
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(info),
    },
    baseKey,
    SECP256K1_KEY_BYTES * 8
  );
  return new Uint8Array(bits);
}

/**
 * Turn a PRF seed into a valid secp256k1 private key.
 *
 * Values outside the curve order are invalid. That is vanishingly unlikely for
 * a 256-bit hash, but retrying with a counter keeps the derivation total and
 * deterministic rather than probabilistic.
 *
 * @param {Uint8Array} seed - PRF output.
 * @param {string} did - Identity DID, mixed in for domain separation.
 * @returns {Promise<Uint8Array>} A valid 32-byte secp256k1 private key.
 */
export async function deriveSigningKeyBytes(seed, did) {
  for (let counter = 0; counter < 256; counter++) {
    const candidate = await hkdf(seed, `${DERIVATION_INFO}:${did}:${counter}`);
    try {
      privateKeyFromRaw(candidate);
      return candidate;
    } catch {
      log('derived scalar %d was not a valid secp256k1 key, retrying', counter);
    }
  }
  // Unreachable short of a broken hash.
  throw new Error('could not derive a valid secp256k1 key from the PRF seed');
}

/**
 * Ask the authenticator for the credential's PRF output.
 *
 * Returns null whenever a stable PRF output cannot be obtained — no stored
 * PRF input, no PRF support, or a refused assertion. Callers must treat null
 * as "carry on without a derived key" rather than as an error.
 *
 * @param {Object} credential - Stored WebAuthn credential info.
 * @param {Object} [options]
 * @param {string} [options.rpId] - Relying party id.
 * @returns {Promise<Uint8Array|null>} PRF output, or null.
 */
export async function getPrfOutput(credential, { rpId } = {}) {
  // Without the original input the output would differ per call, which is
  // worse than not deriving at all.
  if (!credential?.prfInput) {
    log('credential has no stored prfInput; cannot derive a stable key');
    return null;
  }

  if (typeof navigator === 'undefined' || !navigator.credentials?.get) {
    log('no WebAuthn available; cannot derive a key');
    return null;
  }

  const rawCredentialId =
    credential.rawCredentialId instanceof Uint8Array
      ? credential.rawCredentialId
      : new Uint8Array(credential.rawCredentialId ?? []);

  try {
    const assertion = await navigator.credentials.get(
      buildCredentialRequestOptions({
        challenge: await crypto.subtle.digest(
          CRYPTO_ALGORITHMS.SHA_256,
          new TextEncoder().encode(DERIVATION_INFO)
        ),
        credentialId: rawCredentialId,
        rpId: rpId ?? globalThis.window?.location?.hostname,
        userVerification: 'required',
        extensions: { prf: { eval: { first: credential.prfInput } } },
      })
    );

    const results = assertion?.getClientExtensionResults?.()?.prf?.results;
    if (!results?.first) {
      log('authenticator returned no PRF output');
      return null;
    }
    return new Uint8Array(results.first);
  } catch (error) {
    log('PRF assertion failed: %s', error.message);
    return null;
  }
}

/**
 * Seed the keystore with a PRF-derived signing key for this DID.
 *
 * An existing key is never replaced. Overwriting one would change `publicKey`
 * and `signatures.id`, producing a second identity document for the same DID —
 * precisely what this is meant to avoid. Installs that already hold a random
 * key therefore keep it and stay on 0.4.0 behaviour, which is stable per
 * device; only fresh installs get a reproducible identity.
 *
 * @param {Object} params
 * @param {Object} params.keystore - OrbitDB keystore.
 * @param {string} params.did - Identity DID.
 * @param {Object} params.credential - Stored WebAuthn credential info.
 * @param {string} [params.rpId] - Relying party id.
 * @returns {Promise<'derived'|'existing'|'unavailable'>} What happened.
 */
export async function ensureDerivedSigningKey({
  keystore,
  did,
  credential,
  rpId,
}) {
  if (!keystore || !did || !credential) return 'unavailable';

  try {
    if (await keystore.getKey(did)) {
      log('keystore already holds a key for this DID; leaving it alone');
      return 'existing';
    }
  } catch (error) {
    log('could not read the keystore: %s', error.message);
    return 'unavailable';
  }

  const seed = await getPrfOutput(credential, { rpId });
  if (!seed) {
    log(
      'no PRF output; falling back to a keystore-generated key, so this identity is stable per device but not reproducible across devices'
    );
    return 'unavailable';
  }

  try {
    const privateKey = await deriveSigningKeyBytes(seed, did);
    await keystore.addKey(did, { privateKey });
    log('seeded the keystore with a PRF-derived signing key');
    return 'derived';
  } catch (error) {
    log('failed to seed the derived key: %s', error.message);
    return 'unavailable';
  }
}

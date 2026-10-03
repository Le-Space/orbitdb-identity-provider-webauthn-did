/**
 * @module SecretSigner
 * @description
 * An identity that is nobody's passkey: the books of an application, which
 * every registered security key of their owner may write to.
 *
 * A passkey identity belongs to one authenticator — its DID is the
 * credential's key, its signing key comes from that authenticator's PRF
 * output — so a second security key is a second identity. OrbitDB's access
 * controllers fix who may grant write access when a database is created, so
 * a database rooted at one key's identity stays that key's forever. The books
 * get an identity of their own instead, and every key acts as it:
 * the application keeps a random secret in a vault (`createVault`), any slot
 * opens it, and this turns the secret into the books' signing key. Other
 * people are not given the secret; they are granted write access under their
 * own identities, which can be revoked.
 *
 * The key is Ed25519, derived with HKDF-SHA-256 under `info`; its DID is the
 * key's `did:key`. The same secret and `info` give the same key, DID and
 * OrbitDB identity document on every device and for every slot. Use it as
 * `createSessionKeystore({ signer })` and
 * `OrbitDBWebAuthnIdentityProviderFunction({ signer })`.
 */
import { generateKeyPairFromSeed } from '@libp2p/crypto/keys';
import { deriveSubkey } from './prf-keys.js';
import { createEd25519DidFromPublicKey } from './ed25519-did.js';

const MIN_SECRET_BYTES = 32;

/**
 * An Ed25519 signer derived from a secret, in the shape the provider's
 * `signer` option and `createSessionKeystore` take.
 *
 * The private key stays in this closure: what comes back can sign, but has no
 * field that holds the key.
 *
 * @param {Uint8Array} secret - At least 32 random bytes, e.g. from a vault.
 * @param {Object} options
 * @param {string} options.info - Domain separation, part of the identity:
 *   another `info` is another key and another DID. Version it
 *   (`invoice/books-identity/v1`).
 * @returns {Promise<{ did: string, type: 'Ed25519', publicKey: Uint8Array,
 *   sign: (data: Uint8Array) => Promise<Uint8Array> }>}
 */
export async function createSecretSigner(secret, { info } = {}) {
  if (!(secret instanceof Uint8Array) || secret.length < MIN_SECRET_BYTES) {
    throw new TypeError(
      `createSecretSigner needs a secret of at least ${MIN_SECRET_BYTES} bytes`
    );
  }
  if (typeof info !== 'string' || info.length === 0) {
    throw new TypeError('createSecretSigner needs a non-empty info string');
  }
  const seed = await deriveSubkey(secret, info);
  const key = await generateKeyPairFromSeed('Ed25519', seed);
  seed.fill(0);
  const publicKey = key.publicKey.raw;
  return {
    did: createEd25519DidFromPublicKey(publicKey),
    type: 'Ed25519',
    publicKey,
    sign: async (data) => key.sign(data),
  };
}

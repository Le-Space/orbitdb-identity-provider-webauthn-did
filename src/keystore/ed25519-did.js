import { varint } from 'multiformats';
import { base58btc } from 'multiformats/bases/base58';

/**
 * Build a did:key identifier from raw Ed25519 public key bytes.
 * @param {Uint8Array} publicKeyBytes
 * @returns {string}
 */
export function createEd25519DidFromPublicKey(publicKeyBytes) {
  if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length !== 32) {
    throw new Error(
      `Invalid Ed25519 public key length: ${publicKeyBytes?.length || 0}`
    );
  }

  const ED25519_MULTICODEC = 0xed;
  const codecLength = varint.encodingLength(ED25519_MULTICODEC);
  const codecBytes = new Uint8Array(codecLength);
  varint.encodeTo(ED25519_MULTICODEC, codecBytes, 0);

  const multikey = new Uint8Array(codecBytes.length + publicKeyBytes.length);
  multikey.set(codecBytes, 0);
  multikey.set(publicKeyBytes, codecBytes.length);

  return `did:key:${base58btc.encode(multikey)}`;
}

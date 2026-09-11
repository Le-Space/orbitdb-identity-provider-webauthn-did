/**
 * Option 1 — the default path.
 *
 * The DID is the passkey's: did:key of the credential's P-256 public key.
 * OrbitDB signs entries with a key derived from the passkey's PRF output —
 * secp256k1 or Ed25519 — that the provider puts in the OrbitDB keystore. One
 * assertion binds that key to the DID; it is stored and reused, so nothing
 * prompts per write.
 *
 * At rest: the derived key, in the keystore's IndexedDB, in clear. Option 2
 * is for when that is not acceptable.
 *
 * Suite: tests/webauthn-default-path.test.js
 */
import { Identities, useIdentityProvider } from '@orbitdb/core';
import { OrbitDBWebAuthnIdentityProviderFunction } from '@le-space/orbitdb-identity-provider-webauthn-did';

/**
 * @param {Object} params
 * @param {Object} params.ipfs - Helia, so identities are stored as blocks
 * @param {Object} params.credential - The stored WebAuthn credential
 * @param {'secp256k1'|'Ed25519'} [params.signingKeyType] - Type of the derived
 *   key. Only matters the first time this device derives one: a keystore that
 *   already holds a key for the DID keeps it.
 * @param {string} [params.path] - Where the identities keystore lives
 * @returns {Promise<{identities: Object, identity: Object}>}
 */
export async function createDefaultPathIdentity({
  ipfs,
  credential,
  signingKeyType = 'secp256k1',
  path,
}) {
  useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
  const identities = await Identities({ ipfs, path });
  const identity = await identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: credential,
      signingKeyType,
    }),
  });
  return { identities, identity };
}

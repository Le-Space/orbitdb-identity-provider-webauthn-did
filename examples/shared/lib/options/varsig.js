/**
 * Option 3 — varsig: the passkey signs every write.
 *
 * No keystore. The DID is did:key of the credential's public key (P-256 or
 * Ed25519, whichever the authenticator made). Two assertions sign the
 * identity, and each entry is signed by a fresh one — one prompt per write.
 * No signing key exists in JavaScript, and every signature is bound to the
 * origin.
 *
 * Identities are stored as blocks in Helia, so a later login and other peers
 * can read them back.
 *
 * Suite: tests/webauthn-varsig-e2e.test.js
 */
import {
  createIpfsIdentityStorage,
  createWebAuthnVarsigIdentity,
  createWebAuthnVarsigIdentities,
} from '@le-space/orbitdb-identity-provider-webauthn-did';

/**
 * @param {Object} params
 * @param {Object} params.ipfs - Helia, whose blockstore holds the identities
 * @param {Object} params.credential - The stored WebAuthn credential
 * @returns {Promise<{identities: Object, identity: Object}>}
 */
export async function createVarsigIdentity({ ipfs, credential }) {
  const identity = await createWebAuthnVarsigIdentity({ credential });
  // The package's storage, not a copy of it. Helia 7's blockstore gives a
  // block as a generator of chunks, and the copy this demo had handed that on
  // as the block: every todo from an earlier login showed as rejected.
  const identities = createWebAuthnVarsigIdentities(
    identity,
    {},
    createIpfsIdentityStorage(ipfs)
  );
  return { identities, identity };
}

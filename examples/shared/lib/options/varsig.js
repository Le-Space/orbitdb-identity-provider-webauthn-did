/**
 * Option 3 — varsig: the passkey signs every write.
 *
 * No keystore. The DID is did:key of the credential's public key (P-256 or
 * Ed25519, whichever the authenticator made). Two assertions sign the
 * identity, and each entry is signed by a fresh one — one prompt per write.
 * No signing key exists in JavaScript, and every signature is bound to the
 * origin.
 *
 * Identities are stored as blocks in Helia so peers can fetch them.
 *
 * Suite: tests/webauthn-varsig-e2e.test.js
 */
import { CID } from 'multiformats/cid';
import {
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
  const storage = {
    get: async (hash) => {
      try {
        return await ipfs.blockstore.get(CID.parse(hash));
      } catch {
        return undefined;
      }
    },
    put: async (hash, bytes) => {
      await ipfs.blockstore.put(CID.parse(hash), bytes);
    },
  };
  const identities = createWebAuthnVarsigIdentities(identity, {}, storage);
  return { identities, identity };
}

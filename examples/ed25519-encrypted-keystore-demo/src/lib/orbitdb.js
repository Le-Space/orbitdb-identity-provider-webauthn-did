import {
  createHeliaInstance,
  createOrbitDBInstance,
  cleanup,
  resetDemoState,
} from '$shared/lib/stack.js';
import { createSessionKeystoreIdentity } from '$shared/lib/options/encrypted-keystore.js';

// Prefix of every IndexedDB store this demo opens; the demos share an origin.
const NAMESPACE = 'ed25519-encrypted-keystore-demo';

/**
 * The whole stack for one login: Helia, the identity for this option, OrbitDB.
 * @param {Object} credential - The stored WebAuthn credential
 * @param {Object} [options] - See createSessionKeystoreIdentity
 * @returns {Promise<{orbitdb: Object, ipfs: Object, identity: Object, identities: Object, keystore: Object, provider: Object}>}
 */
export async function setupOrbitDB(credential, options = {}) {
  const ipfs = await createHeliaInstance({ namespace: NAMESPACE });
  const { identities, identity, keystore, provider } =
    await createSessionKeystoreIdentity({ ipfs, credential, ...options });
  const orbitdb = await createOrbitDBInstance({
    ipfs,
    identities,
    identity,
    namespace: NAMESPACE,
  });
  return { orbitdb, ipfs, identity, identities, keystore, provider };
}

export { cleanup };

/** Delete this demo's IndexedDB stores. Call cleanup() first. */
export const resetDatabaseState = () => resetDemoState({ namespace: NAMESPACE });

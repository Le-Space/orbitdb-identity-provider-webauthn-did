import {
  createHeliaInstance,
  createOrbitDBInstance,
  cleanup,
  resetDemoState,
} from '$shared/lib/stack.js';
import { createVarsigIdentity } from '$shared/lib/options/varsig.js';

// Prefix of every IndexedDB store this demo opens; the demos share an origin.
const NAMESPACE = 'webauthn-varsig-demo';

/**
 * The whole stack for one login: Helia, the identity for this option, OrbitDB.
 * @param {Object} credential - The stored WebAuthn credential
 * @returns {Promise<{orbitdb: Object, ipfs: Object, identity: Object, identities: Object}>}
 */
export async function setupOrbitDB(credential) {
  const ipfs = await createHeliaInstance({ namespace: NAMESPACE });
  const { identities, identity } = await createVarsigIdentity({
    ipfs,
    credential,
  });
  const orbitdb = await createOrbitDBInstance({
    ipfs,
    identities,
    identity,
    namespace: NAMESPACE,
  });
  return { orbitdb, ipfs, identity, identities };
}

export { cleanup };

/** Delete this demo's IndexedDB stores. Call cleanup() first. */
export const resetDatabaseState = () => resetDemoState({ namespace: NAMESPACE });

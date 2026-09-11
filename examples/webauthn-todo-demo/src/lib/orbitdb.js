import {
  createHeliaInstance,
  createOrbitDBInstance,
  identityKeysPath,
  cleanup,
  resetDemoState,
} from '$shared/lib/stack.js';
import { createDefaultPathIdentity } from '$shared/lib/options/default-path.js';

// Prefix of every IndexedDB store this demo opens; the demos share an origin.
const NAMESPACE = 'webauthn-todo-demo';

/**
 * The whole stack for one login: Helia, the identity for this option, OrbitDB.
 * @param {Object} credential - The stored WebAuthn credential
 * @param {Object} [options]
 * @param {'secp256k1'|'Ed25519'} [options.signingKeyType]
 * @returns {Promise<{orbitdb: Object, ipfs: Object, identity: Object, identities: Object}>}
 */
export async function setupOrbitDB(credential, { signingKeyType } = {}) {
  const ipfs = await createHeliaInstance({ namespace: NAMESPACE });
  const { identities, identity } = await createDefaultPathIdentity({
    ipfs,
    credential,
    signingKeyType,
    path: identityKeysPath(NAMESPACE),
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

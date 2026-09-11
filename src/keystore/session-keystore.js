/**
 * @module SessionKeystore
 * @description
 * An OrbitDB keystore that forgets everything when the page goes away.
 *
 * OrbitDB signs entries with whatever `keystore.getKey(id)` returns, and its
 * default keystore writes every key it holds to persistent storage (Level,
 * which is IndexedDB in a browser). So once the provider has unlocked an
 * encrypted keystore and handed the key to OrbitDB, that key sits on disk in
 * clear — the encrypted copy protects nothing after the first session.
 *
 * The fix has to happen where the keystore is made, which is the app, not
 * the provider. This is that keystore: in memory only, so the encrypted copy
 * is the only thing at rest, and every session unlocks it again.
 *
 *     const keystore = await createSessionKeystore();
 *     const identities = await Identities({ ipfs, keystore });
 */

/**
 * @returns {Promise<Object>} An OrbitDB keystore on memory storage, marked
 *   `sessionOnly` so the provider can tell it apart from a persistent one.
 */
export async function createSessionKeystore() {
  // Loaded here, not at module scope: `@orbitdb/core` is a peer dependency,
  // and the package's main entry must stay importable where it is absent
  // (the tarball check in CI imports every entry in an empty project).
  const { KeyStore, MemoryStorage } = await import('@orbitdb/core');
  const keystore = await KeyStore({ storage: await MemoryStorage() });
  keystore.sessionOnly = true;
  return keystore;
}

/**
 * @param {Object} keystore - An OrbitDB keystore.
 * @returns {boolean} Whether it was made by `createSessionKeystore`.
 */
export function isSessionKeystore(keystore) {
  return keystore?.sessionOnly === true;
}

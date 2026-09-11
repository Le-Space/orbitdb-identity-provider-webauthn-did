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
 * @param {Object} [options]
 * @param {{did: string, type: string, publicKey: Uint8Array, sign: (data: Uint8Array) => Promise<Uint8Array>}} [options.signer]
 *   A key that signs elsewhere — in a Web Worker, say. The keystore answers
 *   `getKey(signer.did)` with an object OrbitDB can call `sign()` on, and the
 *   private half never enters this keystore at all.
 * @returns {Promise<Object>} An OrbitDB keystore on memory storage, marked
 *   `sessionOnly` so the provider can tell it apart from a persistent one.
 */
export async function createSessionKeystore({ signer } = {}) {
  // Loaded here, not at module scope: `@orbitdb/core` is a peer dependency,
  // and the package's main entry must stay importable where it is absent
  // (the tarball check in CI imports every entry in an empty project).
  const { KeyStore, MemoryStorage } = await import('@orbitdb/core');
  const keystore = await KeyStore({ storage: await MemoryStorage() });
  keystore.sessionOnly = true;
  if (signer) {
    assertSigner(signer);
    // What OrbitDB reads off a key: `type`, `publicKey.raw` (for getPublic)
    // and `sign(data)`, which key-store.js awaits — so it may live anywhere.
    const key = {
      type: signer.type,
      publicKey: { type: signer.type, raw: signer.publicKey },
      sign: (data) => signer.sign(data),
    };
    const { getKey, hasKey } = keystore;
    keystore.getKey = async (id) => (id === signer.did ? key : getKey(id));
    keystore.hasKey = async (id) => id === signer.did || hasKey(id);
    keystore.signer = signer;
  }
  return keystore;
}

/**
 * @param {Object} signer
 * @throws {Error} When it is not something OrbitDB could sign with.
 */
export function assertSigner(signer) {
  if (
    !signer ||
    typeof signer.did !== 'string' ||
    !signer.did.startsWith('did:key:') ||
    signer.type !== 'Ed25519' ||
    !(signer.publicKey instanceof Uint8Array) ||
    signer.publicKey.length !== 32 ||
    typeof signer.sign !== 'function'
  ) {
    throw new Error(
      'signer must be { did: "did:key:…", type: "Ed25519", publicKey: Uint8Array(32), sign(data) }'
    );
  }
}

/**
 * @param {Object} keystore - An OrbitDB keystore.
 * @returns {boolean} Whether it was made by `createSessionKeystore`.
 */
export function isSessionKeystore(keystore) {
  return keystore?.sessionOnly === true;
}

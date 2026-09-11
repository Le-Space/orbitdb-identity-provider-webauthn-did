import { createOrbitDB, Identities, useIdentityProvider } from '@orbitdb/core';
import { createLibp2p } from 'libp2p';
import { createHeliaLight } from 'helia';
import { withBitswap } from '@helia/bitswap';
import { withHTTP } from '@helia/http';
import { withLibp2p } from '@helia/libp2p';
import * as dagCbor from '@ipld/dag-cbor';
import * as dagJson from '@ipld/dag-json';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { webSockets } from '@libp2p/websockets';
import { webRTC } from '@libp2p/webrtc';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { identify } from '@libp2p/identify';
import { gossipsub } from '@libp2p/gossipsub';
import { LevelBlockstore } from 'blockstore-level';
import { LevelDatastore } from 'datastore-level';
import * as json from 'multiformats/codecs/json';
import { sha512 } from 'multiformats/hashes/sha2';
import {
  OrbitDBWebAuthnIdentityProviderFunction,
  createSessionKeystore,
} from '@le-space/orbitdb-identity-provider-webauthn-did';

export function createLibp2pOptions() {
  return {
    addresses: {
      listen: [
        '/p2p-circuit', // Essential for relay connections
        '/webrtc', // WebRTC for direct connections
      ],
    },
    transports: [
      webSockets(),
      webRTC({
        rtcConfiguration: {
          iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:global.stun.twilio.com:3478' },
          ],
        },
      }),
      circuitRelayTransport({
        discoverRelays: 2, // Discover more relays
        maxReservations: 2, // Allow more reservations
      }),
    ],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: {
      identify: identify(),
      pubsub: gossipsub({
        emitSelf: true, // Enable to see our own messages
        allowPublishToZeroTopicPeers: true,
      }),
    },
    connectionManager: {
      maxConnections: 20,
      minConnections: 1,
    },
  };
}

/**
 * Creates a browser-compatible libp2p instance with optimal configuration
 * for WebRTC, WebSocket, and circuit relay connections
 */
export async function createLibp2pInstance() {
  const libp2p = await createLibp2p(createLibp2pOptions());

  if (libp2p.status !== 'started') {
    await libp2p.start();
  }

  return libp2p;
}

/**
 * Creates a Helia IPFS instance with persistent Level storage
 * @param {Object} libp2pOptions - The libp2p options to use
 */
// The Level stores handed to Helia. Helia's stop() does not close stores it
// did not create, and an open store blocks the IndexedDB delete in
// resetDatabaseState — so this demo keeps them and closes them in cleanup().
const openStores = new Set();

export async function createHeliaInstance(
  libp2pOptions = createLibp2pOptions()
) {
  const blockstore = new LevelBlockstore('./orbitdb/blocks');
  const datastore = new LevelDatastore('./orbitdb/data');
  const ipfs = withBitswap(
    withLibp2p(
      withHTTP(
        createHeliaLight({
          blockstore,
          datastore,
          codecs: [dagCbor, dagJson, json],
          hashers: [sha512],
        })
      ),
      libp2pOptions
    )
  );

  await ipfs.start();
  openStores.add(blockstore);
  openStores.add(datastore);

  return ipfs;
}

/**
 * Registers the WebAuthn identity provider with OrbitDB
 */
export function registerWebAuthnProvider() {
  useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
}

/**
 * Creates an OrbitDB identities instance
 */
export async function createIdentitiesInstance() {
  return await Identities();
}

/**
 * Creates the identity for one of this demo's two modes, on a keystore that
 * forgets.
 *
 * Both modes give OrbitDB `createSessionKeystore()`: OrbitDB signs with
 * whatever that keystore returns and the default one writes every key to
 * disk, which made `encryptKeystore` decoration. With a `signer` the keystore
 * answers for the signer's DID with something that signs in the Web Worker,
 * and no private key exists in this page at all.
 *
 * @param {Object} identities - The OrbitDB identities instance
 * @param {Object} credential - The WebAuthn credential
 * @param {Object} keystore - The session keystore the identities were built on
 * @param {Object} options
 * @param {boolean} options.useKeystoreDID - Ed25519/secp256k1 DID from the keystore instead of the P-256 credential DID
 * @param {string} options.keystoreKeyType - 'secp256k1' or 'Ed25519'
 * @param {boolean} options.encryptKeystore - Seal the keystore key with the passkey
 * @param {string} options.encryptionMethod - 'prf', 'largeBlob' or 'hmac-secret'
 * @param {Object|null} options.signer - From createWorkerSigner(); makes the other options moot
 * @returns {Promise<{identity: Object, provider: Object}>} The identity and the
 *   provider instance behind it (for `provider.encryptionState`).
 */
export async function createWebAuthnIdentity(
  identities,
  credential,
  keystore,
  options = {}
) {
  const {
    useKeystoreDID = false,
    keystoreKeyType = 'secp256k1',
    encryptKeystore = false,
    // Matches the library's own default since 0.4.0. Hard-coding 'largeBlob'
    // here meant the demo silently overrode it and never exercised PRF.
    encryptionMethod = 'prf',
    signer = null,
  } = options;

  // OrbitDB keeps the provider instance to itself; the demo wants to read
  // `encryptionState` off it, so the factory is wrapped to catch the instance.
  const factory = OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
    useKeystoreDID: signer ? true : useKeystoreDID,
    keystore,
    keystoreKeyType: signer ? 'Ed25519' : keystoreKeyType,
    encryptKeystore: signer ? false : encryptKeystore,
    keystoreEncryptionMethod: encryptionMethod,
    signer,
  });
  let provider = null;
  const identity = await identities.createIdentity({
    provider: async () => {
      provider = await factory();
      return provider;
    },
  });
  return { identity, provider };
}

/**
 * Creates an OrbitDB instance with WebAuthn identity
 * @param {Object} ipfs - The Helia IPFS instance
 * @param {Object} identities - The OrbitDB identities instance
 * @param {Object} identity - The WebAuthn identity
 */
export async function createOrbitDBInstance(ipfs, identities, identity) {
  return await createOrbitDB({
    ipfs,
    identities,
    identity,
  });
}

/**
 * Complete OrbitDB setup with WebAuthn authentication
 * @param {Object} credential - The WebAuthn credential
 * @param {Object} options - Configuration options
 * @param {boolean} options.useKeystoreDID - Use persistent DID from OrbitDB keystore (instead of WebAuthn P-256)
 * @param {string} options.keystoreKeyType - Key type: 'secp256k1' or 'Ed25519'
 * @param {boolean} options.encryptKeystore - Enable keystore encryption
 * @param {string} options.encryptionMethod - Encryption method
 * @returns {Object} Contains orbitdb, ipfs, identity, and identities instances
 */
export async function setupOrbitDB(credential, options = {}) {
  // Create Helia instance
  const ipfs = await createHeliaInstance();

  // Register WebAuthn provider
  registerWebAuthnProvider();

  // A keystore that forgets, for the identities and for OrbitDB alike. See
  // createWebAuthnIdentity for why this is not OrbitDB's default one.
  const keystore = await createSessionKeystore({
    signer: options.signer ?? undefined,
  });
  const identities = await Identities({ ipfs, keystore });

  // Create WebAuthn identity with encryption options
  const { identity, provider } = await createWebAuthnIdentity(
    identities,
    credential,
    keystore,
    options
  );

  console.log('🔍 Created WebAuthn identity:', {
    id: identity.id,
    type: identity.type,
    hash: identity.hash,
    didType: options.useKeystoreDID
      ? `${options.keystoreKeyType} (from keystore)`
      : 'P-256 (from WebAuthn)',
    // Deliberately worded as a request, not a result. This line used to read
    // "Yes (largeBlob)" whether or not the authenticator had honoured
    // largeBlob, which made a failed write look like a success in the console.
    // The second field is what the authenticator actually agreed to, so a
    // mismatch between the two is visible rather than hidden.
    encryptionRequested: options.encryptKeystore
      ? options.encryptionMethod
      : 'none',
    authenticatorSupports: credential?.extensionSupport ?? 'not recorded',
  });

  // Try to verify our identity is in the identities store
  try {
    const storedIdentity = await identities.getIdentity(identity.hash);
    console.log('✅ Identity found in identities store:', !!storedIdentity);
    if (storedIdentity) {
      console.log('📊 Stored identity details:', {
        id: storedIdentity.id,
        type: storedIdentity.type,
      });
    }
  } catch (error) {
    console.warn('⚠️ Could not retrieve identity from store:', error.message);
  }

  // Create OrbitDB instance
  const orbitdb = await createOrbitDBInstance(ipfs, identities, identity);

  return {
    orbitdb,
    ipfs,
    identity,
    identities,
    keystore,
    provider,
  };
}

/**
 * Cleanup function to properly shut down all instances
 * @param {Object} instances - Object containing orbitdb, ipfs instances
 */
export async function cleanup({
  orbitdb,
  ipfs,
  identities = null,
  database = null,
}) {
  try {
    if (database) {
      await database.close();
    }

    if (orbitdb) {
      await orbitdb.stop();
    }

    // The identities' keystore is this demo's, not OrbitDB's to close. A
    // session keystore has nothing on disk, but closing it is still right.
    if (identities?.keystore?.close) {
      await identities.keystore.close();
    }

    if (ipfs) {
      await ipfs.stop();
    }

    for (const store of openStores) {
      await store.close();
      openStores.delete(store);
    }
  } catch (error) {
    console.error('Error during cleanup:', error);
    // Continue with cleanup even if some operations fail
  }
}

/**
 * Delete one IndexedDB database, and say so only once it is gone.
 */
function deleteIndexedDb(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve('deleted');
    request.onerror = () => reject(request.error);
    request.onblocked = () => {
      console.warn(
        '🗑️ Delete blocked, waiting for connections to close:',
        name
      );
    };
  });
}

/**
 * Reset database state by clearing IndexedDB. Call cleanup() first.
 */
export async function resetDatabaseState() {
  try {
    console.log('🗑️ Clearing IndexedDB...');
    if (!('databases' in indexedDB)) return;
    const databases = await indexedDB.databases();
    const ours = databases.filter(
      (db) =>
        db.name.includes('orbitdb') ||
        db.name.includes('helia') ||
        db.name.includes('webauthn')
    );
    await Promise.all(
      ours.map((db) =>
        Promise.race([
          deleteIndexedDb(db.name),
          new Promise((_, reject) =>
            setTimeout(
              () => reject(new Error(`deleting ${db.name} timed out`)),
              15000
            )
          ),
        ]).then((outcome) => console.log('🗑️', outcome, db.name))
      )
    );
  } catch (error) {
    console.error('Error clearing IndexedDB:', error);
    throw error;
  }
}

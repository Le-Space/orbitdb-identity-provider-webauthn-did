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
import { OrbitDBWebAuthnIdentityProviderFunction } from '@le-space/orbitdb-identity-provider-webauthn-did';

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
 * Creates a WebAuthn identity using the provided credential
 * @param {Object} identities - The OrbitDB identities instance
 * @param {Object} credential - The WebAuthn credential
 */
export async function createWebAuthnIdentity(
  identities,
  credential,
  { signingKeyType = 'secp256k1' } = {}
) {
  return await identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: credential,
      // The type of the key derived from the passkey's PRF output. Only
      // matters the first time this device derives one: a keystore that
      // already holds a key for the DID keeps it.
      signingKeyType,
    }),
  });
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
 * @returns {Object} Contains orbitdb, ipfs, identity, and identities instances
 */
export async function setupOrbitDB(credential, options = {}) {
  // Create Helia instance
  const ipfs = await createHeliaInstance();

  // Register WebAuthn provider
  registerWebAuthnProvider();

  // Create identities instance with IPFS for proper storage
  const identities = await Identities({ ipfs });

  // Create WebAuthn identity
  const identity = await createWebAuthnIdentity(
    identities,
    credential,
    options
  );

  console.log('🔍 Created WebAuthn identity:', {
    id: identity.id,
    type: identity.type,
    hash: identity.hash,
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

    // The identities were created by this demo, so their keystore is not
    // OrbitDB's to close. Left open, its IndexedDB store blocks the delete
    // in resetDatabaseState, and the next open waits on that delete forever.
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
 * Reset database state by clearing IndexedDB
 */
/**
 * Delete one IndexedDB database, and say so only once it is gone.
 *
 * `deleteDatabase` returns a request; the demo used to fire it and move on,
 * which is why "Reset DB" reported success while the stores it had asked to
 * delete were still there, blocked by a connection that was still open.
 */
function deleteIndexedDb(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve('deleted');
    request.onerror = () => reject(request.error);
    request.onblocked = () => {
      // Another connection holds it. The delete completes once that
      // connection closes; cleanup() has closed everything this demo opened,
      // so this is worth waiting for — but not forever.
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

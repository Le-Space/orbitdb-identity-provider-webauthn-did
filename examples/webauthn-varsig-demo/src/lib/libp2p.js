import { createOrbitDB } from '@orbitdb/core';
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
import { CID } from 'multiformats/cid';
import * as json from 'multiformats/codecs/json';
import { sha512 } from 'multiformats/hashes/sha2';
import {
  createWebAuthnVarsigIdentity,
  createWebAuthnVarsigIdentities,
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
export async function createHeliaInstance(
  libp2pOptions = createLibp2pOptions()
) {
  const ipfs = withBitswap(
    withLibp2p(
      withHTTP(
        createHeliaLight({
          blockstore: new LevelBlockstore('./orbitdb/blocks'),
          datastore: new LevelDatastore('./orbitdb/data'),
          codecs: [dagCbor, dagJson, json],
          hashers: [sha512],
        })
      ),
      libp2pOptions
    )
  );

  await ipfs.start();

  return ipfs;
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
export async function setupOrbitDB(credential) {
  // Create Helia instance
  const ipfs = await createHeliaInstance();

  // Create WebAuthn Varsig identity (no OrbitDB keystore)
  const identity = await createWebAuthnVarsigIdentity({ credential });
  const identityStorage = {
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
  const identities = createWebAuthnVarsigIdentities(
    identity,
    {},
    identityStorage
  );

  console.log('🔍 Created WebAuthn varsig identity:', {
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
export async function cleanup({ orbitdb, ipfs, database = null }) {
  try {
    if (database) {
      await database.close();
    }

    if (orbitdb) {
      await orbitdb.stop();
    }

    if (ipfs) {
      await ipfs.stop();
    }
  } catch (error) {
    console.error('Error during cleanup:', error);
    // Continue with cleanup even if some operations fail
  }
}

/**
 * Reset database state by clearing IndexedDB
 */
export async function resetDatabaseState() {
  try {
    console.log('🗑️ Clearing IndexedDB...');
    if ('databases' in indexedDB) {
      const databases = await indexedDB.databases();
      for (const db of databases) {
        if (
          db.name.includes('orbitdb') ||
          db.name.includes('helia') ||
          db.name.includes('webauthn')
        ) {
          console.log('🗑️ Deleting database:', db.name);
          indexedDB.deleteDatabase(db.name);
        }
      }
    }
  } catch (error) {
    console.error('Error clearing IndexedDB:', error);
    throw error;
  }
}

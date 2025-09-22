import { createOrbitDB, Identities, useIdentityProvider } from '@orbitdb/core';
import { createLibp2p } from 'libp2p';
import { createHelia } from 'helia';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { webSockets } from '@libp2p/websockets';
import { webRTC } from '@libp2p/webrtc';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { identify } from '@libp2p/identify';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { all } from '@libp2p/websockets/filters';
import { LevelBlockstore } from 'blockstore-level';
import { LevelDatastore } from 'datastore-level';
import { OrbitDBWebAuthnIdentityProviderFunction } from '@le-space/orbitdb-identity-provider-webauthn-did';

/**
 * Creates a browser-compatible libp2p instance with optimal configuration
 * for WebRTC, WebSocket, and circuit relay connections
 */
export async function createLibp2pInstance() {
  return await createLibp2p({
    addresses: {
      listen: [
        '/p2p-circuit', // Essential for relay connections
        '/webrtc', // WebRTC for direct connections
      ],
    },
    transports: [
      webSockets({
        filter: all,
      }),
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
    connectionEncryption: [noise()],
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
  });
}

/**
 * Creates a Helia IPFS instance with persistent Level storage
 * @param {Libp2p} libp2p - The libp2p instance to use
 */
export async function createHeliaInstance(libp2p) {
  return await createHelia({
    libp2p,
    blockstore: new LevelBlockstore('./orbitdb/blocks'),
    datastore: new LevelDatastore('./orbitdb/data'),
  });
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
export async function createWebAuthnIdentity(identities, credential) {
  return await identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: credential,
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
export async function setupOrbitDB(credential) {
  // Create libp2p instance
  const libp2p = await createLibp2pInstance();

  // Create Helia instance
  const ipfs = await createHeliaInstance(libp2p);

  // Register WebAuthn provider
  registerWebAuthnProvider();

  // Create identities instance with IPFS for proper storage
  const identities = await Identities({ ipfs });

  // Create WebAuthn identity
  const identity = await createWebAuthnIdentity(identities, credential);
  
  console.log('🔍 Created WebAuthn identity:', {
    id: identity.id,
    type: identity.type,
    hash: identity.hash
  });
  
  // Try to verify our identity is in the identities store
  try {
    const storedIdentity = await identities.getIdentity(identity.hash);
    console.log('✅ Identity found in identities store:', !!storedIdentity);
    if (storedIdentity) {
      console.log('📊 Stored identity details:', {
        id: storedIdentity.id,
        type: storedIdentity.type
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

import { createOrbitDB, Identities, useIdentityProvider } from '@orbitdb/core';
import { createLibp2p } from 'libp2p';
import { createHelia } from 'helia';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { webSockets } from '@libp2p/websockets';
import { webTransport } from '@libp2p/webtransport'
import { webRTC } from '@libp2p/webrtc';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { identify } from '@libp2p/identify';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { bootstrap } from '@libp2p/bootstrap';
import { pubsubPeerDiscovery } from '@libp2p/pubsub-peer-discovery'
import { all } from '@libp2p/websockets/filters';
import { LevelBlockstore } from 'blockstore-level';
import { LevelDatastore } from 'datastore-level';
import {
  OrbitDBWebAuthnIdentityProviderFunction,
} from '@le-space/orbitdb-identity-provider-webauthn-did';
import {
  registerLinkDeviceHandler,
  unregisterLinkDeviceHandler,
} from '@le-space/orbitdb-identity-provider-webauthn-did';

/**
 * Creates a browser-compatible libp2p instance
 */
// Known Amino DHT bootstrap nodes with WebSocket support.
// libp2p v2 resolves dnsaddr via DNS-over-HTTPS in browser environments.
// These nodes also support circuit relay v2 hop, enabling browser-to-browser
// connections via relay circuit addresses.
const BOOTSTRAP_LIST = [
  '/ip4/192.168.29.184/tcp/9001/ws/p2p/12D3KooWR5QCXiwuRUuAWSu9RfHerfyNywbqTuCZy5c8pKaP9a2D'
];

const PUBSUB_PEER_DISCOVERY = 'browser-peer-discovery'

export async function createLibp2pInstance() {
  let libp2p = await createLibp2p({
    addresses: {
      listen: [
        // 👇 Required to create circuit relay reservations in order to hole punch browser-to-browser WebRTC connections
        '/p2p-circuit',
        // 👇 Listen for webRTC connection
        '/webrtc',
      ],
    },
    transports: [
      webSockets(),
      webTransport(),
      webRTC(),
      circuitRelayTransport(),
    ],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    connectionGater: {
      // Allow private addresses for local testing
      denyDialMultiaddr: async () => false,
    },
    peerDiscovery: [
      bootstrap({
        list: ['/ip4/192.168.29.184/tcp/9001/ws/p2p/12D3KooWMa85d6dZmyeSqFS714tRqQ7hrYrfT6vUzbeggSaZhmVU'],
      }),
      pubsubPeerDiscovery({
        interval: 10_000,
        topics: [PUBSUB_PEER_DISCOVERY],
      }),
    ],
    services: {
      pubsub: gossipsub({
        emitSelf: true,
        allowPublishToZeroTopicPeers: true,
      }),
      identify: identify(),
    },
  })

  return libp2p;
}

/**
 * Creates a Helia IPFS instance with persistent Level storage
 */
export async function createHeliaInstance(libp2p) {
  return await createHelia({
    libp2p,
    blockstore: new LevelBlockstore('./orbitdb/blocks'),
    datastore: new LevelDatastore('./orbitdb/data'),
  });
}

/**
 * Complete OrbitDB setup with WebAuthn authentication (Ed25519 + PRF encryption)
 * @param {Object} credential - The WebAuthn credential
 * @param {Object} options - Configuration options
 * @returns {Object} Contains orbitdb, ipfs, identity
 */
export async function setupOrbitDB(credential, options = {}) {
  const libp2p = await createLibp2pInstance();
  const ipfs = await createHeliaInstance(libp2p);

  useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);

  const identities = await Identities({ ipfs });
  const tempOrbitdb = await createOrbitDB({ ipfs, identities });

  const identity = await identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: credential,
      useKeystoreDID: true,
      keystore: tempOrbitdb.keystore,
      keystoreKeyType: 'Ed25519',
      encryptKeystore: options.encryptKeystore !== false,
      keystoreEncryptionMethod: options.keystoreEncryptionMethod || 'prf',
    }),
  });

  console.log('Multi-device identity created:', {
    id: identity.id,
    type: identity.type,
  });

  const orbitdb = await createOrbitDB({ ipfs, identities, identity });

  return { orbitdb, ipfs, identity, identities };
}

/**
 * Register the libp2p pairing handler for Device A.
 * @param {Object} libp2p - libp2p instance (from ipfs.libp2p)
 * @param {Object} db - Device registry KV database
 * @param {Function} onRequest - async (requestMsg) => 'granted' | 'rejected'
 */
export async function registerPairingHandler(libp2p, db, onRequest) {
  await registerLinkDeviceHandler(libp2p, db, onRequest);
}

/**
 * Unregister the libp2p pairing handler.
 * @param {Object} libp2p - libp2p instance
 */
export async function unregisterPairingHandler(libp2p) {
  await unregisterLinkDeviceHandler(libp2p);
}

/**
 * Build the QR payload for Device A to display.
 * Device B scans this to dial Device A.
 * @param {Object} libp2p - libp2p instance
 * @returns {{ peerId: string, multiaddrs: string[] }}
 */
export function getQRPayload(libp2p) {
  const peerId = libp2p.peerId.toString();
  const multiaddrs = libp2p.getMultiaddrs().map((ma) => ma.toString());
  return { peerId, multiaddrs };
}

/**
 * Cleanup function
 */
export async function cleanup({ orbitdb, ipfs, database = null }) {
  try {
    if (database) await database.close();
    if (orbitdb) await orbitdb.stop();
    if (ipfs) await ipfs.stop();
  } catch (error) {
    console.error('Error during cleanup:', error);
  }
}

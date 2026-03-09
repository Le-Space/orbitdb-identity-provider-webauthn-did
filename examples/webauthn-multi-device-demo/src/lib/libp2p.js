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
  createWebAuthnVarsigIdentity,
  createWebAuthnVarsigIdentities,
  createIpfsIdentityStorage,
} from '@le-space/orbitdb-identity-provider-webauthn-did';
import {
  registerLinkDeviceHandler,
  unregisterLinkDeviceHandler,
} from '@le-space/orbitdb-identity-provider-webauthn-did';
import {
  extractPrfSeedFromCredential,
  initEd25519KeystoreWithPrfSeed,
  generateWorkerEd25519DID,
  loadWorkerEd25519Archive,
  encryptArchive,
  decryptArchive,
  keystoreSign,
  resetDefaultWorkerKeystoreClient,
} from '@le-space/orbitdb-identity-provider-webauthn-did/standalone';
import { createWorkerEd25519Identity, createWorkerEd25519Identities } from './worker-identity.js';

/**
 * Creates a browser-compatible libp2p instance
 */
// Known Amino DHT bootstrap nodes with WebSocket support.
// libp2p v2 resolves dnsaddr via DNS-over-HTTPS in browser environments.
// These nodes also support circuit relay v2 hop, enabling browser-to-browser
// connections via relay circuit addresses.
const BOOTSTRAP_LIST = [
  '/dns4/cc37-2405-201-8012-40d2-4c6-6344-379d-d7e1.ngrok-free.app/tcp/443/wss/p2p/12D3KooWDUypFDmsbdfLYW4iETFExEXQfiDkU2SDqkoNjvfUebwR'
];

const PUBSUB_PEER_DISCOVERY = 'browser-peer-discovery'
const WORKER_ARCHIVE_STORAGE_KEY = 'multi-device-worker-archive'

export const IDENTITY_MODES = {
  KEYSTORE_ED25519: 'keystore-ed25519',
  WORKER_ED25519: 'worker-ed25519',
  VARSIG_ED25519: 'varsig-ed25519',
  VARSIG_P256: 'varsig-p256',
}

function saveWorkerArchive(encryptedArchive) {
  if (typeof localStorage === 'undefined' || !encryptedArchive) return;

  localStorage.setItem(
    WORKER_ARCHIVE_STORAGE_KEY,
    JSON.stringify({
      ciphertext: Array.from(encryptedArchive.ciphertext),
      iv: Array.from(encryptedArchive.iv),
    })
  );
}

function loadWorkerArchive() {
  if (typeof localStorage === 'undefined') return null;

  const raw = localStorage.getItem(WORKER_ARCHIVE_STORAGE_KEY);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw);
    return {
      ciphertext: new Uint8Array(parsed.ciphertext),
      iv: new Uint8Array(parsed.iv),
    };
  } catch (error) {
    console.warn('Failed to parse worker archive:', error);
    localStorage.removeItem(WORKER_ARCHIVE_STORAGE_KEY);
    return null;
  }
}

async function setupWorkerOrbitIdentity(credential, ipfs) {
  const identityStorage = createIpfsIdentityStorage(ipfs);
  const { seed, source } = await extractPrfSeedFromCredential(credential);

  resetDefaultWorkerKeystoreClient();
  await initEd25519KeystoreWithPrfSeed(seed);

  let archiveRestored = false;
  let archive = null;
  let did = null;
  let publicKey = null;

  const encryptedArchive = loadWorkerArchive();
  if (encryptedArchive) {
    try {
      archive = await decryptArchive(encryptedArchive.ciphertext, encryptedArchive.iv);
      await loadWorkerEd25519Archive(archive);
      did = archive.id;
      publicKey = archive.keys?.[did] || null;
      archiveRestored = Boolean(did && publicKey);
    } catch (error) {
      console.warn('Failed to restore worker archive, generating fresh identity:', error);
    }
  }

  if (!archiveRestored) {
    const generated = await generateWorkerEd25519DID();
    did = generated.did;
    publicKey = generated.publicKey;
    archive = generated.archive;
    const encrypted = await encryptArchive(archive);
    saveWorkerArchive(encrypted);
  }

  const identity = await createWorkerEd25519Identity({
    did,
    publicKey,
    sign: (data) => keystoreSign(data),
  });

  const identities = createWorkerEd25519Identities(identity, identityStorage);

  return {
    identity,
    identities,
    worker: {
      did,
      seedSource: source,
      archiveRestored,
    },
  };
}

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
        list: BOOTSTRAP_LIST
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

  const identityMode = options.identityMode || IDENTITY_MODES.KEYSTORE_ED25519;
  let identities;
  let identity;
  let runtimeInfo = {
    identityMode,
    signingBackend: 'main-thread-provider',
    algorithm: 'Ed25519',
    identityType: 'webauthn',
    worker: null,
  };

  if (identityMode === IDENTITY_MODES.KEYSTORE_ED25519) {
    useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);

    identities = await Identities({ ipfs });

    identity = await identities.createIdentity({
      provider: OrbitDBWebAuthnIdentityProviderFunction({
        webauthnCredential: credential,
        useKeystoreDID: true,
        keystore: identities.keystore,
        keystoreKeyType: 'Ed25519',
        encryptKeystore: options.encryptKeystore !== false,
        keystoreEncryptionMethod: options.keystoreEncryptionMethod || 'prf',
      }),
    });
  } else if (identityMode === IDENTITY_MODES.WORKER_ED25519) {
    const workerState = await setupWorkerOrbitIdentity(credential, ipfs);
    identity = workerState.identity;
    identities = workerState.identities;
    runtimeInfo = {
      ...runtimeInfo,
      signingBackend: 'worker-keystore',
      identityType: 'worker-ed25519',
      worker: workerState.worker,
    };
  } else {
    identity = await createWebAuthnVarsigIdentity({ credential });
    identities = createWebAuthnVarsigIdentities(
      identity,
      {},
      createIpfsIdentityStorage(ipfs)
    );
    runtimeInfo = {
      ...runtimeInfo,
      signingBackend: 'webauthn-varsig',
      algorithm: credential.algorithm,
      identityType: 'webauthn-varsig',
    };
  }

  console.log('Multi-device identity created:', {
    id: identity.id,
    type: identity.type,
  });

  const orbitdb = await createOrbitDB({ ipfs, identities, identity });

  return { orbitdb, ipfs, identity, identities, runtimeInfo };
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
 * Includes WebSocket and WebTransport addresses, excludes loopback IPs.
 * @param {Object} libp2p - libp2p instance
 * @returns {{ peerId: string, multiaddrs: string[] }}
 */
export function getQRPayload(libp2p) {
  const peerId = libp2p.peerId.toString();

  const filteredMultiaddrs = libp2p.getMultiaddrs()
    .map((ma) => ma.toString())
    .filter((ma) => {
      const maStr = ma.toLowerCase();

      const hasWebsocketOrTransport = 
        maStr.includes('/ws/') || 
        maStr.includes('/wss/') ||
        maStr.includes('/webtransport');

      const isLoopback = 
        maStr.includes('/ip4/127.') ||
        maStr.includes('/ip4/localhost') ||
        maStr.includes('/ip6/::1');

      return hasWebsocketOrTransport && !isLoopback;
    });

  return { peerId, multiaddrs: filteredMultiaddrs };
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

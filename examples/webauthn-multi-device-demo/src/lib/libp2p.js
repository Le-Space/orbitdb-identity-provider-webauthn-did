import {
  createOrbitDB,
  Identities,
  OrbitDBAccessController,
  useIdentityProvider,
} from '@orbitdb/core';
import { createLibp2p } from 'libp2p';
import { createHelia } from 'helia';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { webSockets } from '@libp2p/websockets';
import { webTransport } from '@libp2p/webtransport'
import { webRTC, webRTCDirect } from '@libp2p/webrtc';
import { dcutr } from '@libp2p/dcutr';
import { autoNAT } from '@libp2p/autonat';
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
  createEd25519DidFromPublicKey,
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
const DEFAULT_BOOTSTRAP_LIST = [
  '/dns4/cc37-2405-201-8012-40d2-4c6-6344-379d-d7e1.ngrok-free.app/tcp/443/wss/p2p/12D3KooWDUypFDmsbdfLYW4iETFExEXQfiDkU2SDqkoNjvfUebwR'
];

const DEFAULT_PUBSUB_PEER_DISCOVERY_TOPICS = ['todo._peer-discovery._p2p._pubsub']
const LEGACY_WORKER_ARCHIVE_STORAGE_KEY = 'multi-device-worker-archive'
const WORKER_RECOVERY_RECORD_KEY = 'worker-recovery-state'
const WORKER_PRF_CONTEXT = new TextEncoder().encode(
  'orbitdb/multi-device/worker-recovery/v1'
);
const DEFAULT_ICE_SERVERS = [
  {
    urls: ['stun:stun.l.google.com:19302', 'stun:global.stun.twilio.com:3478'],
  },
];

export const IDENTITY_MODES = {
  KEYSTORE_ED25519: 'keystore-ed25519',
  WORKER_ED25519: 'worker-ed25519',
  VARSIG_ED25519: 'varsig-ed25519',
  VARSIG_P256: 'varsig-p256',
}

function isBrowserDialableMultiaddr(addr) {
  const lower = addr.toLowerCase();
  return lower.includes('/wss/') || lower.includes('/ws/') || lower.includes('/webtransport');
}

function getBootstrapList() {
  const rawSeedNodes = import.meta.env?.VITE_SEED_NODES;
  if (!rawSeedNodes) {
    return DEFAULT_BOOTSTRAP_LIST;
  }

  const parsed = rawSeedNodes
    .split(',')
    .map((addr) => addr.trim())
    .filter(Boolean);

  const browserSeedNodes = parsed.filter(isBrowserDialableMultiaddr);

  if (browserSeedNodes.length === 0) {
    console.warn(
      '[libp2p] VITE_SEED_NODES was provided but contained no browser-dialable addresses. ' +
      'Expected /ws, /wss, or /webtransport multiaddrs. Falling back to default relay.'
    );
    return DEFAULT_BOOTSTRAP_LIST;
  }

  return browserSeedNodes;
}

function getPubsubPeerDiscoveryTopics() {
  const rawTopics = import.meta.env?.VITE_PUBSUB_TOPICS;
  if (!rawTopics) {
    return DEFAULT_PUBSUB_PEER_DISCOVERY_TOPICS;
  }

  const parsed = rawTopics
    .split(',')
    .map((topic) => topic.trim())
    .filter(Boolean);

  return parsed.length > 0 ? parsed : DEFAULT_PUBSUB_PEER_DISCOVERY_TOPICS;
}

export function getRelayDialHints(targetPeerId) {
  if (!targetPeerId || typeof targetPeerId !== 'string') {
    return [];
  }

  const relayHints = new Set();
  for (const relayAddr of getBootstrapList()) {
    const trimmed = relayAddr.trim();
    if (!trimmed) continue;
    relayHints.add(`${trimmed}/p2p-circuit/p2p/${targetPeerId}`);
    relayHints.add(`${trimmed}/p2p-circuit/webrtc/p2p/${targetPeerId}`);
  }

  return Array.from(relayHints);
}

function dedupeStrings(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function isLoopbackOrPrivateMultiaddr(addr = '') {
  const lower = addr.toLowerCase();
  return (
    lower.includes('/ip4/127.') ||
    lower.includes('/ip4/10.') ||
    lower.includes('/ip4/192.168.') ||
    lower.includes('/ip4/169.254.') ||
    /\/ip4\/172\.(1[6-9]|2\d|3[0-1])\./.test(lower) ||
    lower.includes('/ip4/localhost') ||
    lower.includes('/ip6/::1') ||
    lower.includes('/ip6/fc') ||
    lower.includes('/ip6/fd')
  );
}

function scoreQrMultiaddr(addr = '') {
  const lower = addr.toLowerCase();
  let score = 0;

  if (lower.includes('/webrtc-direct/')) score += 100;
  if (lower.includes('/webrtc/')) score += 80;
  if (lower.includes('/wss/')) score += 60;
  if (lower.includes('/ws/')) score += 40;
  if (lower.includes('/webtransport/')) score += 30;
  if (lower.includes('/dns4/')) score += 20;
  if (lower.includes('/dns6/')) score += 15;
  if (lower.includes('/p2p-circuit/')) score -= 15;
  if (isLoopbackOrPrivateMultiaddr(lower)) score -= 1000;

  return score;
}

function selectQrMultiaddrs(libp2p) {
  const candidates = dedupeStrings(
    libp2p.getMultiaddrs().map((ma) => ma.toString())
  )
    .filter((addr) => !isLoopbackOrPrivateMultiaddr(addr))
    .filter((addr) => {
      const lower = addr.toLowerCase();
      return (
        lower.includes('/webrtc-direct/') ||
        lower.includes('/webrtc/') ||
        lower.includes('/wss/') ||
        lower.includes('/ws/') ||
        lower.includes('/webtransport/')
      );
    })
    .sort((a, b) => scoreQrMultiaddr(b) - scoreQrMultiaddr(a) || a.localeCompare(b));

  const selected = [];
  const seenKinds = new Set();

  for (const addr of candidates) {
    const lower = addr.toLowerCase();
    const kind =
      lower.includes('/webrtc-direct/') ? 'webrtc-direct'
        : lower.includes('/webrtc/') ? 'webrtc'
          : lower.includes('/wss/') ? 'wss'
            : lower.includes('/ws/') ? 'ws'
              : lower.includes('/webtransport/') ? 'webtransport'
                : 'other';

    if (seenKinds.has(kind)) continue;
    selected.push(addr);
    seenKinds.add(kind);

    if (selected.length >= 4) break;
  }

  if (selected.length > 0) {
    return selected;
  }

  return getRelayDialHints(libp2p.peerId.toString()).slice(0, 2);
}

function describeConnection(connection) {
  const remoteAddr = connection?.remoteAddr?.toString?.() || 'unknown';
  return {
    remotePeer: connection?.remotePeer?.toString?.() || 'unknown',
    remoteAddr,
    transportKind: classifyConnectionAddr(remoteAddr),
    limited: connection?.limits != null,
    upgraded: connection?.timeline?.upgraded != null,
    status: connection?.status || 'unknown',
    direction: connection?.direction || 'unknown',
  };
}

export function classifyConnectionAddr(remoteAddr = '') {
  const lower = remoteAddr.toLowerCase();
  if (!lower) return 'unknown';
  if (lower.includes('/p2p-circuit/') && lower.includes('/webrtc/')) return 'relay-webrtc';
  if (lower.includes('/p2p-circuit/')) return 'relay-circuit';
  if (lower.includes('/webrtc/')) return 'direct-webrtc';
  if (lower.includes('/webtransport/')) return 'webtransport';
  if (lower.includes('/wss/') || lower.includes('/ws/')) return 'websocket';
  return 'other';
}

export function classifyConnectionState(connection) {
  if (!connection) {
    return {
      transportKind: 'unknown',
      limited: null,
      upgraded: false,
      pathKind: 'unknown',
    };
  }

  const remoteAddr = connection?.remoteAddr?.toString?.() || '';
  const transportKind = classifyConnectionAddr(remoteAddr);
  const limited = connection?.limits != null;
  const upgraded = connection?.timeline?.upgraded != null;
  let pathKind = 'unknown';

  if (transportKind === 'direct-webrtc') {
    pathKind = 'direct';
  } else if (transportKind === 'relay-webrtc' || transportKind === 'relay-circuit') {
    pathKind = limited ? 'relay-limited' : 'relay-unlimited';
  } else if (transportKind === 'webtransport' || transportKind === 'websocket') {
    pathKind = limited ? 'limited' : 'unlimited';
  }

  return {
    transportKind,
    limited,
    upgraded,
    pathKind,
  };
}

function logCurrentMultiaddrs(libp2p, reason = 'current') {
  const multiaddrs = libp2p.getMultiaddrs().map((ma) => ma.toString());
  console.info(`[relay] ${reason} multiaddrs (${multiaddrs.length})`, multiaddrs);
}

function extractPeerIdFromMultiaddr(addr = '') {
  const match = String(addr).match(/\/p2p\/([^/]+)$/);
  return match ? match[1] : null;
}

function attachLibp2pLogging(libp2p, bootstrapList) {
  console.info('[relay] configured seed relays', bootstrapList);
  console.info('[relay] local peer id', libp2p.peerId.toString());
  logCurrentMultiaddrs(libp2p, 'initial');
  const bootstrapPeerIds = new Set(
    (bootstrapList || []).map((addr) => extractPeerIdFromMultiaddr(addr)).filter(Boolean)
  );
  const autoDialCooldowns = new Map();

  libp2p.addEventListener('peer:discovery', (event) => {
    const discoveredPeer = event.detail;
    const id = discoveredPeer?.id?.toString?.() || discoveredPeer?.toString?.() || 'unknown';
    const multiaddrs = discoveredPeer?.multiaddrs?.map?.((ma) => ma.toString()) || [];
    console.info('[relay] discovered peer', { id, multiaddrs });

    if (!id || id === 'unknown' || id === libp2p.peerId.toString()) return;
    if (bootstrapPeerIds.has(id)) return;
    if (libp2p.getConnections?.(discoveredPeer?.id || id)?.length > 0) return;

    const now = Date.now();
    const lastAttempt = autoDialCooldowns.get(id) || 0;
    if (now - lastAttempt < 15_000) return;
    autoDialCooldowns.set(id, now);

    queueMicrotask(async () => {
      try {
        console.info('[relay] auto-dialing discovered peer by peerId', { id });
        await libp2p.dial(discoveredPeer?.id || id);
      } catch (error) {
        console.warn('[relay] auto-dial failed for discovered peer', {
          id,
          error: error?.message || String(error),
        });
      }
    });
  });

  libp2p.addEventListener('connection:open', (event) => {
    console.info('[relay] connection opened', describeConnection(event.detail));
  });

  libp2p.addEventListener('connection:close', (event) => {
    console.info('[relay] connection closed', describeConnection(event.detail));
  });

  libp2p.addEventListener('self:peer:update', () => {
    logCurrentMultiaddrs(libp2p, 'updated');
  });

  libp2p.addEventListener('transport:listening', () => {
    logCurrentMultiaddrs(libp2p, 'transport listening');
  });

  libp2p.addEventListener('relay:reservation', (event) => {
    const detail = event.detail;
    console.info('[relay] reservation active', {
      relayPeer: detail?.peer?.toString?.() || detail?.peerId?.toString?.() || 'unknown',
      renewed: Boolean(detail?.renewed),
      expires: detail?.reservation?.expire?.toISOString?.() || detail?.expire?.toISOString?.() || null,
    });
    logCurrentMultiaddrs(libp2p, 'post-reservation');
  });
}

function saveLegacyWorkerArchive(encryptedArchive) {
  if (typeof localStorage === 'undefined' || !encryptedArchive) return;

  localStorage.setItem(
    LEGACY_WORKER_ARCHIVE_STORAGE_KEY,
    JSON.stringify({
      ciphertext: Array.from(encryptedArchive.ciphertext),
      iv: Array.from(encryptedArchive.iv),
    })
  );
}

function loadLegacyWorkerArchive() {
  if (typeof localStorage === 'undefined') return null;

  const raw = localStorage.getItem(LEGACY_WORKER_ARCHIVE_STORAGE_KEY);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw);
    return {
      ciphertext: new Uint8Array(parsed.ciphertext),
      iv: new Uint8Array(parsed.iv),
    };
  } catch (error) {
    console.warn('Failed to parse worker archive:', error);
    localStorage.removeItem(LEGACY_WORKER_ARCHIVE_STORAGE_KEY);
    return null;
  }
}

function clearLegacyWorkerArchive() {
  if (typeof localStorage === 'undefined') return;
  localStorage.removeItem(LEGACY_WORKER_ARCHIVE_STORAGE_KEY);
}

function ensureUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new Uint8Array(value || []);
}

async function digestHex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', ensureUint8Array(bytes));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function deriveBytes(seed, info, length = 32) {
  const seedBytes = ensureUint8Array(seed);
  const saltHash = await crypto.subtle.digest('SHA-256', seedBytes);
  const salt = new Uint8Array(saltHash).slice(0, 16);
  const infoBytes =
    typeof info === 'string' ? new TextEncoder().encode(info) : ensureUint8Array(info);
  const baseKey = await crypto.subtle.importKey('raw', seedBytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: infoBytes,
    },
    baseKey,
    length * 8
  );
  return new Uint8Array(bits);
}

function credentialIdToBase64url(credential) {
  const raw = ensureUint8Array(
    credential?.rawCredentialId || credential?.credentialId || []
  );
  if (raw.length === 0) return credential?.credentialId || null;
  return btoa(String.fromCharCode(...raw))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function createRecoveryBootstrapIdentity(seed, ipfs) {
  const bootstrapSeed = await deriveBytes(
    seed,
    'orbitdb/multi-device/worker-recovery-bootstrap'
  );
  const EdSigner = await import('@le-space/ucanto-principal/ed25519');
  const signer = await EdSigner.derive(bootstrapSeed);
  const did = signer.did();
  const publicKey = signer.verifier?.publicKey;

  if (!did || !publicKey) {
    throw new Error('Failed to derive recovery bootstrap identity');
  }

  const identityStorage = createIpfsIdentityStorage(ipfs);
  const identity = await createWorkerEd25519Identity({
    did,
    publicKey: ensureUint8Array(publicKey),
    sign: async (data) => {
      const signature = await signer.sign(ensureUint8Array(data));
      return ensureUint8Array(signature.raw);
    },
  });

  return {
    identity,
    identities: createWorkerEd25519Identities(identity, identityStorage),
  };
}

async function openWorkerRecoveryStore(seed, ipfs) {
  const { identity, identities } = await createRecoveryBootstrapIdentity(seed, ipfs);
  const recoveryOrbitdb = await createOrbitDB({ ipfs, identities, identity });
  const recoveryNameHash = await digestHex(
    await deriveBytes(seed, 'orbitdb/multi-device/worker-recovery-name')
  );
  const db = await recoveryOrbitdb.open(`multi-device-worker-recovery-${recoveryNameHash}`, {
    type: 'keyvalue',
    sync: true,
    AccessController: OrbitDBAccessController({ write: [identity.id] }),
  });

  return {
    orbitdb: recoveryOrbitdb,
    db,
    bootstrapIdentity: identity,
    name: `multi-device-worker-recovery-${recoveryNameHash}`,
  };
}

function normalizeRecoveryRecord(record) {
  if (!record || typeof record !== 'object') return null;
  return {
    ...record,
    archive: record.archive
      ? {
          ciphertext: ensureUint8Array(record.archive.ciphertext),
          iv: ensureUint8Array(record.archive.iv),
        }
      : null,
  };
}

async function writeWorkerRecoveryRecord(recoveryDb, record) {
  await recoveryDb.put(WORKER_RECOVERY_RECORD_KEY, {
    ...record,
    archive: record.archive
      ? {
          ciphertext: Array.from(record.archive.ciphertext),
          iv: Array.from(record.archive.iv),
        }
      : null,
  });
}

async function setupWorkerOrbitIdentity(credential, ipfs) {
  const identityStorage = createIpfsIdentityStorage(ipfs);
  const { seed, source } = await extractPrfSeedFromCredential(credential, {
    prfInput: WORKER_PRF_CONTEXT,
  });
  const credentialId = credentialIdToBase64url(credential);
  const credentialIdHash = credentialId ? await digestHex(new TextEncoder().encode(credentialId)) : null;

  resetDefaultWorkerKeystoreClient();
  await initEd25519KeystoreWithPrfSeed(seed);

  const recoveryStore = await openWorkerRecoveryStore(seed, ipfs);
  let recoveryRecord = normalizeRecoveryRecord(
    await recoveryStore.db.get(WORKER_RECOVERY_RECORD_KEY)
  );
  const hadExistingRecoveryRecord = Boolean(recoveryRecord?.archive);
  let archiveRestored = false;
  let archive = null;
  let did = null;
  let publicKey = null;
  let recoverySource = 'none';

  const encryptedArchive =
    recoveryRecord?.archive || loadLegacyWorkerArchive();
  if (encryptedArchive) {
    try {
      archive = await decryptArchive(encryptedArchive.ciphertext, encryptedArchive.iv);
      await loadWorkerEd25519Archive(archive);
      const EdSigner = await import('@le-space/ucanto-principal/ed25519');
      const restoredSigner = EdSigner.from(archive);
      did = restoredSigner.did();
      publicKey = restoredSigner.verifier.publicKey;
      archiveRestored = Boolean(did && publicKey);
      recoverySource = recoveryRecord?.archive ? 'recovery-db' : 'legacy-localstorage';
    } catch (error) {
      if (recoveryRecord?.archive) {
        throw new Error(
          `Existing worker recovery archive could not be restored: ${error.message || error}`
        );
      }
      console.warn('Failed to restore legacy worker archive, generating fresh identity:', error);
    }
  }

  if (!archiveRestored) {
    const generated = await generateWorkerEd25519DID();
    did = generated.did;
    publicKey = generated.publicKey;
    archive = generated.archive;
    const encrypted = await encryptArchive(archive);
    recoveryRecord = {
      version: 1,
      credentialIdHash,
      workerDid: did,
      archivePrincipalId: archive?.id || null,
      archive: encrypted,
      mainDbAddress: recoveryRecord?.mainDbAddress || null,
      seedSource: source,
      updatedAt: Date.now(),
      createdAt: recoveryRecord?.createdAt || Date.now(),
    };
    await writeWorkerRecoveryRecord(recoveryStore.db, recoveryRecord);
    clearLegacyWorkerArchive();
  } else if (!recoveryRecord?.archive) {
    recoveryRecord = {
      version: 1,
      credentialIdHash,
      workerDid: did,
      archivePrincipalId: archive?.id || null,
      archive: encryptedArchive,
      mainDbAddress: null,
      seedSource: source,
      updatedAt: Date.now(),
      createdAt: Date.now(),
    };
    await writeWorkerRecoveryRecord(recoveryStore.db, recoveryRecord);
    clearLegacyWorkerArchive();
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
    persistRecoveryState: async ({ mainDbAddress } = {}) => {
      const nextRecord = {
        version: 1,
        credentialIdHash,
        workerDid: did,
        archivePrincipalId: archive?.id || null,
        archive: recoveryRecord?.archive || encryptedArchive || null,
        mainDbAddress: mainDbAddress || recoveryRecord?.mainDbAddress || null,
        seedSource: source,
        updatedAt: Date.now(),
        createdAt: recoveryRecord?.createdAt || Date.now(),
      };
      recoveryRecord = nextRecord;
      await writeWorkerRecoveryRecord(recoveryStore.db, nextRecord);
    },
    worker: {
      did,
      seedSource: source,
      archiveRestored,
      archivePrincipalId: archive?.id || null,
      recoveryDbName: recoveryStore.name,
      recoveryDbAddress: recoveryStore.db.address?.toString?.() || recoveryStore.db.address || null,
      recoveryRecordFound: hadExistingRecoveryRecord,
      recoveryRecordSource: recoverySource,
      mainDbAddress: recoveryRecord?.mainDbAddress || null,
    },
  };
}

export async function createLibp2pInstance() {
  const bootstrapList = getBootstrapList();
  const pubsubTopics = getPubsubPeerDiscoveryTopics();

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
      webRTCDirect({
        rtcConfiguration: {
          iceServers: DEFAULT_ICE_SERVERS,
        },
      }),
      webRTC({
        rtcConfiguration: {
          iceServers: DEFAULT_ICE_SERVERS,
        },
      }),
      circuitRelayTransport({
        reservationCompletionTimeout: 20_000,
      }),
    ],
    connectionManager: {
      inboundStreamProtocolNegotiationTimeout: 10_000,
      inboundUpgradeTimeout: 10_000,
      outboundStreamProtocolNegotiationTimeout: 10_000,
      outboundUpgradeTimeout: 10_000,
    },
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    connectionGater: {
      // Allow private addresses for local testing
      denyDialMultiaddr: async () => false,
    },
    peerDiscovery: [
      bootstrap({
        list: bootstrapList
      }),
      pubsubPeerDiscovery({
        interval: 10_000,
        topics: pubsubTopics,
      }),
    ],
    services: {
      pubsub: gossipsub({
        emitSelf: true,
        allowPublishToZeroTopicPeers: true,
      }),
      identify: identify(),
      autonat: autoNAT(),
      dcutr: dcutr(),
    },
  })

  attachLibp2pLogging(libp2p, bootstrapList);
  console.info('[relay] pubsub discovery topics', pubsubTopics);

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
    options.onWorkerRecoveryReady?.(workerState.persistRecoveryState);
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
 * Includes a compact, deduplicated set of browser-dialable addresses and
 * prefers WebRTC-capable addresses so the payload fits in a QR code.
 * @param {Object} libp2p - libp2p instance
 * @returns {{ peerId: string, multiaddrs: string[] }}
 */
export function getQRPayload(libp2p) {
  const peerId = libp2p.peerId.toString();
  return { peerId, multiaddrs: selectQrMultiaddrs(libp2p) };
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

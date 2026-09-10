/**
 * The stack the three demos share: libp2p, Helia on Level stores in
 * IndexedDB, OrbitDB, and the two operations that tear it all down.
 *
 * Each demo used to carry a copy of this, and the copies drifted — the varsig
 * one still fired IndexedDB deletes without waiting for them and never closed
 * the Level stores it had opened, so its "Reset DB" could report success and
 * then hang the next login on a blocked delete.
 *
 * The demos are published under one origin, so they share IndexedDB. Each
 * names a `namespace` that prefixes every store it opens, and a reset deletes
 * that demo's stores and nothing else.
 */
import { createOrbitDB } from '@orbitdb/core';
import { createHeliaLight } from 'helia';
import { withBitswap } from '@helia/bitswap';
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

export function createLibp2pOptions() {
  return {
    addresses: {
      listen: ['/p2p-circuit', '/webrtc'],
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
      circuitRelayTransport({ discoverRelays: 2, maxReservations: 2 }),
    ],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: {
      identify: identify(),
      pubsub: gossipsub({ emitSelf: true, allowPublishToZeroTopicPeers: true }),
    },
    connectionManager: { maxConnections: 20, minConnections: 1 },
  };
}

// The Level stores handed to Helia. Helia's stop() does not close stores it
// did not create, and an open store blocks the IndexedDB delete in
// resetDemoState — so they are kept here and closed in cleanup().
const openStores = new Set();

/**
 * Helia with persistent Level stores under the demo's namespace. No HTTP
 * gateway fallback: these demos hold their own blocks, and a public gateway
 * would only make a miss slow.
 */
export async function createHeliaInstance({
  namespace,
  libp2pOptions = createLibp2pOptions(),
}) {
  const blockstore = new LevelBlockstore(`./${namespace}/blocks`);
  const datastore = new LevelDatastore(`./${namespace}/data`);
  const ipfs = withBitswap(
    withLibp2p(
      createHeliaLight({
        blockstore,
        datastore,
        codecs: [dagCbor, dagJson, json],
        hashers: [sha512],
      }),
      libp2pOptions
    )
  );

  await ipfs.start();
  openStores.add(blockstore);
  openStores.add(datastore);

  return ipfs;
}

/** Where a demo's identities keystore goes, when it has one on disk. */
export function identityKeysPath(namespace) {
  return `./${namespace}/identities`;
}

export async function createOrbitDBInstance({
  ipfs,
  identities,
  identity,
  namespace,
}) {
  return createOrbitDB({
    ipfs,
    identities,
    identity,
    directory: `./${namespace}/orbitdb`,
  });
}

/**
 * Shut everything down, in dependency order. Errors are logged, not thrown:
 * a cleanup that stops halfway leaves more open than one that carries on.
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

    // The identities were created by the demo, so their keystore is not
    // OrbitDB's to close. Left open, an IndexedDB keystore blocks the delete
    // in resetDemoState, and the next login waits on that delete forever. A
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
  }
}

/**
 * Delete one IndexedDB database, and say so only once it is gone.
 *
 * `deleteDatabase` returns a request; the demos used to fire it and move on,
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
      // connection closes; cleanup() has closed everything the demo opened,
      // so this is worth waiting for — but not forever.
      console.warn(
        '🗑️ Delete blocked, waiting for connections to close:',
        name
      );
    };
  });
}

/**
 * Delete every IndexedDB database under the demo's namespace. Call cleanup()
 * first.
 */
export async function resetDemoState({ namespace }) {
  try {
    console.log('🗑️ Clearing IndexedDB for', namespace);
    if (!('databases' in indexedDB)) return;
    const databases = await indexedDB.databases();
    const ours = databases.filter((db) => db.name.includes(namespace));
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

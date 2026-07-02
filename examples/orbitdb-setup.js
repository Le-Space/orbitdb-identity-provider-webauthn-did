import { createOrbitDB } from '@orbitdb/core';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import * as dagCbor from '@ipld/dag-cbor';
import * as dagJson from '@ipld/dag-json';
import { gossipsub } from '@libp2p/gossipsub';
import { identify } from '@libp2p/identify';
import { webSockets } from '@libp2p/websockets';
import { LevelBlockstore } from 'blockstore-level';
import { LevelDatastore } from 'datastore-level';
import { createLibp2p } from 'libp2p';
import * as json from 'multiformats/codecs/json';
import { sha512 } from 'multiformats/hashes/sha2';

export function createExampleLibp2pOptions() {
  return {
    transports: [webSockets()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: {
      identify: identify(),
      pubsub: gossipsub({
        emitSelf: true,
        allowPublishToZeroTopicPeers: true,
      }),
    },
  };
}

export async function createExampleLibp2p() {
  const libp2p = await createLibp2p(createExampleLibp2pOptions());

  if (libp2p.status !== 'started') {
    await libp2p.start();
  }

  return libp2p;
}

export async function createExampleHelia({
  libp2pOptions = createExampleLibp2pOptions(),
  storagePrefix = './orbitdb/examples',
} = {}) {
  const [{ createHeliaLight }, { withBitswap }, { withHTTP }, { withLibp2p }] =
    await Promise.all([
      import('helia'),
      import('@helia/bitswap'),
      import('@helia/http'),
      import('@helia/libp2p'),
    ]);

  const ipfs = withBitswap(
    withLibp2p(
      withHTTP(
        createHeliaLight({
          blockstore: new LevelBlockstore(`${storagePrefix}/blocks`),
          datastore: new LevelDatastore(`${storagePrefix}/data`),
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

export async function createExampleOrbitDB(options = {}) {
  const { storagePrefix, libp2pOptions, ...orbitdbOptions } = options;
  const ipfs = await createExampleHelia({ storagePrefix, libp2pOptions });
  const orbitdb = await createOrbitDB({ ipfs, ...orbitdbOptions });

  return { ipfs, orbitdb };
}

export async function cleanupExampleOrbitDB({ db, orbitdb, ipfs }) {
  if (db) {
    await db.close();
  }

  if (orbitdb) {
    await orbitdb.stop();
  }

  if (ipfs) {
    await ipfs.stop();
  }
}

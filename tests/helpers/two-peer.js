/**
 * Two-peer OrbitDB harness for Node-context tests.
 *
 * Builds real libp2p + Helia + OrbitDB nodes over loopback TCP, so replication
 * is exercised end to end rather than mocked.
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { withBitswap } from '@helia/bitswap';
import { withLibp2p } from '@helia/libp2p';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import * as dagCbor from '@ipld/dag-cbor';
import { gossipsub } from '@libp2p/gossipsub';
import { identify } from '@libp2p/identify';
import { tcp } from '@libp2p/tcp';
import { MemoryBlockstore } from 'blockstore-core';
import { MemoryDatastore } from 'datastore-core';
import { createHeliaLight } from 'helia';
import { createLibp2p } from 'libp2p';
import { sha512 } from 'multiformats/hashes/sha2';
import {
  createOrbitDB,
  Identities,
  KeyStore,
  useIdentityProvider,
} from '@orbitdb/core';

import { OrbitDBWebAuthnIdentityProviderFunction } from '../../src/keystore/provider.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Silence the package's unconditional credential dumps for the duration of a
 * test. logWebAuthnResponse() writes the full credential to console on every
 * WebAuthn call, which floods CI output.
 * @returns {Function} Restores console.
 */
export function silenceWebAuthnDebugLogging() {
  const original = {
    group: console.group,
    groupEnd: console.groupEnd,
    log: console.log,
  };
  let depth = 0;

  console.group = (label) => {
    if (typeof label === 'string' && label.startsWith('[WebAuthn Debug]')) {
      depth += 1;
      return;
    }
    original.group(label);
  };
  console.groupEnd = () => {
    if (depth > 0) {
      depth -= 1;
      return;
    }
    original.groupEnd();
  };
  console.log = (...args) => {
    if (depth > 0) return;
    original.log(...args);
  };

  return () => {
    console.group = original.group;
    console.groupEnd = original.groupEnd;
    console.log = original.log;
  };
}

/**
 * Create a started Helia node on loopback TCP with gossipsub.
 * @param {Object} [options]
 * @returns {Promise<Object>} Helia instance.
 */
export async function createPeer() {
  const libp2p = await createLibp2p({
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: {
      identify: identify(),
      pubsub: gossipsub({ allowPublishToZeroTopicPeers: true }),
    },
  });

  // Helia 7 ignores init.libp2p — the instance has to be composed in.
  const helia = await withBitswap(
    withLibp2p(
      createHeliaLight({
        blockstore: new MemoryBlockstore(),
        datastore: new MemoryDatastore(),
        codecs: [dagCbor],
        hashers: [sha512],
      }),
      libp2p
    )
  );

  await helia.start();
  return helia;
}

/**
 * Dial `b` from `a` and wait until the connection is established.
 * @param {Object} a - Dialing Helia node.
 * @param {Object} b - Listening Helia node.
 */
export async function connectPeers(a, b) {
  await a.libp2p.dial(b.libp2p.getMultiaddrs());
  await waitFor(() => b.libp2p.getConnections().length > 0, 15000);
}

/**
 * Build an OrbitDB instance backed by a WebAuthn identity.
 *
 * Calling this twice with the same keystorePath, directory and credential
 * models a page reload: same keystore, same passkey, fresh Identities.
 *
 * @param {Object} params
 * @returns {Promise<Object>} { orbitdb, identity, identities }
 */
export async function createOrbitForCredential({
  helia,
  credential,
  keystorePath,
  directory,
  id,
}) {
  useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);

  const keystore = await KeyStore({ path: keystorePath });
  const identities = await Identities({ ipfs: helia, keystore });
  const identity = await identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: credential,
    }),
  });

  const orbitdb = await createOrbitDB({
    ipfs: helia,
    identities,
    identity,
    directory,
    id,
  });

  return { orbitdb, identity, identities, keystore };
}

/**
 * Poll until `fn` is truthy or the timeout elapses.
 * @param {Function} fn - Predicate, may be async.
 * @param {number} timeoutMs - Timeout in ms.
 * @param {number} [intervalMs] - Poll interval.
 * @returns {Promise<boolean>} Whether the predicate became true.
 */
export async function waitFor(fn, timeoutMs, intervalMs = 250) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await fn()) return true;
    await sleep(intervalMs);
  }
  return false;
}

/**
 * Collect the values a database holds, polling until `expected` show up.
 * @param {Object} db - OrbitDB events database.
 * @param {number} expected - Number of distinct values to wait for.
 * @param {number} timeoutMs - Timeout in ms.
 * @returns {Promise<string[]>} Values seen.
 */
export async function collectValues(db, expected, timeoutMs) {
  const seen = new Set();
  await waitFor(async () => {
    for (const entry of await db.all()) seen.add(entry.value);
    return seen.size >= expected;
  }, timeoutMs);
  return [...seen];
}

/**
 * Create a scratch directory that is removed on cleanup.
 * @returns {Promise<Object>} { path, cleanup }
 */
export async function scratchDir() {
  const path = await mkdtemp(join(tmpdir(), 'webauthn-two-peer-'));
  return {
    path,
    sub: (name) => join(path, name),
    cleanup: () => rm(path, { recursive: true, force: true }),
  };
}

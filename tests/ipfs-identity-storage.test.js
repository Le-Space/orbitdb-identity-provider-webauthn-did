/**
 * Loading another peer's varsig identity from IPFS.
 *
 * `createIpfsIdentityStorage` returned whatever `blockstore.get` gave. Helia
 * 7's blockstore (interface-blockstore 7) gives a generator of chunks, and
 * both callers — `getIdentity` in `createWebAuthnVarsigIdentities` and the
 * IPFS fallback in `wrapWithVarsigVerification` — decoded it as bytes. The
 * decode threw, their catch swallowed it, and a peer that had not cached an
 * identity never got it. The last two tests are that peer, over real libp2p
 * and bitswap.
 */
import { test, expect } from '@playwright/test';
import { MemoryBlockstore } from 'blockstore-core';
import { CID } from 'multiformats/cid';
import * as raw from 'multiformats/codecs/raw';
import { sha256 } from 'multiformats/hashes/sha2';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import {
  connectPeers,
  createPeer,
  silenceWebAuthnDebugLogging,
} from './helpers/two-peer.js';
import { WebAuthnVarsigProvider } from '../src/varsig/provider.js';
import {
  createIpfsIdentityStorage,
  createWebAuthnVarsigIdentities,
  createWebAuthnVarsigIdentity,
  wrapWithVarsigVerification,
} from '../src/varsig/identity.js';

async function rawBlock(bytes) {
  return { bytes, cid: CID.create(1, raw.code, await sha256.digest(bytes)) };
}

test.describe('createIpfsIdentityStorage', () => {
  test('reads a block back from a Helia 7 blockstore, whose get is a generator', async () => {
    const blockstore = new MemoryBlockstore();
    const { bytes, cid } = await rawBlock(new Uint8Array([1, 2, 3]));
    const storage = createIpfsIdentityStorage({ blockstore });
    await storage.put(cid.toString(), bytes);

    // What this used to hand on as if it were the block.
    expect(Object.prototype.toString.call(blockstore.get(cid))).toBe(
      '[object Generator]'
    );
    expect(await storage.get(cid.toString())).toEqual(bytes);
  });

  test('reads a block from an older blockstore, whose get resolves to bytes', async () => {
    const { bytes, cid } = await rawBlock(new Uint8Array([4, 5, 6]));
    const storage = createIpfsIdentityStorage({
      blockstore: { get: async () => bytes, put: async () => {} },
    });
    expect(await storage.get(cid.toString())).toEqual(bytes);
  });

  test('joins a block that arrives in chunks', async () => {
    const { cid } = await rawBlock(new Uint8Array([7]));
    const storage = createIpfsIdentityStorage({
      blockstore: {
        async *get() {
          yield new Uint8Array([1, 2]);
          yield new Uint8Array([3]);
        },
        put: async () => {},
      },
    });
    expect(await storage.get(cid.toString())).toEqual(
      new Uint8Array([1, 2, 3])
    );
  });

  test('a block nobody has is undefined, and the wait for it is bounded', async () => {
    const blockstore = new MemoryBlockstore();
    const { cid } = await rawBlock(new Uint8Array([9]));
    const signals = [];
    const storage = createIpfsIdentityStorage({
      blockstore: {
        get: (key, options) => {
          signals.push(options?.signal);
          return blockstore.get(key, options);
        },
        put: async () => {},
      },
    });
    expect(await storage.get(cid.toString())).toBeUndefined();
    // Iterating Helia 7's generator fetches a missing block from the network;
    // the signal is what ends that wait.
    expect(signals[0]).toBeInstanceOf(AbortSignal);
  });
});

test.describe('another peer, with nothing cached, over libp2p and bitswap', () => {
  test.describe.configure({ mode: 'serial' });

  /** Restore functions, newest first. */
  let restores = [];
  let holder;
  let reader;

  /** A varsig identity of its own passkey: one mock authenticator each. */
  async function varsigIdentity(userId) {
    restores.unshift(installMockAuthenticator(await createMockAuthenticator()));
    const credential = await WebAuthnVarsigProvider.createCredential({
      userId,
      displayName: userId,
    });
    return createWebAuthnVarsigIdentity({ credential });
  }

  test.beforeEach(async () => {
    test.setTimeout(120000);
    restores = [silenceWebAuthnDebugLogging()];
    holder = await createPeer();
    reader = await createPeer();
    await connectPeers(reader, holder);
  });

  test.afterEach(async () => {
    await reader?.stop();
    await holder?.stop();
    for (const restore of restores) restore();
  });

  test('wrapWithVarsigVerification loads it from the peer that holds it, and verifies it', async () => {
    const identity = await varsigIdentity('anna');
    // The holder keeps its identity in IPFS, as createWebAuthnVarsigIdentities
    // does when it is given storage.
    await createIpfsIdentityStorage(holder).put(identity.hash, identity.bytes);

    // The reader's own OrbitDB identities know nothing of it.
    const stranger = {
      getIdentity: async () => undefined,
      verifyIdentity: async () => false,
      verify: async () => false,
    };
    const identities = wrapWithVarsigVerification(stranger, reader);
    const loaded = await identities.getIdentity(identity.hash);

    expect(loaded).toMatchObject({
      id: identity.id,
      hash: identity.hash,
      type: 'webauthn-varsig',
    });
    expect(await identities.verifyIdentity(loaded)).toBe(true);
  });

  test('createWebAuthnVarsigIdentities finds it the same way', async () => {
    const identity = await varsigIdentity('anna');
    await createIpfsIdentityStorage(holder).put(identity.hash, identity.bytes);

    const own = await varsigIdentity('ben');
    expect(own.id).not.toBe(identity.id);
    const identities = createWebAuthnVarsigIdentities(
      own,
      {},
      createIpfsIdentityStorage(reader)
    );
    const loaded = await identities.getIdentity(identity.hash);

    expect(loaded).toMatchObject({ id: identity.id, hash: identity.hash });
    expect(await identities.verifyIdentity(loaded)).toBe(true);
  });
});

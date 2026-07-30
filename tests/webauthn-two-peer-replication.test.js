/**
 * Two-peer OrbitDB replication with a WebAuthn identity.
 *
 * The suite this repo previously had never opened a second peer and never
 * looked at an identity hash, so the failure mode described in issue #18 —
 * a database that replicates some entries and silently drops the rest —
 * had no coverage at all.
 *
 * Tests marked `test.fail()` pin the open bug. When it is fixed they will
 * start passing and Playwright will report "expected to fail but passed",
 * which is the signal to drop the annotation.
 */
import { test, expect } from '@playwright/test';

import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import {
  collectValues,
  connectPeers,
  createOrbitForCredential,
  createPeer,
  scratchDir,
  silenceWebAuthnDebugLogging,
} from './helpers/two-peer.js';

const REPLICATION_TIMEOUT = 25000;

test.describe('WebAuthn identity across two OrbitDB peers', () => {
  test.describe.configure({ mode: 'serial' });

  let restoreAuthenticator;
  let restoreLogging;
  let scratch;
  let credential;
  let alice;
  let bob;

  test.beforeEach(async () => {
    test.setTimeout(120000);

    restoreLogging = silenceWebAuthnDebugLogging();
    const authenticator = await createMockAuthenticator();
    restoreAuthenticator = installMockAuthenticator(authenticator);
    scratch = await scratchDir();

    const { WebAuthnDIDProvider } = await import('../src/webauthn/provider.js');
    credential = await WebAuthnDIDProvider.createCredential({
      userId: 'two-peer-user',
      displayName: 'Two Peer User',
    });

    alice = await createPeer();
    bob = await createPeer();
    await connectPeers(bob, alice);
  });

  test.afterEach(async () => {
    await bob?.stop();
    await alice?.stop();
    await scratch?.cleanup();
    restoreAuthenticator?.();
    restoreLogging?.();
  });

  const openAlice = (label) =>
    createOrbitForCredential({
      helia: alice,
      credential,
      keystorePath: scratch.sub('alice-keys'),
      directory: scratch.sub('alice-orbit'),
      id: label,
    });

  const openBob = () =>
    createOrbitForCredential({
      helia: bob,
      credential,
      keystorePath: scratch.sub('bob-keys'),
      directory: scratch.sub('bob-orbit'),
      id: 'bob',
    });

  test('peers are connected and share a pubsub-capable libp2p', async () => {
    expect(alice.libp2p.getConnections().length).toBeGreaterThan(0);
    expect(bob.libp2p.getConnections().length).toBeGreaterThan(0);
    expect(alice.libp2p.services.pubsub).toBeTruthy();
  });

  test('replicates entries written under a single identity document', async () => {
    const a = await openAlice('alice');
    const db = await a.orbitdb.open('single-identity', { type: 'events' });
    await db.add('entry-1');
    await db.add('entry-2');

    const b = await openBob();
    const dbB = await b.orbitdb.open(db.address, { type: 'events' });

    const seen = await collectValues(dbB, 2, REPLICATION_TIMEOUT);
    expect(seen.sort()).toEqual(['entry-1', 'entry-2']);

    await dbB.close();
    await b.orbitdb.stop();
    await db.close();
    await a.orbitdb.stop();
  });

  test('the remote peer can resolve identity documents over bitswap', async () => {
    const a = await openAlice('alice');
    const db = await a.orbitdb.open('identity-resolution', { type: 'events' });
    await db.add('entry-1');

    const b = await openBob();
    const dbB = await b.orbitdb.open(db.address, { type: 'events' });
    await collectValues(dbB, 1, REPLICATION_TIMEOUT);

    // Identities are plain IPFS blocks fetched on demand — not replicated
    // through any OrbitDB database.
    const resolved = await b.identities.getIdentity(a.identity.hash);
    expect(resolved).toBeTruthy();
    expect(resolved.id).toBe(a.identity.id);

    await dbB.close();
    await b.orbitdb.stop();
    await db.close();
    await a.orbitdb.stop();
  });

  // ---------------------------------------------------------------------
  // Issue #18
  // ---------------------------------------------------------------------

  test.fail('identity hash is stable across reloads (issue #18)', async () => {
    const first = await openAlice('alice');
    await first.orbitdb.stop();

    const second = await openAlice('alice');
    await second.orbitdb.stop();

    // The DID and the keypair are stable; only the document hash moves,
    // because signIdentity() performs a live WebAuthn assertion whose
    // result is embedded in the content-addressed document.
    expect(second.identity.id).toBe(first.identity.id);
    expect(second.identity.publicKey).toBe(first.identity.publicKey);
    expect(second.identity.signatures.id).toBe(first.identity.signatures.id);

    expect(second.identity.hash).toBe(first.identity.hash);
  });

  test.fail(
    'entries written before and after a reload both replicate (issue #18)',
    async () => {
      const load1 = await openAlice('alice');
      const db1 = await load1.orbitdb.open('reload-test', { type: 'events' });
      const address = db1.address;
      await db1.add('entry-1-before-reload');
      await db1.close();
      await load1.orbitdb.stop();

      // page reload: same keystore, same passkey, fresh Identities
      const load2 = await openAlice('alice');
      const db2 = await load2.orbitdb.open(address, { type: 'events' });
      await db2.add('entry-2-after-reload');

      expect((await db2.all()).length).toBe(2);

      const b = await openBob();
      const dbB = await b.orbitdb.open(address, { type: 'events' });
      const seen = await collectValues(dbB, 2, REPLICATION_TIMEOUT);

      await dbB.close();
      await b.orbitdb.stop();
      await db2.close();
      await load2.orbitdb.stop();

      // Today bob receives only whichever entry was signed by the identity
      // document he happened to verify first.
      expect(seen.sort()).toEqual([
        'entry-1-before-reload',
        'entry-2-after-reload',
      ]);
    }
  );

  test.fail(
    'a second identity document from the same DID still verifies (issue #18)',
    async () => {
      // One load at a time — the keystore holds an exclusive lock.
      const load1 = await openAlice('alice');
      const hash1 = load1.identity.hash;
      await load1.orbitdb.stop();

      const load2 = await openAlice('alice');
      const hash2 = load2.identity.hash;

      const b = await openBob();

      // Both documents are retrievable — resolution is not the problem.
      const doc1 = await b.identities.getIdentity(hash1);
      const doc2 = await b.identities.getIdentity(hash2);
      expect(doc1).toBeTruthy();
      expect(doc2).toBeTruthy();

      // signatures.id is deterministic, so both documents collide on the key
      // of verifiedIdentitiesCache in @orbitdb/core identities.js. The first
      // document verified wins; isEqual() then rejects every later document
      // because signatures.publicKey differs.
      expect(doc1.signatures.id).toBe(doc2.signatures.id);
      expect(doc1.publicKey).toBe(doc2.publicKey);
      expect(doc1.signatures.publicKey).not.toBe(doc2.signatures.publicKey);

      expect(await b.identities.verifyIdentity(doc1)).toBe(true);
      expect(await b.identities.verifyIdentity(doc2)).toBe(true);

      await b.orbitdb.stop();
      await load2.orbitdb.stop();
    }
  );
});

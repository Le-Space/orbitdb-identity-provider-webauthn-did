/**
 * Two-peer OrbitDB replication with a WebAuthn identity.
 *
 * The suite this repo previously had never opened a second peer and never
 * looked at an identity hash, so the failure mode described in issue #18 —
 * a database that replicates some entries and silently drops the rest —
 * had no coverage at all.
 *
 * The issue #18 cases below were introduced as `test.fail()` and flipped once
 * signIdentity() started reusing a stored proof. They now guard the fix.
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

  test('identity hash is stable across reloads (issue #18)', async () => {
    const first = await openAlice('alice');
    await first.orbitdb.stop();

    const second = await openAlice('alice');
    await second.orbitdb.stop();

    // signIdentity() reuses the stored proof instead of running a fresh
    // WebAuthn assertion, so every field — and therefore the content address
    // of the document — survives the reload.
    expect(second.identity.id).toBe(first.identity.id);
    expect(second.identity.publicKey).toBe(first.identity.publicKey);
    expect(second.identity.signatures.id).toBe(first.identity.signatures.id);

    expect(second.identity.hash).toBe(first.identity.hash);
  });

  test('entries written before and after a reload both replicate (issue #18)', async () => {
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

    // Both entries were signed under the same identity document, so nothing
    // collides in verifiedIdentitiesCache and both survive canAppend.
    expect(seen.sort()).toEqual([
      'entry-1-before-reload',
      'entry-2-after-reload',
    ]);
  });

  test('a reload reuses the identity document rather than minting one (issue #18)', async () => {
    // One load at a time — the keystore holds an exclusive lock.
    const load1 = await openAlice('alice');
    const hash1 = load1.identity.hash;
    await load1.orbitdb.stop();

    const load2 = await openAlice('alice');
    const hash2 = load2.identity.hash;

    const b = await openBob();

    // One document, so verifiedIdentitiesCache in @orbitdb/core (keyed on the
    // deterministic signatures.id) cannot be poisoned by a second one.
    expect(hash2).toBe(hash1);

    const doc = await b.identities.getIdentity(hash1);
    expect(doc).toBeTruthy();
    expect(await b.identities.verifyIdentity(doc)).toBe(true);

    await b.orbitdb.stop();
    await load2.orbitdb.stop();
  });

  test('two devices sharing a passkey derive the same identity document', async () => {
    // The point of deriving the signing key from PRF: separate keystores, one
    // passkey, and the identity document comes out identical — so there is a
    // single block to keep retrievable rather than one per device.
    const deviceA = await openAlice('deviceA');
    await deviceA.orbitdb.stop();

    const deviceB = await createOrbitForCredential({
      helia: alice,
      credential,
      keystorePath: scratch.sub('deviceB-keys'),
      directory: scratch.sub('deviceB-orbit'),
      id: 'deviceB',
    });

    expect(deviceB.identity.id).toBe(deviceA.identity.id);
    expect(deviceB.identity.publicKey).toBe(deviceA.identity.publicKey);
    expect(deviceB.identity.signatures.id).toBe(deviceA.identity.signatures.id);
    expect(deviceB.identity.hash).toBe(deviceA.identity.hash);

    const bob2 = await openBob();
    for (const hash of [deviceA.identity.hash, deviceB.identity.hash]) {
      const doc = await bob2.identities.getIdentity(hash);
      expect(doc).toBeTruthy();
      expect(await bob2.identities.verifyIdentity(doc)).toBe(true);
    }

    await bob2.orbitdb.stop();
    await deviceB.orbitdb.stop();
  });

  test('an authenticator without PRF still works, one identity per device', async () => {
    // The fallback. No PRF output means no reproducible key, so the keystore
    // generates its own — 0.4.0 behaviour: stable per device, distinct across
    // devices, and every document still valid.
    restoreAuthenticator?.();
    const noPrf = await createMockAuthenticator({ supportsPrf: false });
    restoreAuthenticator = installMockAuthenticator(noPrf);

    const { WebAuthnDIDProvider } = await import('../src/webauthn/provider.js');
    const plainCredential = await WebAuthnDIDProvider.createCredential({
      userId: 'no-prf-user',
      displayName: 'No PRF User',
    });

    const open = (name) =>
      createOrbitForCredential({
        helia: alice,
        credential: plainCredential,
        keystorePath: scratch.sub(`${name}-keys`),
        directory: scratch.sub(`${name}-orbit`),
        id: name,
      });

    const first = await open('noPrfA');
    const firstHash = first.identity.hash;
    await first.orbitdb.stop();

    // Reloading the same device is still stable — that is 0.4.0's fix.
    const reloaded = await open('noPrfA');
    expect(reloaded.identity.hash).toBe(firstHash);
    await reloaded.orbitdb.stop();

    // A second device diverges, which is the cost of having no PRF.
    const second = await open('noPrfB');
    expect(second.identity.id).toBe(first.identity.id);
    expect(second.identity.publicKey).not.toBe(first.identity.publicKey);

    const b = await openBob();
    for (const hash of [firstHash, second.identity.hash]) {
      const doc = await b.identities.getIdentity(hash);
      expect(doc).toBeTruthy();
      expect(await b.identities.verifyIdentity(doc)).toBe(true);
    }

    await b.orbitdb.stop();
    await second.orbitdb.stop();
  });

  test('an existing keystore key is never replaced', async () => {
    // Upgrading from 0.4.0 must not swap the signing key underneath a device
    // that already has history: that would mint a second document for the DID.
    const { KeyStore } = await import('@orbitdb/core');
    const { ensureDerivedSigningKey } =
      await import('../src/keystore/derived-signing-key.js');
    const { WebAuthnDIDProvider } = await import('../src/webauthn/provider.js');

    const did = await WebAuthnDIDProvider.createDID(credential);
    const keystore = await KeyStore({ path: scratch.sub('preexisting-keys') });
    await keystore.createKey(did); // whatever 0.4.0 left behind
    const before = keystore.getPublic(await keystore.getKey(did));

    const outcome = await ensureDerivedSigningKey({
      keystore,
      did,
      credential,
    });

    expect(outcome).toBe('existing');
    expect(keystore.getPublic(await keystore.getKey(did))).toBe(before);
    await keystore.close();
  });
});

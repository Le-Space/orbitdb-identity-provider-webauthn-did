/**
 * The books' identity: nobody's passkey, derived from a secret in a vault, and
 * the same identity whichever key opened the vault.
 *
 * What the invoice app builds on: every registered security key writes as this
 * identity, it is the root of the books' access controller, and an identity
 * from any other secret is refused there.
 */
import { test, expect } from '@playwright/test';
import {
  Identities,
  MemoryStorage,
  OrbitDBAccessController,
  createOrbitDB,
  useIdentityProvider,
} from '@orbitdb/core';
import { generateKeyPairFromSeed, publicKeyFromRaw } from '@libp2p/crypto/keys';

import {
  createSecretSigner,
  createVault,
  openVault,
  addSlot,
  deriveSubkey,
  createSessionKeystore,
  OrbitDBWebAuthnIdentityProviderFunction,
} from '../src/index.js';
import { createEd25519DidFromPublicKey } from '../src/standalone/index.js';
import { connectPeers, createPeer, scratchDir } from './helpers/two-peer.js';

const SECRET = new Uint8Array(32).fill(7);
const INFO = 'test/books/v1';
const hex = (bytes) => Buffer.from(bytes).toString('hex');

/** The identity OrbitDB gets for a signer: a session keystore, no passkey. */
async function identityOf(signer, ipfs) {
  const keystore = await createSessionKeystore({ signer });
  const identities = await Identities({
    keystore,
    ...(ipfs ? { ipfs } : { storage: await MemoryStorage() }),
  });
  const identity = await identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ signer }),
  });
  return { identities, identity };
}

test.beforeAll(() => {
  try {
    useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
  } catch {
    // registered by an earlier suite in this worker
  }
});

test.describe('createSecretSigner', () => {
  test('the same secret and info give the same key and DID; another either, another', async () => {
    const a = await createSecretSigner(SECRET, { info: INFO });
    const b = await createSecretSigner(Uint8Array.from(SECRET), { info: INFO });
    expect(b.did).toBe(a.did);
    expect(hex(b.publicKey)).toBe(hex(a.publicKey));

    const otherInfo = await createSecretSigner(SECRET, {
      info: 'test/books/v2',
    });
    const otherSecret = await createSecretSigner(new Uint8Array(32).fill(8), {
      info: INFO,
    });
    expect(otherInfo.did).not.toBe(a.did);
    expect(otherSecret.did).not.toBe(a.did);
  });

  test('is the Ed25519 key of deriveSubkey(secret, info), and its did:key', async () => {
    const signer = await createSecretSigner(SECRET, { info: INFO });
    // Pinned: changing the derivation changes the identity, and with it who
    // may write to every database rooted at it.
    expect(signer.did).toBe(
      'did:key:z6MkjkUkrC7MwvGYiDtj1CefwDdrUYcrg55cEwGYqUUe4GwK'
    );
    const key = await generateKeyPairFromSeed(
      'Ed25519',
      await deriveSubkey(SECRET, INFO)
    );
    expect(hex(signer.publicKey)).toBe(hex(key.publicKey.raw));
    expect(signer.did).toBe(createEd25519DidFromPublicKey(key.publicKey.raw));
    expect(signer.type).toBe('Ed25519');
    // Nothing on it holds the private key.
    expect(Object.keys(signer).sort()).toEqual([
      'did',
      'publicKey',
      'sign',
      'type',
    ]);
  });

  test('signs what its public key verifies', async () => {
    const signer = await createSecretSigner(SECRET, { info: INFO });
    const data = new TextEncoder().encode('an entry');
    const signature = await signer.sign(data);
    const publicKey = publicKeyFromRaw(signer.publicKey);
    expect(await publicKey.verify(data, signature)).toBe(true);
    expect(
      await publicKey.verify(new TextEncoder().encode('another'), signature)
    ).toBe(false);
  });

  test('refuses a short secret, a secret that is not bytes, and no info', async () => {
    await expect(
      createSecretSigner(new Uint8Array(31), { info: INFO })
    ).rejects.toThrow(TypeError);
    await expect(createSecretSigner('secret', { info: INFO })).rejects.toThrow(
      TypeError
    );
    await expect(createSecretSigner(SECRET, { info: '' })).rejects.toThrow(
      TypeError
    );
    await expect(createSecretSigner(SECRET)).rejects.toThrow(TypeError);
  });
});

test.describe('the identity it makes', () => {
  test('needs no passkey: no credential, no WebAuthn call', async () => {
    // No authenticator is installed here at all: a prompt would throw.
    const signer = await createSecretSigner(SECRET, { info: INFO });
    const { identities, identity } = await identityOf(signer);
    expect(identity.id).toBe(signer.did);
    expect(identity.publicKey).toBe(hex(signer.publicKey));
    expect(await identities.verifyIdentity(identity)).toBe(true);
  });

  test('is the same document whichever key opened the vault', async () => {
    // Two security keys, two slots, one vault holding the secret.
    const slotA = {
      slotKey: new Uint8Array(32).fill(1),
      rawCredentialId: Uint8Array.of(1),
    };
    const slotB = {
      slotKey: new Uint8Array(32).fill(2),
      rawCredentialId: Uint8Array.of(2),
    };
    const { vault, vaultKey } = await createVault(SECRET, slotA);
    const withB = await addSlot(vault, vaultKey, slotB);

    const byA = (await openVault(withB, slotA)).payload;
    const byB = (await openVault(withB, slotB)).payload;
    const viaA = await identityOf(
      await createSecretSigner(byA, { info: INFO })
    );
    const viaB = await identityOf(
      await createSecretSigner(byB, { info: INFO })
    );

    expect(viaB.identity.id).toBe(viaA.identity.id);
    expect(viaB.identity.hash).toBe(viaA.identity.hash);
  });

  test('a provider with neither credential nor signer is refused', async () => {
    await expect(OrbitDBWebAuthnIdentityProviderFunction({})()).rejects.toThrow(
      /webauthnCredential, or a signer/
    );
  });
});

test.describe('the root of the books', () => {
  test('every key writes as the books; an identity from another secret is refused', async () => {
    test.setTimeout(90000);
    const dirs = await scratchDir();
    /** Each key on a device of its own: its own node, its own storage. */
    const devices = [];
    const open = async (signer, name) => {
      const helia = await createPeer();
      // Later devices reach the first, to fetch the books' manifest from it.
      if (devices.length > 0) await connectPeers(helia, devices[0].helia);
      const { identities, identity } = await identityOf(signer, helia);
      const orbitdb = await createOrbitDB({
        ipfs: helia,
        identities,
        identity,
        directory: dirs.sub(name),
      });
      devices.push({ helia, orbitdb });
      return orbitdb;
    };

    try {
      const books = await createSecretSigner(SECRET, { info: INFO });
      // The device where key A opened the vault creates the books, rooted at
      // the books' identity.
      const first = await open(books, 'key-a');
      const db = await first.open('books', {
        type: 'events',
        AccessController: OrbitDBAccessController({ write: [books.did] }),
      });
      await db.add('written through key A');

      // Key B opened the same vault elsewhere: a second instance, the same
      // identity, and the books accept it as their root.
      const second = await open(
        await createSecretSigner(Uint8Array.from(SECRET), { info: INFO }),
        'key-b'
      );
      const same = await second.open(db.address);
      await same.add('written through key B');
      expect((await same.all()).map((e) => e.value)).toContain(
        'written through key B'
      );

      // A secret that is not the vault's: another identity, refused.
      const stranger = await open(
        await createSecretSigner(new Uint8Array(32).fill(9), { info: INFO }),
        'stranger'
      );
      const theirs = await stranger.open(db.address);
      await expect(theirs.add('not ours')).rejects.toThrow(
        /not allowed to write/
      );
    } finally {
      for (const { orbitdb, helia } of devices.reverse()) {
        await orbitdb.stop().catch(() => {});
        await helia.stop().catch(() => {});
      }
      await dirs.cleanup();
    }
  });
});

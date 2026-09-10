/**
 * A forged identity must not pass verification; a genuine one must.
 *
 * GHSA-326j-4cc3-4rrg: every "does not" below passed before. The static
 * `verifyIdentity` OrbitDB calls accepted any `did:key:` of type `webauthn`,
 * `WebAuthnDIDProvider.verify()` accepted any proof with the right fields,
 * varsig verification switched itself off when `window.__PLAYWRIGHT__` was set,
 * and a varsig identity's id was never compared with the key that signs for it.
 *
 * Each forgery comes with the genuine case beside it, so a check that simply
 * refused everything would fail here too.
 */
import { test, expect } from '@playwright/test';
import {
  Identities,
  KeyStore,
  MemoryStorage,
  useIdentityProvider,
} from '@orbitdb/core';
import Identity from '@orbitdb/core/src/identities/identity.js';
import { signMessage } from '@orbitdb/core/src/key-store.js';
import { generateKeyPair } from '@libp2p/crypto/keys';
import { base58btc } from 'multiformats/bases/base58';

import {
  OrbitDBWebAuthnIdentityProvider,
  OrbitDBWebAuthnIdentityProviderFunction,
} from '../src/keystore/provider.js';
import { WebAuthnDIDProvider } from '../src/webauthn/provider.js';
import { WebAuthnVarsigProvider } from '../src/varsig/provider.js';
import {
  createWebAuthnVarsigIdentity,
  verifyVarsigIdentity,
} from '../src/varsig/identity.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { silenceWebAuthnDebugLogging } from './helpers/two-peer.js';

const noop = async () => '';

async function ed25519Did() {
  const key = await generateKeyPair('Ed25519');
  return `did:key:${base58btc.encode(new Uint8Array([0xed, 0x01, ...key.publicKey.raw]))}`;
}

async function orbitIdentities() {
  const keystore = await KeyStore({ storage: await MemoryStorage() });
  const identities = await Identities({
    keystore,
    storage: await MemoryStorage(),
  });
  return { keystore, identities };
}

/** An identity that claims `id` but holds only a key of its own. */
async function forge({ keystore, id, publicKeySignature = 'not-a-signature' }) {
  const attacker = await keystore.createKey(`attacker-${Math.random()}`);
  return Identity({
    id,
    publicKey: Buffer.from(attacker.publicKey.raw).toString('hex'),
    type: 'webauthn',
    signatures: {
      id: await signMessage(attacker, id),
      publicKey: publicKeySignature,
    },
    sign: noop,
    verify: noop,
  });
}

function withMockAuthenticator() {
  let restoreAuthenticator;
  let restoreLogging;
  test.beforeEach(async () => {
    restoreLogging = silenceWebAuthnDebugLogging();
    restoreAuthenticator = installMockAuthenticator(
      await createMockAuthenticator()
    );
    try {
      useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
    } catch {
      // registered by an earlier test
    }
  });
  test.afterEach(() => {
    restoreAuthenticator?.();
    restoreLogging?.();
  });
}

test.describe('webauthn identity verification', () => {
  withMockAuthenticator();

  async function genuine(options = {}) {
    const { keystore, identities } = await orbitIdentities();
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'alice',
      displayName: 'Alice',
    });
    const identity = await identities.createIdentity({
      provider: OrbitDBWebAuthnIdentityProviderFunction({
        webauthnCredential: credential,
        ...options,
        ...(options.useKeystoreDID ? { keystore } : {}),
      }),
    });
    return { keystore, identities, identity, credential };
  }

  test('a genuine passkey identity passes', async () => {
    const { identities, identity } = await genuine();
    expect(identity.id).toMatch(/^did:key:z/);
    expect(await identities.verifyIdentity(identity)).toBe(true);
  });

  test('its derived signing key is secp256k1 unless asked otherwise', async () => {
    const { keystore, identity } = await genuine();
    expect((await keystore.getKey(identity.id)).type).toBe('secp256k1');
    expect(identity.publicKey).toHaveLength(66); // 33-byte compressed point
  });

  test("signingKeyType 'Ed25519' derives an Ed25519 key, and the identity still verifies", async () => {
    const { keystore, identities, identity } = await genuine({
      signingKeyType: 'Ed25519',
    });
    expect((await keystore.getKey(identity.id)).type).toBe('Ed25519');
    expect(identity.publicKey).toHaveLength(64); // 32-byte Ed25519 key
    expect(await identities.verifyIdentity(identity)).toBe(true);
  });

  test('the same passkey derives the same Ed25519 key on a second device', async () => {
    const first = await genuine({ signingKeyType: 'Ed25519' });
    const { identities } = await orbitIdentities();
    const second = await identities.createIdentity({
      provider: OrbitDBWebAuthnIdentityProviderFunction({
        webauthnCredential: first.credential,
        signingKeyType: 'Ed25519',
      }),
    });
    expect(second.id).toBe(first.identity.id);
    expect(second.publicKey).toBe(first.identity.publicKey);
  });

  test('a keystore that already holds a secp256k1 key for the DID keeps it', async () => {
    const { keystore, identities } = await orbitIdentities();
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'alice',
      displayName: 'Alice',
    });
    const did = await WebAuthnDIDProvider.createDID(credential);
    await keystore.createKey(did); // whatever an earlier version left behind
    const identity = await identities.createIdentity({
      provider: OrbitDBWebAuthnIdentityProviderFunction({
        webauthnCredential: credential,
        signingKeyType: 'Ed25519',
      }),
    });
    expect((await keystore.getKey(did)).type).toBe('secp256k1');
    expect(await identities.verifyIdentity(identity)).toBe(true);
  });

  test('an unknown signingKeyType is refused up front', async () => {
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'alice',
      displayName: 'Alice',
    });
    expect(
      () =>
        new OrbitDBWebAuthnIdentityProvider({
          webauthnCredential: credential,
          signingKeyType: 'P-256',
        })
    ).toThrow(/signingKeyType/);
  });

  test('a stranger key claiming that DID does not', async () => {
    const { keystore, identities, identity } = await genuine();
    const forged = await forge({ keystore, id: identity.id });
    expect(await identities.verifyIdentity(forged)).toBe(false);
  });

  test('nor does it by replaying the genuine passkey proof', async () => {
    // The passkey signed `publicKey + signatures.id`. Beside a different key
    // that proof has to fail on the challenge, not pass on its shape.
    const { keystore, identities, identity } = await genuine();
    const forged = await forge({
      keystore,
      id: identity.id,
      publicKeySignature: identity.signatures.publicKey,
    });
    expect(await identities.verifyIdentity(forged)).toBe(false);
  });

  test('a legacy hash id cannot be bound to a key and is refused', async () => {
    const { keystore, identities } = await orbitIdentities();
    const forged = await forge({ keystore, id: 'a'.repeat(64) });
    expect(await identities.verifyIdentity(forged)).toBe(false);
  });

  test('WebAuthnDIDProvider.verify checks the signature, not the shape', async () => {
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'bob',
      displayName: 'Bob',
    });
    const provider = new WebAuthnDIDProvider(credential);
    const proof = await provider.sign('hello');
    const strangerKey = (await createMockAuthenticator()).publicKey;

    expect(await provider.verify(proof, 'hello', credential.publicKey)).toBe(
      true
    );
    expect(await provider.verify(proof, 'hello!', credential.publicKey)).toBe(
      false
    );
    expect(await provider.verify(proof, 'hello', strangerKey)).toBe(false);
  });

  test('an Ed25519 keystore identity is signed by the key its DID names', async () => {
    // It used to store its key under the credential's P-256 DID; OrbitDB then
    // found nothing under the Ed25519 DID and signed with a fresh secp256k1 key.
    const { keystore, identities, identity } = await genuine({
      useKeystoreDID: true,
      keystoreKeyType: 'Ed25519',
    });
    expect(identity.id).toMatch(/^did:key:z6Mk/);
    const signingKey = await keystore.getKey(identity.id);
    expect(signingKey?.type).toBe('Ed25519');
    expect(identity.publicKey).toBe(
      Buffer.from(signingKey.publicKey.raw).toString('hex')
    );
    expect(await identities.verifyIdentity(identity)).toBe(true);
  });

  test('so is an encrypted one', async () => {
    const { keystore, identities, identity } = await genuine({
      useKeystoreDID: true,
      keystoreKeyType: 'Ed25519',
      encryptKeystore: true,
    });
    expect(identity.id).toMatch(/^did:key:z6Mk/);
    expect((await keystore.getKey(identity.id))?.type).toBe('Ed25519');
    expect(await identities.verifyIdentity(identity)).toBe(true);
  });

  test('a keystore DID signed by some other key is refused', async () => {
    const { keystore, identities } = await orbitIdentities();
    const forged = await forge({ keystore, id: await ed25519Did() });
    expect(await identities.verifyIdentity(forged)).toBe(false);
  });
});

test.describe('varsig identity verification', () => {
  withMockAuthenticator();

  async function genuineVarsig() {
    const credential = await WebAuthnVarsigProvider.createCredential({
      userId: 'carol',
      displayName: 'Carol',
    });
    return createWebAuthnVarsigIdentity({ credential });
  }

  test('a genuine varsig identity passes', async () => {
    const identity = await genuineVarsig();
    expect(await verifyVarsigIdentity(identity)).toBe(true);
  });

  test('its signatures do not carry over to another DID', async () => {
    const identity = await genuineVarsig();
    const relabelled = { ...identity, id: await ed25519Did() };
    expect(await verifyVarsigIdentity(relabelled)).toBe(false);
  });

  test('the Playwright flag no longer switches verification off', async () => {
    const junk = new Uint8Array([1, 2, 3]);
    const forged = {
      id: await ed25519Did(),
      type: 'webauthn-varsig',
      publicKey: crypto.getRandomValues(new Uint8Array(32)),
      signatures: { id: junk, publicKey: junk },
    };
    globalThis.window.__PLAYWRIGHT__ = true;
    try {
      expect(await verifyVarsigIdentity(forged)).toBe(false);
    } finally {
      delete globalThis.window.__PLAYWRIGHT__;
    }
  });
});

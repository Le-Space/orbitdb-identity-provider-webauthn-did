/**
 * An identity whose key signs somewhere else — in the browser that is a Web
 * Worker, here it is an in-process Ed25519 key behind the same interface.
 * What has to hold: the identity is the signer's DID, OrbitDB signs entries
 * and the identity document through `sign()` without ever holding the key,
 * the passkey is not asked at all, verification accepts it by the
 * keystore-DID rule, and an impostor claiming the DID is refused.
 */
import { test, expect } from '@playwright/test';
import { Identities, MemoryStorage, useIdentityProvider } from '@orbitdb/core';
import { signMessage } from '@orbitdb/core/src/key-store.js';
import { generateKeyPair } from '@libp2p/crypto/keys';

import {
  OrbitDBWebAuthnIdentityProvider,
  OrbitDBWebAuthnIdentityProviderFunction,
} from '../src/keystore/provider.js';
import {
  createSessionKeystore,
  assertSigner,
} from '../src/keystore/session-keystore.js';
import { createEd25519DidFromPublicKey } from '../src/standalone/worker/client.js';
import { WebAuthnDIDProvider } from '../src/webauthn/provider.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { silenceWebAuthnDebugLogging } from './helpers/two-peer.js';

const hex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** What createWorkerSigner hands out, with the key kept in this closure. */
async function inProcessSigner() {
  const key = await generateKeyPair('Ed25519');
  let signatures = 0;
  return {
    signer: {
      type: 'Ed25519',
      did: createEd25519DidFromPublicKey(key.publicKey.raw),
      publicKey: key.publicKey.raw,
      sign: async (data) => {
        signatures += 1;
        return key.sign(data);
      },
    },
    key,
    count: () => signatures,
  };
}

let restoreAuthenticator;
let restoreLogging;
let authenticator;

test.beforeEach(async () => {
  restoreLogging = silenceWebAuthnDebugLogging();
  authenticator = await createMockAuthenticator();
  restoreAuthenticator = installMockAuthenticator(authenticator);
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

async function identityWithSigner(signer) {
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'alice',
    displayName: 'Alice',
  });
  const keystore = await createSessionKeystore({ signer });
  const identities = await Identities({
    keystore,
    storage: await MemoryStorage(),
  });
  const identity = await identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: credential,
      signer,
    }),
  });
  return { credential, keystore, identities, identity };
}

test('the identity is the signer, and OrbitDB signs through it', async () => {
  const { signer, count } = await inProcessSigner();
  const assertionsBefore = authenticator.state.assertions;
  const { keystore, identities, identity } = await identityWithSigner(signer);

  expect(identity.id).toBe(signer.did);
  expect(identity.id).toMatch(/^did:key:z6Mk/);
  expect(identity.publicKey).toBe(hex(signer.publicKey));
  expect(identity.type).toBe('webauthn');
  // The document: id signed by the signer, the public key signed by the
  // signer — two signatures, and no passkey prompt for either.
  expect(count()).toBe(2);
  expect(authenticator.state.assertions).toBe(assertionsBefore);
  // An entry signature goes through the signer as well.
  const sig = await identities.sign(identity, 'an entry');
  expect(count()).toBe(3);
  expect(await identities.verify(sig, identity.publicKey, 'an entry')).toBe(
    true
  );
  expect(await identities.verifyIdentity(identity)).toBe(true);
  // The keystore never held the private key.
  expect((await keystore.getKey(signer.did)).raw).toBeUndefined();
});

test('the same signer on a second device is the same identity document', async () => {
  const { signer } = await inProcessSigner();
  const first = await identityWithSigner(signer);
  const second = await identityWithSigner(signer);
  expect(second.identity.id).toBe(first.identity.id);
  expect(second.identity.publicKey).toBe(first.identity.publicKey);
  expect(second.identity.hash).toBe(first.identity.hash);
});

test('an impostor claiming the signer DID is refused', async () => {
  const { signer } = await inProcessSigner();
  const { identities } = await identityWithSigner(signer);
  const other = await generateKeyPair('Ed25519');
  const forged = {
    id: signer.did,
    type: 'webauthn',
    publicKey: hex(other.publicKey.raw),
    signatures: {
      id: await signMessage(other, signer.did),
      publicKey: 'not-a-proof',
    },
  };
  expect(await identities.verifyIdentity(forged)).toBe(false);
});

test('a keystore that does not serve the signer is refused up front', async () => {
  const { signer } = await inProcessSigner();
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'alice',
    displayName: 'Alice',
  });
  const plain = await createSessionKeystore();
  const provider = new OrbitDBWebAuthnIdentityProvider({
    webauthnCredential: credential,
    signer,
  });
  await expect(provider.getId({ keystore: plain })).rejects.toThrow(
    /createSessionKeystore\(\{ signer \}\)/
  );
  expect(provider.encryptionState).toEqual({
    enabled: false,
    reason: 'external-signer',
  });
  await plain.close();
});

test('a signer has to look like one', async () => {
  const { signer } = await inProcessSigner();
  expect(() => assertSigner(signer)).not.toThrow();
  expect(() => assertSigner({ ...signer, type: 'secp256k1' })).toThrow(
    /signer must be/
  );
  expect(() =>
    assertSigner({ ...signer, publicKey: new Uint8Array(31) })
  ).toThrow();
  expect(() => assertSigner({ ...signer, sign: undefined })).toThrow();
});

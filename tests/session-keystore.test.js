/**
 * `encryptKeystore` only means something at rest if OrbitDB's own keystore
 * does not write the unlocked key to disk — and that keystore is the app's
 * to choose. These tests cover the helper that makes a forgetful one, the
 * warning when the app did not, and what happens without PRF: the key goes
 * in unencrypted and the provider says so, instead of sealing it under the
 * credential id as before.
 */
import { test, expect } from '@playwright/test';
import {
  Identities,
  KeyStore,
  MemoryStorage,
  useIdentityProvider,
} from '@orbitdb/core';

import {
  OrbitDBWebAuthnIdentityProvider,
  OrbitDBWebAuthnIdentityProviderFunction,
} from '../src/keystore/provider.js';
import {
  createSessionKeystore,
  isSessionKeystore,
} from '../src/keystore/session-keystore.js';
import {
  wrapSKWithPRF,
  generateSecretKey,
} from '../src/keystore/encryption.js';
import { PrfUnavailableError } from '../src/errors.js';
import { WebAuthnDIDProvider } from '../src/webauthn/provider.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { silenceWebAuthnDebugLogging } from './helpers/two-peer.js';

let restoreAuthenticator;
let restoreLogging;
let warnings;
const originalWarn = console.warn;

async function useAuthenticator(options = {}) {
  restoreAuthenticator?.();
  restoreAuthenticator = installMockAuthenticator(
    await createMockAuthenticator(options)
  );
}

test.beforeEach(async () => {
  restoreLogging = silenceWebAuthnDebugLogging();
  warnings = [];
  console.warn = (...args) => warnings.push(args.join(' '));
  await useAuthenticator();
  try {
    useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
  } catch {
    // registered by an earlier test
  }
});

test.afterEach(() => {
  console.warn = originalWarn;
  restoreAuthenticator?.();
  restoreAuthenticator = null;
  restoreLogging?.();
});

async function credential() {
  return WebAuthnDIDProvider.createCredential({
    userId: 'alice',
    displayName: 'Alice',
  });
}

/** The provider the way OrbitDB drives it: getId() with its keystore. */
async function encryptedKeystoreIdentity(keystore) {
  const provider = new OrbitDBWebAuthnIdentityProvider({
    webauthnCredential: await credential(),
    useKeystoreDID: true,
    keystoreKeyType: 'Ed25519',
    encryptKeystore: true,
    keystore,
  });
  const did = await provider.getId({ keystore });
  return { provider, did };
}

test('createSessionKeystore makes a keystore the provider can recognise', async () => {
  const session = await createSessionKeystore();
  expect(isSessionKeystore(session)).toBe(true);
  // Memory storage alone is not enough to tell: from the outside every
  // keystore looks the same.
  const plain = await KeyStore({ storage: await MemoryStorage() });
  expect(isSessionKeystore(plain)).toBe(false);
  await session.close();
  await plain.close();
});

test('an encrypted keystore on a session keystore unlocks, signs and warns about nothing', async () => {
  const keystore = await createSessionKeystore();
  const { provider, did } = await encryptedKeystoreIdentity(keystore);
  expect(did).toMatch(/^did:key:z6Mk/);
  expect(provider.encryptionState).toEqual({ enabled: true, method: 'prf' });
  expect((await keystore.getKey(did))?.type).toBe('Ed25519');
  expect(warnings).toEqual([]);
  await keystore.close();
});

test('a keystore that persists the unlocked key is warned about, once', async () => {
  const keystore = await KeyStore({ storage: await MemoryStorage() });
  const { provider, did } = await encryptedKeystoreIdentity(keystore);
  expect(provider.encryptionState.enabled).toBe(true);
  await provider.getId({ keystore }); // a second call must not repeat it
  expect(warnings).toHaveLength(1);
  expect(warnings[0]).toContain('createSessionKeystore');
  expect(await keystore.getKey(did)).toBeTruthy();
  await keystore.close();
});

test('creating the encrypted keystore leaves it unlocked — no second prompt', async () => {
  const keystore = await createSessionKeystore();
  const provider = new OrbitDBWebAuthnIdentityProvider({
    webauthnCredential: await credential(),
    useKeystoreDID: true,
    keystoreKeyType: 'Ed25519',
    encryptKeystore: true,
    keystore,
  });
  let unlocks = 0;
  const unlock = provider.unlockEncryptedKeystore.bind(provider);
  provider.unlockEncryptedKeystore = async () => {
    unlocks += 1;
    return unlock();
  };
  await provider.getId({ keystore });
  expect(provider.unlockedKeypair).toBeTruthy();
  expect(unlocks).toBe(0);
  await keystore.close();
});

test('without PRF the key is not encrypted, and the provider says so', async () => {
  await useAuthenticator({ supportsPrf: false });
  const keystore = await createSessionKeystore();
  const { provider, did } = await encryptedKeystoreIdentity(keystore);

  expect(did).toMatch(/^did:key:z6Mk/);
  expect(provider.encryptionState).toEqual({
    enabled: false,
    reason: 'prf-unavailable',
  });
  expect(provider.encryptKeystore).toBe(false);
  expect(warnings.join('\n')).toContain('NOT encrypted');
  // Nothing sealed under a non-secret was written down.
  expect(
    localStorage.getItem(
      `encrypted-keystore-${provider.credential.credentialId}`
    )
  ).toBeNull();
  // The identity still works, as an unencrypted keystore identity.
  expect((await keystore.getKey(did))?.type).toBe('Ed25519');
  await keystore.close();
});

test('the identity created without PRF still verifies', async () => {
  await useAuthenticator({ supportsPrf: false });
  const keystore = await createSessionKeystore();
  const identities = await Identities({
    keystore,
    storage: await MemoryStorage(),
  });
  const identity = await identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: await credential(),
      useKeystoreDID: true,
      keystoreKeyType: 'Ed25519',
      encryptKeystore: true,
      keystore,
    }),
  });
  expect(await identities.verifyIdentity(identity)).toBe(true);
  await keystore.close();
});

test('wrapSKWithPRF refuses to wrap with anything but PRF', async () => {
  await useAuthenticator({ supportsPrf: false });
  const cred = await credential();
  await expect(
    wrapSKWithPRF(cred.rawCredentialId, generateSecretKey(), 'localhost')
  ).rejects.toBeInstanceOf(PrfUnavailableError);
});

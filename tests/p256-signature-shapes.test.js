/**
 * Genuine P-256 signatures in the shapes that DER handling gets wrong.
 *
 * An authenticator returns an ES256 signature as DER with r and s as minimal
 * integers, so either can be 31 bytes; and a raw r‖s can start with 0x30, the
 * DER SEQUENCE tag. Together about one signature in 90. The identity binding
 * (default path) and varsig verification both refused them: the unwrapper did
 * not pad, and the varsig path re-read raw bytes as DER. Found as a 2% flake
 * of the forgery suite; forced here so it cannot hide again.
 */
import { test, expect } from '@playwright/test';
import {
  Identities,
  KeyStore,
  MemoryStorage,
  useIdentityProvider,
} from '@orbitdb/core';

import { OrbitDBWebAuthnIdentityProviderFunction } from '../src/index.js';
import { WebAuthnDIDProvider } from '../src/webauthn/provider.js';
import { WebAuthnVarsigProvider } from '../src/varsig/provider.js';
import {
  createWebAuthnVarsigIdentity,
  verifyVarsigIdentity,
} from '../src/varsig/index.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { silenceWebAuthnDebugLogging } from './helpers/two-peer.js';

const SHAPES = {
  'a short r': (raw) => raw[0] === 0x00,
  'a short s': (raw) => raw[32] === 0x00,
  'a raw r‖s that starts like DER': (raw) => raw[0] === 0x30,
};

for (const [shape, signatureShape] of Object.entries(SHAPES)) {
  test.describe(`a signature with ${shape}`, () => {
    let restore = [];
    test.beforeEach(async () => {
      restore = [
        silenceWebAuthnDebugLogging(),
        installMockAuthenticator(
          await createMockAuthenticator({ signatureShape })
        ),
      ];
      try {
        useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
      } catch {
        // registered by an earlier test
      }
    });
    test.afterEach(() => restore.forEach((undo) => undo?.()));

    test('binds a passkey identity', async () => {
      const keystore = await KeyStore({ storage: await MemoryStorage() });
      const identities = await Identities({
        keystore,
        storage: await MemoryStorage(),
      });
      const credential = await WebAuthnDIDProvider.createCredential({
        userId: 'alice',
        displayName: 'Alice',
      });
      const identity = await identities.createIdentity({
        provider: OrbitDBWebAuthnIdentityProviderFunction({
          webauthnCredential: credential,
        }),
      });
      expect(await identities.verifyIdentity(identity)).toBe(true);
      await keystore.close();
    });

    test('signs and verifies a varsig identity', async () => {
      const credential = await WebAuthnVarsigProvider.createCredential({
        userId: 'carol',
        displayName: 'Carol',
      });
      const identity = await createWebAuthnVarsigIdentity({ credential });
      expect(await verifyVarsigIdentity(identity)).toBe(true);
    });
  });
}

/**
 * Which authenticators a registration offers.
 *
 * `createCredential` named `authenticatorAttachment: 'platform'` from March to
 * October 2026, and `buildAuthenticatorSelection` never passed it on: the
 * request named no attachment, so the browser offered every kind of
 * authenticator — a security key as much as the device's own. That stays the
 * default; `authenticatorType` narrows it.
 *
 * The varsig registration — `WebAuthnVarsigProvider.createCredential` and the
 * standalone signers built on it — lost its `authenticatorType` the same way,
 * along with a `userVerification: 'preferred'` that never reached the browser
 * either. Every registration requires user verification: a varsig signature
 * without the UV flag is refused.
 *
 * Like the user-handle suite, these assert what the library sends, which holds
 * however faithfully the mock models an authenticator.
 * tests/webauthn-security-key.test.js shows the same in Chromium.
 */
import { test, expect } from '@playwright/test';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { silenceWebAuthnDebugLogging } from './helpers/two-peer.js';

/** Every registration that takes its options as given. */
const REGISTRATIONS = {
  'WebAuthnDIDProvider.createCredential': async () => {
    const { WebAuthnDIDProvider } = await import('../src/webauthn/provider.js');
    return (options) => WebAuthnDIDProvider.createCredential(options);
  },
  'WebAuthnVarsigProvider.createCredential': async () => {
    const { WebAuthnVarsigProvider } =
      await import('../src/varsig/provider.js');
    return (options) => WebAuthnVarsigProvider.createCredential(options);
  },
  createWebAuthnSigner: async () => {
    const { createWebAuthnSigner } =
      await import('../src/standalone/webauthn/signers.js');
    return createWebAuthnSigner;
  },
};

let restoreAuthenticator;
let restoreLogging;
let authenticator;
/** `authenticatorSelection` of every registration request sent. */
let sent;

test.beforeEach(async () => {
  restoreLogging = silenceWebAuthnDebugLogging();
  authenticator = await createMockAuthenticator();
  const { credentials } = authenticator.navigator;
  const create = credentials.create.bind(credentials);
  sent = [];
  credentials.create = (options) => {
    sent.push(options.publicKey.authenticatorSelection);
    return create(options);
  };
  restoreAuthenticator = installMockAuthenticator(authenticator);
});

test.afterEach(() => {
  restoreAuthenticator?.();
  restoreLogging?.();
});

for (const [name, load] of Object.entries(REGISTRATIONS)) {
  test.describe(`${name}: which authenticators it offers`, () => {
    let register;

    test.beforeEach(async () => {
      const registration = await load();
      register = (options = {}) =>
        registration({ userId: 'anna', displayName: 'Anna', ...options });
    });

    test('by default the request names no attachment, as it has since 0.2.8', async () => {
      await register();
      expect(sent).toHaveLength(1);
      expect(sent[0]).not.toHaveProperty('authenticatorAttachment');
      expect(sent[0]).toMatchObject({
        residentKey: 'required',
        userVerification: 'required',
      });
    });

    for (const [options, expected] of [
      [{ authenticatorType: 'platform' }, 'platform'],
      [{ authenticatorType: 'cross-platform' }, 'cross-platform'],
      [{ authenticatorType: 'any' }, undefined],
      [{ authenticatorType: null }, undefined],
      [{ authenticatorAttachment: 'platform' }, 'platform'],
      [{ authenticatorAttachment: 'cross-platform' }, 'cross-platform'],
      [
        {
          authenticatorType: 'cross-platform',
          authenticatorAttachment: 'cross-platform',
        },
        'cross-platform',
      ],
    ]) {
      test(`${JSON.stringify(options)} asks for ${expected ?? 'any authenticator'}`, async () => {
        await register(options);
        if (expected === undefined) {
          expect(sent[0]).not.toHaveProperty('authenticatorAttachment');
        } else {
          expect(sent[0].authenticatorAttachment).toBe(expected);
        }
      });
    }

    test('refuses a choice it cannot honour, before anyone is asked', async () => {
      for (const options of [
        { authenticatorType: 'usb' },
        { authenticatorType: 'Platform' },
        { authenticatorAttachment: 'any' },
        {
          authenticatorType: 'platform',
          authenticatorAttachment: 'cross-platform',
        },
        { authenticatorType: 'any', authenticatorAttachment: 'platform' },
      ]) {
        await expect(
          register(options),
          JSON.stringify(options)
        ).rejects.toThrow(TypeError);
      }
      expect(sent).toHaveLength(0);
      expect(authenticator.state.creations).toBe(0);
    });

    test('the discoverable-credential policy still comes from the options', async () => {
      await register({
        authenticatorType: 'cross-platform',
        discoverableCredentials: false,
      });
      expect(sent[0]).toMatchObject({
        authenticatorAttachment: 'cross-platform',
        requireResidentKey: false,
        residentKey: 'discouraged',
        userVerification: 'required',
      });
    });

    test('user verification is required, whatever the options ask', async () => {
      // The options cannot lower it. Through the varsig registrations a
      // credential without user verification could never sign: a varsig
      // signature without the UV flag is refused.
      await register({ userVerification: 'preferred' });
      await register({ userVerification: 'discouraged' });
      expect(sent.map((selection) => selection.userVerification)).toEqual([
        'required',
        'required',
      ]);
    });
  });
}

test.describe('createWebAuthnEd25519Credential: which authenticators it offers', () => {
  let createWebAuthnEd25519Credential;

  test.beforeEach(async () => {
    ({ createWebAuthnEd25519Credential } =
      await import('../src/standalone/webauthn/signers.js'));
  });

  // It passes on `authenticatorType` alone, positional arguments first.
  for (const [options, expected] of [
    [undefined, undefined],
    [{ authenticatorType: 'platform' }, 'platform'],
    [{ authenticatorType: 'cross-platform' }, 'cross-platform'],
    [{ authenticatorType: 'any' }, undefined],
  ]) {
    test(`${JSON.stringify(options ?? {})} asks for ${expected ?? 'any authenticator'}`, async () => {
      await createWebAuthnEd25519Credential('anna', 'Anna', options);
      expect(sent).toHaveLength(1);
      if (expected === undefined) {
        expect(sent[0]).not.toHaveProperty('authenticatorAttachment');
      } else {
        expect(sent[0].authenticatorAttachment).toBe(expected);
      }
    });
  }
});

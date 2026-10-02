/**
 * Which authenticators a registration offers.
 *
 * `createCredential` named `authenticatorAttachment: 'platform'` from March to
 * October 2026, and `buildAuthenticatorSelection` never passed it on: the
 * request named no attachment, so the browser offered every kind of
 * authenticator — a security key as much as the device's own. That stays the
 * default; `authenticatorType` narrows it.
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

test.describe('createCredential: which authenticators it offers', () => {
  let restoreAuthenticator;
  let restoreLogging;
  let authenticator;
  let WebAuthnDIDProvider;
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
    ({ WebAuthnDIDProvider } = await import('../src/webauthn/provider.js'));
  });

  test.afterEach(() => {
    restoreAuthenticator?.();
    restoreLogging?.();
  });

  const register = (options = {}) =>
    WebAuthnDIDProvider.createCredential({
      userId: 'anna',
      displayName: 'Anna',
      ...options,
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
      await expect(register(options), JSON.stringify(options)).rejects.toThrow(
        TypeError
      );
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
});

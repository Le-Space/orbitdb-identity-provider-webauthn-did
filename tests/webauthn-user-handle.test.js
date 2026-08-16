/**
 * The WebAuthn user handle must not be derived from anything a person types.
 *
 * An authenticator keeps one discoverable credential per (rp.id, user.id) and
 * replaces the previous one when both match — no prompt, no undo. While the
 * handle was `TextEncoder().encode(userId)`, two people registering under the
 * same name on one device destroyed each other's passkey, and with it the DID
 * and every entry signed under it (#45).
 *
 * The first test is the load-bearing one: it asserts what the library *sends*,
 * so it holds regardless of how faithfully the mock models an authenticator.
 * The rest describe the consequence.
 */
import { test, expect } from '@playwright/test';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { silenceWebAuthnDebugLogging } from './helpers/two-peer.js';

const NAME = 'anna';

test.describe('WebAuthn user handle', () => {
  let restoreAuthenticator;
  let restoreLogging;
  let authenticator;
  let WebAuthnDIDProvider;

  test.beforeEach(async () => {
    restoreLogging = silenceWebAuthnDebugLogging();
    authenticator = await createMockAuthenticator();
    restoreAuthenticator = installMockAuthenticator(authenticator);
    ({ WebAuthnDIDProvider } = await import('../src/webauthn/provider.js'));
  });

  test.afterEach(() => {
    restoreAuthenticator?.();
    restoreLogging?.();
  });

  test('is 64 random bytes, and carries nothing the user typed', async () => {
    await WebAuthnDIDProvider.createCredential({
      userId: NAME,
      displayName: 'Anna',
    });
    await WebAuthnDIDProvider.createCredential({
      userId: NAME,
      displayName: 'Anna',
    });

    const [first, second] = authenticator.state.createdUsers;
    const firstHandle = new Uint8Array(first.id);
    const secondHandle = new Uint8Array(second.id);

    expect(firstHandle.length).toBe(64);
    expect(secondHandle.length).toBe(64);

    // Same input, different handle — the property the whole fix rests on.
    expect(Buffer.from(firstHandle).equals(Buffer.from(secondHandle))).toBe(
      false
    );

    // And nothing recognisable in it: not the typed bytes, not the name as text.
    const typed = new TextEncoder().encode(NAME);
    expect(
      Buffer.from(firstHandle.subarray(0, typed.length)).equals(
        Buffer.from(typed)
      )
    ).toBe(false);
    expect(new TextDecoder().decode(firstHandle)).not.toContain(NAME);
  });

  test('keeps the typed value as the label the picker shows', async () => {
    await WebAuthnDIDProvider.createCredential({
      userId: NAME,
      displayName: 'Anna at the front desk',
    });

    const [user] = authenticator.state.createdUsers;
    expect(user.name).toBe(NAME);
    expect(user.displayName).toBe('Anna at the front desk');
  });

  test('two people with the same name no longer overwrite each other', async () => {
    const first = await WebAuthnDIDProvider.createCredential({
      userId: NAME,
      displayName: 'Anna',
    });
    const second = await WebAuthnDIDProvider.createCredential({
      userId: NAME,
      displayName: 'Anna',
    });

    expect(second.credentialId).not.toBe(first.credentialId);

    // Both survive. Under a name-derived handle the second registration would
    // have landed in the first one's slot and left a single credential here.
    const resident = authenticator.residentCredentials();
    expect(resident.length).toBe(2);
    expect(resident.map((entry) => entry.credentialId).sort()).toEqual(
      [first.credentialId, second.credentialId].sort()
    );
  });

  test('returns the handle, base64url of 64 bytes', async () => {
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: NAME,
      displayName: 'Anna',
    });

    expect(credential.userHandle).toBeTruthy();
    expect(credential.userHandle).toMatch(/^[A-Za-z0-9_-]+$/);

    const decoded = new Uint8Array(
      WebAuthnDIDProvider.base64urlToArrayBuffer(credential.userHandle)
    );
    expect(decoded.length).toBe(64);
    expect(
      Buffer.from(decoded).equals(
        Buffer.from(new Uint8Array(authenticator.state.createdUsers[0].id))
      )
    ).toBe(true);
  });
});

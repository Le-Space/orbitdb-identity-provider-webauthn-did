/**
 * Restoring the identity on a device that has stored nothing (#61).
 *
 * The device that registered keeps the credential's public key and the PRF
 * input; a second device holding the same passkey has neither. These tests
 * play that second device: they touch the authenticator twice and ask whether
 * what comes back is the same identity, byte for byte.
 *
 * Measured on hardware first — one YubiKey, a Galaxy Fold 5 and a Galaxy A57,
 * 2026-09-19: same PRF value, the same DID recovered from two signatures, the
 * same derived signing key. What is machine-checkable of that runs here.
 */
import { test, expect } from '@playwright/test';

import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { prfInputForRelyingParty } from '../src/webauthn/prf-input.js';
import {
  recoverPublicKey,
  recoverPublicKeyCandidates,
} from '../src/webauthn/recovery.js';
import { restoreIdentityFromAuthenticator } from '../src/webauthn/restore.js';
import { deriveSigningKeyBytes } from '../src/keystore/derived-signing-key.js';
import { WebAuthnDIDProvider } from '../src/webauthn/provider.js';
import { PrfUnavailableError } from '../src/errors.js';

const hex = (bytes) =>
  [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');

/** A touch: what `navigator.credentials.get()` gives a page. */
const touch = (extensions) =>
  globalThis.navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: 'required',
      ...(extensions ? { extensions } : {}),
    },
  });

test.describe('recovering the public key from assertions', () => {
  let authenticator;
  let restore;

  test.beforeEach(async () => {
    authenticator = await createMockAuthenticator({ rpId: 'localhost' });
    restore = installMockAuthenticator(authenticator);
  });

  test.afterEach(() => restore?.());

  test('two touches give back the key registration handed out', async () => {
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'someone',
      domain: 'localhost',
    });

    const recovered = await recoverPublicKey(await touch(), await touch());

    expect(hex(recovered.x)).toBe(hex(credential.publicKey.x));
    expect(hex(recovered.y)).toBe(hex(credential.publicKey.y));
    // And therefore the same DID, which is the point of recovering it at all.
    expect(await WebAuthnDIDProvider.createDID({ publicKey: recovered })).toBe(
      await WebAuthnDIDProvider.createDID(credential)
    );
  });

  test('one touch is not enough, and that is why there are two', async () => {
    await WebAuthnDIDProvider.createCredential({
      userId: 'someone',
      domain: 'localhost',
    });

    // A signature admits two keys. Nothing in the assertion says which.
    expect(await recoverPublicKeyCandidates(await touch())).toHaveLength(2);
  });

  test('two different credentials never settle on one key', async () => {
    await WebAuthnDIDProvider.createCredential({
      userId: 'someone',
      domain: 'localhost',
    });
    const mine = await touch();

    const otherKey = await createMockAuthenticator({ rpId: 'localhost' });
    const restoreOther = installMockAuthenticator(otherKey);
    await WebAuthnDIDProvider.createCredential({
      userId: 'somebody else',
      domain: 'localhost',
    });
    const theirs = await touch();
    restoreOther();

    await expect(recoverPublicKey(mine, theirs)).rejects.toThrow(
      /do not share a public key/
    );
  });

  test('a signature that is not ES256 is refused rather than guessed at', async () => {
    await WebAuthnDIDProvider.createCredential({
      userId: 'someone',
      domain: 'localhost',
    });
    const assertion = await touch();
    const response = {
      authenticatorData: assertion.response.authenticatorData,
      clientDataJSON: assertion.response.clientDataJSON,
      signature: new Uint8Array(64), // r = s = 0: no ECDSA signature has that
    };

    await expect(recoverPublicKeyCandidates(response)).rejects.toThrow(
      /not an ES256 signature/
    );
  });
});

test.describe('the identity a second device gets back', () => {
  let authenticator;
  let restore;

  test.beforeEach(async () => {
    authenticator = await createMockAuthenticator({ rpId: 'localhost' });
    restore = installMockAuthenticator(authenticator);
  });

  test.afterEach(() => restore?.());

  test('is the same DID and the same signing key, with nothing stored', async () => {
    // The device that registered. Everything it keeps stays on this side of
    // the test; the restore below is given none of it.
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'someone',
      domain: 'localhost',
    });
    const registeredDid = await WebAuthnDIDProvider.createDID(credential);

    const restored = await restoreIdentityFromAuthenticator({
      rpId: 'localhost',
    });

    expect(restored.did).toBe(registeredDid);

    // The signing key is what makes it a *writing* identity rather than a
    // lookalike: derived from the PRF output with the DID mixed in.
    const prfOutput = (
      await touch({
        prf: { eval: { first: await prfInputForRelyingParty('localhost') } },
      })
    ).getClientExtensionResults().prf.results.first;
    expect(hex(restored.signingKey)).toBe(
      hex(await deriveSigningKeyBytes(new Uint8Array(prfOutput), registeredDid))
    );
  });

  test('takes two touches of the authenticator, not one', async () => {
    await WebAuthnDIDProvider.createCredential({
      userId: 'someone',
      domain: 'localhost',
    });
    const before = authenticator.state.assertions;

    const touches = [];
    await restoreIdentityFromAuthenticator({
      rpId: 'localhost',
      onTouch: (step) => touches.push(step.touch),
    });

    expect(authenticator.state.assertions - before).toBe(2);
    expect(touches).toEqual([1, 2]);
  });

  test('is refused when the authenticator has no PRF, never substituted', async () => {
    restore?.();
    const noPrf = await createMockAuthenticator({
      rpId: 'localhost',
      supportsPrf: false,
    });
    restore = installMockAuthenticator(noPrf);
    await WebAuthnDIDProvider.createCredential({
      userId: 'someone',
      domain: 'localhost',
    });

    await expect(
      restoreIdentityFromAuthenticator({ rpId: 'localhost' })
    ).rejects.toThrow(PrfUnavailableError);
  });
});

test.describe('the PRF input', () => {
  test('is the same on every device, and different per relying party', async () => {
    const here = await prfInputForRelyingParty('example.org');
    const again = await prfInputForRelyingParty('example.org');
    const elsewhere = await prfInputForRelyingParty('example.net');

    expect(hex(here)).toBe(hex(again));
    expect(hex(here)).not.toBe(hex(elsewhere));
    expect(here).toHaveLength(32);
  });
});

test.describe('createDID', () => {
  test('refuses a key it cannot encode instead of inventing an identifier', async () => {
    // What stood here built a "base58-like" string out of the coordinates: it
    // looked like a DID, was not `did:key`, and nothing else would ever
    // compute it — an identity that fails silently at registration.
    await expect(
      WebAuthnDIDProvider.createDID({
        publicKey: { x: new Uint8Array(4), y: new Uint8Array(4) },
      })
    ).rejects.toThrow(/could not encode the public key/);
  });
});

/**
 * Registering a security key, in Chromium.
 *
 * Each page holds one virtual authenticator, mostly on the USB transport — a
 * roaming authenticator, as a YubiKey is. What the library asks for decides
 * whether the browser offers it: the default names no attachment and does,
 * `'cross-platform'` asks for it, `'platform'` asks for the device's own and
 * leaves it out. The varsig registration behaves the same since 0.9.1; before,
 * it offered every authenticator whatever it was given. Two more cases are its
 * own: `'cross-platform'` leaves the device's authenticator out, and a key that
 * cannot verify its user is refused at registration, because none of its
 * signatures would count. tests/webauthn-authenticator-type.test.js checks the
 * request itself.
 */
import { test, expect } from '@playwright/test';
import {
  addVirtualAuthenticator,
  requireChromium,
} from './helpers/virtual-authenticator.js';
import { loadLibrary } from './helpers/library-in-page.js';

/**
 * Register through the library, then read the PRF output from the new
 * credential. A request no authenticator answers is given up after `wait`
 * ms rather than the minute createCredential allows; a virtual key that is
 * asked answers at once.
 */
function register(page, options, wait = 30000) {
  return page.evaluate(
    ({ options, wait }) => {
      const { WebAuthnDIDProvider, readPrfOutput } = window.WebAuthnModule;
      const attempt = WebAuthnDIDProvider.createCredential({
        userId: 'owner',
        displayName: 'Security key',
        ...options,
      }).then(
        async (credential) => ({
          registered: true,
          prfBytes: (await readPrfOutput(credential)).length,
        }),
        (error) => ({ registered: false, refusal: error.name })
      );
      const unanswered = new Promise((resolve) =>
        setTimeout(() => resolve({ registered: false, unanswered: true }), wait)
      );
      return Promise.race([attempt, unanswered]);
    },
    { options, wait }
  );
}

/**
 * Register through the varsig path, then sign with the new credential. A
 * varsig signature is an assertion, refused without the UV flag, so `signed`
 * is the name of the error when there is one.
 */
function registerVarsig(page, options, wait = 30000) {
  return page.evaluate(
    ({ options, wait }) => {
      const { WebAuthnVarsigProvider } = window.WebAuthnModule;
      const attempt = WebAuthnVarsigProvider.createCredential({
        userId: 'owner',
        displayName: 'Security key',
        ...options,
      }).then(
        async (credential) => {
          const provider = new WebAuthnVarsigProvider(credential);
          const signed = await provider.sign('entry').then(
            (signature) =>
              provider.verify(signature, credential.publicKey, 'entry'),
            (error) => error.name
          );
          return { registered: true, signed };
        },
        (error) => ({ registered: false, refusal: error.name })
      );
      const unanswered = new Promise((resolve) =>
        setTimeout(() => resolve({ registered: false, unanswered: true }), wait)
      );
      return Promise.race([attempt, unanswered]);
    },
    { options, wait }
  );
}

test.describe('a security key', () => {
  test.beforeEach(async ({ page, browserName }) => {
    requireChromium(test, browserName);
    await addVirtualAuthenticator(page, { transport: 'usb' });
    await loadLibrary(page);
  });

  test('is offered by default, as it has been since 0.2.8', async ({
    page,
  }) => {
    expect(await register(page, {})).toEqual({
      registered: true,
      prfBytes: 32,
    });
  });

  test("is asked for with authenticatorType 'cross-platform'", async ({
    page,
  }) => {
    expect(
      await register(page, { authenticatorType: 'cross-platform' })
    ).toEqual({ registered: true, prfBytes: 32 });
  });

  test("is left out with authenticatorType 'platform'", async ({ page }) => {
    // Not refused: never asked. The browser waits for an authenticator of the
    // device, and the key on the page answers nothing in ten seconds.
    expect(
      await register(page, { authenticatorType: 'platform' }, 10000)
    ).toEqual({ registered: false, unanswered: true });
  });
});

test.describe('a security key, through the varsig registration', () => {
  test.beforeEach(async ({ page, browserName }) => {
    requireChromium(test, browserName);
    await addVirtualAuthenticator(page, { transport: 'usb' });
    await loadLibrary(page);
  });

  test('is offered by default, and signs', async ({ page }) => {
    expect(await registerVarsig(page, {})).toEqual({
      registered: true,
      signed: true,
    });
  });

  test("is asked for with authenticatorType 'cross-platform'", async ({
    page,
  }) => {
    expect(
      await registerVarsig(page, { authenticatorType: 'cross-platform' })
    ).toEqual({ registered: true, signed: true });
  });

  test("is left out with authenticatorType 'platform'", async ({ page }) => {
    // Until 0.9.1 this registered on the key regardless.
    expect(
      await registerVarsig(page, { authenticatorType: 'platform' }, 10000)
    ).toEqual({ registered: false, unanswered: true });
  });
});

test.describe("the device's own authenticator, through the varsig registration", () => {
  test.beforeEach(async ({ page, browserName }) => {
    requireChromium(test, browserName);
    await addVirtualAuthenticator(page);
    await loadLibrary(page);
  });

  test("is left out with authenticatorType 'cross-platform'", async ({
    page,
  }) => {
    // Until 0.9.1 this registered on the device's authenticator regardless.
    expect(
      await registerVarsig(page, { authenticatorType: 'cross-platform' }, 10000)
    ).toEqual({ registered: false, unanswered: true });
  });
});

test.describe('a security key that cannot verify its user', () => {
  test.beforeEach(async ({ page, browserName }) => {
    requireChromium(test, browserName);
    // Like an older key with neither a PIN nor room for resident keys — and
    // so no large blobs, which need them.
    await addVirtualAuthenticator(page, {
      transport: 'usb',
      hasUserVerification: false,
      isUserVerified: false,
      hasResidentKey: false,
      hasLargeBlob: false,
    });
    await loadLibrary(page);
  });

  test('is refused at varsig registration, not at its first signature', async ({
    page,
  }) => {
    // Not discoverable, so that user verification alone decides: the browser
    // refuses a discoverable credential from such a key either way. Asked with
    // userVerification 'preferred', it registers, and every signature fails:
    // { registered: true, signed: 'VarsigVerificationError' }.
    expect(
      await registerVarsig(page, { discoverableCredentials: false })
    ).toEqual({ registered: false, refusal: 'NotAllowedError' });
  });
});

/**
 * Registering a security key, in Chromium.
 *
 * The only authenticator on the page is a virtual one on the USB transport —
 * a roaming authenticator, as a YubiKey is. What the library asks for decides
 * whether the browser offers it: the default names no attachment and does,
 * `'cross-platform'` asks for it, `'platform'` asks for the device's own and
 * leaves it out. tests/webauthn-authenticator-type.test.js checks the request
 * itself.
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

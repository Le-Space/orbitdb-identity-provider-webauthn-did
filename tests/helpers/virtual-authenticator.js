/**
 * A real authenticator for browser tests, through Chromium's WebAuthn domain.
 *
 * The browser suites used to replace `navigator.credentials` with mocks that
 * returned a zero-filled 64-byte signature and a zero-filled attestation. That
 * was only possible because nothing verified a WebAuthn signature
 * (GHSA-326j-4cc3-4rrg); with verification in place those identities are, as
 * they should be, refused on the first write. A virtual authenticator signs
 * with a real P-256 key and supports the extensions the provider asks for, so
 * the tests exercise the same code a user's passkey does.
 *
 * Chromium only: the WebAuthn CDP domain is Chromium's. Firefox and WebKit
 * projects skip what needs it.
 */

/**
 * Attach a virtual authenticator to a page.
 *
 * @param {import('@playwright/test').Page} page
 * @param {Partial<{ hasPrf: boolean, hasLargeBlob: boolean, hasCredBlob: boolean, isUserVerified: boolean }>} [options]
 * @returns {Promise<{ authenticatorId: string, cdp: import('@playwright/test').CDPSession }>}
 */
export async function addVirtualAuthenticator(page, options = {}) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send(
    'WebAuthn.addVirtualAuthenticator',
    {
      options: {
        protocol: 'ctap2',
        ctap2Version: 'ctap2_1',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        hasLargeBlob: true,
        hasPrf: true,
        automaticPresenceSimulation: true,
        ...options,
      },
    }
  );
  return { authenticatorId, cdp };
}

/**
 * Skip a test outside Chromium, where no virtual authenticator exists.
 *
 * @param {import('@playwright/test').TestType<any, any>} test
 * @param {string} browserName
 */
export function requireChromium(test, browserName) {
  test.skip(
    browserName !== 'chromium',
    'needs a Chromium virtual authenticator (CDP WebAuthn domain)'
  );
}

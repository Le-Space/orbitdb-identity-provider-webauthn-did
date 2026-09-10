/**
 * The default path, as the README describes it: a P-256 passkey DID, a
 * signing key derived from the passkey's PRF output, no prompt per write,
 * the same identity document after the keystore is wiped, and an Ed25519
 * key on request. Everything read off the identity panel the demo shows.
 */
import { test, expect } from '@playwright/test';
import {
  addVirtualAuthenticator,
  requireChromium,
} from './helpers/virtual-authenticator.js';
import {
  expectForgeryRejected,
  expectTodosVerified,
} from './helpers/verification-ui.js';

const TODO_INPUT = 'input[placeholder="Add a new TODO..."]';

async function createCredential(page) {
  await page.waitForSelector('text=WebAuthn is fully supported', {
    timeout: 30000,
  });
  await page.click('button:has-text("Create Credential")');
  await expect(
    page.locator('text=Credential created successfully!')
  ).toBeVisible({ timeout: 30000 });
}

async function authenticate(page) {
  await page.click('button:has-text("Authenticate with WebAuthn")');
  await page.waitForSelector(TODO_INPUT, { timeout: 60000 });
}

async function panel(page) {
  const text = async (id) =>
    (await page.getByTestId(id).textContent()).replace(/\s+/g, ' ').trim();
  const counts = await text('prompt-count');
  const m = counts.match(/create (\d+) · get (\d+)/);
  return {
    hash: await text('identity-hash'),
    key: await text('signing-key-type'),
    create: Number(m?.[1]),
    get: Number(m?.[2]),
  };
}

test.describe('the default path', () => {
  test.beforeEach(async ({ page, browserName }) => {
    requireChromium(test, browserName);
    await addVirtualAuthenticator(page);
    await page.goto('/');
  });

  test('a secp256k1 key derived from the passkey, no prompt per write, one document across a wipe', async ({
    page,
  }) => {
    test.setTimeout(180000);
    await createCredential(page);
    await authenticate(page);

    const first = await panel(page);
    expect(first.key).toMatch(/^secp256k1 — derived from the passkey/);
    expect(first.hash).toMatch(/^zdpu/);
    // Registration; then the largeBlob write of the identity metadata (the
    // virtual authenticator supports it), the PRF assertion for the derived
    // key, and the identity assertion.
    expect(first).toMatchObject({ create: 1, get: 3 });

    await page.fill(TODO_INPUT, 'no prompt for this');
    await page.click('button:has-text("Add")');
    await page.waitForSelector('text=no prompt for this', { timeout: 30000 });
    expect((await panel(page)).get).toBe(3); // OrbitDB signed, not the passkey

    const writer = await expectTodosVerified(page);
    expect(writer).toMatch(/^did:key:z4oJ8/);
    await expectForgeryRejected(page);

    // Reset DB wipes IndexedDB, keystore included. The key is derived again
    // from PRF (one assertion) and the stored identity assertion is reused,
    // so the identity document — its hash — is the same one.
    await page.click('button:has-text("Reset DB")');
    await page.waitForSelector('text=Database reset complete', {
      timeout: 30000,
    });
    await authenticate(page);
    const second = await panel(page);
    expect(second.hash).toBe(first.hash);
    expect(second.key).toMatch(/^secp256k1/);
    expect(second.get).toBe(4);
  });

  test('Ed25519 on request, and the verifier accepts it', async ({ page }) => {
    test.setTimeout(120000);
    await createCredential(page);
    await page
      .getByTestId('signing-key-type-choice')
      .getByText('Ed25519', { exact: true })
      .click();
    await authenticate(page);
    expect((await panel(page)).key).toMatch(
      /^Ed25519 — derived from the passkey/
    );

    await page.fill(TODO_INPUT, 'signed by an Ed25519 key');
    await page.click('button:has-text("Add")');
    await page.waitForSelector('text=signed by an Ed25519 key', {
      timeout: 30000,
    });
    const writer = await expectTodosVerified(page);
    expect(writer).toMatch(/^did:key:z4oJ8/);
    await expectForgeryRejected(page);
  });

  test('logout keeps the passkey; forgetting takes two clicks and clears the device', async ({
    page,
  }) => {
    test.setTimeout(120000);
    await createCredential(page);
    await authenticate(page);

    await page.click('button:has-text("Logout")');
    await page.waitForSelector('text=Logged out successfully', {
      timeout: 15000,
    });
    // The metadata is still there: straight back to authenticating.
    await expect(
      page.locator('button:has-text("Authenticate with WebAuthn")')
    ).toBeVisible();
    expect(
      await page.evaluate(() => localStorage.getItem('webauthn-credential'))
    ).toBeTruthy();

    await authenticate(page);
    await page.getByTestId('forget-identity').click();
    await expect(page.getByTestId('forget-identity')).toHaveText(
      /Confirm: forget identity/
    );
    await page.getByTestId('forget-identity').click();
    await page.waitForSelector('text=Identity forgotten on this device', {
      timeout: 30000,
    });
    await expect(
      page.locator('button:has-text("Create Credential")')
    ).toBeVisible();
    const left = await page.evaluate(() =>
      Object.keys(localStorage).filter(
        (k) =>
          k === 'webauthn-credential' || k.startsWith('webauthn-identity-proof')
      )
    );
    expect(left).toEqual([]);
  });
});

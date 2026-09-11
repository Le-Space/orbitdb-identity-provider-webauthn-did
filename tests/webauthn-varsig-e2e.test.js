/**
 * The varsig demo, driven by a real authenticator.
 *
 * It used to run with `window.__PLAYWRIGHT__`, a flag the demo honoured by
 * faking the credential, skipping OrbitDB and keeping todos in an array —
 * so the one browser test of the "passkey signs every write" option never
 * let the passkey sign anything. The flag is gone from the demo; this drives
 * the same UI with Chromium's virtual authenticator, which signs with a real
 * P-256 key and supports largeBlob for the recovery path.
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

async function shownDid(page) {
  return (
    await page
      .locator('code')
      .filter({ hasText: 'did:key:' })
      .first()
      .textContent()
  ).trim();
}

test.describe('WebAuthn Varsig Demo E2E', () => {
  test('the passkey signs every write, the verifier says so, and the passkey comes back after logout', async ({
    page,
    browserName,
  }) => {
    requireChromium(test, browserName);
    test.setTimeout(180000);
    await addVirtualAuthenticator(page);

    await page.goto('/');
    await page.waitForSelector('button:has-text("Create Credential")', {
      timeout: 30000,
    });
    await page.click('button:has-text("Create Credential")');
    await expect(
      page.locator('text=Credential created successfully!')
    ).toBeVisible({ timeout: 30000 });

    // Two assertions for the identity document, no prompt dialog: the
    // virtual authenticator answers by itself.
    await page.click('button:has-text("Authenticate with Passkey")');
    await page.waitForSelector(TODO_INPUT, { timeout: 90000 });
    await expect(page.locator('text=WebAuthn Varsig DID')).toBeVisible();
    const did = await shownDid(page);
    // The DID is the passkey's key: Ed25519 (z6Mk…) where the authenticator
    // has it — Chromium's virtual one does — otherwise P-256 (zDn…).
    expect(did).toMatch(/^did:key:z(6Mk|Dn)/);

    const todoText = `Test Varsig TODO ${Date.now()}`;
    await page.fill(TODO_INPUT, todoText);
    await page.click('button:has-text("Add")');
    await page.waitForSelector(`text=${todoText}`, { timeout: 30000 });

    // The entry carries a varsig by the passkey; the verifier checks it and
    // names the writer, and refuses an edited entry and an impostor.
    const writer = await expectTodosVerified(page);
    expect(writer).toBe(did);
    await expectForgeryRejected(page);

    await page.click('button[data-testid="toggle-todo"]', { timeout: 5000 });
    await expect(page.locator('text=1 total • 1 completed')).toBeVisible({
      timeout: 30000,
    });

    // Logout forgets the local metadata. Recovery reads it back from the
    // passkey's largeBlob, and the DID must be the same key.
    await page.click('button:has-text("Logout")');
    await page.waitForSelector('text=Logged out successfully', {
      timeout: 15000,
    });
    await page.click('button:has-text("Use Existing Passkey")');
    await expect(page.locator('text=Ready to authenticate')).toBeVisible({
      timeout: 30000,
    });
    await page.click('button:has-text("Authenticate with Passkey")');
    await page.waitForSelector(TODO_INPUT, { timeout: 90000 });
    expect(await shownDid(page)).toBe(did);
    await expect(page.locator(`text=${todoText}`)).toBeVisible({
      timeout: 30000,
    });
  });
});

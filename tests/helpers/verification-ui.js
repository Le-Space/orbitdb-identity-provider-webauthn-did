/**
 * What the demos' badges and forgery panel must show once a todo exists.
 * Shared by the demo suites so each of them proves the same thing: the
 * verifier in examples/shared/lib/verification.js says "verified" for the
 * owner's entries, names the writer, and refuses both forgeries.
 */
import { expect } from '@playwright/test';

/**
 * Every badge on the page reaches "verified" and names the DID the page shows.
 * @param {import('@playwright/test').Page} page
 * @param {{ count?: number }} [options]
 * @returns {Promise<string>} The writer DID the badges name.
 */
export async function expectTodosVerified(page, { count = 1 } = {}) {
  const badges = page.getByTestId('verification-badge');
  await expect(badges).toHaveCount(count);
  // Verification runs after the add settles (the demo waits 2 s), so allow
  // for that before reading the state.
  for (const badge of await badges.all()) {
    await expect(badge).toHaveAttribute('data-state', 'verified', {
      timeout: 20000,
    });
  }
  const shown = (
    await page.locator('code:has-text("did:key:")').first().textContent()
  ).trim();
  for (const badge of await badges.all()) {
    await expect(badge).toHaveAttribute('data-writer', shown);
  }
  return shown;
}

/**
 * The forgery panel runs both forgeries against the same verifier and both
 * come back rejected.
 * @param {import('@playwright/test').Page} page
 */
export async function expectForgeryRejected(page) {
  await page.getByTestId('forgery-run').click();
  await expect(page.getByTestId('forgery-tampered')).toHaveAttribute(
    'data-rejected',
    'true',
    { timeout: 20000 }
  );
  await expect(page.getByTestId('forgery-impostor')).toHaveAttribute(
    'data-rejected',
    'true'
  );
}

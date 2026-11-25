/**
 * `<passkey-step-dialog>` between two passkey prompts.
 *
 * The element's source is served to a blank page by `page.route`, imports and
 * all, so what runs is exactly what an application imports from ./elements.
 * The prompts are announced through the package's own `withPasskeySteps` and
 * `beforePasskeyCeremony`, as a WebAuthn call would announce them.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ORIGIN = 'https://elements.test';

/**
 * @param {import('@playwright/test').Page} page
 * @param {string} lang
 */
async function open(page, lang = 'en') {
  await page.route(`${ORIGIN}/**`, (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/') {
      return route.fulfill({
        contentType: 'text/html',
        body: `<!doctype html><html lang="${lang}"><body>
          <passkey-step-dialog></passkey-step-dialog>
          <script type="module">
            import * as elements from '/src/elements/index.js';
            const dialog = document.querySelector('passkey-step-dialog');
            elements.connectPasskeyStepDialog(dialog);
            Object.assign(window, { elements, dialog, ready: true });
          </script></body></html>`,
      });
    }
    return route.fulfill({
      contentType: 'text/javascript',
      body: readFileSync(ROOT + path.slice(1), 'utf8'),
    });
  });
  await page.goto(`${ORIGIN}/`);
  await page.waitForFunction(() => window.ready === true);
}

/**
 * Start a plan, let its first prompt pass, and leave the second waiting on
 * the dialog. The outcome lands on `window.outcome`.
 *
 * @param {import('@playwright/test').Page} page
 * @param {{ of?: number | null, purpose?: string }} [options]
 */
async function secondPrompt(page, { of = 3, purpose = 'signing-key' } = {}) {
  await page.evaluate(
    ({ of, purpose }) => {
      const { withPasskeySteps } = window.elements;
      window.outcome = null;
      window.plan = withPasskeySteps(of, async () => {
        // Imported from the core module, as the package's own calls do.
        const { beforePasskeyCeremony } = await import('/src/passkey-steps.js');
        await beforePasskeyCeremony('create', 'create');
        await beforePasskeyCeremony(purpose);
      }).then(
        () => (window.outcome = 'continued'),
        (error) => (window.outcome = error.name)
      );
    },
    { of, purpose }
  );
  await expect.poll(() => page.evaluate(() => window.dialog.isOpen)).toBe(true);
}

const dialog = (page) => page.locator('passkey-step-dialog');
const outcome = (page) => page.evaluate(() => window.outcome);

test.describe('<passkey-step-dialog>', () => {
  test('says which prompt comes, what for and why, and "Continue" starts it', async ({
    page,
  }) => {
    await open(page);
    await secondPrompt(page);

    await expect(dialog(page).locator('[part=count]')).toHaveText(
      'Passkey prompt 2 of 3'
    );
    await expect(dialog(page).getByRole('heading')).toHaveText(
      'Now the key that signs your entries'
    );
    await expect(dialog(page).locator('[part=loop]')).toContainText(
      'it is not a repeat'
    );
    // The way on is where the cursor is.
    await expect(
      dialog(page).getByRole('button', { name: 'Continue' })
    ).toBeFocused();

    // A person reads first; a click in the first moment is ignored.
    await page.waitForTimeout(
      await page.evaluate(() => window.elements.CONTINUE_DELAY_MS)
    );
    await dialog(page).getByRole('button', { name: 'Continue' }).click();
    await expect.poll(() => outcome(page)).toBe('continued');
    expect(await page.evaluate(() => window.dialog.isOpen)).toBe(false);
  });

  test('the first prompt of a plan is not announced', async ({ page }) => {
    await open(page);
    await page.evaluate(async () => {
      const { withPasskeySteps } = window.elements;
      const { beforePasskeyCeremony } = await import('/src/passkey-steps.js');
      await withPasskeySteps(3, () =>
        beforePasskeyCeremony('create', 'create')
      );
    });
    expect(await page.evaluate(() => window.dialog.isOpen)).toBe(false);
  });

  test('"Cancel" and Escape stop the action with PasskeyStepCancelled', async ({
    page,
  }) => {
    await open(page);
    await secondPrompt(page);
    await dialog(page).getByRole('button', { name: 'Cancel' }).click();
    await expect.poll(() => outcome(page)).toBe('PasskeyStepCancelled');

    await secondPrompt(page);
    await page.keyboard.press('Escape');
    await expect.poll(() => outcome(page)).toBe('PasskeyStepCancelled');
    expect(await page.evaluate(() => window.dialog.isOpen)).toBe(false);
  });

  test('a dialog closed by other means cancels the step instead of leaving it waiting', async ({
    page,
  }) => {
    await open(page);
    await secondPrompt(page);
    await page.evaluate(() => window.dialog.dialog.close());
    await expect.poll(() => outcome(page)).toBe('PasskeyStepCancelled');
    expect(await page.evaluate(() => window.dialog.isOpen)).toBe(false);
    await expect(dialog(page)).not.toHaveAttribute('data-purpose');
  });

  test('a step on an element off the page fails at once and leaves nothing behind', async ({
    page,
  }) => {
    await open(page);
    const result = await page.evaluate(async () => {
      const loose = document.createElement('passkey-step-dialog');
      const error = await loose
        .ask({ purpose: 'prf', n: 2, of: 3, kind: 'get' })
        .catch((e) => e);
      return {
        name: error?.name,
        purpose: loose.getAttribute('data-purpose'),
        open: loose.isOpen,
      };
    });
    expect(result).toEqual({
      name: 'InvalidStateError',
      purpose: null,
      open: false,
    });
  });

  test('"Continue" ignores a click in the first moment, so a double click does not approve the next step', async ({
    page,
  }) => {
    await open(page);
    const answered = await page.evaluate(async () => {
      const { dialog, elements } = window;
      const results = [];
      const step = (n) =>
        dialog.ask({ purpose: 'prf', n, of: 3, kind: 'get' }).then(
          () => results.push(`continued ${n}`),
          (e) => results.push(`${e.name} ${n}`)
        );
      const button = dialog.shadowRoot.querySelector('[part=continue]');
      // A click right away is ignored; one after the delay counts.
      const first = step(2);
      button.click();
      await new Promise((r) => setTimeout(r, elements.CONTINUE_DELAY_MS + 50));
      button.click();
      await first;
      // The next step comes straight after; the second click of a double
      // click lands on it at once and must not approve it.
      const second = step(3);
      button.click();
      await new Promise((r) => setTimeout(r, 50));
      const stillOpen = dialog.isOpen;
      dialog.shadowRoot.querySelector('[part=cancel]').click();
      await second;
      return { results, stillOpen };
    });
    expect(answered).toEqual({
      results: ['continued 2', 'PasskeyStepCancelled 3'],
      stillOpen: true,
    });
  });

  test('speaks the document’s language', async ({ page }) => {
    await open(page, 'de');
    await secondPrompt(page, { purpose: 'restore-confirm' });
    await expect(dialog(page).locator('[part=count]')).toHaveText(
      'Passkey-Abfrage 2 von 3'
    );
    await expect(dialog(page).getByRole('heading')).toHaveText(
      'Noch einmal derselbe Passkey'
    );
    await expect(
      dialog(page).getByRole('button', { name: 'Weiter' })
    ).toBeVisible();
    await dialog(page).getByRole('button', { name: 'Abbrechen' }).click();
    await expect.poll(() => outcome(page)).toBe('PasskeyStepCancelled');
  });

  test('takes an application’s own words, per language and purpose', async ({
    page,
  }) => {
    await open(page);
    await page.evaluate(() => {
      window.dialog.strings = {
        en: {
          purposes: {
            prf: {
              title: 'Now the key for your books',
              why: 'Belege’s words.',
            },
          },
        },
      };
    });
    await secondPrompt(page, { purpose: 'prf' });
    await expect(dialog(page).getByRole('heading')).toHaveText(
      'Now the key for your books'
    );
    await expect(dialog(page).locator('[part=why]')).toHaveText(
      'Belege’s words.'
    );
    // What it did not replace stays built in.
    await expect(
      dialog(page).getByRole('button', { name: 'Continue' })
    ).toBeVisible();
  });

  test('a plan without a count says only which prompt it is', async ({
    page,
  }) => {
    await open(page);
    await secondPrompt(page, { of: null });
    await expect(dialog(page).locator('[part=count]')).toHaveText(
      'Passkey prompt 2'
    );
  });

  test('every purpose the package announces has wording in both languages', async ({
    page,
  }) => {
    await open(page);
    const missing = await page.evaluate(() => {
      const { PASSKEY_PURPOSES, PASSKEY_STEP_STRINGS } = window.elements;
      return ['en', 'de'].flatMap((language) =>
        PASSKEY_PURPOSES.filter((purpose) => {
          const text = PASSKEY_STEP_STRINGS[language].purposes[purpose];
          return !text?.title || !text?.why;
        }).map((purpose) => `${language}:${purpose}`)
      );
    });
    expect(missing).toEqual([]);
  });
});

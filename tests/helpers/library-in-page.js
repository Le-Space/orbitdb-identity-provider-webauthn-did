/**
 * The library itself in a real page, for browser suites that call its API
 * directly rather than through a demo's UI.
 *
 * Imports `src/index.js` through Vite's /@fs route, which only the dev server
 * has: a suite using this needs `pnpm run dev`, so CI runs it with `CI`
 * cleared (see the unit-test step in ci.yml).
 */
import { expect } from '@playwright/test';

/**
 * Load `src/index.js` into the page as `window.WebAuthnModule`, retrying a
 * context reset from the dev server's first navigation.
 */
export async function loadLibrary(page) {
  await page.goto('/', { waitUntil: 'domcontentloaded' });
  await page.waitForLoadState('networkidle');
  const moduleUrl = `/@fs${process.cwd().replace(/\\/g, '/')}/src/index.js`;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await page.evaluate(async (url) => {
        try {
          const module = await import(url);
          window.WebAuthnModule = module;
          window.moduleLoaded = true;
        } catch (error) {
          window.moduleLoadError = String(error?.stack || error);
          window.moduleLoaded = false;
        }
      }, moduleUrl);
      break;
    } catch (error) {
      const isContextReset = String(error).includes(
        'Execution context was destroyed'
      );
      if (!isContextReset || attempt === 2) throw error;
      await page.waitForLoadState('networkidle');
    }
  }
  await page.waitForFunction(
    () => window.moduleLoaded === true || !!window.moduleLoadError
  );
  const moduleLoadError = await page.evaluate(
    () => window.moduleLoadError || null
  );
  expect(moduleLoadError).toBeNull();
}

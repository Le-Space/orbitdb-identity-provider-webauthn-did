import { defineConfig, devices } from '@playwright/test';

/**
 * Browser tests for the custom elements in ./elements.
 *
 * They need a DOM, so they cannot sit in the Node-context config, and they
 * need no demo: each test serves the element's source to a blank page itself
 * (`page.route`). The main playwright.config.js builds and starts a demo first,
 * which these would wait for and never use. CI runs this config once the
 * browsers are installed.
 */
export default defineConfig({
  testDir: './tests',
  testMatch: ['passkey-step-dialog.test.js'],
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'line',
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});

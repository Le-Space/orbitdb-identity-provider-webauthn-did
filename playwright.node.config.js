import { defineConfig } from '@playwright/test';

delete process.env.NO_COLOR;

/**
 * Node-context test suites.
 *
 * These import the package directly and never open a page, so they need
 * neither a browser nor a demo server. The main playwright.config.js declares
 * a `webServer`, which makes every run there boot and build a demo — fine in
 * CI, too slow to sit in front of `npm version` / `npm publish`.
 *
 * Files listed here that do not exist yet are simply not matched, so this
 * config stays valid regardless of which branches have landed.
 */
export default defineConfig({
  testDir: './tests',
  testMatch: [
    'standalone-toolkit.test.js',
    'webauthn-debug-log.test.js',
    'webauthn-attestation-parsing.test.js',
    'webauthn-two-peer-replication.test.js',
  ],
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'line',
  projects: [{ name: 'node' }],
});

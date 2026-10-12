import { defineConfig } from '@playwright/test';

delete process.env.NO_COLOR;

/**
 * Suites that run against a Sepolia fork in anvil: they need Foundry and an
 * RPC, so CI does not run them. `npm run test:wallet-fork` sets a public
 * Sepolia RPC unless PASSKEY_WALLET_FORK_URL names another.
 */
export default defineConfig({
  testDir: './packages/passkey-wallet/test/fork',
  testMatch: ['*.test.js'],
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: 'line',
  projects: [{ name: 'fork' }],
});

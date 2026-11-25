import { defineConfig } from '@playwright/test';

delete process.env.NO_COLOR;

/**
 * Suites that run against a Sepolia fork in anvil: they need Foundry and a
 * Sepolia RPC in PASSKEY_WALLET_FORK_URL, so CI does not run them.
 *
 * There is no public default any more. sepolia.drpc.org, the one this used,
 * stopped serving Sepolia on its free plan, and the free endpoints tried
 * since (publicnode) answer plain calls but leave anvil's fork start hanging
 * often enough that the suite fails for reasons of their own. A key from a
 * provider (Alchemy, Infura, …) works.
 */
if (!process.env.PASSKEY_WALLET_FORK_URL) {
  throw new Error(
    'test:wallet-fork needs PASSKEY_WALLET_FORK_URL, a Sepolia RPC URL — e.g. https://eth-sepolia.g.alchemy.com/v2/<key>'
  );
}

export default defineConfig({
  testDir: './packages/passkey-wallet/test/fork',
  testMatch: ['*.test.js'],
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: 'line',
  projects: [{ name: 'fork' }],
});

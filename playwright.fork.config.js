import { defineConfig } from '@playwright/test';

delete process.env.NO_COLOR;

/**
 * Suites that run against a Sepolia fork in anvil: they need Foundry and a
 * Sepolia RPC in PASSKEY_WALLET_FORK_URL. CI runs them as the `wallet-fork`
 * job, with that URL from a repository secret.
 *
 * There is no public default any more. sepolia.drpc.org, the one this used,
 * stopped serving Sepolia on its free plan, and the free endpoints tried
 * since (publicnode) answer plain calls but leave anvil's fork start hanging
 * often enough that the suite fails for reasons of their own. A key from a
 * provider (Alchemy, Infura, …) works. `npm run test:wallet-fork` stops with
 * a message when the variable is missing; this file itself stays loadable
 * without it, since scripts/check-ci-runs-every-test.mjs lists its files.
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

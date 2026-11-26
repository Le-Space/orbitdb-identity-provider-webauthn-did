/**
 * @le-space/passkey-wallet: sending a user operation again without it
 * running twice.
 *
 * A bundler can include an operation and still answer with an error or a
 * timeout; an app that sends the calls again then gets the next nonce, and
 * both run. `sendUserOperationWithRetry` reads the nonce once and sends every
 * attempt with it, so at most one is included. The bundler and the account
 * here are stand-ins that record what they were asked: what is asserted is
 * which nonces were sent and when the helper stops.
 */
import { test, expect } from '@playwright/test';
import { register } from 'node:module';

register(
  '../packages/passkey-wallet/test/support/resolve-package-self.mjs',
  import.meta.url
);
const wallet = await import('../packages/passkey-wallet/src/index.js');

/** Key 0, sequence 5: the account's next nonce when a test starts. */
const NONCE = 5n;

/**
 * An account whose EntryPoint nonce the test moves, and a bundler that
 * includes or loses what it is sent as each test scripts it.
 * @param {Array<{ send?: 'throw' | 'ok', include?: boolean, wait?: 'timeout' | 'ok' }>} script
 */
function chain(script) {
  const state = { nonce: NONCE, included: new Map(), sent: [], nonceReads: 0 };
  const account = {
    async getNonce(parameters) {
      state.nonceReads += 1;
      expect(parameters?.key ?? 0n).toBe(0n);
      return state.nonce;
    },
  };
  let attempt = 0;
  const bundler = {
    account,
    async sendUserOperation(parameters) {
      const step = script[attempt] ?? {};
      attempt += 1;
      state.sent.push(parameters.nonce);
      const hash = `0x${attempt.toString(16).padStart(64, '0')}`;
      if (step.include) {
        // The EntryPoint runs one operation per nonce.
        if (parameters.nonce === state.nonce) {
          state.nonce += 1n;
          state.included.set(hash, { userOpHash: hash, success: true });
        }
      }
      if (step.send === 'throw') throw new Error('bundler: internal error');
      return hash;
    },
    async waitForUserOperationReceipt({ hash }) {
      const step = script[attempt - 1] ?? {};
      if (step.wait === 'timeout') throw new Error('timed out');
      const receipt = state.included.get(hash);
      if (!receipt) throw new Error('timed out');
      return receipt;
    },
    async getUserOperationReceipt({ hash }) {
      const receipt = state.included.get(hash);
      if (!receipt) throw new Error('UserOperationReceiptNotFoundError');
      return receipt;
    },
  };
  return { state, bundler, account };
}

const CALLS = { calls: [{ to: '0x0000000000000000000000000000000000000001' }] };

test.describe('sendUserOperationWithRetry', () => {
  test('a first attempt that was included behind a timeout is not sent again', async () => {
    const { state, bundler } = chain([{ include: true, wait: 'timeout' }]);
    const result = await wallet.sendUserOperationWithRetry(bundler, CALLS);
    expect(state.sent).toEqual([NONCE]);
    expect(result.hash).toBe(result.hashes[0]);
    expect(result.receipt.success).toBe(true);
    expect(result.nonce).toBe(NONCE);
  });

  test('a retry takes the first attempt’s nonce', async () => {
    const { state, bundler } = chain([{ wait: 'timeout' }, { include: true }]);
    const result = await wallet.sendUserOperationWithRetry(bundler, CALLS);
    expect(state.sent).toEqual([NONCE, NONCE]);
    expect(result.hashes).toHaveLength(2);
    expect(result.hash).toBe(result.hashes[1]);
  });

  test('a nonce used without a receipt to show for it stops the retries', async () => {
    // The bundler included the operation and then failed to answer with its
    // hash: the helper cannot find a receipt, but the nonce has moved on.
    const { state, bundler } = chain([{ include: true, send: 'throw' }]);
    const error = await wallet
      .sendUserOperationWithRetry(bundler, CALLS)
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.UserOperationNonceUsedError);
    expect(error.nonce).toBe(NONCE);
    expect(error.hashes).toEqual([]);
    expect(state.sent).toEqual([NONCE]);
  });

  test('after every attempt failed, the nonce comes back for the next call', async () => {
    const { state, bundler } = chain([
      { wait: 'timeout' },
      { send: 'throw' },
      { include: true },
    ]);
    const error = await wallet
      .sendUserOperationWithRetry(bundler, CALLS, { attempts: 2 })
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.UserOperationNotIncludedError);
    expect(error.nonce).toBe(NONCE);
    expect(error.hashes).toHaveLength(1);
    expect(state.sent).toEqual([NONCE, NONCE]);

    // Sent again with that nonce, the next call stays on it.
    const result = await wallet.sendUserOperationWithRetry(bundler, {
      ...CALLS,
      nonce: error.nonce,
    });
    expect(state.sent).toEqual([NONCE, NONCE, NONCE]);
    expect(result.receipt.success).toBe(true);
  });

  test('without a retry of the same nonce, the operation would have run twice', async () => {
    // What the helper is for, stated against the stand-in: two plain sends,
    // each with the nonce read just before it, both included.
    const { state, bundler, account } = chain([
      { include: true, send: 'throw' },
      { include: true },
    ]);
    await bundler
      .sendUserOperation({ ...CALLS, nonce: await account.getNonce() })
      .catch(() => {});
    await bundler.sendUserOperation({
      ...CALLS,
      nonce: await account.getNonce(),
    });
    expect(state.included.size).toBe(2);
  });

  test('needs an account and at least one attempt', async () => {
    const { bundler } = chain([]);
    await expect(
      wallet.sendUserOperationWithRetry(
        { ...bundler, account: undefined },
        CALLS
      )
    ).rejects.toThrow(/needs a smart account/);
    await expect(
      wallet.sendUserOperationWithRetry(bundler, CALLS, { attempts: 0 })
    ).rejects.toThrow(/attempts/);
  });
});

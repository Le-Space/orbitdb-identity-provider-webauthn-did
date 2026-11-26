/**
 * Sending a user operation again without it running twice.
 *
 * A bundler can include a user operation and still answer with an error or a
 * timeout. An app that then sends the same calls again gets a new user
 * operation, with the next nonce, and both run: the transfer goes out twice.
 * The EntryPoint only ever runs one operation per nonce, so a retry is safe
 * exactly when it reuses the first attempt's nonce — whichever of them is
 * included retires the others.
 *
 * `sendUserOperationWithRetry` does that: it reads the nonce once, sends every
 * attempt with it, and between attempts looks for a receipt of any earlier
 * one and checks whether the nonce has been used.
 */

const SEQUENCE_MASK = (1n << 64n) - 1n;

/**
 * The nonce has been used, but by none of the attempts whose receipt the
 * bundler could find — perhaps by an attempt whose hash never came back, or
 * by another operation of the account. Nothing more is sent; check whether
 * the calls ran before sending them again.
 */
export class UserOperationNonceUsedError extends Error {
  /**
   * @param {bigint} nonce
   * @param {readonly import('viem').Hex[]} hashes
   * @param {unknown} cause
   */
  constructor(nonce, hashes, cause) {
    super(
      `nonce ${nonce} has been used, but no receipt was found for ${hashes.length ? hashes.join(', ') : 'any attempt (the bundler returned no hash)'}; check whether the operation ran before sending it again`,
      { cause }
    );
    this.name = 'UserOperationNonceUsedError';
    this.nonce = nonce;
    this.hashes = hashes;
  }
}

/**
 * No attempt was seen to be included, and the nonce is still unused. Any of
 * `hashes` may still be included later. Sending again with `{ nonce }` keeps
 * it at most once; sending without it does not.
 */
export class UserOperationNotIncludedError extends Error {
  /**
   * @param {bigint} nonce
   * @param {readonly import('viem').Hex[]} hashes
   * @param {number} attempts
   * @param {unknown} cause
   */
  constructor(nonce, hashes, attempts, cause) {
    super(
      `user operation not included after ${attempts} attempt${attempts === 1 ? '' : 's'}; nonce ${nonce} is still unused, and ${hashes.length} sent attempt${hashes.length === 1 ? '' : 's'} may still be included — retry with { nonce: ${nonce}n } to keep it at most once`,
      { cause }
    );
    this.name = 'UserOperationNotIncludedError';
    this.nonce = nonce;
    this.hashes = hashes;
  }
}

/**
 * @param {any} bundlerClient
 * @param {readonly import('viem').Hex[]} hashes
 */
async function findReceipt(bundlerClient, hashes) {
  for (const hash of [...hashes].reverse()) {
    try {
      const receipt = await bundlerClient.getUserOperationReceipt({ hash });
      if (receipt) return { hash, receipt };
    } catch {
      // Not found, or the bundler did not answer: not evidence either way.
    }
  }
  return undefined;
}

/**
 * Whether the EntryPoint has moved past `nonce` on its key.
 * @param {any} account
 * @param {bigint} nonce
 */
async function nonceUsed(account, nonce) {
  const key = nonce >> 64n;
  const current = BigInt(await account.getNonce({ key }));
  return (
    current >> 64n === key &&
    (current & SEQUENCE_MASK) > (nonce & SEQUENCE_MASK)
  );
}

/**
 * Send a user operation, and on failure send it again with the same nonce,
 * so that at most one attempt runs.
 *
 * Each attempt goes through `bundlerClient.sendUserOperation` with the
 * parameters given (calls, paymaster, gas and fee fields) and the nonce read
 * before the first one, then waits for its receipt. When an attempt fails —
 * the send, or the wait — the receipt of every attempt so far is looked for
 * and returned if one is found. If the nonce has been used without a receipt
 * to show for it, `UserOperationNonceUsedError` is thrown and nothing more is
 * sent. Otherwise the next attempt is sent; gas and fees may be estimated
 * anew, the nonce is not.
 *
 * The guarantee holds within one call. A second call reads a new nonce: wrap
 * this in a retry loop of your own and the operation can run twice again. To
 * retry after `UserOperationNotIncludedError`, or after a reload, pass the
 * error's `nonce` back in as `parameters.nonce`.
 *
 * A receipt is returned whether the operation succeeded or reverted; check
 * `receipt.success`.
 *
 * @param {any} bundlerClient - a viem bundler client: `sendUserOperation`,
 *   `waitForUserOperationReceipt` and `getUserOperationReceipt`.
 * @param {{ account?: any, nonce?: bigint | undefined } & Record<string, unknown>} parameters
 *   what viem's `sendUserOperation` takes; `account` defaults to the bundler
 *   client's.
 * @param {{ attempts?: number | undefined, timeout?: number | undefined, pollingInterval?: number | undefined }} [options]
 *   `attempts` (default 3) counts sends; `timeout` and `pollingInterval` go
 *   to `waitForUserOperationReceipt`.
 * @returns {Promise<{ hash: import('viem').Hex, receipt: any, nonce: bigint, hashes: import('viem').Hex[] }>}
 */
export async function sendUserOperationWithRetry(
  bundlerClient,
  parameters,
  options = {}
) {
  const { attempts = 3, timeout, pollingInterval } = options;
  if (!Number.isSafeInteger(attempts) || attempts < 1) {
    throw new TypeError('attempts must be a positive integer');
  }
  const account = parameters?.account ?? bundlerClient?.account;
  if (!account || typeof account.getNonce !== 'function') {
    throw new TypeError(
      'sendUserOperationWithRetry needs a smart account, in parameters or on the bundler client'
    );
  }
  const nonce = BigInt(parameters.nonce ?? (await account.getNonce()));
  /** @type {import('viem').Hex[]} */
  const hashes = [];
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const hash = await bundlerClient.sendUserOperation({
        ...parameters,
        account,
        nonce,
      });
      hashes.push(hash);
      const receipt = await bundlerClient.waitForUserOperationReceipt({
        hash,
        ...(timeout === undefined ? {} : { timeout }),
        ...(pollingInterval === undefined ? {} : { pollingInterval }),
      });
      return { hash, receipt, nonce, hashes: [...hashes] };
    } catch (error) {
      lastError = error;
    }
    const landed = await findReceipt(bundlerClient, hashes);
    if (landed) return { ...landed, nonce, hashes: [...hashes] };
    if (await nonceUsed(account, nonce)) {
      throw new UserOperationNonceUsedError(nonce, [...hashes], lastError);
    }
  }
  throw new UserOperationNotIncludedError(
    nonce,
    [...hashes],
    attempts,
    lastError
  );
}

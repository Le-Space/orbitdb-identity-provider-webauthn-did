/**
 * Send a user operation, and on failure send it again with the same nonce, so
 * that at most one attempt runs. A second call reads a new nonce: to retry
 * after `UserOperationNotIncludedError` or a reload, pass its `nonce` back in.
 * The receipt is returned whether the operation succeeded or reverted.
 */
export function sendUserOperationWithRetry(
  bundlerClient: {
    account?: unknown;
    sendUserOperation: (parameters: any) => Promise<import('viem').Hex>;
    waitForUserOperationReceipt: (parameters: {
      hash: import('viem').Hex;
      timeout?: number;
      pollingInterval?: number;
    }) => Promise<any>;
    getUserOperationReceipt: (parameters: {
      hash: import('viem').Hex;
    }) => Promise<any>;
  },
  parameters: {
    account?: unknown;
    /** The nonce of an earlier call, to keep a retry across calls at most once. */
    nonce?: bigint | undefined;
    [key: string]: unknown;
  },
  options?: {
    /** Sends in all, default 3. */
    attempts?: number | undefined;
    timeout?: number | undefined;
    pollingInterval?: number | undefined;
  }
): Promise<{
  hash: import('viem').Hex;
  receipt: any;
  nonce: bigint;
  hashes: import('viem').Hex[];
}>;
/** The nonce was used, but no receipt of these attempts was found; nothing more was sent. */
export class UserOperationNonceUsedError extends Error {
  constructor(
    nonce: bigint,
    hashes: readonly import('viem').Hex[],
    cause: unknown
  );
  nonce: bigint;
  hashes: readonly import('viem').Hex[];
}
/** No attempt was seen to be included and the nonce is unused; any of `hashes` may still be. Retry with `{ nonce }`. */
export class UserOperationNotIncludedError extends Error {
  constructor(
    nonce: bigint,
    hashes: readonly import('viem').Hex[],
    attempts: number,
    cause: unknown
  );
  nonce: bigint;
  hashes: readonly import('viem').Hex[];
}

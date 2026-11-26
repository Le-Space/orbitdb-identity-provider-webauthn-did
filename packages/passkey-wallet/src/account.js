/**
 * The passkey as a viem smart account on Calibur and EntryPoint v0.8.
 */
import { signP256Challenge } from '@le-space/orbitdb-identity-provider-webauthn-did/standalone';
import { getAddress, hashMessage, hexToBytes, isAddress } from 'viem';
import {
  entryPoint08Abi,
  getUserOperationHash,
  toSmartAccount,
} from 'viem/account-abstraction';
import { getChainId, readContract } from 'viem/actions';

import { caliburAbi } from './abi.js';
import {
  decodeExecuteUserOpCallData,
  encodeExecuteUserOpCallData,
  encodeTypedDataSignSignature,
  encodeUserOperationSignature,
  encodeWebAuthnAuth,
  getCaliburStubSignature,
  getKeyHash,
  getPersonalSignNestedDigest,
  getTypedDataSignDigests,
  toWebAuthnP256Key,
} from './calibur.js';
import {
  CALIBUR_ADDRESS,
  CALIBUR_VERSION,
  ENTRY_POINT_ADDRESS,
} from './constants.js';

/**
 * @typedef {import('viem').Address} Address
 * @typedef {import('viem').Hex} Hex
 * @typedef {import('./calibur.js').Key} Key
 */

/**
 * What `getP256CredentialDescriptor` returns: the passkey's credential id, its
 * P-256 key as 32-byte coordinates, and the rpId it is registered under.
 * @typedef {import('@le-space/orbitdb-identity-provider-webauthn-did/standalone').P256CredentialDescriptor} P256CredentialDescriptor
 */

/**
 * The client a smart account reads chain state through; a public client will
 * do.
 * @typedef {import('viem').Client<
 *   import('viem').Transport,
 *   import('viem').Chain | undefined,
 *   import('viem').JsonRpcAccount | import('viem').LocalAccount | undefined
 * >} AccountClient
 */

/**
 * The smart account `toCaliburPasskeyAccount` returns: a viem SmartAccount for
 * EntryPoint v0.8, extended with Calibur's ABI, the passkey descriptor, its
 * Calibur key and key hash.
 * @typedef {import('viem/account-abstraction').SmartAccount<
 *   import('viem/account-abstraction').SmartAccountImplementation<
 *     typeof entryPoint08Abi,
 *     '0.8',
 *     {
 *       abi: typeof caliburAbi,
 *       descriptor: P256CredentialDescriptor,
 *       key: Key,
 *       keyHash: Hex,
 *     }
 *   >
 * >} CaliburPasskeyAccount
 */

/**
 * The verification gas a passkey user operation is given at least.
 *
 * Measured on a Sepolia fork (test/fork, to within 1k gas): a user operation
 * with a real passkey signature needs a verificationGasLimit of about 81k
 * where the P-256 precompile (EIP-7951, at 0x100) exists, and about 370k
 * without it, where webauthn-sol verifies in Solidity (FreshCryptoLib). With
 * the stub signature it needs about 72k either way: the stub stops before the
 * P-256 verification — see `getCaliburStubSignature` — so an estimate made
 * with it falls short. 800k covers the precompile-less case with room, the
 * floor viem's Coinbase account sets for WebAuthn owners too. EntryPoint v0.8
 * charges no penalty for unused verification gas, but the limit raises the
 * prefund; pass less for a chain known to have the precompile.
 */
export const DEFAULT_VERIFICATION_GAS_LIMIT = 800_000n;

/**
 * The most gas a user operation may carry in each field before the passkey is
 * asked to sign it.
 *
 * The bundler and the RPC choose these numbers, and until now the passkey
 * signed whatever came back: a bundler that answered with a preVerificationGas
 * of fifty million was paid for fifty million out of the account's balance —
 * it is the beneficiary of the difference. Gas is counted in gas, not wei, so
 * these ceilings hold on any chain; what a unit costs is a separate question,
 * answered by `maxUserOperationCost`.
 *
 * Generous on purpose: an L1 user operation with a passkey uses about a tenth
 * of each. preVerificationGas depends on the chain: see
 * `PRE_VERIFICATION_GAS_CEILINGS`, and `getDefaultGasCeilings(chainId)` for
 * what an account on a chain gets. An app on another rollup may need to raise
 * it — the refusal names the field and the value, so the app can tell.
 */
/**
 * @typedef {{
 *   callGasLimit: bigint,
 *   verificationGasLimit: bigint,
 *   preVerificationGas: bigint,
 *   paymasterVerificationGasLimit: bigint,
 *   paymasterPostOpGasLimit: bigint,
 * }} UserOperationGasCeilings
 */

/** @type {Readonly<UserOperationGasCeilings>} */
export const DEFAULT_USER_OPERATION_GAS_CEILINGS = Object.freeze({
  callGasLimit: 10_000_000n,
  verificationGasLimit: 2_000_000n,
  preVerificationGas: 1_000_000n,
  paymasterVerificationGasLimit: 1_000_000n,
  paymasterPostOpGasLimit: 1_000_000n,
});

/**
 * The preVerificationGas ceiling on chains whose needs are known; any other
 * chain gets the 1M of `DEFAULT_USER_OPERATION_GAS_CEILINGS`.
 *
 * On Ethereum and its testnets preVerificationGas is the calldata and the
 * bundler's overhead: a passkey user operation needs well under 100k, so 250k
 * leaves room and little to skim. Rollups that post their data to L1 have the
 * bundler recover that cost through preVerificationGas, converted at the L2
 * gas price — the cheaper L2 gas, the more of it, into the millions. There the
 * ceiling is 5M, and `maxUserOperationCost` is what bounds the amount.
 * @type {Readonly<Record<number, bigint>>}
 */
export const PRE_VERIFICATION_GAS_CEILINGS = Object.freeze({
  1: 250_000n, // Ethereum
  11155111: 250_000n, // Sepolia
  10: 5_000_000n, // OP Mainnet
  11155420: 5_000_000n, // OP Sepolia
  8453: 5_000_000n, // Base
  84532: 5_000_000n, // Base Sepolia
  42161: 5_000_000n, // Arbitrum One
  421614: 5_000_000n, // Arbitrum Sepolia
});

/**
 * The gas ceilings a user operation on `chainId` gets unless the app passes
 * its own: `DEFAULT_USER_OPERATION_GAS_CEILINGS`, with the chain's
 * preVerificationGas ceiling from `PRE_VERIFICATION_GAS_CEILINGS` where there
 * is one.
 * @param {number} chainId
 * @returns {Readonly<typeof DEFAULT_USER_OPERATION_GAS_CEILINGS>}
 */
export function getDefaultGasCeilings(chainId) {
  const preVerificationGas = PRE_VERIFICATION_GAS_CEILINGS[chainId];
  return Object.freeze({
    ...DEFAULT_USER_OPERATION_GAS_CEILINGS,
    ...(preVerificationGas === undefined ? {} : { preVerificationGas }),
  });
}

/**
 * One nonce key, 0, for every user operation of the account.
 *
 * viem's default draws a fresh 192-bit key from Date.now() for each operation,
 * which gives every operation a lane of its own at sequence 0. Nothing then
 * retires an operation that was signed but not included: a bundler that
 * reported an error and kept it can submit it later, after the app has retried
 * on a new lane, and the transfer runs twice. On a single key a retry takes the
 * same nonce, so whichever of the two lands first makes the other invalid.
 *
 * The cost is that operations of one account are sequential. An app that wants
 * parallel lanes passes its own `nonceKeyManager` and takes on the duty of
 * retiring operations it gave up on.
 * @type {import('viem').NonceManager}
 */
export const SINGLE_NONCE_KEY = Object.freeze({
  async consume() {
    return 0;
  },
  increment() {},
  async get() {
    return 0;
  },
  reset() {},
});

const ADDRESS_MASK = (1n << 160n) - 1n;

/**
 * `eip712Domain()` answered with a domain that is not this account's on this
 * chain, so a signature over it would be valid somewhere the user did not ask
 * for. Thrown before the passkey is prompted.
 */
export class AccountDomainMismatchError extends Error {
  /** @param {string} field @param {unknown} actual @param {unknown} expected */
  constructor(field, actual, expected) {
    super(
      `eip712Domain() reported ${field} ${String(actual)}, expected ${String(expected)}; refusing to sign for a domain that is not this account's`
    );
    this.name = 'AccountDomainMismatchError';
    this.field = field;
  }
}

/**
 * A user operation exceeded a gas ceiling or the cost limit, or names another
 * chain than the account's. Thrown before the passkey is prompted.
 */
export class UserOperationLimitError extends Error {
  /** @param {string} message @param {string} field */
  constructor(message, field) {
    super(message);
    this.name = 'UserOperationLimitError';
    this.field = field;
  }
}

const NONCE_SEQUENCE_BITS = 64n;

/**
 * The chain every signature is bound to: the app's `chainId`, else the
 * client's chain, and only for a client without one the RPC's answer — read
 * once, by the caller, so that it does not change from one signature to the
 * next. Zero is refused: an EIP-7702 authorization for chain 0 is valid on
 * every chain.
 * @param {AccountClient} client
 * @param {number | bigint | undefined} chainId
 * @returns {Promise<number>}
 */
export async function pinChainId(client, chainId) {
  const pinned = Number(
    chainId ?? client.chain?.id ?? (await getChainId(client))
  );
  if (!Number.isSafeInteger(pinned) || pinned <= 0) {
    throw new TypeError('chainId must be a positive integer');
  }
  return pinned;
}

/**
 * The gas ceilings and the cost limit an app asked for, checked.
 * @param {{
 *   chainId: number,
 *   gasCeilings?: Partial<typeof DEFAULT_USER_OPERATION_GAS_CEILINGS> | undefined,
 *   maxUserOperationCost?: bigint | undefined,
 *   what: string,
 * }} parameters
 */
export function readUserOperationLimits({
  chainId,
  gasCeilings: overrides,
  maxUserOperationCost,
  what,
}) {
  const gasCeilings = { ...getDefaultGasCeilings(chainId) };
  for (const [field, value] of Object.entries(overrides ?? {})) {
    if (!(field in gasCeilings)) {
      throw new TypeError(`gasCeilings has no field ${field}`);
    }
    if (typeof value !== 'bigint' || value < 0n) {
      throw new TypeError(`gasCeilings.${field} must be a non-negative bigint`);
    }
    gasCeilings[/** @type {keyof typeof gasCeilings} */ (field)] = value;
  }
  // No default: what a user operation may cost is the app's to say, in the
  // chain's currency, and without a limit the bundler or the RPC says it —
  // through maxFeePerGas, which the gas ceilings do not bound.
  if (typeof maxUserOperationCost !== 'bigint' || maxUserOperationCost < 0n) {
    throw new TypeError(
      `${what} needs maxUserOperationCost: the most, in wei, one user operation may cost (its gas limits times maxFeePerGas). Without it the bundler or the RPC decides through the fee.`
    );
  }
  return { gasCeilings, maxUserOperationCost };
}

/**
 * The checks a user operation passes before a key is asked to sign it: the
 * chain, each gas field against its ceiling, the fees, the most it can cost,
 * and — for an account on one nonce key — that key.
 * @param {{
 *   chainId: number,
 *   gasCeilings: typeof DEFAULT_USER_OPERATION_GAS_CEILINGS,
 *   maxUserOperationCost: bigint,
 *   singleNonceKey: boolean,
 * }} limits
 * @returns {(userOperation: Record<string, unknown>, requestedChainId: number | undefined) => void}
 */
export function createUserOperationGuard({
  chainId,
  gasCeilings,
  maxUserOperationCost,
  singleNonceKey,
}) {
  return function assertWithinLimits(userOperation, requestedChainId) {
    if (
      requestedChainId !== undefined &&
      Number(requestedChainId) !== chainId
    ) {
      throw new UserOperationLimitError(
        `user operation is for chain ${requestedChainId}, the account signs for chain ${chainId}`,
        'chainId'
      );
    }
    if (singleNonceKey) {
      // The nonce comes from EntryPoint.getNonce over the RPC. An RPC that
      // answered with another key would give this operation a lane of its
      // own again, beside every retry.
      const nonce = BigInt(
        /** @type {bigint | number | string} */ (userOperation.nonce ?? 0n)
      );
      const key = nonce >> NONCE_SEQUENCE_BITS;
      if (key !== 0n) {
        throw new UserOperationLimitError(
          `user operation nonce has key ${key}; the account signs on nonce key 0 only (SINGLE_NONCE_KEY)`,
          'nonce'
        );
      }
    }
    let gas = 0n;
    for (const [field, ceiling] of Object.entries(gasCeilings)) {
      const value = userOperation[field];
      if (value === undefined || value === null) continue;
      const amount = BigInt(/** @type {bigint | number | string} */ (value));
      if (amount > ceiling) {
        throw new UserOperationLimitError(
          `user operation ${field} ${amount} exceeds the ceiling ${ceiling}; raise gasCeilings.${field} if this chain needs it`,
          field
        );
      }
      gas += amount;
    }
    const maxFeePerGas = BigInt(
      /** @type {bigint} */ (userOperation.maxFeePerGas ?? 0n)
    );
    const maxPriorityFeePerGas = BigInt(
      /** @type {bigint} */ (userOperation.maxPriorityFeePerGas ?? 0n)
    );
    if (maxPriorityFeePerGas > maxFeePerGas) {
      throw new UserOperationLimitError(
        `user operation maxPriorityFeePerGas ${maxPriorityFeePerGas} exceeds maxFeePerGas ${maxFeePerGas}`,
        'maxPriorityFeePerGas'
      );
    }
    const cost = gas * maxFeePerGas;
    if (cost > maxUserOperationCost) {
      throw new UserOperationLimitError(
        `user operation could cost up to ${cost} wei, more than maxUserOperationCost ${maxUserOperationCost}`,
        'maxUserOperationCost'
      );
    }
  };
}

/**
 * The same passkey as `signP256Challenge` expects it; refuses anything that
 * could not sign, before a smart account is built around it.
 * @param {unknown} descriptor
 * @returns {P256CredentialDescriptor}
 */
function readDescriptor(descriptor) {
  const d = /** @type {P256CredentialDescriptor} */ (descriptor);
  if (
    !d ||
    typeof d !== 'object' ||
    !(d.rawCredentialId instanceof Uint8Array) ||
    d.rawCredentialId.length === 0 ||
    typeof d.rpId !== 'string' ||
    !d.rpId
  ) {
    throw new TypeError(
      'A passkey descriptor from getP256CredentialDescriptor() is needed'
    );
  }
  return d;
}

/**
 * What signs a 32-byte challenge for the account: by default the passkey,
 * through `signP256Challenge` (one WebAuthn prompt, user verification
 * required). Anything that returns the same parts of a WebAuthn assertion for
 * the registered key will do.
 * @typedef {(challenge: Uint8Array) => Promise<import('./calibur.js').WebAuthnAuth>} ChallengeSigner
 */

/**
 * A viem smart account for a Calibur account whose passkey is registered.
 *
 * - `signUserOperation` computes the EntryPoint v0.8 user operation hash, has
 *   the passkey sign exactly those 32 bytes with `signP256Challenge` (one
 *   WebAuthn prompt, user verification required) and encodes Calibur's
 *   `abi.encode(keyHash, abi.encode(WebAuthnAuth), hookData)`.
 * - `encodeCalls` batches through Calibur's `executeUserOp`: all calls run in
 *   one `BatchedCall`, and one failure reverts them all.
 * - The account is already an EIP-7702 delegate, so there are no factory
 *   arguments; set it up first with `createCaliburPasskeySetup`.
 * - `signTypedData` and `signMessage` sign for ERC-1271 (`isValidSignature`)
 *   in the ERC-7739 form Calibur takes from a registered key: the nested
 *   `TypedDataSign` or `PersonalSign` hash, in the account's domain as
 *   `eip712Domain()` reads it from `client`'s chain (one read per signature).
 *   An app checks the result with the plain hash of what it asked to have
 *   signed — `hashTypedData` or `hashMessage` — as it would for any account.
 *
 * Bundler and paymaster are the app's: pass this account to a bundler client
 * the app creates (`createCaliburBundlerClient` takes URLs and headers).
 *
 * @param {{
 *   client: AccountClient,
 *   address: Address,
 *   descriptor: P256CredentialDescriptor,
 *   chainId?: number | undefined,
 *   implementation?: Address | undefined,
 *   verificationGasLimit?: bigint | undefined,
 *   gasCeilings?: Partial<typeof DEFAULT_USER_OPERATION_GAS_CEILINGS> | undefined,
 *   maxUserOperationCost: bigint,
 *   nonceKeyManager?: import('viem').NonceManager | undefined,
 *   sign?: ChallengeSigner | undefined,
 * }} parameters
 *   `client` reads chain state (nonce, code, the account's EIP-712 domain);
 *   `address` is the Calibur account, the EOA the setup created;
 *   `chainId` is the chain every signature is bound to — by default
 *   `client.chain.id`, and only when the client has no chain is it asked of the
 *   RPC, once, here: give the client a chain or pass this to keep the RPC from
 *   choosing it; `implementation` is the Calibur the account delegates to
 *   (default `CALIBUR_ADDRESS`), checked in the domain's salt;
 *   `verificationGasLimit` is the floor for user operations (default
 *   `DEFAULT_VERIFICATION_GAS_LIMIT`); `gasCeilings` overrides fields of
 *   `getDefaultGasCeilings(chainId)`; `maxUserOperationCost` is required: the
 *   most, in wei, a user operation may charge — its gas limits times
 *   maxFeePerGas — which only the app can name, in the chain's currency;
 *   `nonceKeyManager` defaults to `SINGLE_NONCE_KEY`, and with it every user
 *   operation must be on nonce key 0; `sign` replaces the passkey prompt, for
 *   a test or another signer of the same key.
 * @returns {Promise<CaliburPasskeyAccount>}
 */
export async function toCaliburPasskeyAccount(parameters) {
  const {
    client,
    address,
    descriptor: descriptorParameter,
    chainId: chainIdParameter,
    implementation = CALIBUR_ADDRESS,
    verificationGasLimit = DEFAULT_VERIFICATION_GAS_LIMIT,
    gasCeilings: gasCeilingsParameter,
    maxUserOperationCost,
    nonceKeyManager = SINGLE_NONCE_KEY,
    sign: signParameter,
  } = parameters ?? /** @type {any} */ ({});
  if (!client) {
    throw new TypeError('toCaliburPasskeyAccount needs a viem client');
  }
  if (typeof address !== 'string' || !isAddress(address, { strict: false })) {
    throw new TypeError('toCaliburPasskeyAccount needs the account address');
  }
  if (typeof verificationGasLimit !== 'bigint' || verificationGasLimit < 0n) {
    throw new TypeError('verificationGasLimit must be a non-negative bigint');
  }
  if (signParameter !== undefined && typeof signParameter !== 'function') {
    throw new TypeError('sign must be a function');
  }
  if (
    typeof implementation !== 'string' ||
    !isAddress(implementation, { strict: false })
  ) {
    throw new TypeError('implementation must be an address');
  }
  // Pinned once, here. Read per signature from the RPC, the chain id would be
  // whatever the RPC said that time — and the chain id is what keeps a
  // signature from being valid on another chain.
  const chainId = await pinChainId(client, chainIdParameter);
  const { gasCeilings } = readUserOperationLimits({
    chainId,
    gasCeilings: gasCeilingsParameter,
    maxUserOperationCost,
    what: 'toCaliburPasskeyAccount',
  });
  if (verificationGasLimit > gasCeilings.verificationGasLimit) {
    throw new TypeError(
      `verificationGasLimit ${verificationGasLimit} exceeds the verificationGasLimit ceiling ${gasCeilings.verificationGasLimit}`
    );
  }
  const assertWithinLimits = createUserOperationGuard({
    chainId,
    gasCeilings,
    maxUserOperationCost: /** @type {bigint} */ (maxUserOperationCost),
    singleNonceKey: nonceKeyManager === SINGLE_NONCE_KEY,
  });
  const implementationAddress = BigInt(getAddress(implementation));
  const descriptor = readDescriptor(descriptorParameter);
  /** @type {ChallengeSigner} */
  const sign =
    signParameter ?? ((challenge) => signP256Challenge(descriptor, challenge));
  const account = getAddress(address);
  const key = toWebAuthnP256Key(descriptor);
  const keyHash = getKeyHash(key);
  const entryPoint = /** @type {const} */ ({
    abi: entryPoint08Abi,
    address: ENTRY_POINT_ADDRESS,
    version: '0.8',
  });

  /**
   * The account's EIP-712 domain as Calibur reports it on `client`'s chain.
   * @returns {Promise<import('./calibur.js').AccountDomain>}
   */
  async function readAccountDomain() {
    const [, name, version, domainChainId, verifyingContract, salt] =
      await readContract(client, {
        address: account,
        abi: caliburAbi,
        functionName: 'eip712Domain',
      });
    // The domain comes from the RPC, and every field of it ends up in what the
    // passkey signs. A domain naming another account or another chain makes a
    // signature that is valid there — for a second account the same passkey
    // administers, or this address on a chain where it has the same key. So
    // each field is held to what this account is, and a mismatch is refused
    // before the passkey is asked.
    if (name !== 'Calibur') {
      throw new AccountDomainMismatchError('name', name, 'Calibur');
    }
    if (version !== CALIBUR_VERSION) {
      throw new AccountDomainMismatchError('version', version, CALIBUR_VERSION);
    }
    if (getAddress(verifyingContract) !== account) {
      throw new AccountDomainMismatchError(
        'verifyingContract',
        verifyingContract,
        account
      );
    }
    if (BigInt(domainChainId) !== BigInt(chainId)) {
      throw new AccountDomainMismatchError('chainId', domainChainId, chainId);
    }
    if ((BigInt(salt) & ADDRESS_MASK) !== implementationAddress) {
      throw new AccountDomainMismatchError(
        'salt implementation',
        getAddress(
          `0x${(BigInt(salt) & ADDRESS_MASK).toString(16).padStart(40, '0')}`
        ),
        getAddress(implementation)
      );
    }
    return {
      name,
      version,
      chainId: domainChainId,
      verifyingContract,
      salt,
    };
  }

  /** @param {import('viem').Hex} digest */
  async function signWithKey(digest) {
    return encodeWebAuthnAuth(await sign(hexToBytes(digest)));
  }

  return /** @type {Promise<CaliburPasskeyAccount>} */ (
    toSmartAccount({
      client,
      entryPoint,
      nonceKeyManager,
      extend: { abi: caliburAbi, descriptor, key, keyHash },

      async decodeCalls(data) {
        return decodeExecuteUserOpCallData(data).calls;
      },

      async encodeCalls(calls) {
        return encodeExecuteUserOpCallData(calls);
      },

      async getAddress() {
        return account;
      },

      async getFactoryArgs() {
        return { factory: undefined, factoryData: undefined };
      },

      async getStubSignature() {
        return getCaliburStubSignature({ keyHash, rpId: descriptor.rpId });
      },

      async signMessage({ message }) {
        const nestedDigest = getPersonalSignNestedDigest({
          hash: hashMessage(message),
          accountDomain: await readAccountDomain(),
        });
        return encodeUserOperationSignature({
          keyHash,
          signature: await signWithKey(nestedDigest),
        });
      },

      async signTypedData(typedData) {
        const {
          nestedDigest,
          appDomainSeparator,
          contentsHash,
          contentsDescription,
        } = getTypedDataSignDigests({
          typedData: /** @type {import('./calibur.js').TypedDataParameters} */ (
            /** @type {unknown} */ (typedData)
          ),
          accountDomain: await readAccountDomain(),
        });
        return encodeUserOperationSignature({
          keyHash,
          signature: encodeTypedDataSignSignature({
            signature: await signWithKey(nestedDigest),
            appDomainSeparator,
            contentsHash,
            contentsDescription,
          }),
        });
      },

      async signUserOperation(userOperationParameters) {
        const { chainId: requestedChainId, ...userOperation } =
          userOperationParameters;
        assertWithinLimits(
          /** @type {Record<string, unknown>} */ (
            /** @type {unknown} */ (userOperation)
          ),
          requestedChainId
        );
        const hash = getUserOperationHash({
          chainId,
          entryPointAddress: entryPoint.address,
          entryPointVersion: entryPoint.version,
          userOperation: { ...userOperation, sender: account },
        });
        return encodeUserOperationSignature({
          keyHash,
          signature: await signWithKey(hash),
        });
      },

      userOperation: {
        async estimateGas(userOperation) {
          const requested = userOperation.verificationGasLimit ?? 0n;
          return {
            verificationGasLimit:
              requested > verificationGasLimit
                ? requested
                : verificationGasLimit,
          };
        },
      },
    })
  );
}

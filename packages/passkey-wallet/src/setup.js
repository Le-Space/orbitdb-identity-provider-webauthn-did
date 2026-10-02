/**
 * Turning a fresh EOA into a Calibur account whose admin key is a passkey.
 *
 * A secp256k1 key is generated in memory. It signs the EIP-7702 authorization
 * that delegates its address to Calibur, and it authorises the account's first
 * batch — `register(passkey)`, `update(keyHash, admin)` and any extra calls —
 * which Calibur runs as self-calls, the only way to register a key. After that
 * the passkey can do everything the account does, and the setup key is dropped.
 *
 * It stays Calibur's root key forever: Calibur treats the account's own
 * address as the root key, which cannot be revoked, and the same key could sign
 * a new EIP-7702 authorization. Whoever obtains it owns the account. It is
 * never written anywhere by this module; JavaScript cannot wipe it from
 * memory, only drop every reference to it (`discard()`).
 */
import { getAddress, isAddressEqual } from 'viem';
import {
  generatePrivateKey,
  privateKeyToAccount,
  toAccount,
} from 'viem/accounts';
import {
  entryPoint08Abi,
  getUserOperationHash,
  toSmartAccount,
} from 'viem/account-abstraction';
import {
  getChainId,
  getCode,
  getTransactionCount,
  readContract,
} from 'viem/actions';

import { caliburAbi } from './abi.js';
import {
  ROOT_STUB_SIGNATURE,
  decodeExecuteUserOpCallData,
  decodeKeySettings,
  encodeExecuteSignedBatchedCall,
  encodeExecuteUserOpCallData,
  encodeUserOperationSignature,
  getKeyHash,
  getRegisterKeyCalls,
  getSignedBatchedCallTypedData,
  normalizeCalls,
  toWebAuthnP256Key,
} from './calibur.js';
import {
  CALIBUR_ADDRESS,
  ENTRY_POINT_ADDRESS,
  ROOT_KEY_HASH,
} from './constants.js';

/**
 * @typedef {import('viem').Address} Address
 * @typedef {import('viem').Hex} Hex
 * @typedef {import('./calibur.js').Call} Call
 * @typedef {import('./calibur.js').KeySettings} KeySettings
 * @typedef {import('./calibur.js').P256PublicKey} P256PublicKey
 * @typedef {import('./account.js').AccountClient} AccountClient
 */

/**
 * Path (a)'s smart account: signed by the setup key, delegating under
 * EIP-7702.
 * @typedef {import('viem/account-abstraction').SmartAccount<
 *   import('viem/account-abstraction').SmartAccountImplementation<
 *     typeof entryPoint08Abi,
 *     '0.8',
 *     { abi: typeof caliburAbi, keyHash: Hex },
 *     true
 *   >
 * >} CaliburSetupAccount
 */

/**
 * What `createCaliburPasskeySetup` returns. The setup key is in none of its
 * fields.
 * @typedef {{
 *   readonly address: Address,
 *   readonly key: import('./calibur.js').Key,
 *   readonly keyHash: Hex,
 *   readonly implementation: Address,
 *   readonly calls: readonly { to: Address, value: bigint, data: Hex }[],
 *   readonly discarded: boolean,
 *   signAuthorization(parameters: { chainId: number, nonce: number }): Promise<import('viem').SignedAuthorization>,
 *   toSmartAccount(parameters: { client: AccountClient, nonceKeyManager?: import('viem').NonceManager | undefined }): Promise<CaliburSetupAccount>,
 *   sendUserOperation(bundlerClient: import('viem/account-abstraction').BundlerClient | { client?: AccountClient | undefined, sendUserOperation: Function }, parameters?: { client?: AccountClient | undefined, [key: string]: unknown }): Promise<Hex>,
 *   sendTransaction(walletClient: import('viem').WalletClient | { account?: { address: Address } | undefined, chain?: import('viem').Chain | undefined, sendTransaction: Function }, parameters?: { client?: AccountClient | undefined, executor?: Address | undefined, deadline?: bigint | undefined, gas?: bigint | undefined }): Promise<Hex>,
 *   isActive(client: AccountClient): Promise<boolean>,
 *   discard(): void,
 * }} CaliburPasskeySetup
 */

const EIP7702_DELEGATION_PREFIX = '0xef0100';

/**
 * Where an address's code delegates to under EIP-7702, if it does.
 * @param {Hex | undefined} code
 * @returns {Address | undefined}
 */
function readDelegation(code) {
  if (
    typeof code !== 'string' ||
    code.length !== 48 ||
    !code.toLowerCase().startsWith(EIP7702_DELEGATION_PREFIX)
  ) {
    return undefined;
  }
  return getAddress(`0x${code.slice(8)}`);
}

/**
 * The state of a Calibur account and one of its keys, read from the chain.
 * @param {{
 *   client: AccountClient,
 *   address: Address,
 *   keyHash: Hex,
 *   implementation?: Address | undefined,
 * }} parameters
 * @returns {Promise<{
 *   delegatedTo: Address | undefined,
 *   isCalibur: boolean,
 *   isRegistered: boolean,
 *   settings: { isAdmin: boolean, expiration: number, hook: Address } | undefined,
 * }>}
 */
export async function getCaliburKeyState({
  client,
  address,
  keyHash,
  implementation = CALIBUR_ADDRESS,
}) {
  const delegatedTo = readDelegation(await getCode(client, { address }));
  const isCalibur =
    !!delegatedTo && isAddressEqual(delegatedTo, implementation);
  if (!isCalibur) {
    return { delegatedTo, isCalibur, isRegistered: false, settings: undefined };
  }
  const isRegistered = await readContract(client, {
    address,
    abi: caliburAbi,
    functionName: 'isRegistered',
    args: [keyHash],
  });
  const settings = isRegistered
    ? decodeKeySettings(
        await readContract(client, {
          address,
          abi: caliburAbi,
          functionName: 'getKeySettings',
          args: [keyHash],
        })
      )
    : undefined;
  return { delegatedTo, isCalibur, isRegistered, settings };
}

/**
 * Prepare a Calibur account for a passkey.
 *
 * Returns the new account's address and the setup batch, and two ways to send
 * it; the setup key never leaves the returned object:
 *
 * - (a) `sendUserOperation(bundlerClient)` — a user operation carrying the
 *   EIP-7702 authorization, signed by the setup key, for a bundler (and a
 *   paymaster, so the new account needs no ETH).
 * - (b) `sendTransaction(walletClient)` — an EIP-7702 (type 4) transaction
 *   from a funded account, calling `execute(SignedBatchedCall, bytes)` with a
 *   batch the setup key signed.
 *
 * Wait until `isActive(client)` is true, then call `discard()`. Until the
 * passkey is registered the setup key is the only key of the account; discard
 * it earlier and nobody can use the address. Fund the account only once it is
 * active.
 *
 * @param {{
 *   descriptor: P256PublicKey,
 *   calls?: readonly Call[] | undefined,
 *   keySettings?: KeySettings | undefined,
 *   implementation?: Address | undefined,
 * }} parameters
 *   `descriptor` is the passkey (`getP256CredentialDescriptor`); `calls` run in
 *   the same batch after the registration, as the account (Zama delegations,
 *   say); `keySettings` default to `{ isAdmin: true }`.
 * @returns {CaliburPasskeySetup}
 */
export function createCaliburPasskeySetup(parameters) {
  const {
    descriptor,
    calls = [],
    keySettings = { isAdmin: true },
    implementation: implementationParameter = CALIBUR_ADDRESS,
  } = parameters ?? {};
  const implementation = getAddress(implementationParameter);
  const key = toWebAuthnP256Key(descriptor);
  const keyHash = getKeyHash(key);

  /** @type {import('viem/accounts').PrivateKeyAccount | undefined} */
  let owner = privateKeyToAccount(generatePrivateKey());
  const address = owner.address;

  const setupCalls = Object.freeze([
    ...getRegisterKeyCalls({ account: address, key, settings: keySettings }),
    ...normalizeCalls(calls),
  ]);

  /** @param {string} action */
  const useOwner = (action) => {
    if (!owner) {
      throw new Error(
        `The setup key was discarded; ${action} needs a new setup (and a new address)`
      );
    }
    return owner;
  };

  // What leaves this closure — viem's account.authorization.account, say — is
  // this forwarding account, never the key's own: after discard() it cannot
  // sign, however long the app keeps it.
  const signer = {
    /** @param {{ hash: Hex }} signParameters */
    sign: async (signParameters) => useOwner('signing').sign(signParameters),
    /** @param {import('viem').AuthorizationRequest} authorization */
    signAuthorization: async (authorization) =>
      useOwner('signing an authorization').signAuthorization(authorization),
    /** @param {import('viem').TypedDataDefinition} typedData */
    signTypedData: async (typedData) =>
      useOwner('signing typed data').signTypedData(typedData),
  };
  const forwardingAccount = toAccount({
    address,
    sign: signer.sign,
    signAuthorization: signer.signAuthorization,
    signMessage: async () => {
      throw new Error('The setup key signs no messages');
    },
    signTransaction: async () => {
      throw new Error('The setup key signs no transactions');
    },
    signTypedData: async () => {
      throw new Error('The setup key signs no typed data but its own batch');
    },
  });

  /**
   * @param {AccountClient} client
   * @param {number | undefined} chainId
   */
  const readChainId = async (client, chainId) =>
    chainId ?? client.chain?.id ?? (await getChainId(client));

  /**
   * The EOA's current nonce, as an authorization sent by another account
   * needs it.
   * @param {AccountClient} client
   */
  const readAuthorizationNonce = (client) =>
    getTransactionCount(client, { address, blockTag: 'pending' });

  const setup = {
    /** The account: the new EOA, delegated to Calibur. */
    address,
    /** The passkey as a Calibur key, and the hash it is registered under. */
    key,
    keyHash,
    implementation,
    /** register, update (unless default settings), then the extra calls. */
    calls: setupCalls,

    /** Whether `discard()` has dropped the setup key. */
    get discarded() {
      return !owner;
    },

    /**
     * The EIP-7702 authorization delegating the account to Calibur.
     * `nonce` is the EOA's transaction count when someone else sends the
     * transaction that carries it, as both paths here do.
     * @param {{ chainId: number, nonce: number }} authorizationParameters
     */
    async signAuthorization({ chainId, nonce }) {
      return signer.signAuthorization({
        address: implementation,
        chainId,
        nonce,
      });
    },

    /**
     * Path (a)'s account: a viem smart account signed by the setup key, with
     * the EIP-7702 `authorization` viem expects of a delegating account.
     * @param {{ client: AccountClient, nonceKeyManager?: import('viem').NonceManager | undefined }} accountParameters
     */
    async toSmartAccount({ client, nonceKeyManager }) {
      useOwner('building the setup account');
      const entryPoint = /** @type {const} */ ({
        abi: entryPoint08Abi,
        address: ENTRY_POINT_ADDRESS,
        version: '0.8',
      });
      return toSmartAccount({
        client,
        entryPoint,
        nonceKeyManager,
        authorization: {
          // viem types this as a PrivateKeyAccount; it only reads the address
          // and signs through it.
          account: /** @type {any} */ (forwardingAccount),
          address: implementation,
        },
        extend: { abi: caliburAbi, keyHash: ROOT_KEY_HASH },

        async decodeCalls(data) {
          return decodeExecuteUserOpCallData(data).calls;
        },

        async encodeCalls(accountCalls) {
          return encodeExecuteUserOpCallData(accountCalls);
        },

        async getAddress() {
          return address;
        },

        async getFactoryArgs() {
          return { factory: '0x7702', factoryData: '0x' };
        },

        async getStubSignature() {
          return encodeUserOperationSignature({
            keyHash: ROOT_KEY_HASH,
            signature: ROOT_STUB_SIGNATURE,
          });
        },

        async signMessage() {
          throw new Error('The setup account only signs its user operation');
        },

        async signTypedData() {
          throw new Error('The setup account only signs its user operation');
        },

        async signUserOperation(userOperationParameters) {
          const { chainId, ...userOperation } = userOperationParameters;
          // EntryPoint v0.8 hashes a 0x7702 initCode as the delegate address,
          // so the hash needs the authorization's address even before one is
          // signed.
          const authorization = userOperation.authorization ?? {
            address: implementation,
            chainId: 0,
            nonce: 0,
            r: '0x',
            s: '0x',
            yParity: 0,
          };
          const hash = getUserOperationHash({
            chainId: await readChainId(client, chainId),
            entryPointAddress: entryPoint.address,
            entryPointVersion: entryPoint.version,
            userOperation: { ...userOperation, authorization, sender: address },
          });
          const signature = await signer.sign({ hash });
          return encodeUserOperationSignature({
            keyHash: ROOT_KEY_HASH,
            signature,
          });
        },
      });
    },

    /**
     * Path (a): send the setup batch as a user operation that carries the
     * EIP-7702 authorization. `bundlerClient` is the app's, with its
     * paymaster if the new account holds no ETH; other parameters
     * (`paymaster`, `paymasterContext`, gas and fee fields) pass through to
     * viem's `sendUserOperation`. Resolves to the user operation hash.
     * @param {any} bundlerClient a viem bundler client
     * @param {{ client?: AccountClient | undefined } & Record<string, unknown>} [sendParameters]
     *   `client` reads chain state; defaults to `bundlerClient.client`.
     * @returns {Promise<Hex>}
     */
    async sendUserOperation(bundlerClient, sendParameters = {}) {
      const { client = bundlerClient?.client, ...rest } = sendParameters;
      if (!client) {
        throw new TypeError(
          'sendUserOperation needs a client for chain state, on the bundler client or as { client }'
        );
      }
      useOwner('sending the setup');
      const account = await setup.toSmartAccount({ client });
      const authorization = await setup.signAuthorization({
        chainId: await readChainId(client, undefined),
        nonce: await readAuthorizationNonce(client),
      });
      return bundlerClient.sendUserOperation({
        ...rest,
        account,
        calls: setupCalls,
        authorization,
      });
    },

    /**
     * Path (b): send the setup batch in an EIP-7702 transaction from
     * `walletClient`'s funded account. The setup key signs the authorization
     * and a `SignedBatchedCall` (key hash 0, the root key) that only
     * `executor` may submit — by default the sender. Resolves to the
     * transaction hash.
     * @param {any} walletClient a viem wallet client with an account
     * @param {{
     *   client?: AccountClient | undefined,
     *   executor?: Address | undefined,
     *   deadline?: bigint | undefined,
     *   gas?: bigint | undefined,
     * }} [sendParameters]
     *   `client` reads chain state (default: the wallet client);
     *   `deadline` is a unix time after which the batch is refused (0: none).
     * @returns {Promise<Hex>}
     */
    async sendTransaction(walletClient, sendParameters = {}) {
      const sender = walletClient?.account;
      if (!sender) {
        throw new TypeError(
          'sendTransaction needs a wallet client with an account'
        );
      }
      const { client = walletClient, deadline = 0n, gas } = sendParameters;
      const executor = getAddress(sendParameters.executor ?? sender.address);
      useOwner('sending the setup');
      const chainId = await readChainId(walletClient, undefined);
      const authorization = await setup.signAuthorization({
        chainId,
        nonce: await readAuthorizationNonce(client),
      });
      const signedBatchedCall = {
        batchedCall: { calls: setupCalls, revertOnFailure: true },
        // A fresh account's first nonce: key 0, sequence 0.
        nonce: 0n,
        keyHash: ROOT_KEY_HASH,
        executor,
        deadline,
      };
      const signature = await signer.signTypedData(
        getSignedBatchedCallTypedData({
          account: address,
          chainId,
          signedBatchedCall,
          implementation,
        })
      );
      return walletClient.sendTransaction({
        account: sender,
        chain: walletClient.chain,
        to: address,
        data: encodeExecuteSignedBatchedCall({ signedBatchedCall, signature }),
        authorizationList: [authorization],
        ...(gas === undefined ? {} : { gas }),
      });
    },

    /**
     * Whether the account is delegated to Calibur with the passkey registered
     * (as admin, if the settings asked for it) — the moment to `discard()`.
     * @param {AccountClient} client
     */
    async isActive(client) {
      const state = await getCaliburKeyState({
        client,
        address,
        keyHash,
        implementation,
      });
      return (
        state.isCalibur &&
        state.isRegistered &&
        (!keySettings.isAdmin || !!state.settings?.isAdmin)
      );
    },

    /**
     * Drop the setup key. Every later signing call throws.
     */
    discard() {
      owner = undefined;
    },
  };

  return /** @type {CaliburPasskeySetup} */ (Object.freeze(setup));
}

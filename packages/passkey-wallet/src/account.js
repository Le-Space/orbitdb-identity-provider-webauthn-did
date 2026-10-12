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
import { ENTRY_POINT_ADDRESS } from './constants.js';

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
 *   verificationGasLimit?: bigint | undefined,
 *   nonceKeyManager?: import('viem').NonceManager | undefined,
 *   sign?: ChallengeSigner | undefined,
 * }} parameters
 *   `client` reads chain state (nonce, chain id, code, the account's EIP-712
 *   domain); `address` is the Calibur account, the EOA the setup created;
 *   `verificationGasLimit` is the floor for user operations (default
 *   `DEFAULT_VERIFICATION_GAS_LIMIT`); `sign` replaces the passkey prompt,
 *   for a test or another signer of the same key.
 * @returns {Promise<CaliburPasskeyAccount>}
 */
export async function toCaliburPasskeyAccount(parameters) {
  const {
    client,
    address,
    descriptor: descriptorParameter,
    verificationGasLimit = DEFAULT_VERIFICATION_GAS_LIMIT,
    nonceKeyManager,
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
    const [, name, version, chainId, verifyingContract, salt] =
      await readContract(client, {
        address: account,
        abi: caliburAbi,
        functionName: 'eip712Domain',
      });
    return { name, version, chainId, verifyingContract, salt };
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
        const { chainId: chainIdParameter, ...userOperation } =
          userOperationParameters;
        const chainId =
          chainIdParameter ?? client.chain?.id ?? (await getChainId(client));
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

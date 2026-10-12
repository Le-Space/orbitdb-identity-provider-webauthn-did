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
export function toCaliburPasskeyAccount(parameters: {
  client: AccountClient;
  address: Address;
  descriptor: P256CredentialDescriptor;
  verificationGasLimit?: bigint | undefined;
  nonceKeyManager?: import('viem').NonceManager | undefined;
  sign?: ChallengeSigner | undefined;
}): Promise<CaliburPasskeyAccount>;
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
export const DEFAULT_VERIFICATION_GAS_LIMIT: 800000n;
/**
 * What signs a 32-byte challenge for the account: by default the passkey,
 * through `signP256Challenge` (one WebAuthn prompt, user verification
 * required). Anything that returns the same parts of a WebAuthn assertion for
 * the registered key will do.
 */
export type ChallengeSigner = (
  challenge: Uint8Array
) => Promise<import('./calibur.js').WebAuthnAuth>;
export type Address = import('viem').Address;
export type Hex = import('viem').Hex;
export type Key = import('./calibur.js').Key;
/**
 * What `getP256CredentialDescriptor` returns: the passkey's credential id, its
 * P-256 key as 32-byte coordinates, and the rpId it is registered under.
 */
export type P256CredentialDescriptor =
  import('@le-space/orbitdb-identity-provider-webauthn-did/standalone').P256CredentialDescriptor;
/**
 * The client a smart account reads chain state through; a public client will
 * do.
 */
export type AccountClient = import('viem').Client<
  import('viem').Transport,
  import('viem').Chain | undefined,
  import('viem').JsonRpcAccount | import('viem').LocalAccount | undefined
>;
/**
 * The smart account `toCaliburPasskeyAccount` returns: a viem SmartAccount for
 * EntryPoint v0.8, extended with Calibur's ABI, the passkey descriptor, its
 * Calibur key and key hash.
 */
export type CaliburPasskeyAccount =
  import('viem/account-abstraction').SmartAccount<
    import('viem/account-abstraction').SmartAccountImplementation<
      typeof entryPoint08Abi,
      '0.8',
      {
        abi: typeof caliburAbi;
        descriptor: P256CredentialDescriptor;
        key: Key;
        keyHash: Hex;
      }
    >
  >;
import { entryPoint08Abi } from 'viem/account-abstraction';
import { caliburAbi } from './abi.js';

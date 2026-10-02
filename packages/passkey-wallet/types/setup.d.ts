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
export function getCaliburKeyState({ client, address, keyHash, implementation, }: {
    client: AccountClient;
    address: Address;
    keyHash: Hex;
    implementation?: Address | undefined;
}): Promise<{
    delegatedTo: Address | undefined;
    isCalibur: boolean;
    isRegistered: boolean;
    settings: {
        isAdmin: boolean;
        expiration: number;
        hook: Address;
    } | undefined;
}>;
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
export function createCaliburPasskeySetup(parameters: {
    descriptor: P256PublicKey;
    calls?: readonly Call[] | undefined;
    keySettings?: KeySettings | undefined;
    implementation?: Address | undefined;
}): CaliburPasskeySetup;
export type Address = import("viem").Address;
export type Hex = import("viem").Hex;
export type Call = import("./calibur.js").Call;
export type KeySettings = import("./calibur.js").KeySettings;
export type P256PublicKey = import("./calibur.js").P256PublicKey;
export type AccountClient = import("./account.js").AccountClient;
/**
 * Path (a)'s smart account: signed by the setup key, delegating under
 * EIP-7702.
 */
export type CaliburSetupAccount = import("viem/account-abstraction").SmartAccount<import("viem/account-abstraction").SmartAccountImplementation<typeof entryPoint08Abi, "0.8", {
    abi: typeof caliburAbi;
    keyHash: Hex;
}, true>>;
/**
 * What `createCaliburPasskeySetup` returns. The setup key is in none of its
 * fields.
 */
export type CaliburPasskeySetup = {
    readonly address: Address;
    readonly key: import("./calibur.js").Key;
    readonly keyHash: Hex;
    readonly implementation: Address;
    readonly calls: readonly {
        to: Address;
        value: bigint;
        data: Hex;
    }[];
    readonly discarded: boolean;
    signAuthorization(parameters: {
        chainId: number;
        nonce: number;
    }): Promise<import("viem").SignedAuthorization>;
    toSmartAccount(parameters: {
        client: AccountClient;
        nonceKeyManager?: import("viem").NonceManager | undefined;
    }): Promise<CaliburSetupAccount>;
    sendUserOperation(bundlerClient: import("viem/account-abstraction").BundlerClient | {
        client?: AccountClient | undefined;
        sendUserOperation: Function;
    }, parameters?: {
        client?: AccountClient | undefined;
        [key: string]: unknown;
    }): Promise<Hex>;
    sendTransaction(walletClient: import("viem").WalletClient | {
        account?: {
            address: Address;
        } | undefined;
        chain?: import("viem").Chain | undefined;
        sendTransaction: Function;
    }, parameters?: {
        client?: AccountClient | undefined;
        executor?: Address | undefined;
        deadline?: bigint | undefined;
        gas?: bigint | undefined;
    }): Promise<Hex>;
    isActive(client: AccountClient): Promise<boolean>;
    discard(): void;
};
import { entryPoint08Abi } from 'viem/account-abstraction';
import { caliburAbi } from './abi.js';

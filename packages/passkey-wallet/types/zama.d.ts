/**
 * A new secp256k1 session key, in memory. `seal(sealingKey)` stores it.
 * @returns {ZamaSessionKey}
 */
export function createZamaSessionKey(): ZamaSessionKey;
/**
 * Open a sealed session key. Refuses a wrong sealing key, a changed address
 * and anything that is not a sealed session key.
 * @param {SealedZamaSessionKey} sealed
 * @param {SealingKey} sealingKey
 * @returns {Promise<ZamaSessionKey>}
 */
export function openZamaSessionKey(sealed: SealedZamaSessionKey, sealingKey: SealingKey): Promise<ZamaSessionKey>;
/**
 * The ACL for a chain: `acl` when given, else Zama's deployment.
 * @param {{ chainId?: number | undefined, acl?: Address | undefined }} parameters
 * @returns {Address}
 */
export function getZamaAclAddress({ chainId, acl }: {
    chainId?: number | undefined;
    acl?: Address | undefined;
}): Address;
/**
 * Calls to Zama's ACL that delegate user decryption to `delegate` — a session
 * key's address — for each contract, until `expirationDate` (unix seconds).
 * They have to run as the account, the delegator: batch them into the setup
 * (`createCaliburPasskeySetup({ calls })`) or send them as a passkey user
 * operation.
 *
 * Checked here, as ACL v0.4.0 checks on-chain: the delegate is neither the
 * account, a contract, nor the wildcard address; no contract is the account or
 * named twice; the expiration is a uint64. The ACL also refuses an expiration
 * not after the current block, an unchanged one, and a second delegation or
 * revocation of the same triple in one block. The wildcard address as a
 * contract delegates for every contract.
 * @param {{
 *   chainId?: number | undefined,
 *   acl?: Address | undefined,
 *   account?: Address | undefined,
 *   delegate: Address,
 *   contractAddresses: readonly Address[],
 *   expirationDate: bigint | number,
 * }} parameters
 * @returns {{ to: Address, value: bigint, data: Hex }[]}
 */
export function getDelegateForUserDecryptionCalls(parameters: {
    chainId?: number | undefined;
    acl?: Address | undefined;
    account?: Address | undefined;
    delegate: Address;
    contractAddresses: readonly Address[];
    expirationDate: bigint | number;
}): {
    to: Address;
    value: bigint;
    data: Hex;
}[];
/**
 * Calls to Zama's ACL that revoke `delegate`'s user decryption for each
 * contract. Run them as the account. The ACL refuses a revocation of a triple
 * that is not delegated, or that changed in the same block.
 * @param {{
 *   chainId?: number | undefined,
 *   acl?: Address | undefined,
 *   account?: Address | undefined,
 *   delegate: Address,
 *   contractAddresses: readonly Address[],
 * }} parameters
 * @returns {{ to: Address, value: bigint, data: Hex }[]}
 */
export function getRevokeDelegationForUserDecryptionCalls(parameters: {
    chainId?: number | undefined;
    acl?: Address | undefined;
    account?: Address | undefined;
    delegate: Address;
    contractAddresses: readonly Address[];
}): {
    to: Address;
    value: bigint;
    data: Hex;
}[];
export type Address = import("viem").Address;
export type Hex = import("viem").Hex;
/**
 * A session key: its address, and the key as a viem LocalAccount — the signer
 * for Zama's SDK (wrap it in a wallet client for `ViemSigner`).
 */
export type ZamaSessionKey = {
    address: Address;
    account: import("viem/accounts").PrivateKeyAccount;
    seal: (sealingKey: SealingKey) => Promise<SealedZamaSessionKey>;
};
/**
 * A caller-provided AES-GCM key: a 256-bit WebCrypto key with encrypt and
 * decrypt usages, or its 32 raw bytes.
 */
export type SealingKey = CryptoKey | Uint8Array;
/**
 * A session key sealed with AES-GCM; safe to store as JSON. The address is
 * bound to the ciphertext as associated data.
 */
export type SealedZamaSessionKey = {
    version: 1;
    algorithm: "AES-GCM";
    address: Address;
    iv: Hex;
    ciphertext: Hex;
};

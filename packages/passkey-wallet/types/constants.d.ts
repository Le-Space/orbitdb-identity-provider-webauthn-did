/**
 * Addresses and values this package is built against. Each is read from the
 * source named beside it, and the fork test checks the addresses on Sepolia.
 */
/**
 * Uniswap Calibur v1.0.0, deployed with CREATE2 (salt 0) at the same address on
 * Ethereum mainnet and Sepolia. Its runtime code on both chains is the
 * `CaliburEntry` contract compiled from the v1.0.0 tag (commit 35d8091), apart
 * from its three immutables: keccak256("Calibur"), keccak256("1.0.0") and this
 * address.
 * @type {import('viem').Address}
 */
export const CALIBUR_ADDRESS: import("viem").Address;
/** The version string in Calibur's EIP-712 domain. */
export const CALIBUR_VERSION: "1.0.0";
/**
 * ERC-4337 EntryPoint v0.8, the one Calibur accepts by default
 * (`Static.ENTRY_POINT_V_0_8`).
 * @type {import('viem').Address}
 */
export const ENTRY_POINT_ADDRESS: import("viem").Address;
/**
 * Calibur's `KeyType` enum (KeyLib.sol). A passkey is `WebAuthnP256`.
 */
export const KeyType: Readonly<{
    P256: 0;
    WebAuthnP256: 1;
    Secp256k1: 2;
}>;
/**
 * The key hash Calibur uses for the account's own secp256k1 key — the EOA key
 * that signed the EIP-7702 authorization (`KeyLib.ROOT_KEY_HASH`).
 * @type {import('viem').Hex}
 */
export const ROOT_KEY_HASH: import("viem").Hex;
/**
 * The address Zama's ACL treats as "every contract" in a user-decryption
 * delegation (`ACL.WILDCARD_DELEGATION_ADDRESS`, ACL v0.4.0). It may be the
 * contract of a delegation, never its delegate.
 * @type {import('viem').Address}
 */
export const ZAMA_WILDCARD_CONTRACT_ADDRESS: import("viem").Address;
/**
 * Zama's ACL contract per chain id, from `ZamaConfig` in
 * `@fhevm/solidity@0.11.1` (config/ZamaConfig.sol, `_getSepoliaConfig` and
 * `_getEthereumConfig`). Both answer `getVersion()` with "ACL v0.4.0" as of
 * 2026-09-16; 0.11.1 still calls the mainnet values placeholders, so check
 * Zama's documentation before relying on chain 1.
 * @type {Readonly<Record<number, import('viem').Address>>}
 */
export const ZAMA_ACL_ADDRESSES: Readonly<Record<number, import("viem").Address>>;

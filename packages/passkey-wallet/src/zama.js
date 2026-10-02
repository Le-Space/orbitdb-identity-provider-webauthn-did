/**
 * Read keys for Zama user decryption.
 *
 * Zama's relayer decrypts a handle for whoever signs the EIP-712 request, if
 * the ACL lets that address see it. A smart account cannot sign that request
 * with a plain ECDSA key, and a passkey prompt per decryption is too many
 * prompts. So the account delegates user decryption to a session key — an
 * ordinary secp256k1 key — per contract and until an expiry, with the ACL's
 * `delegateForUserDecryption`; the session key then signs as the delegate.
 *
 * The session key lives in memory, or sealed (AES-GCM) under a key the caller
 * provides, such as one derived from the passkey's PRF output.
 */
import {
  bytesToHex,
  encodeFunctionData,
  getAddress,
  hexToBytes,
  isAddress,
  isAddressEqual,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';

import { zamaAclAbi } from './abi.js';
import {
  ZAMA_ACL_ADDRESSES,
  ZAMA_WILDCARD_CONTRACT_ADDRESS,
} from './constants.js';

/**
 * @typedef {import('viem').Address} Address
 * @typedef {import('viem').Hex} Hex
 */

/**
 * A session key: its address, and the key as a viem LocalAccount — the signer
 * for Zama's SDK (wrap it in a wallet client for `ViemSigner`).
 * @typedef {{
 *   address: Address,
 *   account: import('viem/accounts').PrivateKeyAccount,
 *   seal: (sealingKey: SealingKey) => Promise<SealedZamaSessionKey>,
 * }} ZamaSessionKey
 */

/**
 * A caller-provided AES-GCM key: a 256-bit WebCrypto key with encrypt and
 * decrypt usages, or its 32 raw bytes.
 * @typedef {CryptoKey | Uint8Array} SealingKey
 */

/**
 * A session key sealed with AES-GCM; safe to store as JSON. The address is
 * bound to the ciphertext as associated data.
 * @typedef {{
 *   version: 1,
 *   algorithm: 'AES-GCM',
 *   address: Address,
 *   iv: Hex,
 *   ciphertext: Hex,
 * }} SealedZamaSessionKey
 */

const SEALED_VERSION = 1;
const UINT64_MAX = (1n << 64n) - 1n;
const encoder = new TextEncoder();

/** @param {Address} address */
function associatedData(address) {
  return encoder.encode(
    `@le-space/passkey-wallet:zama-session-key:v${SEALED_VERSION}:${getAddress(address)}`
  );
}

/**
 * @param {SealingKey} sealingKey
 * @returns {Promise<CryptoKey>}
 */
async function readSealingKey(sealingKey) {
  if (sealingKey instanceof Uint8Array) {
    if (sealingKey.length !== 32) {
      throw new TypeError('A raw sealing key must be 32 bytes');
    }
    return crypto.subtle.importKey(
      'raw',
      new Uint8Array(sealingKey),
      'AES-GCM',
      false,
      ['encrypt', 'decrypt']
    );
  }
  const key = /** @type {CryptoKey} */ (sealingKey);
  if (
    !key ||
    typeof key !== 'object' ||
    key.type !== 'secret' ||
    key.algorithm?.name !== 'AES-GCM'
  ) {
    throw new TypeError(
      'The sealing key must be an AES-GCM CryptoKey or 32 raw bytes'
    );
  }
  return key;
}

/**
 * @param {Hex} privateKey
 * @returns {ZamaSessionKey}
 */
function toSessionKey(privateKey) {
  const account = privateKeyToAccount(privateKey);
  return Object.freeze({
    address: account.address,
    account,
    /**
     * Seal the session key under `sealingKey` for storage.
     * @param {SealingKey} sealingKey
     * @returns {Promise<SealedZamaSessionKey>}
     */
    async seal(sealingKey) {
      const key = await readSealingKey(sealingKey);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: associatedData(account.address),
        },
        key,
        new Uint8Array(hexToBytes(privateKey))
      );
      return {
        version: SEALED_VERSION,
        algorithm: 'AES-GCM',
        address: account.address,
        iv: bytesToHex(iv),
        ciphertext: bytesToHex(new Uint8Array(ciphertext)),
      };
    },
  });
}

/**
 * A new secp256k1 session key, in memory. `seal(sealingKey)` stores it.
 * @returns {ZamaSessionKey}
 */
export function createZamaSessionKey() {
  return toSessionKey(generatePrivateKey());
}

/**
 * Open a sealed session key. Refuses a wrong sealing key, a changed address
 * and anything that is not a sealed session key.
 * @param {SealedZamaSessionKey} sealed
 * @param {SealingKey} sealingKey
 * @returns {Promise<ZamaSessionKey>}
 */
export async function openZamaSessionKey(sealed, sealingKey) {
  if (
    !sealed ||
    typeof sealed !== 'object' ||
    sealed.version !== SEALED_VERSION ||
    sealed.algorithm !== 'AES-GCM' ||
    typeof sealed.address !== 'string' ||
    !isAddress(sealed.address, { strict: false }) ||
    typeof sealed.iv !== 'string' ||
    typeof sealed.ciphertext !== 'string'
  ) {
    throw new TypeError('Not a sealed Zama session key');
  }
  const key = await readSealingKey(sealingKey);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(hexToBytes(/** @type {Hex} */ (sealed.iv))),
        additionalData: associatedData(sealed.address),
      },
      key,
      new Uint8Array(hexToBytes(/** @type {Hex} */ (sealed.ciphertext)))
    );
  } catch (error) {
    throw new Error(
      'The session key does not open with this sealing key, or was altered',
      { cause: error }
    );
  }
  const sessionKey = toSessionKey(bytesToHex(new Uint8Array(plaintext)));
  if (!isAddressEqual(sessionKey.address, sealed.address)) {
    throw new Error('The sealed session key is not the address it names');
  }
  return sessionKey;
}

/**
 * The ACL for a chain: `acl` when given, else Zama's deployment.
 * @param {{ chainId?: number | undefined, acl?: Address | undefined }} parameters
 * @returns {Address}
 */
export function getZamaAclAddress({ chainId, acl }) {
  if (acl !== undefined) {
    if (!isAddress(acl, { strict: false })) {
      throw new TypeError('acl must be an address');
    }
    return getAddress(acl);
  }
  const address =
    chainId === undefined ? undefined : ZAMA_ACL_ADDRESSES[chainId];
  if (!address) {
    throw new Error(
      `No Zama ACL is known for chain ${chainId}; pass { acl } explicitly`
    );
  }
  return address;
}

/**
 * @param {{
 *   delegate: Address,
 *   contractAddresses: readonly Address[],
 *   account?: Address | undefined,
 * }} parameters
 */
function readDelegation({ delegate, contractAddresses, account }) {
  if (typeof delegate !== 'string' || !isAddress(delegate, { strict: false })) {
    throw new TypeError('delegate must be an address');
  }
  const delegateAddress = getAddress(delegate);
  if (isAddressEqual(delegateAddress, ZAMA_WILDCARD_CONTRACT_ADDRESS)) {
    throw new RangeError('The wildcard address cannot be a delegate');
  }
  const accountAddress =
    account === undefined ? undefined : getAddress(account);
  if (accountAddress && isAddressEqual(accountAddress, delegateAddress)) {
    throw new RangeError('The account cannot delegate to itself');
  }
  if (!Array.isArray(contractAddresses) || contractAddresses.length === 0) {
    throw new TypeError('contractAddresses must name at least one contract');
  }
  const contracts = contractAddresses.map((contract, index) => {
    if (
      typeof contract !== 'string' ||
      !isAddress(contract, { strict: false })
    ) {
      throw new TypeError(`contractAddresses[${index}] must be an address`);
    }
    const address = getAddress(contract);
    if (isAddressEqual(address, delegateAddress)) {
      throw new RangeError('The delegate cannot be one of the contracts');
    }
    if (accountAddress && isAddressEqual(address, accountAddress)) {
      throw new RangeError('The account cannot be one of the contracts');
    }
    return address;
  });
  // The ACL refuses a second change to one (account, delegate, contract) in a
  // block, so a batch naming a contract twice would revert as a whole.
  if (new Set(contracts).size !== contracts.length) {
    throw new RangeError('contractAddresses names a contract twice');
  }
  return { delegate: delegateAddress, contracts };
}

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
export function getDelegateForUserDecryptionCalls(parameters) {
  const { expirationDate } = parameters;
  const to = getZamaAclAddress(parameters);
  const { delegate, contracts } = readDelegation(parameters);
  if (
    (typeof expirationDate !== 'bigint' &&
      !Number.isSafeInteger(expirationDate)) ||
    BigInt(expirationDate) <= 0n ||
    BigInt(expirationDate) > UINT64_MAX
  ) {
    throw new RangeError(
      'expirationDate must be a positive uint64 (unix seconds)'
    );
  }
  return contracts.map((contract) => ({
    to,
    value: 0n,
    data: encodeFunctionData({
      abi: zamaAclAbi,
      functionName: 'delegateForUserDecryption',
      args: [delegate, contract, BigInt(expirationDate)],
    }),
  }));
}

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
export function getRevokeDelegationForUserDecryptionCalls(parameters) {
  const to = getZamaAclAddress(parameters);
  const { delegate, contracts } = readDelegation(parameters);
  return contracts.map((contract) => ({
    to,
    value: 0n,
    data: encodeFunctionData({
      abi: zamaAclAbi,
      functionName: 'revokeDelegationForUserDecryption',
      args: [delegate, contract],
    }),
  }));
}

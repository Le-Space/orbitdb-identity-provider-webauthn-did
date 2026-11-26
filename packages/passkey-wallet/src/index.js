/**
 * @le-space/passkey-wallet
 *
 * A passkey — the same one that can be an OrbitDB identity through
 * @le-space/orbitdb-identity-provider-webauthn-did — as the admin key of a
 * Uniswap Calibur v1.0.0 account (EIP-7702, ERC-4337 EntryPoint v0.8), and
 * session keys for Zama user decryption.
 */
export { caliburAbi, zamaAclAbi } from './abi.js';
export {
  CALIBUR_ADDRESS,
  CALIBUR_VERSION,
  ENTRY_POINT_ADDRESS,
  KeyType,
  ROOT_KEY_HASH,
  ZAMA_ACL_ADDRESSES,
  ZAMA_WILDCARD_CONTRACT_ADDRESS,
} from './constants.js';
export {
  EXECUTE_USER_OP_SELECTOR,
  ROOT_STUB_SIGNATURE,
  decodeExecuteUserOpCallData,
  decodeKeySettings,
  decodeUserOperationSignature,
  decodeWebAuthnAuth,
  encodeExecuteSignedBatchedCall,
  encodeExecuteUserOpCallData,
  encodeKeySettings,
  encodeTypedDataSignSignature,
  encodeTypedDataType,
  encodeUserOperationSignature,
  encodeWebAuthnAuth,
  encodeWrappedSignature,
  getAccountDomainSeparator,
  getCaliburStubSignature,
  getKeyHash,
  getPersonalSignNestedDigest,
  getRegisterKeyCalls,
  getRevokeKeyCall,
  getSignedBatchedCallTypedData,
  getTypedDataSignDigests,
  normalizeCalls,
  toWebAuthnP256Key,
} from './calibur.js';
export {
  AccountDomainMismatchError,
  DEFAULT_USER_OPERATION_GAS_CEILINGS,
  DEFAULT_VERIFICATION_GAS_LIMIT,
  PRE_VERIFICATION_GAS_CEILINGS,
  SINGLE_NONCE_KEY,
  getDefaultGasCeilings,
  toCaliburPasskeyAccount,
  UserOperationLimitError,
} from './account.js';
export {
  sendUserOperationWithRetry,
  UserOperationNonceUsedError,
  UserOperationNotIncludedError,
} from './send.js';
export { createCaliburPasskeySetup, getCaliburKeyState } from './setup.js';
export { createCaliburBundlerClient } from './bundler.js';
export {
  createZamaSessionKey,
  getDelegateForUserDecryptionCalls,
  getRevokeDelegationForUserDecryptionCalls,
  getZamaAclAddress,
  openZamaSessionKey,
} from './zama.js';

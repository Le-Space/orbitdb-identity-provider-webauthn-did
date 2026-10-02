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
  encodeUserOperationSignature,
  encodeWebAuthnAuth,
  encodeWrappedSignature,
  getCaliburStubSignature,
  getKeyHash,
  getRegisterKeyCalls,
  getRevokeKeyCall,
  getSignedBatchedCallTypedData,
  normalizeCalls,
  toWebAuthnP256Key,
} from './calibur.js';
export {
  DEFAULT_VERIFICATION_GAS_LIMIT,
  toCaliburPasskeyAccount,
} from './account.js';
export { createCaliburPasskeySetup, getCaliburKeyState } from './setup.js';
export { createCaliburBundlerClient } from './bundler.js';
export {
  createZamaSessionKey,
  getDelegateForUserDecryptionCalls,
  getRevokeDelegationForUserDecryptionCalls,
  getZamaAclAddress,
  openZamaSessionKey,
} from './zama.js';

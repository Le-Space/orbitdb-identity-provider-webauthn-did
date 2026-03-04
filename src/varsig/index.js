/**
 * WebAuthn varsig public exports.
 */
export { WebAuthnVarsigProvider } from './provider.js';
export {
  createWebAuthnVarsigIdentity,
  createWebAuthnVarsigIdentities,
  encodeIdentityValue,
  decodeVarsigIdentityFromBytes,
  verifyVarsigIdentity,
  createIpfsIdentityStorage,
  wrapWithVarsigVerification,
} from './identity.js';
export { DEFAULT_DOMAIN_LABELS } from './domain.js';
export {
  storeWebAuthnVarsigCredential,
  loadWebAuthnVarsigCredential,
  clearWebAuthnVarsigCredential,
} from './storage.js';

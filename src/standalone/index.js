/**
 * Standalone WebAuthn toolkit exports.
 *
 * These APIs are designed to be consumed without OrbitDB provider wiring.
 */
export {
  StandaloneWebAuthnVarsigSigner,
  WebAuthnEd25519Signer,
  WebAuthnP256Signer,
  createWebAuthnSigner,
  createWebAuthnEd25519Credential,
  createWebAuthnEd25519Signer,
  createWebAuthnP256Signer,
  checkEd25519Support
} from './webauthn/signers.js';

export {
  WebAuthnHardwareSignerService,
  getStoredWebAuthnHardwareSignerInfo
} from './webauthn/hardware-service.js';

export {
  storeWebAuthnCredentialSafe,
  loadWebAuthnCredentialSafe,
  clearWebAuthnCredentialSafe,
  extractPrfSeedFromCredential
} from './webauthn/credential.js';

export {
  createWorkerKeystoreClient,
  isWorkerKeystoreAvailable,
  createEd25519DidFromPublicKey,
  getDefaultWorkerKeystoreClient,
  resetDefaultWorkerKeystoreClient,
  initEd25519KeystoreWithPrfSeed,
  generateWorkerEd25519DID,
  loadWorkerEd25519Archive,
  keystoreEncrypt,
  keystoreDecrypt,
  keystoreSign,
  keystoreVerify,
  encryptArchive,
  decryptArchive
} from './worker/client.js';

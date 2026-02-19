import {
  clearWebAuthnVarsigCredential,
  loadWebAuthnVarsigCredential,
  storeWebAuthnVarsigCredential
} from '../../varsig/storage.js';
import { StandaloneWebAuthnVarsigSigner, createWebAuthnSigner } from './signers.js';

const DEFAULT_STORAGE_KEY = 'webauthn_ed25519_hardware_signer';

/**
 * Read persisted hardware signer identity metadata without creating a signer instance.
 * @param {string} [key]
 * @returns {{did: string, algorithm: 'Ed25519'|'P-256'}|null}
 */
export function getStoredWebAuthnHardwareSignerInfo(key = DEFAULT_STORAGE_KEY) {
  const credential = loadWebAuthnVarsigCredential(key);
  if (!credential?.did) return null;
  return {
    did: credential.did,
    algorithm: credential.algorithm === 'P-256' ? 'P-256' : 'Ed25519'
  };
}

/**
 * Standalone hardware signer service.
 * Keeps creation/storage/loading concerns separate from app-specific UCAN logic.
 */
export class WebAuthnHardwareSignerService {
  constructor({ storageKey = DEFAULT_STORAGE_KEY } = {}) {
    this.storageKey = storageKey;
    this.signer = null;
  }

  /**
   * Create a new signer or load existing signer from storage.
   * @param {Object} [options]
   * @returns {Promise<StandaloneWebAuthnVarsigSigner>}
   */
  async initialize(options = {}) {
    const loaded = this.load();
    if (loaded) return loaded;

    const created = await createWebAuthnSigner(options);
    this.store(created);
    this.signer = created;
    return created;
  }

  /**
   * Load signer from persisted credential.
   * @returns {StandaloneWebAuthnVarsigSigner|null}
   */
  load() {
    const credential = loadWebAuthnVarsigCredential(this.storageKey);
    if (!credential) return null;
    this.signer = new StandaloneWebAuthnVarsigSigner(credential);
    return this.signer;
  }

  /**
   * Persist signer credential data.
   * @param {StandaloneWebAuthnVarsigSigner} signer
   */
  store(signer) {
    storeWebAuthnVarsigCredential(signer.credential, this.storageKey);
  }

  /**
   * Remove signer credential data from storage and reset local instance.
   */
  clear() {
    clearWebAuthnVarsigCredential(this.storageKey);
    this.signer = null;
  }

  /**
   * @returns {StandaloneWebAuthnVarsigSigner|null}
   */
  getSigner() {
    return this.signer;
  }

  /**
   * @returns {string|null}
   */
  getDID() {
    return this.signer?.did || null;
  }

  /**
   * @returns {'Ed25519'|'P-256'|null}
   */
  getAlgorithm() {
    return this.signer?.algorithm || null;
  }
}

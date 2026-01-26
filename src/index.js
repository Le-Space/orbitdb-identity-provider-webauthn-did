/**
 * WebAuthn DID Provider for OrbitDB
 *
 * Creates hardware-secured DIDs using WebAuthn authentication (Passkey, Yubikey, Ledger, etc.)
 * Integrates with OrbitDB's identity system while keeping private keys in secure hardware
 */

import { useIdentityProvider } from '@orbitdb/core';
import * as KeystoreEncryption from './keystore/encryption.js';
import { WebAuthnDIDProvider } from './webauthn/provider.js';
import {
  OrbitDBWebAuthnIdentityProvider,
  OrbitDBWebAuthnIdentityProviderFunction
} from './keystore/provider.js';
import {
  WebAuthnVarsigProvider,
  createWebAuthnVarsigIdentity,
  createWebAuthnVarsigIdentities,
  storeWebAuthnVarsigCredential,
  loadWebAuthnVarsigCredential,
  clearWebAuthnVarsigCredential
} from './varsig/index.js';

export {
  WebAuthnDIDProvider,
  OrbitDBWebAuthnIdentityProvider,
  OrbitDBWebAuthnIdentityProviderFunction
};

/**
 * Register WebAuthn identity provider with OrbitDB
 * @returns {boolean} True if registration succeeded.
 */
export function registerWebAuthnProvider() {
  try {
    useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
    return true;
  } catch (error) {
    console.error('Failed to register WebAuthn provider:', error);
    return false;
  }
}

/**
 * Check WebAuthn support and provide user-friendly messages
 * @returns {Promise<Object>} Support status and message.
 */
export async function checkWebAuthnSupport() {
  const support = {
    supported: false,
    platformAuthenticator: false,
    error: null,
    message: ''
  };

  try {
    // Check basic WebAuthn support
    if (!WebAuthnDIDProvider.isSupported()) {
      support.error = 'WebAuthn is not supported in this browser';
      support.message = 'Please use a modern browser that supports WebAuthn (Chrome 67+, Firefox 60+, Safari 14+)';
      return support;
    }

    support.supported = true;

    // Check platform authenticator availability
    support.platformAuthenticator = await WebAuthnDIDProvider.isPlatformAuthenticatorAvailable();

    if (support.platformAuthenticator) {
      support.message = 'WebAuthn is fully supported! You can use Face ID, Touch ID, or Windows Hello for secure authentication.';
    } else {
      support.message = 'WebAuthn is supported, but no biometric authenticator was detected. You may need to use a security key.';
    }

  } catch (error) {
    support.error = `WebAuthn support check failed: ${error.message}`;
    support.message = 'Unable to determine WebAuthn support. Please check your browser settings.';
  }

  return support;
}

/**
 * Store WebAuthn credential to localStorage with proper serialization
 * @param {Object} credential - The WebAuthn credential object
 * @param {string} key - The localStorage key (defaults to 'webauthn-credential')
 */
export function storeWebAuthnCredential(credential, key = 'webauthn-credential') {
  try {
    const serializedCredential = {
      ...credential,
      rawCredentialId: Array.from(credential.rawCredentialId),
      attestationObject: Array.from(credential.attestationObject),
      prfInput: credential.prfInput ? Array.from(credential.prfInput) : undefined,
      publicKey: {
        ...credential.publicKey,
        x: Array.from(credential.publicKey.x),
        y: Array.from(credential.publicKey.y)
      }
    };
    localStorage.setItem(key, JSON.stringify(serializedCredential));
  } catch (error) {
    console.error('Failed to store WebAuthn credential:', error);
    throw new Error(`Failed to store WebAuthn credential: ${error.message}`);
  }
}

/**
 * Load WebAuthn credential from localStorage with proper deserialization
 * @param {string} key - The localStorage key (defaults to 'webauthn-credential')
 * @returns {Object|null} The deserialized credential object or null if not found
 */
export function loadWebAuthnCredential(key = 'webauthn-credential') {
  try {
    const storedCredential = localStorage.getItem(key);
    if (storedCredential) {
      const parsed = JSON.parse(storedCredential);
      return {
        ...parsed,
        rawCredentialId: new Uint8Array(parsed.rawCredentialId),
        attestationObject: new Uint8Array(parsed.attestationObject),
        prfInput: parsed.prfInput ? new Uint8Array(parsed.prfInput) : undefined,
        publicKey: {
          ...parsed.publicKey,
          x: new Uint8Array(parsed.publicKey.x),
          y: new Uint8Array(parsed.publicKey.y)
        }
      };
    }
  } catch (error) {
    console.warn('Failed to load WebAuthn credential from localStorage:', error);
    localStorage.removeItem(key);
  }
  return null;
}

/**
 * Clear WebAuthn credential from localStorage
 * @param {string} key - The localStorage key (defaults to 'webauthn-credential')
 */
export function clearWebAuthnCredential(key = 'webauthn-credential') {
  try {
    localStorage.removeItem(key);
  } catch (error) {
    console.warn('Failed to clear WebAuthn credential:', error);
  }
}

// Import verification utilities
import * as VerificationUtils from './verification.js';

export {
  // Verification utilities
  VerificationUtils,
  // Keystore encryption utilities
  KeystoreEncryption,
};

export {
  WebAuthnVarsigProvider,
  createWebAuthnVarsigIdentity,
  createWebAuthnVarsigIdentities,
  storeWebAuthnVarsigCredential,
  loadWebAuthnVarsigCredential,
  clearWebAuthnVarsigCredential
} from './varsig/index.js';

// Re-export individual verification functions for convenience
export {
  verifyDatabaseUpdate,
  verifyIdentityStorage,
  verifyDataEntries,
  isValidWebAuthnDID,
  extractWebAuthnDIDSuffix,
  compareWebAuthnDIDs,
  createVerificationResult
} from './verification.js';

// Re-export individual keystore encryption functions for convenience
export {
  generateSecretKey,
  encryptWithAESGCM,
  decryptWithAESGCM,
  addLargeBlobToCredentialOptions,
  addPRFToCredentialOptions,
  retrieveSKFromLargeBlob,
  addHmacSecretToCredentialOptions,
  wrapSKWithPRF,
  unwrapSKWithPRF,
  wrapSKWithHmacSecret,
  unwrapSKWithHmacSecret,
  storeEncryptedKeystore,
  loadEncryptedKeystore,
  clearEncryptedKeystore,
  checkExtensionSupport
} from './keystore/encryption.js';

export default {
  WebAuthnDIDProvider,
  OrbitDBWebAuthnIdentityProvider,
  OrbitDBWebAuthnIdentityProviderFunction,
  registerWebAuthnProvider,
  checkWebAuthnSupport,
  storeWebAuthnCredential,
  loadWebAuthnCredential,
  clearWebAuthnCredential,
  WebAuthnVarsigProvider,
  createWebAuthnVarsigIdentity,
  createWebAuthnVarsigIdentities,
  storeWebAuthnVarsigCredential,
  loadWebAuthnVarsigCredential,
  clearWebAuthnVarsigCredential,
  // Include verification utilities in default export
  VerificationUtils
};

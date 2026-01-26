/**
 * Keystore Encryption Utilities
 *
 * Provides AES-GCM encryption for OrbitDB keystore private keys,
 * protected by WebAuthn credentials using largeBlob or hmac-secret extensions.
 */

import { logger } from '@libp2p/logger';

const log = logger('orbitdb-identity-provider-webauthn-did:keystore-encryption');

/**
 * Generate a random AES-GCM secret key (256-bit)
 * @returns {Uint8Array} Secret key bytes.
 */
export function generateSecretKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Encrypt data with AES-GCM
 * @param {Uint8Array} data - Data to encrypt
 * @param {Uint8Array} sk - Secret key (32 bytes)
 * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array}>}
 */
export async function encryptWithAESGCM(data, sk) {
  log('Encrypting data with AES-GCM');

  // Generate random IV (12 bytes for GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Import secret key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    sk,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    data
  );

  log('Encryption successful, ciphertext length: %d', ciphertext.byteLength);

  return {
    ciphertext: new Uint8Array(ciphertext),
    iv
  };
}

/**
 * Decrypt data with AES-GCM
 * @param {Uint8Array} ciphertext - Encrypted data
 * @param {Uint8Array} sk - Secret key (32 bytes)
 * @param {Uint8Array} iv - Initialization vector
 * @returns {Promise<Uint8Array>}
 */
export async function decryptWithAESGCM(ciphertext, sk, iv) {
  log('Decrypting data with AES-GCM');

  try {
    // Import secret key
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      sk,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Decrypt
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      ciphertext
    );

    log('Decryption successful, plaintext length: %d', plaintext.byteLength);

    return new Uint8Array(plaintext);
  } catch (error) {
    log.error('Decryption failed: %s', error.message);
    throw new Error(`Failed to decrypt data: ${error.message}`);
  }
}

/**
 * Store secret key in WebAuthn credential using largeBlob extension
 * @param {Object} credentialOptions - WebAuthn credential creation options
 * @param {Uint8Array} sk - Secret key to store
 * @returns {Promise<Object>} Enhanced credential options with largeBlob
 */
export function addLargeBlobToCredentialOptions(credentialOptions, sk) {
  log('Adding largeBlob extension to credential options');

  return {
    ...credentialOptions,
    extensions: {
      ...credentialOptions.extensions,
      largeBlob: {
        support: 'required',
        write: sk
      }
    }
  };
}

/**
 * Retrieve secret key from WebAuthn credential using largeBlob extension
 * @param {Uint8Array} credentialId - WebAuthn credential ID
 * @param {string} rpId - Relying party ID (domain)
 * @returns {Promise<Uint8Array>} Secret key
 */
export async function retrieveSKFromLargeBlob(credentialId, rpId) {
  log('Retrieving secret key from largeBlob');

  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{
          id: credentialId,
          type: 'public-key'
        }],
        rpId: rpId,
        userVerification: 'required',
        extensions: {
          largeBlob: {
            read: true
          }
        }
      }
    });

    const extensions = assertion.getClientExtensionResults();

    if (!extensions.largeBlob || !extensions.largeBlob.blob) {
      throw new Error('No largeBlob data found in credential');
    }

    const sk = new Uint8Array(extensions.largeBlob.blob);
    log('Retrieved secret key from largeBlob, length: %d', sk.length);

    return sk;
  } catch (error) {
    log.error('Failed to retrieve secret key from largeBlob: %s', error.message);
    throw new Error(`Failed to retrieve secret key: ${error.message}`);
  }
}

/**
 * Add hmac-secret extension to credential options
 * @param {Object} credentialOptions - WebAuthn credential creation options
 * @returns {Object} Enhanced credential options with hmac-secret
 */
export function addHmacSecretToCredentialOptions(credentialOptions) {
  log('Adding hmac-secret extension to credential options');

  return {
    ...credentialOptions,
    extensions: {
      ...credentialOptions.extensions,
      hmacCreateSecret: true
    }
  };
}

/**
 * Wrap secret key using hmac-secret extension
 * @param {Uint8Array} credentialId - WebAuthn credential ID
 * @param {Uint8Array} sk - Secret key to wrap
 * @param {string} rpId - Relying party ID (domain)
 * @returns {Promise<{wrappedSK: Uint8Array, salt: Uint8Array}>}
 */
export async function wrapSKWithHmacSecret(credentialId, sk, rpId) {
  log('Wrapping secret key with hmac-secret');

  const salt = crypto.getRandomValues(new Uint8Array(32));

  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{
          id: credentialId,
          type: 'public-key'
        }],
        rpId: rpId,
        userVerification: 'required',
        extensions: {
          hmacGetSecret: {
            salt1: salt
          }
        }
      }
    });

    const extensions = assertion.getClientExtensionResults();

    if (!extensions.hmacGetSecret || !extensions.hmacGetSecret.output1) {
      throw new Error('No hmac-secret output from credential');
    }

    const hmacOutput = new Uint8Array(extensions.hmacGetSecret.output1);

    // Use HMAC output as wrapping key
    const wrappedSK = await encryptWithAESGCM(sk, hmacOutput.slice(0, 32));

    log('Secret key wrapped with hmac-secret');

    return {
      wrappedSK: wrappedSK.ciphertext,
      wrappingIV: wrappedSK.iv,
      salt
    };
  } catch (error) {
    log.error('Failed to wrap secret key with hmac-secret: %s', error.message);
    throw new Error(`Failed to wrap secret key: ${error.message}`);
  }
}

/**
 * Unwrap secret key using hmac-secret extension
 * @param {Uint8Array} credentialId - WebAuthn credential ID
 * @param {Uint8Array} wrappedSK - Wrapped secret key
 * @param {Uint8Array} wrappingIV - IV used for wrapping
 * @param {Uint8Array} salt - Salt used for HMAC
 * @param {string} rpId - Relying party ID (domain)
 * @returns {Promise<Uint8Array>} Unwrapped secret key
 */
export async function unwrapSKWithHmacSecret(credentialId, wrappedSK, wrappingIV, salt, rpId) {
  log('Unwrapping secret key with hmac-secret');

  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{
          id: credentialId,
          type: 'public-key'
        }],
        rpId: rpId,
        userVerification: 'required',
        extensions: {
          hmacGetSecret: {
            salt1: salt
          }
        }
      }
    });

    const extensions = assertion.getClientExtensionResults();

    if (!extensions.hmacGetSecret || !extensions.hmacGetSecret.output1) {
      throw new Error('No hmac-secret output from credential');
    }

    const hmacOutput = new Uint8Array(extensions.hmacGetSecret.output1);

    // Unwrap with HMAC output
    const sk = await decryptWithAESGCM(wrappedSK, hmacOutput.slice(0, 32), wrappingIV);

    log('Secret key unwrapped with hmac-secret');

    return sk;
  } catch (error) {
    log.error('Failed to unwrap secret key with hmac-secret: %s', error.message);
    throw new Error(`Failed to unwrap secret key: ${error.message}`);
  }
}

/**
 * Store encrypted keystore data in IndexedDB
 * @param {Object} data - Encrypted keystore data
 * @param {string} credentialId - WebAuthn credential ID (used as key)
 */
export async function storeEncryptedKeystore(data, credentialId) {
  log('Storing encrypted keystore in IndexedDB');

  const storageKey = `encrypted-keystore-${credentialId}`;

  const serializedData = {
    ciphertext: Array.from(data.ciphertext),
    iv: Array.from(data.iv),
    credentialId: data.credentialId,
    publicKey: data.publicKey ? {
      ...data.publicKey,
      x: data.publicKey.x ? Array.from(data.publicKey.x) : undefined,
      y: data.publicKey.y ? Array.from(data.publicKey.y) : undefined
    } : undefined,
    wrappedSK: data.wrappedSK ? Array.from(data.wrappedSK) : undefined,
    wrappingIV: data.wrappingIV ? Array.from(data.wrappingIV) : undefined,
    salt: data.salt ? Array.from(data.salt) : undefined,
    encryptionMethod: data.encryptionMethod || 'largeBlob',
    timestamp: Date.now()
  };

  try {
    localStorage.setItem(storageKey, JSON.stringify(serializedData));
    log('Encrypted keystore stored successfully');
  } catch (error) {
    log.error('Failed to store encrypted keystore: %s', error.message);
    throw new Error(`Failed to store encrypted keystore: ${error.message}`);
  }
}

/**
 * Load encrypted keystore data from IndexedDB
 * @param {string} credentialId - WebAuthn credential ID
 * @returns {Promise<Object>} Encrypted keystore data
 */
export async function loadEncryptedKeystore(credentialId) {
  log('Loading encrypted keystore from IndexedDB');

  const storageKey = `encrypted-keystore-${credentialId}`;

  try {
    const stored = localStorage.getItem(storageKey);

    if (!stored) {
      throw new Error('No encrypted keystore found for this credential');
    }

    const data = JSON.parse(stored);

    const deserialized = {
      ciphertext: new Uint8Array(data.ciphertext),
      iv: new Uint8Array(data.iv),
      credentialId: data.credentialId,
      publicKey: data.publicKey ? {
        ...data.publicKey,
        x: data.publicKey.x ? new Uint8Array(data.publicKey.x) : undefined,
        y: data.publicKey.y ? new Uint8Array(data.publicKey.y) : undefined
      } : undefined,
      wrappedSK: data.wrappedSK ? new Uint8Array(data.wrappedSK) : undefined,
      wrappingIV: data.wrappingIV ? new Uint8Array(data.wrappingIV) : undefined,
      salt: data.salt ? new Uint8Array(data.salt) : undefined,
      encryptionMethod: data.encryptionMethod || 'largeBlob',
      timestamp: data.timestamp
    };

    log('Encrypted keystore loaded successfully');

    return deserialized;
  } catch (error) {
    log.error('Failed to load encrypted keystore: %s', error.message);
    throw new Error(`Failed to load encrypted keystore: ${error.message}`);
  }
}

/**
 * Clear encrypted keystore from storage
 * @param {string} credentialId - WebAuthn credential ID
 */
export async function clearEncryptedKeystore(credentialId) {
  log('Clearing encrypted keystore from storage');

  const storageKey = `encrypted-keystore-${credentialId}`;

  try {
    localStorage.removeItem(storageKey);
    log('Encrypted keystore cleared successfully');
  } catch (error) {
    log.error('Failed to clear encrypted keystore: %s', error.message);
  }
}

/**
 * Check if browser supports WebAuthn extensions
 * @returns {Promise<Object>} Support status for largeBlob and hmac-secret
 */
export async function checkExtensionSupport() {
  const support = {
    largeBlob: false,
    hmacSecret: false
  };

  if (!window.PublicKeyCredential) {
    return support;
  }

  try {
    // Check largeBlob support
    if (window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
      const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      // largeBlob is available in Chrome 106+, Edge 106+
      support.largeBlob = available && 'largeBlob' in PublicKeyCredential.prototype;
    }

    // hmac-secret is more widely supported but harder to detect
    // Assume support if WebAuthn is available (will fail gracefully if not)
    support.hmacSecret = true;

  } catch (error) {
    log.error('Failed to check extension support: %s', error.message);
  }

  return support;
}

export default {
  generateSecretKey,
  encryptWithAESGCM,
  decryptWithAESGCM,
  addLargeBlobToCredentialOptions,
  retrieveSKFromLargeBlob,
  addHmacSecretToCredentialOptions,
  wrapSKWithHmacSecret,
  unwrapSKWithHmacSecret,
  storeEncryptedKeystore,
  loadEncryptedKeystore,
  clearEncryptedKeystore,
  checkExtensionSupport
};

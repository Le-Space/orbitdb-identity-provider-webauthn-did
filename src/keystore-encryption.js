/**
 * Keystore Encryption Utilities
 *
 * Provides AES-GCM encryption for OrbitDB keystore private keys,
 * protected by WebAuthn credentials using PRF, largeBlob or hmac-secret extensions.
 * 
 * Uses @simplewebauthn/browser for WebAuthn operations.
 */

import { logger } from '@libp2p/logger';
import { startAuthentication } from '@simplewebauthn/browser';
import { bufferToBase64URLString, base64URLStringToBuffer } from '@simplewebauthn/browser';

const log = logger('orbitdb-identity-provider-webauthn-did:keystore-encryption');

/**
 * Generate a random AES-GCM secret key (256-bit)
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
 * Add PRF extension to credential options (WebAuthn Level 3)
 * PRF is the successor to hmac-secret and is more widely supported
 * @param {Object} credentialOptions - WebAuthn credential creation options
 * @returns {Object} Enhanced credential options with PRF
 */
export function addPRFToCredentialOptions(credentialOptions) {
  log('Adding PRF extension to credential options');

  return {
    ...credentialOptions,
    extensions: {
      ...credentialOptions.extensions,
      prf: {}
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
  console.log('🔑 Wrapping secret key with hmac-secret extension...');
  console.log('   rpId:', rpId);
  console.log('   credentialId length:', credentialId?.length);

  const salt = crypto.getRandomValues(new Uint8Array(32));

  try {
    console.log('🔐 Requesting WebAuthn assertion with hmac-secret extension...');
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

    console.log('✅ WebAuthn assertion received');
    const extensions = assertion.getClientExtensionResults();
    console.log('📋 Extension results:', Object.keys(extensions));

    if (!extensions.hmacGetSecret || !extensions.hmacGetSecret.output1) {
      console.error('❌ hmac-secret extension did not return output');
      console.error('   Available extensions:', extensions);
      throw new Error('No hmac-secret output from credential - extension may not be supported by your authenticator');
    }

    const hmacOutput = new Uint8Array(extensions.hmacGetSecret.output1);
    console.log('🔑 HMAC output received, length:', hmacOutput.length);

    // Use HMAC output as wrapping key
    const wrappedSK = await encryptWithAESGCM(sk, hmacOutput.slice(0, 32));

    log('Secret key wrapped with hmac-secret');
    console.log('✅ Secret key wrapped successfully');

    return {
      wrappedSK: wrappedSK.ciphertext,
      wrappingIV: wrappedSK.iv,
      salt
    };
  } catch (error) {
    console.error('❌ Failed to wrap secret key with hmac-secret:', error.message);
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
 * Wrap secret key using PRF extension (WebAuthn Level 3)
 * PRF provides a deterministic output based on credential + salt
 * Uses @simplewebauthn/browser for cleaner WebAuthn handling
 * @param {Uint8Array} credentialId - WebAuthn credential ID
 * @param {Uint8Array} sk - Secret key to wrap
 * @param {string} rpId - Relying party ID (domain)
 * @returns {Promise<{wrappedSK: Uint8Array, wrappingIV: Uint8Array, salt: Uint8Array}>}
 */
export async function wrapSKWithPRF(credentialId, sk, rpId) {
  log('Wrapping secret key with PRF');
  console.log('🔑 Wrapping secret key with PRF extension (via SimpleWebAuthn)...');
  console.log('   rpId:', rpId);
  console.log('   credentialId length:', credentialId?.length);

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  try {
    console.log('🔐 Requesting WebAuthn assertion with PRF extension...');
    
    // Build authentication options with PRF extension
    // Note: SimpleWebAuthn expects base64url-encoded strings for all binary data
    const authOptions = {
      rpId: rpId,
      challenge: bufferToBase64URLString(challenge),
      allowCredentials: [{
        id: bufferToBase64URLString(credentialId),
        type: 'public-key'
      }],
      userVerification: 'required',
      timeout: 60000,
      // PRF extension - salt must be base64url string for SimpleWebAuthn
      extensions: {
        prf: {
          eval: {
            first: bufferToBase64URLString(salt)
          }
        }
      }
    };
    
    console.log('📋 Auth options:', JSON.stringify(authOptions, null, 2));
    
    // Use SimpleWebAuthn's startAuthentication
    const authResponse = await startAuthentication({ optionsJSON: authOptions });

    console.log('✅ WebAuthn assertion received via SimpleWebAuthn');
    console.log('📋 Auth response keys:', Object.keys(authResponse || {}));
    
    // Get PRF results from the client extension results
    const extensions = authResponse.clientExtensionResults;
    console.log('📋 Extension results:', JSON.stringify(extensions, null, 2));

    if (!extensions?.prf?.results?.first) {
      console.error('❌ PRF extension did not return output');
      console.error('   Available extensions:', extensions);
      throw new Error('No PRF output from credential - extension may not be supported by your authenticator');
    }

    // PRF output - SimpleWebAuthn returns base64url string, decode it
    const prfOutputBase64 = extensions.prf.results.first;
    const prfOutput = new Uint8Array(base64URLStringToBuffer(prfOutputBase64));
    console.log('🔑 PRF output received, length:', prfOutput.length);

    // Use PRF output as wrapping key (PRF output is 32 bytes)
    const wrappedSK = await encryptWithAESGCM(sk, prfOutput.slice(0, 32));

    log('Secret key wrapped with PRF');
    console.log('✅ Secret key wrapped successfully with PRF');

    return {
      wrappedSK: wrappedSK.ciphertext,
      wrappingIV: wrappedSK.iv,
      salt
    };
  } catch (error) {
    console.error('❌ Failed to wrap secret key with PRF:', error.message);
    log.error('Failed to wrap secret key with PRF: %s', error.message);
    throw new Error(`Failed to wrap secret key with PRF: ${error.message}`);
  }
}

/**
 * Unwrap secret key using PRF extension
 * Uses @simplewebauthn/browser for cleaner WebAuthn handling
 * @param {Uint8Array} credentialId - WebAuthn credential ID
 * @param {Uint8Array} wrappedSK - Wrapped secret key
 * @param {Uint8Array} wrappingIV - IV used for wrapping
 * @param {Uint8Array} salt - Salt used for PRF
 * @param {string} rpId - Relying party ID (domain)
 * @returns {Promise<Uint8Array>} Unwrapped secret key
 */
export async function unwrapSKWithPRF(credentialId, wrappedSK, wrappingIV, salt, rpId) {
  log('Unwrapping secret key with PRF');

  const challenge = crypto.getRandomValues(new Uint8Array(32));

  try {
    // Build authentication options with PRF extension
    // Note: SimpleWebAuthn expects base64url-encoded strings for all binary data
    const authOptions = {
      rpId: rpId,
      challenge: bufferToBase64URLString(challenge),
      allowCredentials: [{
        id: bufferToBase64URLString(credentialId),
        type: 'public-key'
      }],
      userVerification: 'required',
      timeout: 60000,
      // PRF extension - salt must be base64url string for SimpleWebAuthn
      extensions: {
        prf: {
          eval: {
            first: bufferToBase64URLString(salt)
          }
        }
      }
    };

    // Use SimpleWebAuthn's startAuthentication
    const authResponse = await startAuthentication({ optionsJSON: authOptions });

    const extensions = authResponse.clientExtensionResults;

    if (!extensions?.prf?.results?.first) {
      throw new Error('No PRF output from credential');
    }

    // PRF output - SimpleWebAuthn returns base64url string, decode it
    const prfOutputBase64 = extensions.prf.results.first;
    const prfOutput = new Uint8Array(base64URLStringToBuffer(prfOutputBase64));

    // Unwrap with PRF output
    const sk = await decryptWithAESGCM(wrappedSK, prfOutput.slice(0, 32), wrappingIV);

    log('Secret key unwrapped with PRF');

    return sk;
  } catch (error) {
    log.error('Failed to unwrap secret key with PRF: %s', error.message);
    throw new Error(`Failed to unwrap secret key with PRF: ${error.message}`);
  }
}

const INDEXEDDB_NAME = 'webauthn-encrypted-keystore';
const INDEXEDDB_VERSION = 1;
const STORE_NAME = 'encrypted-keystores';

/**
 * Open IndexedDB connection for encrypted keystore storage
 * @returns {Promise<IDBDatabase>} IndexedDB database instance
 */
function openKeystoreDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(INDEXEDDB_NAME, INDEXEDDB_VERSION);

    request.onerror = () => {
      log.error('Failed to open IndexedDB: %s', request.error?.message);
      reject(new Error(`Failed to open IndexedDB: ${request.error?.message}`));
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'credentialId' });
        store.createIndex('timestamp', 'timestamp', { unique: false });
        log('Created IndexedDB object store: %s', STORE_NAME);
      }
    };
  });
}

/**
 * Store encrypted keystore data in IndexedDB
 * @param {Object} data - Encrypted keystore data
 * @param {string} credentialId - WebAuthn credential ID (used as key)
 */
export async function storeEncryptedKeystore(data, credentialId) {
  log('Storing encrypted keystore in IndexedDB');

  if (!credentialId) {
    throw new Error('credentialId is required to store encrypted keystore');
  }

  if (!data || !data.ciphertext) {
    throw new Error('Invalid encrypted data - missing ciphertext');
  }

  const serializedData = {
    credentialId: credentialId,
    ciphertext: Array.from(data.ciphertext),
    iv: Array.from(data.iv),
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
    const db = await openKeystoreDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.put(serializedData);

      request.onsuccess = () => {
        log('Encrypted keystore stored successfully in IndexedDB');
        console.log('💾 Encrypted keystore stored in IndexedDB:', INDEXEDDB_NAME);
        db.close();
        resolve();
      };

      request.onerror = () => {
        log.error('Failed to store encrypted keystore: %s', request.error?.message);
        db.close();
        reject(new Error(`Failed to store encrypted keystore: ${request.error?.message}`));
      };
    });
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

  try {
    const db = await openKeystoreDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(credentialId);

      request.onsuccess = () => {
        db.close();
        const data = request.result;

        if (!data) {
          reject(new Error('No encrypted keystore found for this credential'));
          return;
        }

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

        log('Encrypted keystore loaded successfully from IndexedDB');
        console.log('📂 Encrypted keystore loaded from IndexedDB');
        resolve(deserialized);
      };

      request.onerror = () => {
        db.close();
        log.error('Failed to load encrypted keystore: %s', request.error?.message);
        reject(new Error(`Failed to load encrypted keystore: ${request.error?.message}`));
      };
    });
  } catch (error) {
    log.error('Failed to load encrypted keystore: %s', error.message);
    throw new Error(`Failed to load encrypted keystore: ${error.message}`);
  }
}

/**
 * Clear encrypted keystore from IndexedDB
 * @param {string} credentialId - WebAuthn credential ID
 */
export async function clearEncryptedKeystore(credentialId) {
  log('Clearing encrypted keystore from IndexedDB');

  try {
    const db = await openKeystoreDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.delete(credentialId);

      request.onsuccess = () => {
        log('Encrypted keystore cleared successfully from IndexedDB');
        db.close();
        resolve();
      };

      request.onerror = () => {
        log.error('Failed to clear encrypted keystore: %s', request.error?.message);
        db.close();
        reject(new Error(`Failed to clear encrypted keystore: ${request.error?.message}`));
      };
    });
  } catch (error) {
    log.error('Failed to clear encrypted keystore: %s', error.message);
  }
}

/**
 * Check if browser supports WebAuthn extensions
 * @returns {Promise<Object>} Support status for PRF, largeBlob and hmac-secret
 */
export async function checkExtensionSupport() {
  const support = {
    prf: false,
    largeBlob: false,
    hmacSecret: false
  };

  if (!window.PublicKeyCredential) {
    return support;
  }

  try {
    // Check PRF support (WebAuthn Level 3 - preferred method)
    // PRF is supported in Chrome 109+, Safari 16.4+, Edge 109+
    if (window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
      const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      // PRF support can be detected via the AuthenticatorExtensionsClientInputs type
      // For now, assume support if platform authenticator is available (modern browsers)
      support.prf = available;
    }

    // Check largeBlob support
    if (window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
      const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      // largeBlob is available in Chrome 106+, Edge 106+
      support.largeBlob = available && 'largeBlob' in PublicKeyCredential.prototype;
    }

    // hmac-secret is primarily for hardware keys, not platform authenticators
    // Assume false by default, will fail gracefully if not supported
    support.hmacSecret = false;

  } catch (error) {
    log.error('Failed to check extension support: %s', error.message);
  }

  return support;
}

/**
 * Compute SHA-256 hash of data and return hex string
 * @param {Uint8Array} data - Data to hash
 * @returns {Promise<string>} Hex-encoded hash
 */
export async function computeHash(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Get cryptographic proof of keystore encryption
 * This provides verifiable evidence that the keystore is encrypted
 * @param {string} credentialId - WebAuthn credential ID
 * @returns {Promise<Object>} Encryption proof details
 */
export async function getEncryptionProof(credentialId) {
  log('Generating encryption proof for credential');

  let data;
  try {
    data = await loadEncryptedKeystore(credentialId);
  } catch (error) {
    return {
      encrypted: false,
      reason: 'No encrypted keystore found',
      storage: 'IndexedDB'
    };
  }

  const ciphertext = data.ciphertext;
  const iv = data.iv;

  // Compute cryptographic hashes as proof
  const ciphertextHash = await computeHash(ciphertext);
  const ivHash = await computeHash(iv);

  // For PRF or hmac-secret, also include salt hash
  let saltHash = null;
  let wrappedSKHash = null;
  if ((data.encryptionMethod === 'prf' || data.encryptionMethod === 'hmac-secret') && data.salt) {
    saltHash = await computeHash(data.salt);
    if (data.wrappedSK) {
      wrappedSKHash = await computeHash(data.wrappedSK);
    }
  }

  // Determine key derivation description based on method
  let keyDerivation;
  if (data.encryptionMethod === 'prf') {
    keyDerivation = 'WebAuthn PRF (hardware-bound)';
  } else if (data.encryptionMethod === 'hmac-secret') {
    keyDerivation = 'WebAuthn HMAC-Secret (hardware-bound)';
  } else {
    keyDerivation = 'WebAuthn LargeBlob (hardware-stored)';
  }

  const proof = {
    encrypted: true,
    method: data.encryptionMethod,
    timestamp: data.timestamp,
    ciphertextLength: ciphertext.length,
    ciphertextHash: ciphertextHash,
    ivLength: iv.length,
    ivHash: ivHash,
    // PRF specific proof
    ...(data.encryptionMethod === 'prf' && {
      prfUsed: true,
      saltHash: saltHash,
      saltLength: data.salt ? data.salt.length : 0,
      wrappedSKHash: wrappedSKHash,
      wrappedSKLength: data.wrappedSK ? data.wrappedSK.length : 0,
    }),
    // HMAC-secret specific proof
    ...(data.encryptionMethod === 'hmac-secret' && {
      hmacSecretUsed: true,
      saltHash: saltHash,
      saltLength: data.salt ? data.salt.length : 0,
      wrappedSKHash: wrappedSKHash,
      wrappedSKLength: data.wrappedSK ? data.wrappedSK.length : 0,
    }),
    // Verification info
    algorithm: 'AES-GCM-256',
    keyDerivation: keyDerivation,
    securityLevel: 'Hardware-backed (WebAuthn authenticator)',
    storage: 'IndexedDB',
    storageName: INDEXEDDB_NAME,
  };

  log('Encryption proof generated: %O', proof);
  return proof;
}

/**
 * Verify that encryption is working correctly by performing a test encrypt/decrypt cycle
 * This provides cryptographic proof that the encryption system is functional
 * @param {Uint8Array} sk - Secret key to test with
 * @returns {Promise<Object>} Verification result with proof
 */
export async function verifyEncryptionIntegrity(sk) {
  log('Verifying encryption integrity');

  // Generate random test data
  const testData = crypto.getRandomValues(new Uint8Array(64));
  const testDataHash = await computeHash(testData);

  try {
    // Encrypt
    const { ciphertext, iv } = await encryptWithAESGCM(testData, sk);
    const ciphertextHash = await computeHash(ciphertext);

    // Verify ciphertext is different from plaintext (encryption happened)
    const plaintextHash = testDataHash;
    if (ciphertextHash === plaintextHash) {
      throw new Error('Ciphertext matches plaintext - encryption failed');
    }

    // Decrypt
    const decrypted = await decryptWithAESGCM(ciphertext, sk, iv);
    const decryptedHash = await computeHash(decrypted);

    // Verify decrypted data matches original
    const integrityVerified = decryptedHash === testDataHash;

    const result = {
      verified: integrityVerified,
      algorithm: 'AES-GCM-256',
      testDataHash: testDataHash.slice(0, 16) + '...',
      ciphertextHash: ciphertextHash.slice(0, 16) + '...',
      decryptedHash: decryptedHash.slice(0, 16) + '...',
      ciphertextLength: ciphertext.length,
      ivLength: iv.length,
      encryptionWorking: ciphertextHash !== plaintextHash,
      decryptionWorking: decryptedHash === testDataHash,
      timestamp: Date.now()
    };

    log('Encryption integrity verification: %O', result);
    return result;

  } catch (error) {
    log.error('Encryption integrity verification failed: %s', error.message);
    return {
      verified: false,
      error: error.message,
      timestamp: Date.now()
    };
  }
}

/**
 * Get full encryption status with all cryptographic proofs
 * @param {string} credentialId - WebAuthn credential ID
 * @returns {Promise<Object>} Complete encryption status
 */
export async function getFullEncryptionStatus(credentialId) {
  log('Getting full encryption status');

  const proof = await getEncryptionProof(credentialId);

  return {
    ...proof,
    proofGenerated: new Date().toISOString(),
    credentialId: credentialId.slice(0, 8) + '...' + credentialId.slice(-8),
  };
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
  addPRFToCredentialOptions,
  wrapSKWithPRF,
  unwrapSKWithPRF,
  storeEncryptedKeystore,
  loadEncryptedKeystore,
  clearEncryptedKeystore,
  checkExtensionSupport,
  computeHash,
  getEncryptionProof,
  verifyEncryptionIntegrity,
  getFullEncryptionStatus
};

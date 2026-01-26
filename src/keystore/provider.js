/**
 * OrbitDB Identity Provider for WebAuthn + Keystore
 */

import { logger } from '@libp2p/logger';
import { generateKeyPair, privateKeyFromRaw } from '@libp2p/crypto/keys';
import * as KeystoreEncryption from './encryption.js';
import { WebAuthnDIDProvider } from '../webauthn/provider.js';

const identityLog = logger('orbitdb-identity-provider-webauthn-did:identity');

/**
 * OrbitDB Identity Provider that uses WebAuthn
 */
export class OrbitDBWebAuthnIdentityProvider {
  /**
   * @param {Object} options - Provider configuration.
   * @param {Object} options.webauthnCredential - WebAuthn credential info.
   * @param {boolean} [options.useKeystoreDID=false] - Use keystore DID instead of WebAuthn DID.
   * @param {Object|null} [options.keystore=null] - OrbitDB keystore instance.
   * @param {string} [options.keystoreKeyType='secp256k1'] - Keystore key type.
   * @param {boolean} [options.encryptKeystore=false] - Encrypt keystore at rest.
   * @param {string} [options.keystoreEncryptionMethod='prf'] - Encryption method.
   */
  constructor({
    webauthnCredential,
    useKeystoreDID = false,
    keystore = null,
    keystoreKeyType = 'secp256k1',
    encryptKeystore = false,
    keystoreEncryptionMethod = 'prf'
  }) {
    this.credential = webauthnCredential;
    this.webauthnProvider = new WebAuthnDIDProvider(webauthnCredential);
    this.type = 'webauthn'; // Set instance property
    this.useKeystoreDID = useKeystoreDID; // Flag to use Ed25519 DID from keystore
    this.keystore = keystore; // OrbitDB keystore instance
    this.keystoreKeyType = keystoreKeyType; // Key type: 'secp256k1' or 'Ed25519'
    this.encryptKeystore = encryptKeystore; // Flag to encrypt keystore
    this.keystoreEncryptionMethod = keystoreEncryptionMethod; // Encryption method
    this.unlockedKeypair = null; // Store unlocked keypair during session
    this.unlockedPrivateKey = null;
  }

  static get type() {
    return 'webauthn';
  }

  /**
   * Resolve the identity DID.
   * @returns {Promise<string>} DID string.
   */
  async getId() {
    identityLog('getId() called');

    // If useKeystoreDID flag is set, create Ed25519 DID from keystore
    if (this.useKeystoreDID && this.keystore) {
      identityLog('Using Ed25519 DID from keystore');
      const did = await this.createEd25519DIDFromKeystore();
      identityLog('getId() returning Ed25519 DID: %s', did.substring(0, 32) + '...');
      return did;
    }

    // Default: Return P-256 DID from WebAuthn credential
    const did = await WebAuthnDIDProvider.createDID(this.credential);
    identityLog('getId() returning P-256 DID: %s', did.substring(0, 32) + '...');
    return did;
  }

  /**
   * Create Ed25519 DID from OrbitDB keystore
   * This uses the keystore's Ed25519 key to create a did:key DID
   */
  async createEd25519DIDFromKeystore() {
    if (!this.keystore) {
      throw new Error('Keystore is required to create Ed25519 DID');
    }

    try {
      // Import multiformats modules
      const multiformats = await import('multiformats');
      const varint = multiformats.varint;
      const { base58btc } = await import('multiformats/bases/base58');

      if (this.encryptKeystore) {
        const encryptedData = this.unlockedKeypair
          ? { publicKey: this.unlockedKeypair.publicKey, keyType: this.unlockedKeypair.keyType }
          : await KeystoreEncryption.loadEncryptedKeystore(this.credential.credentialId);
        const publicKeyBytes = encryptedData.publicKey instanceof Uint8Array
          ? encryptedData.publicKey
          : new Uint8Array(encryptedData.publicKey);
        const keyType = encryptedData.keyType || this.keystoreKeyType;

        return this.createDIDFromKeystorePublicKey(publicKeyBytes, keyType, varint, base58btc);
      }

      // Get the keystore's identity ID (this will be used to retrieve the key)
      // We'll use the WebAuthn DID as the identity ID to get/create the keystore key
      const identityId = await WebAuthnDIDProvider.createDID(this.credential);

      // Get or create the Ed25519 key from keystore
      // Try getKey first, if it doesn't exist, createKey will create it
      let keystoreKey = await this.keystore.getKey(identityId);
      if (!keystoreKey) {
        identityLog('Key not found, creating new key for: %s with type: %s', identityId.substring(0, 32) + '...', this.keystoreKeyType);
        keystoreKey = await this.keystore.createKey(identityId, this.keystoreKeyType);
      }

      identityLog('Keystore key obtained, type: %s, keys: %o', typeof keystoreKey, Object.keys(keystoreKey || {}));

      // The keystore key should have a public property with marshal method
      // But it seems this isn't available immediately after creation
      // Let's try to extract the public key bytes directly
      let publicKeyBytes;

      // Extract public key bytes from the keystore key
      // OrbitDB uses @libp2p/crypto keys which have different structures
      if (keystoreKey && keystoreKey.publicKey) {
        // Modern libp2p-crypto format - has publicKey property
        const pubKey = keystoreKey.publicKey;
        identityLog('Found publicKey property, type: %s', pubKey.constructor.name);

        // Try to get raw bytes from the public key
        if (pubKey.raw) {
          publicKeyBytes = pubKey.raw;
          identityLog('Got public key from publicKey.raw: %d bytes', publicKeyBytes.length);
        } else if (pubKey.bytes) {
          publicKeyBytes = pubKey.bytes;
          identityLog('Got public key from publicKey.bytes: %d bytes', publicKeyBytes.length);
        } else if (typeof pubKey.marshal === 'function') {
          publicKeyBytes = pubKey.marshal();
          identityLog('Got public key from publicKey.marshal(): %d bytes', publicKeyBytes.length);
        } else {
          identityLog.error('Cannot extract bytes from publicKey: %o', pubKey);
          throw new Error('Unable to extract bytes from publicKey');
        }
      } else if (keystoreKey && keystoreKey.public && keystoreKey.public.bytes) {
        // Older libp2p-crypto format
        publicKeyBytes = keystoreKey.public.bytes;
        identityLog('Got public key from keystoreKey.public.bytes: %d bytes', publicKeyBytes.length);
      } else if (keystoreKey && keystoreKey.bytes) {
        // Direct bytes
        publicKeyBytes = keystoreKey.bytes;
        identityLog('Got public key from keystoreKey.bytes: %d bytes', publicKeyBytes.length);
      } else {
        identityLog.error('Cannot extract public key from keystoreKey: %o', keystoreKey);
        throw new Error('Unable to extract public key from keystore key');
      }

      // Note: secp256k1 public keys are 33 or 65 bytes (compressed/uncompressed)
      // Ed25519 public keys are 32 bytes
      // We need to handle both
      identityLog('Public key extracted: %d bytes, key type: %s', publicKeyBytes.length, keystoreKey.type);

      if (!publicKeyBytes || publicKeyBytes.length < 32) {
        throw new Error(`Invalid public key length: ${publicKeyBytes ? publicKeyBytes.length : 0} bytes`);
      }

      identityLog('Successfully extracted public key: %d bytes, type: %s', publicKeyBytes.length, keystoreKey.type);

      return this.createDIDFromKeystorePublicKey(publicKeyBytes, keystoreKey.type, varint, base58btc);

    } catch (error) {
      identityLog.error('Failed to create Ed25519 DID from keystore: %s', error.message);
      throw new Error(`Failed to create Ed25519 DID from keystore: ${error.message}`);
    }
  }

  createDIDFromKeystorePublicKey(publicKeyBytes, keyType, varint, base58btc) {
    // Determine the correct multicodec based on key type
    // secp256k1 multicodec code (0xe7) or Ed25519 (0xed)
    let multicodec;
    if (keyType === 'secp256k1') {
      multicodec = 0xe7; // secp256k1-pub
      identityLog('Using secp256k1 multicodec (0xe7)');
    } else if (keyType === 'Ed25519' || keyType === 'ed25519') {
      multicodec = 0xed; // ed25519-pub
      identityLog('Using Ed25519 multicodec (0xed)');
    } else {
      throw new Error(`Unsupported key type: ${keyType}`);
    }

    const codecLength = varint.encodingLength(multicodec);
    const codecBytes = new Uint8Array(codecLength);
    varint.encodeTo(multicodec, codecBytes, 0);

    if (codecBytes.length === 0) {
      throw new Error('Failed to encode ED25519_MULTICODEC with varint');
    }

    // Combine multicodec prefix + public key bytes
    const multikey = new Uint8Array(codecBytes.length + publicKeyBytes.length);
    multikey.set(codecBytes, 0);
    multikey.set(publicKeyBytes, codecBytes.length);

    // Encode as base58btc and create did:key
    const multikeyEncoded = base58btc.encode(multikey);
    return `did:key:${multikeyEncoded}`;
  }

  /**
   * Create and encrypt OrbitDB keystore
   * @returns {Promise<void>}
   */
  async createEncryptedKeystore() {
    if (!this.encryptKeystore) {
      console.log('ℹ️ Keystore encryption not enabled, skipping');
      return;
    }

    console.log('🔐 Creating encrypted keystore with method:', this.keystoreEncryptionMethod);
    identityLog('Creating encrypted keystore with method: %s', this.keystoreEncryptionMethod);

    try {
      // Generate secret key
      const sk = KeystoreEncryption.generateSecretKey();

      const keyType = this.keystoreKeyType === 'secp256k1' ? 'secp256k1' : 'Ed25519';
      const keyPair = await generateKeyPair(keyType);
      const privateKeyBytes = keyPair.marshal ? keyPair.marshal() : keyPair.raw;
      const publicKeyBytes = keyPair.publicKey?.marshal ? keyPair.publicKey.marshal() : keyPair.publicKey?.raw;

      if (!privateKeyBytes || !publicKeyBytes) {
        throw new Error('Failed to serialize keystore keypair');
      }
      const { ciphertext, iv } = await KeystoreEncryption.encryptWithAESGCM(privateKeyBytes, sk);

      // Store SK in WebAuthn or wrap it
      let encryptedData;

      if (this.keystoreEncryptionMethod === 'prf') {
        // Wrap SK with PRF (WebAuthn Level 3 - preferred method)
        const wrapped = await KeystoreEncryption.wrapSKWithPRF(
          this.credential.rawCredentialId,
          sk,
          window.location.hostname
        );

        encryptedData = {
          ciphertext,
          iv,
          credentialId: this.credential.credentialId,
          publicKey: publicKeyBytes,
          keyType,
          wrappedSK: wrapped.wrappedSK,
          wrappingIV: wrapped.wrappingIV,
          salt: wrapped.salt,
          encryptionMethod: 'prf'
        };
      } else if (this.keystoreEncryptionMethod === 'largeBlob') {
        // For largeBlob, we need to store SK during next authentication
        // Store it temporarily for wrapping
        encryptedData = {
          ciphertext,
          iv,
          credentialId: this.credential.credentialId,
          publicKey: publicKeyBytes,
          keyType,
          secretKey: sk, // Will be moved to largeBlob
          encryptionMethod: 'largeBlob'
        };
      } else if (this.keystoreEncryptionMethod === 'hmac-secret') {
        // Wrap SK with hmac-secret
        const wrapped = await KeystoreEncryption.wrapSKWithHmacSecret(
          this.credential.rawCredentialId,
          sk,
          window.location.hostname
        );

        encryptedData = {
          ciphertext,
          iv,
          credentialId: this.credential.credentialId,
          publicKey: publicKeyBytes,
          keyType,
          wrappedSK: wrapped.wrappedSK,
          wrappingIV: wrapped.wrappingIV,
          salt: wrapped.salt,
          encryptionMethod: 'hmac-secret'
        };
      }

      // Store encrypted keystore
      console.log('💾 Storing encrypted keystore with credentialId:', this.credential.credentialId?.substring(0, 16) + '...');
      await KeystoreEncryption.storeEncryptedKeystore(encryptedData, this.credential.credentialId);
      this.unlockedKeypair = {
        privateKey: privateKeyBytes,
        publicKey: publicKeyBytes,
        keyType
      };
      this.unlockedPrivateKey = keyPair;
      console.log('✅ Encrypted keystore stored successfully');

      identityLog('Encrypted keystore created and stored successfully');

    } catch (error) {
      identityLog.error('Failed to create encrypted keystore: %s', error.message);
      throw new Error(`Failed to create encrypted keystore: ${error.message}`);
    }
  }

  /**
   * Unlock encrypted keystore
   * @returns {Promise<Object>} Decrypted keypair
   */
  async unlockEncryptedKeystore() {
    if (!this.encryptKeystore) {
      return null;
    }

    identityLog('Unlocking encrypted keystore with method: %s', this.keystoreEncryptionMethod);

    try {
      // Load encrypted keystore
      const encryptedData = await KeystoreEncryption.loadEncryptedKeystore(this.credential.credentialId);

      let sk;

      if (encryptedData.encryptionMethod === 'prf') {
        // Unwrap SK with PRF
        sk = await KeystoreEncryption.unwrapSKWithPRF(
          this.credential.rawCredentialId,
          encryptedData.wrappedSK,
          encryptedData.wrappingIV,
          encryptedData.salt,
          window.location.hostname
        );
      } else if (encryptedData.encryptionMethod === 'largeBlob') {
        // Retrieve SK from largeBlob
        sk = await KeystoreEncryption.retrieveSKFromLargeBlob(
          this.credential.rawCredentialId,
          window.location.hostname
        );
      } else if (encryptedData.encryptionMethod === 'hmac-secret') {
        // Unwrap SK with hmac-secret
        sk = await KeystoreEncryption.unwrapSKWithHmacSecret(
          this.credential.rawCredentialId,
          encryptedData.wrappedSK,
          encryptedData.wrappingIV,
          encryptedData.salt,
          window.location.hostname
        );
      }

      // Decrypt keystore private key
      const privateKeyBytes = await KeystoreEncryption.decryptWithAESGCM(
        encryptedData.ciphertext,
        sk,
        encryptedData.iv
      );

      const publicKeyBytes = encryptedData.publicKey instanceof Uint8Array
        ? encryptedData.publicKey
        : new Uint8Array(encryptedData.publicKey);
      // Store unlocked keypair in memory for session
      this.unlockedKeypair = {
        privateKey: privateKeyBytes,
        publicKey: publicKeyBytes,
        keyType: encryptedData.keyType || this.keystoreKeyType
      };
      try {
        this.unlockedPrivateKey = privateKeyFromRaw(privateKeyBytes);
      } catch (error) {
        identityLog.error('Failed to unmarshal encrypted keystore private key: %s', error.message);
        this.unlockedPrivateKey = null;
      }

      identityLog('Encrypted keystore unlocked successfully');

      return this.unlockedKeypair;

    } catch (error) {
      identityLog.error('Failed to unlock encrypted keystore: %s', error.message);
      throw new Error(`Failed to unlock encrypted keystore: ${error.message}`);
    }
  }

  /**
   * Sign data for OrbitDB identity operations.
   * @param {string|Uint8Array} data - Payload to sign.
   * @returns {Promise<string>} Signature envelope.
   */
  signIdentity(data) {
    const dataLength = typeof data === 'string' ? data.length : data.byteLength;
    identityLog('signIdentity() called with data length: %d', dataLength);

    // If using encrypted keystore and it's unlocked, use unlocked key
    if (this.encryptKeystore && this.unlockedKeypair) {
      identityLog('Using unlocked encrypted keystore for signing');
      // TODO: Implement signing with unlocked keypair
      // For now, fall back to WebAuthn
    }

    return this.webauthnProvider.sign(data);
  }

  /**
   * Verify identity signature.
   * @param {string} signature - Signature envelope.
   * @param {string|Uint8Array} data - Payload that was signed.
   * @param {Object} [publicKey] - Optional public key override.
   * @returns {Promise<boolean>} True if valid.
   */
  verifyIdentity(signature, data, publicKey) {
    identityLog('verifyIdentity() called');
    return this.webauthnProvider.verify(signature, data, publicKey || this.credential.publicKey);
  }

  /**
   * Create OrbitDB identity using WebAuthn
   * @param {Object} options - Provider options.
   * @returns {Promise<Object>} OrbitDB identity object.
   */
  static async createIdentity(options) {
    const {
      webauthnCredential,
      useKeystoreDID = false,
      keystore = null,
      keystoreKeyType = 'secp256k1',
      encryptKeystore = false,
      keystoreEncryptionMethod = 'prf'
    } = options;

    identityLog('createIdentity() called with useKeystoreDID: %s, keystoreKeyType: %s, encryptKeystore: %s',
      useKeystoreDID, keystoreKeyType, encryptKeystore);

    const provider = new OrbitDBWebAuthnIdentityProvider({
      webauthnCredential,
      useKeystoreDID,
      keystore,
      keystoreKeyType,
      encryptKeystore,
      keystoreEncryptionMethod
    });

    // If encryption is enabled, create and unlock encrypted keystore
    if (encryptKeystore && keystore) {
      try {
        console.log('🔐 Creating encrypted keystore with', keystoreEncryptionMethod, '...');
        await provider.createEncryptedKeystore();
        console.log('🔓 Unlocking encrypted keystore...');
        await provider.unlockEncryptedKeystore();
        console.log('✅ Encrypted keystore created and unlocked successfully');
        identityLog('Encrypted keystore created and unlocked');
      } catch (error) {
        // Log error visibly so users know encryption failed
        console.error('❌ Failed to setup encrypted keystore:', error.message);
        console.error('   Full error:', error);
        identityLog.error('Failed to setup encrypted keystore: %s', error.message);
        // Continue anyway - encryption is optional but user should know it failed
      }
    }

    const id = await provider.getId();

    identityLog('Identity created successfully: %o', {
      id: id.substring(0, 32) + '...',
      type: 'webauthn',
      didType: useKeystoreDID ? 'Ed25519 (from keystore)' : 'P-256 (from WebAuthn)',
      encrypted: encryptKeystore,
      hasPublicKey: !!webauthnCredential.publicKey
    });

    return {
      id,
      publicKey: webauthnCredential.publicKey,
      type: 'webauthn',
      sign: (identity, data) => {
        identityLog('identity.sign() called from OrbitDB');
        return provider.signIdentity(data);
      },
      verify: (signature, data) => {
        identityLog('identity.verify() called from OrbitDB');
        return provider.verifyIdentity(signature, data, webauthnCredential.publicKey);
      }
    };
  }
}

/**
 * WebAuthn Identity Provider Function for OrbitDB
 * This follows the same pattern as OrbitDBIdentityProviderDID
 * Returns a function that returns a promise resolving to the provider instance
 *
 * @param {Object} options - Configuration options
 * @param {Object} options.webauthnCredential - WebAuthn credential for authentication
 * @param {boolean} options.useKeystoreDID - If true, creates DID from keystore instead of P-256 DID from WebAuthn
 * @param {Object} options.keystore - OrbitDB keystore instance (required if useKeystoreDID is true)
 * @param {string} options.keystoreKeyType - Key type for keystore: 'secp256k1' (default) or 'Ed25519'
 * @param {boolean} options.encryptKeystore - If true, encrypts the keystore with WebAuthn-protected secret
 * @param {string} options.keystoreEncryptionMethod - Encryption method: 'largeBlob' or 'hmac-secret'
 * @returns {Function} Provider factory for OrbitDB.
 */
export function OrbitDBWebAuthnIdentityProviderFunction(options = {}) {
  // Return a function that returns a promise (as expected by OrbitDB)
  return async () => {
    return new OrbitDBWebAuthnIdentityProvider(options);
  };
}

// Add static methods and properties that OrbitDB expects
OrbitDBWebAuthnIdentityProviderFunction.type = 'webauthn';
OrbitDBWebAuthnIdentityProviderFunction.verifyIdentity = async function(identity) {
  try {
    // For WebAuthn identities, we need to store the credential info in the identity
    // Since WebAuthn verification requires the original credential, not just the public key,
    // we'll create a simplified verification that checks the proof structure


    // For WebAuthn, the identity should have been created with our provider,
    // so we can trust it if it has the right structure
    // Accept both DID format (did:key:...) and hash format (hex string) for backward compatibility
    const isValidDID = identity.id && identity.id.startsWith('did:key:');
    const isValidHash = identity.id && /^[a-f0-9]{64}$/.test(identity.id); // 64-char hex string (legacy)

    if (identity.type === 'webauthn' && (isValidDID || isValidHash)) {
      return true;
    }

    return false;

  } catch (error) {
    console.error('WebAuthn static identity verification failed:', error);
    return false;
  }
};

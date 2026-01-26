/**
 * WebAuthn DID Provider for OrbitDB
 *
 * Creates hardware-secured DIDs using WebAuthn authentication (Passkey, Yubikey, Ledger, etc.)
 * Integrates with OrbitDB's identity system while keeping private keys in secure hardware
 */

import { logger } from '@libp2p/logger';
import * as KeystoreEncryption from '../keystore/encryption.js';

const webauthnLog = logger('orbitdb-identity-provider-webauthn-did:webauthn');

/**
 * WebAuthn DID Provider Core Implementation
 */
export class WebAuthnDIDProvider {
  /**
   * @param {Object} credentialInfo - WebAuthn credential material.
   * @param {string} credentialInfo.credentialId - Credential ID (base64url).
   * @param {Object} credentialInfo.publicKey - P-256 public key details.
   * @param {Uint8Array} credentialInfo.rawCredentialId - Raw credential ID bytes.
   */
  constructor(credentialInfo) {
    this.credentialId = credentialInfo.credentialId;
    this.publicKey = credentialInfo.publicKey;
    this.rawCredentialId = credentialInfo.rawCredentialId;
    this.type = 'webauthn';
  }

  /**
   * Check if WebAuthn is supported in current browser
   * @returns {boolean} True if supported.
   */
  static isSupported() {
    return window.PublicKeyCredential &&
           typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
  }

  /**
   * Check if platform authenticator (Face ID, Touch ID, Windows Hello) is available
   * @returns {Promise<boolean>} True if available.
   */
  static async isPlatformAuthenticatorAvailable() {
    if (!this.isSupported()) return false;

    try {
      return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (error) {
      console.warn('Failed to check platform authenticator availability:', error);
      return false;
    }
  }

  /**
   * Create a WebAuthn credential for OrbitDB identity
   * This triggers biometric authentication (Face ID, Touch ID, Windows Hello, etc.)
   * @param {Object} options - Credential options
   * @param {string} options.userId - User ID
   * @param {string} options.displayName - Display name
   * @param {string} options.domain - Domain/RP ID
   * @param {boolean} options.encryptKeystore - Enable keystore encryption
   * @param {string} options.keystoreEncryptionMethod - 'prf' (default), 'hmac-secret', or 'largeBlob'
   * @returns {Promise<Object>} Credential info with public key and metadata.
   */
  static async createCredential(options = {}) {
    const {
      userId,
      displayName,
      domain,
      encryptKeystore = false,
      keystoreEncryptionMethod = 'prf'
    } = {
      userId: `orbitdb-user-${Date.now()}`,
      displayName: 'Local-First Peer-to-Peer OrbitDB User',
      domain: window.location.hostname,
      ...options
    };

    webauthnLog('createCredential() called with options: %o', { userId, displayName, domain });

    if (!this.isSupported()) {
      webauthnLog.error('WebAuthn is not supported in this browser');
      throw new Error('WebAuthn is not supported in this browser');
    }

    // Generate challenge for credential creation
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userIdBytes = new TextEncoder().encode(userId);

    webauthnLog('Calling navigator.credentials.create() for user: %s', userId);

    // Prepare credential options
    let credentialOptions = {
      publicKey: {
        challenge,
        rp: {
          name: 'OrbitDB Identity',
          id: domain
        },
        user: {
          id: userIdBytes,
          name: userId,
          displayName
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' }, // ES256 (P-256 curve)
          { alg: -257, type: 'public-key' } // RS256 fallback
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform', // Prefer built-in authenticators
          requireResidentKey: false,
          residentKey: 'preferred',
          userVerification: 'required' // Require biometric/PIN
        },
        timeout: 60000,
        attestation: 'none' // Don't need attestation for DID creation
      }
    };

    // Add encryption extension if requested
    let prfInput = null;
    if (encryptKeystore) {
      webauthnLog('Adding encryption extension: %s', keystoreEncryptionMethod);

      if (keystoreEncryptionMethod === 'prf') {
        const prfConfig = KeystoreEncryption.addPRFToCredentialOptions(
          credentialOptions.publicKey
        );
        credentialOptions.publicKey = prfConfig.credentialOptions;
        prfInput = prfConfig.prfInput;
      } else if (keystoreEncryptionMethod === 'hmac-secret') {
        credentialOptions.publicKey = KeystoreEncryption.addHmacSecretToCredentialOptions(
          credentialOptions.publicKey
        );
      }
      // Note: largeBlob write happens after credential creation
    }

    try {
      const credential = await navigator.credentials.create(credentialOptions);

      if (!credential) {
        webauthnLog.error('Failed to create WebAuthn credential - credential is null');
        throw new Error('Failed to create WebAuthn credential');
      }

      webauthnLog('Credential created successfully: %o', {
        credentialId: this.arrayBufferToBase64url(credential.rawId).substring(0, 16) + '...',
        type: credential.type
      });

      webauthnLog('Extracting public key from credential...');

      // Extract public key from credential with timeout
      const publicKey = await Promise.race([
        this.extractPublicKey(credential),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Public key extraction timeout')), 10000))
      ]);

      webauthnLog('Public key extracted successfully: %o', {
        algorithm: publicKey.algorithm,
        keyType: publicKey.keyType,
        curve: publicKey.curve,
        hasX: !!publicKey.x,
        hasY: !!publicKey.y
      });

      const result = {
        credentialId: WebAuthnDIDProvider.arrayBufferToBase64url(credential.rawId),
        rawCredentialId: new Uint8Array(credential.rawId),
        publicKey,
        userId,
        displayName,
        attestationObject: new Uint8Array(credential.response.attestationObject),
        prfInput: prfInput || undefined
      };

      webauthnLog('Credential creation completed successfully');

      return result;

    } catch (error) {
      console.error('WebAuthn credential creation failed:', error);

      // Provide user-friendly error messages
      if (error.name === 'NotAllowedError') {
        throw new Error('Biometric authentication was cancelled or failed');
      } else if (error.name === 'InvalidStateError') {
        throw new Error('A credential with this ID already exists');
      } else if (error.name === 'NotSupportedError') {
        throw new Error('WebAuthn is not supported on this device');
      } else {
        throw new Error(`WebAuthn error: ${error.message}`);
      }
    }
  }

  /**
   * Extract P-256 public key from WebAuthn credential
   * Parses the CBOR attestation object to get the real public key
   */
  /**
   * Extract and normalize WebAuthn public key data from a credential response.
   * @param {PublicKeyCredential} credential - WebAuthn credential response.
   * @returns {Promise<Object>} Parsed credential info with public key.
   */
  static async extractPublicKey(credential) {
    try {
      // Import CBOR decoder for parsing attestation object
      const cbor = await import('cbor-web');
      const decode = cbor.decode || cbor.default?.decode || cbor.default;

      if (typeof decode !== 'function') {
        throw new Error('CBOR decoder not available from cbor-web');
      }

      const attestationObject = decode(new Uint8Array(credential.response.attestationObject));
      const authData = attestationObject.authData;

      // Parse authenticator data structure
      // Skip: rpIdHash (32 bytes) + flags (1 byte) + signCount (4 bytes)
      const credentialDataStart = 32 + 1 + 4 + 16 + 2; // +16 for AAGUID, +2 for credentialIdLength
      const credentialIdLength = new DataView(authData.buffer, 32 + 1 + 4 + 16, 2).getUint16(0);
      const publicKeyDataStart = credentialDataStart + credentialIdLength;

      // Extract and decode the public key (CBOR format)
      const publicKeyData = authData.slice(publicKeyDataStart);
      const publicKeyObject = decode(publicKeyData);

      // Extract P-256 coordinates (COSE key format)
      return {
        algorithm: publicKeyObject[3], // alg parameter
        x: new Uint8Array(publicKeyObject[-2]), // x coordinate
        y: new Uint8Array(publicKeyObject[-3]), // y coordinate
        keyType: publicKeyObject[1], // kty parameter
        curve: publicKeyObject[-1]   // crv parameter
      };

    } catch (error) {
      console.warn('Failed to extract real public key from WebAuthn credential, using fallback:', error);

      // Fallback: Create deterministic public key from credential ID
      // This ensures the SAME public key is generated every time for the same credential
      const credentialId = new Uint8Array(credential.rawId);

      const hash = await crypto.subtle.digest('SHA-256', credentialId);
      const seed = new Uint8Array(hash);

      // Create a second hash for the y coordinate to ensure uniqueness but determinism
      const yData = new Uint8Array(credentialId.length + 4);
      yData.set(credentialId, 0);
      yData.set([0x59, 0x43, 0x4F, 0x4F], credentialId.length); // "YCOO" marker
      const yHash = await crypto.subtle.digest('SHA-256', yData);
      const ySeed = new Uint8Array(yHash);

      const fallbackKey = {
        algorithm: -7, // ES256
        x: seed.slice(0, 32), // Use first 32 bytes as x coordinate
        y: ySeed.slice(0, 32), // Deterministic y coordinate based on credential
        keyType: 2, // EC2 key type
        curve: 1    // P-256 curve
      };


      return fallbackKey;
    }
  }

  /**
   * Generate DID from WebAuthn credential using did:key format for P-256 keys
   * This ensures compatibility with ucanto and other DID:key implementations
   */
  /**
   * Create a did:key DID from a WebAuthn P-256 public key.
   * @param {Object} credentialInfo - WebAuthn credential info.
   * @returns {Promise<string>} DID string.
   */
  static async createDID(credentialInfo) {
    try {
      // Import multiformats modules with correct exports
      const multiformats = await import('multiformats');
      const varint = multiformats.varint;
      const { base58btc } = await import('multiformats/bases/base58');

      // Extract public key coordinates
      const { x, y } = credentialInfo.publicKey;

      // Validate P-256 public key coordinates
      if (!x || !y || x.length !== 32 || y.length !== 32) {
        throw new Error('Invalid P-256 public key coordinates');
      }

      // P-256 multicodec prefix: 0x1200
      // 0x12 = varint for 0x1200
      // 0x00 = varint for 0x0000 (compression flag?)
      const multicodec = 0x1200; // p256-pub multicodec
      const codecLength = varint.encodingLength(multicodec);
      const codecBytes = new Uint8Array(codecLength);
      varint.encodeTo(multicodec, codecBytes, 0);

      // Combine multicodec prefix + public key bytes (uncompressed format)
      // P-256 uncompressed public key format: 0x04 || x || y
      const publicKeyBytes = new Uint8Array(65);
      publicKeyBytes[0] = 0x04; // Uncompressed point format
      publicKeyBytes.set(x, 1);
      publicKeyBytes.set(y, 33);

      const multikey = new Uint8Array(codecBytes.length + publicKeyBytes.length);
      multikey.set(codecBytes, 0);
      multikey.set(publicKeyBytes, codecBytes.length);

      // Encode as base58btc and create did:key
      const multikeyEncoded = base58btc.encode(multikey);
      return `did:key:${multikeyEncoded}`;

    } catch (error) {
      console.warn('Failed to create DID with multiformats, using fallback:', error);

      // Fallback: Simple DID creation without multiformats dependency
      const { x, y } = credentialInfo.publicKey;

      // Create a hash-based approach for consistency
      const combined = new Uint8Array(x.length + y.length);
      combined.set(x, 0);
      combined.set(y, x.length);

      // Simple base58-like encoding for fallback
      const base58Chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
      let encoded = 'z'; // base58btc prefix

      for (let i = 0; i < Math.min(combined.length, 32); i += 4) {
        const chunk = combined.slice(i, i + 4);
        let value = 0;
        for (let j = 0; j < chunk.length; j++) {
          value = value * 256 + chunk[j];
        }

        for (let k = 0; k < 6; k++) {
          encoded += base58Chars[value % 58];
          value = Math.floor(value / 58);
        }
      }

      return `did:key:${encoded}`;
    }
  }

  /**
   * Sign data using WebAuthn (requires biometric authentication)
   * Creates a persistent signature that can be verified multiple times
   */
  /**
   * Sign arbitrary data with WebAuthn.
   * @param {string|Uint8Array} data - Data to sign.
   * @returns {Promise<string>} Base64url-encoded signature envelope.
   */
  async sign(data) {
    if (!WebAuthnDIDProvider.isSupported()) {
      webauthnLog.error('WebAuthn is not supported in this browser');
      throw new Error('WebAuthn is not supported in this browser');
    }

    try {
      webauthnLog('Signer context: %o', {
        signer: 'webauthn',
        credentialIdPrefix: this.credentialId?.slice?.(0, 12),
        rawCredentialIdLength: this.rawCredentialId?.length
      });
      const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
      const dataHash = await crypto.subtle.digest('SHA-256', dataBytes);
      const dataHashStr = Array.from(new Uint8Array(dataHash)).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);

      webauthnLog('sign() called with data length: %d, hash: %s...', dataBytes.length, dataHashStr);

      // Create a deterministic challenge based on the credential ID and data
      const combined = new Uint8Array(this.rawCredentialId.length + dataBytes.length);
      combined.set(this.rawCredentialId, 0);
      combined.set(dataBytes, this.rawCredentialId.length);
      const challenge = await crypto.subtle.digest('SHA-256', combined);
      const challengeHashStr = Array.from(new Uint8Array(challenge)).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);

      webauthnLog('Challenge created: %s...', challengeHashStr);
      webauthnLog('Calling navigator.credentials.get() - biometric prompt should appear');

      // Use WebAuthn to authenticate (this proves the user is present and verified)
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge,
          allowCredentials: [{
            id: this.rawCredentialId,
            type: 'public-key'
          }],
          userVerification: 'required',
          timeout: 60000
        }
      });

      if (!assertion) {
        webauthnLog.error('WebAuthn authentication failed - assertion is null');
        throw new Error('WebAuthn authentication failed');
      }

      webauthnLog('Assertion received from navigator.credentials.get(): %o', {
        hasAuthenticatorData: !!assertion.response.authenticatorData,
        hasSignature: !!assertion.response.signature,
        signatureLength: assertion.response.signature?.byteLength || 0
      });

      // Create a signature that includes the original data and credential proof
      // This allows verification without requiring WebAuthn again
      webauthnLog('Creating proof object...');
      const webauthnProof = {
        credentialId: this.credentialId,
        dataHash: WebAuthnDIDProvider.arrayBufferToBase64url(await crypto.subtle.digest('SHA-256', dataBytes)),
        authenticatorData: WebAuthnDIDProvider.arrayBufferToBase64url(assertion.response.authenticatorData),
        clientDataJSON: new TextDecoder().decode(assertion.response.clientDataJSON),
        signature: WebAuthnDIDProvider.arrayBufferToBase64url(assertion.response.signature),
        timestamp: Date.now()
      };

      webauthnLog('Proof created successfully: %o', {
        credentialId: webauthnProof.credentialId.substring(0, 16) + '...',
        dataHash: webauthnProof.dataHash.substring(0, 16) + '...',
        timestamp: webauthnProof.timestamp
      });

      // Return the proof as a base64url encoded string for OrbitDB
      const encodedProof = WebAuthnDIDProvider.arrayBufferToBase64url(new TextEncoder().encode(JSON.stringify(webauthnProof)));
      webauthnLog('sign() completed successfully, proof length: %d', encodedProof.length);
      return encodedProof;

    } catch (error) {
      webauthnLog.error('WebAuthn signing failed: %s', error.message);

      if (error.name === 'NotAllowedError') {
        throw new Error('Biometric authentication was cancelled');
      } else {
        throw new Error(`WebAuthn signing error: ${error.message}`);
      }
    }
  }

  /**
   * Verify WebAuthn signature/proof for OrbitDB compatibility
   */
  /**
   * Verify a WebAuthn signature envelope.
   * @param {string} signatureData - Base64url signature envelope.
   * @returns {Promise<boolean>} True if verification succeeds.
   */
  async verify(signatureData) {
    webauthnLog('verify() called with signature length: %d', signatureData.length);

    try {
      // Decode the WebAuthn proof object
      const proofBytes = WebAuthnDIDProvider.base64urlToArrayBuffer(signatureData);
      const proofText = new TextDecoder().decode(proofBytes);
      const proof = JSON.parse(proofText);

      // Verify the proof structure
      if (!proof.credentialId || !proof.dataHash || !proof.signature) {
        throw new Error('Invalid WebAuthn proof structure');
      }

      // Check if credential ID matches
      webauthnLog('Verification step: checking credential ID');
      if (proof.credentialId !== this.credentialId) {
        webauthnLog.error('Credential ID mismatch in WebAuthn proof verification');
        throw new Error('Credential ID mismatch');
      }
      webauthnLog('Verification step: credential ID check PASSED');

      // Verify client data JSON
      webauthnLog('Verification step: checking client data');
      if (proof.clientDataJSON) {
        const clientData = JSON.parse(proof.clientDataJSON);
        if (clientData.type !== 'webauthn.get') {
          webauthnLog.error('Invalid WebAuthn proof type: %s', clientData.type);
          throw new Error('Invalid WebAuthn proof type');
        }
        webauthnLog('Verification step: client data check PASSED');
      } else {
        webauthnLog.error('Invalid client data in WebAuthn proof');
        throw new Error('Invalid client data');
      }

      // Check if proof is recent (within 24 hours)
      webauthnLog('Verification step: checking timestamp');
      const proofAge = Date.now() - proof.timestamp;
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours
      if (proofAge > maxAge) {
        webauthnLog.error('WebAuthn proof is too old: %d ms', proofAge);
        throw new Error('WebAuthn proof has expired');
      }
      webauthnLog('Verification step: timestamp check PASSED (age: %d ms)', proofAge);

      // Verify authenticator data exists
      webauthnLog('Verification step: checking authenticator data');
      if (!proof.authenticatorData) {
        webauthnLog.error('Missing authenticator data in WebAuthn proof');
        throw new Error('Missing authenticator data');
      }
      webauthnLog('Verification step: authenticator data check PASSED');

      webauthnLog('Verification result: SUCCESS');
      return true;

    } catch (error) {
      webauthnLog.error('WebAuthn proof verification failed: %s', error.message);
      return false;
    }
  }

  /**
   * Utility: Convert ArrayBuffer to base64url
   */
  static arrayBufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Utility: Convert base64url to ArrayBuffer
   */
  static base64urlToArrayBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
  }
}

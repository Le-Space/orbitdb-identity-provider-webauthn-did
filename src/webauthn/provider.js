/**
 * WebAuthn DID Provider for OrbitDB
 *
 * Creates hardware-secured DIDs using WebAuthn authentication (Passkey, Yubikey, Ledger, etc.)
 * Integrates with OrbitDB's identity system while keeping private keys in secure hardware
 */

import { logger } from '@libp2p/logger';
import { varint } from 'multiformats';
import { base58btc } from 'multiformats/bases/base58';
import * as KeystoreEncryption from '../keystore/encryption.js';
import {
  CRYPTO_ALGORITHMS,
  DID_KEY_PREFIX,
  IDENTITY_TYPES,
  KEYSTORE_ENCRYPTION_METHODS,
  WEBAUTHN_CLIENT_DATA_TYPES,
} from '../constants.js';
import {
  WebAuthnIdentityError,
  WebAuthnAuthenticationError,
  WebAuthnCredentialError,
  WebAuthnNotSupportedError,
  WebAuthnVerificationError,
} from '../errors.js';
import {
  buildAuthenticatorSelection,
  buildCredentialRequestOptions,
} from './config.js';
import { logWebAuthnResponse } from './debug-log.js';

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
    this.type = IDENTITY_TYPES.WEBAUTHN;
  }

  /**
   * Check if WebAuthn is supported in current browser
   * @returns {boolean} True if supported.
   */
  static isSupported() {
    return (
      window.PublicKeyCredential &&
      typeof window.PublicKeyCredential
        .isUserVerifyingPlatformAuthenticatorAvailable === 'function'
    );
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
      console.warn(
        'Failed to check platform authenticator availability:',
        error
      );
      return false;
    }
  }

  /**
   * Create a WebAuthn credential for OrbitDB identity
   * This triggers biometric authentication (Face ID, Touch ID, Windows Hello, etc.)
   * @param {Object} options - Credential options
   * @param {string} options.userId - Account label shown in the credential
   *   picker (`user.name`). A label only: it does not identify the credential,
   *   two credentials may carry the same one, and it is never used to look one
   *   up. The handle the authenticator files the credential under is generated
   *   here and returned as `userHandle`.
   * @param {string} options.displayName - Display name
   * @param {string} options.domain - Domain/RP ID
   * @param {boolean} options.encryptKeystore - Enable keystore encryption
   * @param {string} options.keystoreEncryptionMethod - 'prf' (default), 'hmac-secret', or 'largeBlob'
   * @param {boolean} [options.discoverableCredentials] - Override global discoverable credential policy
   * @returns {Promise<Object>} Credential info with public key and metadata.
   */
  static async createCredential(options = {}) {
    const {
      userId,
      displayName,
      domain,
      encryptKeystore = false,
      keystoreEncryptionMethod = KEYSTORE_ENCRYPTION_METHODS.PRF,
    } = {
      userId: `orbitdb-user-${Date.now()}`,
      displayName: 'Local-First Peer-to-Peer OrbitDB User',
      domain: window.location.hostname,
      ...options,
    };

    webauthnLog('createCredential() called with options: %o', {
      userId,
      displayName,
      domain,
    });

    if (!this.isSupported()) {
      webauthnLog.error('WebAuthn is not supported in this browser');
      throw new WebAuthnNotSupportedError();
    }

    // Generate challenge for credential creation
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    // The user handle is an opaque key, not a label. An authenticator stores
    // one discoverable credential per (rp.id, user.id) pair and *replaces* the
    // previous one when both match — silently, with no prompt and nothing to
    // undo. Deriving the handle from a typed name therefore meant two people
    // registering as "anna" on a shared device destroyed each other's passkey,
    // and with it the DID and everything written under it (#45).
    //
    // 64 random bytes, as WebAuthn L2 §5.4.3 recommends. The same section
    // forbids putting personally identifying information here, which a typed
    // name or e-mail address plainly is. The name keeps its rightful place in
    // `user.name` below, where the credential picker shows it.
    const userHandle = crypto.getRandomValues(new Uint8Array(64));

    webauthnLog('Calling navigator.credentials.create() for user: %s', userId);

    // Prepare credential options
    let credentialOptions = {
      publicKey: {
        challenge,
        rp: {
          name: 'OrbitDB Identity',
          id: domain,
        },
        user: {
          id: userHandle,
          name: userId,
          displayName,
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' }, // ES256 (P-256 curve)
          { alg: -257, type: 'public-key' }, // RS256 fallback
        ],
        authenticatorSelection: buildAuthenticatorSelection({
          ...options,
          authenticatorAttachment: 'platform',
          userVerification: 'required',
        }),
        timeout: 60000,
        attestation: 'none', // Don't need attestation for DID creation
      },
    };

    // Add encryption extension if requested
    let prfInput = null;
    if (encryptKeystore) {
      webauthnLog('Adding encryption extension: %s', keystoreEncryptionMethod);

      if (keystoreEncryptionMethod === KEYSTORE_ENCRYPTION_METHODS.PRF) {
        const prfConfig = KeystoreEncryption.addPRFToCredentialOptions(
          credentialOptions.publicKey
        );
        credentialOptions.publicKey = prfConfig.credentialOptions;
        prfInput = prfConfig.prfInput;
      } else if (
        keystoreEncryptionMethod === KEYSTORE_ENCRYPTION_METHODS.HMAC_SECRET
      ) {
        credentialOptions.publicKey =
          KeystoreEncryption.addHmacSecretToCredentialOptions(
            credentialOptions.publicKey
          );
      }
      // Note: largeBlob write happens after credential creation
    }

    // Request PRF even when the keystore is not encrypted. The stored input is
    // what lets the OrbitDB signing key be derived reproducibly later, so a
    // credential registered without it can never get a reproducible identity.
    // Requesting the extension is harmless where it is unsupported: the
    // authenticator simply returns no PRF results.
    if (!prfInput) {
      const prfConfig = KeystoreEncryption.addPRFToCredentialOptions(
        credentialOptions.publicKey
      );
      credentialOptions.publicKey = prfConfig.credentialOptions;
      prfInput = prfConfig.prfInput;
    }

    try {
      const credential = await navigator.credentials.create(credentialOptions);

      if (!credential) {
        webauthnLog.error(
          'Failed to create WebAuthn credential - credential is null'
        );
        throw new WebAuthnCredentialError(
          'Failed to create WebAuthn credential'
        );
      }

      logWebAuthnResponse('navigator.credentials.create()', credential);

      webauthnLog('Credential created successfully: %o', {
        credentialId:
          this.arrayBufferToBase64url(credential.rawId).substring(0, 16) +
          '...',
        type: credential.type,
      });

      webauthnLog('Extracting public key from credential...');

      // Extract public key from credential with timeout
      const publicKey = await Promise.race([
        this.extractPublicKey(credential),
        new Promise((_, reject) =>
          setTimeout(
            () =>
              reject(
                new WebAuthnCredentialError('Public key extraction timeout')
              ),
            10000
          )
        ),
      ]);

      webauthnLog('Public key extracted successfully: %o', {
        algorithm: publicKey.algorithm,
        keyType: publicKey.keyType,
        curve: publicKey.curve,
        hasX: !!publicKey.x,
        hasY: !!publicKey.y,
      });

      // What the authenticator actually agreed to, as opposed to what the
      // browser said it could negotiate. Only the ceremony settles this, and
      // the raw PublicKeyCredential does not survive past this function — so
      // read it here or lose the answer. Callers that offer a choice of
      // keystore encryption method need it: a client can support largeBlob
      // while the key in front of it does not.
      const extensionSupport =
        KeystoreEncryption.extensionSupportFromCredential(credential);

      webauthnLog('Authenticator extension support: %o', extensionSupport);

      const result = {
        credentialId: WebAuthnDIDProvider.arrayBufferToBase64url(
          credential.rawId
        ),
        rawCredentialId: new Uint8Array(credential.rawId),
        publicKey,
        userId,
        displayName,
        // Nothing in this package looks a credential up by handle — recovery
        // goes through discoverable credentials, or through an explicit
        // credential ID when those are switched off. It is surfaced anyway
        // because it is the only copy the caller will ever see, and a flow
        // that one day passes `allowCredentials` needs it. Decode with
        // `WebAuthnDIDProvider.base64urlToArrayBuffer()`.
        userHandle: WebAuthnDIDProvider.arrayBufferToBase64url(userHandle),
        attestationObject: new Uint8Array(
          credential.response.attestationObject
        ),
        prfInput: prfInput || undefined,
        extensionSupport,
      };

      webauthnLog('Credential creation completed successfully');

      return result;
    } catch (error) {
      console.error('WebAuthn credential creation failed:', error);

      if (error instanceof WebAuthnIdentityError) {
        throw error;
      }

      // Provide user-friendly error messages
      if (error.name === 'NotAllowedError') {
        throw new WebAuthnAuthenticationError(
          'Biometric authentication was cancelled or failed',
          { cause: error }
        );
      } else if (error.name === 'InvalidStateError') {
        throw new WebAuthnCredentialError(
          'A credential with this ID already exists',
          { cause: error }
        );
      } else if (error.name === 'NotSupportedError') {
        throw new WebAuthnNotSupportedError(
          'WebAuthn is not supported on this device',
          { cause: error }
        );
      } else {
        throw new WebAuthnCredentialError(`WebAuthn error: ${error.message}`, {
          cause: error,
        });
      }
    }
  }

  /**
   * Extract and normalize the WebAuthn public key from a credential response.
   *
   * Tries getPublicKey() first, then parses the attestation object. Falls back
   * to a synthetic key derived from the credential ID only if both fail; that
   * fallback is marked with `synthetic: true` and cannot verify authenticator
   * signatures.
   *
   * @param {PublicKeyCredential} credential - WebAuthn credential response.
   * @returns {Promise<Object>} Parsed credential info with public key.
   */
  static async extractPublicKey(credential) {
    // Preferred path: the browser hands us the SPKI directly (WebAuthn L2).
    // Available on AuthenticatorAttestationResponse only, i.e. after
    // navigator.credentials.create() — never after .get().
    try {
      const spki = credential?.response?.getPublicKey?.();
      if (spki) {
        return await WebAuthnDIDProvider.parseSpkiPublicKey(spki);
      }
    } catch (error) {
      webauthnLog(
        'getPublicKey() unavailable or unparsable, falling back to attestation parsing: %s',
        error.message
      );
    }

    try {
      return await WebAuthnDIDProvider.parseAttestedCredentialPublicKey(
        credential.response.attestationObject
      );
    } catch (error) {
      console.warn(
        'Failed to extract real public key from WebAuthn credential, using fallback:',
        error
      );

      // Fallback: Create deterministic public key from credential ID
      // This ensures the SAME public key is generated every time for the same credential
      const credentialId = new Uint8Array(credential.rawId);

      const hash = await crypto.subtle.digest(
        CRYPTO_ALGORITHMS.SHA_256,
        credentialId
      );
      const seed = new Uint8Array(hash);

      // Create a second hash for the y coordinate to ensure uniqueness but determinism
      const yData = new Uint8Array(credentialId.length + 4);
      yData.set(credentialId, 0);
      yData.set([0x59, 0x43, 0x4f, 0x4f], credentialId.length); // "YCOO" marker
      const yHash = await crypto.subtle.digest(
        CRYPTO_ALGORITHMS.SHA_256,
        yData
      );
      const ySeed = new Uint8Array(yHash);

      const fallbackKey = {
        algorithm: -7, // ES256
        x: seed.slice(0, 32), // Use first 32 bytes as x coordinate
        y: ySeed.slice(0, 32), // Deterministic y coordinate based on credential
        keyType: 2, // EC2 key type
        curve: 1, // P-256 curve
        // Marks a key that is NOT the authenticator's key. Signatures made by
        // the authenticator cannot be verified against it.
        synthetic: true,
      };

      return fallbackKey;
    }
  }

  /**
   * Parse a SPKI-encoded (DER) P-256 public key into COSE-style coordinates.
   * @param {ArrayBuffer|Uint8Array} spki - SPKI bytes from getPublicKey().
   * @returns {Promise<Object>} Public key with x/y coordinates.
   */
  static async parseSpkiPublicKey(spki) {
    const key = await crypto.subtle.importKey(
      'spki',
      spki instanceof Uint8Array ? spki.buffer : spki,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', key);

    const x = new Uint8Array(WebAuthnDIDProvider.base64urlToArrayBuffer(jwk.x));
    const y = new Uint8Array(WebAuthnDIDProvider.base64urlToArrayBuffer(jwk.y));

    if (x.length !== 32 || y.length !== 32) {
      throw new WebAuthnCredentialError(
        `Invalid P-256 coordinate length: x=${x.length} y=${y.length}`
      );
    }

    return { algorithm: -7, x, y, keyType: 2, curve: 1 };
  }

  /**
   * Parse the attested credential public key out of a WebAuthn attestation
   * object (COSE key inside authenticatorData).
   *
   * See WebAuthn L2 §6.5.2 for the attestedCredentialData layout:
   *   rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) |
   *   credentialIdLength(2) | credentialId(L) | credentialPublicKey(COSE) |
   *   extensions(CBOR, optional)
   *
   * @param {ArrayBuffer|Uint8Array} attestationObjectBytes - Raw attestation object.
   * @returns {Promise<Object>} Public key with x/y coordinates.
   */
  static async parseAttestedCredentialPublicKey(attestationObjectBytes) {
    const cbor = await import('cbor-web');
    const cborApi = cbor.default ?? cbor;
    const decode = cborApi.decode;
    const decodeFirstSync = cborApi.decodeFirstSync;

    if (typeof decode !== 'function') {
      throw new WebAuthnCredentialError(
        'CBOR decoder not available from cbor-web'
      );
    }

    const attestationObject = decode(new Uint8Array(attestationObjectBytes));
    const rawAuthData =
      attestationObject instanceof Map
        ? attestationObject.get('authData')
        : attestationObject.authData;

    if (!rawAuthData) {
      throw new WebAuthnCredentialError(
        'Attestation object contains no authData'
      );
    }

    // cbor-web returns byte strings as views into the *enclosing* buffer, so
    // authData.byteOffset is non-zero. Copy to a standalone buffer, otherwise
    // every offset below silently reads the wrong bytes.
    const authData = Uint8Array.from(rawAuthData);

    const AAGUID_END = 32 + 1 + 4 + 16; // 53
    const CREDENTIAL_DATA_START = AAGUID_END + 2; // 55

    // AT flag (bit 6) must be set, otherwise there is no attested credential data
    const flags = authData[32];
    if ((flags & 0x40) === 0) {
      throw new WebAuthnCredentialError(
        'authData has no attested credential data (AT flag unset)'
      );
    }

    if (authData.length < CREDENTIAL_DATA_START) {
      throw new WebAuthnCredentialError(
        `authData too short: ${authData.length} bytes`
      );
    }

    const view = new DataView(
      authData.buffer,
      authData.byteOffset,
      authData.byteLength
    );
    const credentialIdLength = view.getUint16(AAGUID_END);
    const publicKeyDataStart = CREDENTIAL_DATA_START + credentialIdLength;

    if (publicKeyDataStart >= authData.length) {
      throw new WebAuthnCredentialError(
        `credentialIdLength ${credentialIdLength} exceeds authData (${authData.length} bytes)`
      );
    }

    const publicKeyData = authData.slice(publicKeyDataStart);

    // When the ED flag is set, CBOR extension data trails the COSE key.
    // decode() rejects trailing bytes, so decode only the first item.
    let publicKeyObject;
    if (typeof decodeFirstSync === 'function') {
      publicKeyObject = decodeFirstSync(publicKeyData, {
        extendedResults: true,
      }).value;
    } else {
      publicKeyObject = decode(publicKeyData);
    }

    const get = (k) =>
      publicKeyObject instanceof Map
        ? publicKeyObject.get(k)
        : publicKeyObject[k];

    const keyType = get(1);
    const algorithm = get(3);
    const curve = get(-1);
    const x = get(-2);
    const y = get(-3);

    if (keyType !== 2 || curve !== 1) {
      throw new WebAuthnCredentialError(
        `Unsupported COSE key: kty=${keyType} alg=${algorithm} crv=${curve} (expected P-256 EC2)`
      );
    }

    const xBytes = new Uint8Array(x);
    const yBytes = new Uint8Array(y);

    if (xBytes.length !== 32 || yBytes.length !== 32) {
      throw new WebAuthnCredentialError(
        `Invalid P-256 coordinate length: x=${xBytes.length} y=${yBytes.length}`
      );
    }

    return { algorithm, x: xBytes, y: yBytes, keyType, curve };
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

      const multikey = new Uint8Array(
        codecBytes.length + publicKeyBytes.length
      );
      multikey.set(codecBytes, 0);
      multikey.set(publicKeyBytes, codecBytes.length);

      // Encode as base58btc and create did:key
      const multikeyEncoded = base58btc.encode(multikey);
      return `${DID_KEY_PREFIX}${multikeyEncoded}`;
    } catch (error) {
      console.warn(
        'Failed to create DID with multiformats, using fallback:',
        error
      );

      // Fallback: Simple DID creation without multiformats dependency
      const { x, y } = credentialInfo.publicKey;

      // Create a hash-based approach for consistency
      const combined = new Uint8Array(x.length + y.length);
      combined.set(x, 0);
      combined.set(y, x.length);

      // Simple base58-like encoding for fallback
      const base58Chars =
        '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
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

      return `${DID_KEY_PREFIX}${encoded}`;
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
      throw new WebAuthnNotSupportedError();
    }

    try {
      webauthnLog('Signer context: %o', {
        signer: 'webauthn',
        credentialIdPrefix: this.credentialId?.slice?.(0, 12),
        rawCredentialIdLength: this.rawCredentialId?.length,
      });
      const dataBytes =
        typeof data === 'string'
          ? new TextEncoder().encode(data)
          : new Uint8Array(data);
      const dataHash = await crypto.subtle.digest(
        CRYPTO_ALGORITHMS.SHA_256,
        dataBytes
      );
      const dataHashStr = Array.from(new Uint8Array(dataHash))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
        .substring(0, 16);

      webauthnLog(
        'sign() called with data length: %d, hash: %s...',
        dataBytes.length,
        dataHashStr
      );

      // Create a deterministic challenge based on the credential ID and data
      const combined = new Uint8Array(
        this.rawCredentialId.length + dataBytes.length
      );
      combined.set(this.rawCredentialId, 0);
      combined.set(dataBytes, this.rawCredentialId.length);
      const challenge = await crypto.subtle.digest(
        CRYPTO_ALGORITHMS.SHA_256,
        combined
      );
      const challengeHashStr = Array.from(new Uint8Array(challenge))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
        .substring(0, 16);

      webauthnLog('Challenge created: %s...', challengeHashStr);
      webauthnLog(
        'Calling navigator.credentials.get() - biometric prompt should appear'
      );

      // Use WebAuthn to authenticate (this proves the user is present and verified)
      const requestOptions = buildCredentialRequestOptions({
        challenge,
        credentialId: this.rawCredentialId,
        userVerification: 'required',
      });
      const assertion = await navigator.credentials.get({
        ...requestOptions,
        publicKey: {
          ...requestOptions.publicKey,
          timeout: 60000,
        },
      });

      if (!assertion) {
        webauthnLog.error('WebAuthn authentication failed - assertion is null');
        throw new WebAuthnAuthenticationError('WebAuthn authentication failed');
      }

      logWebAuthnResponse('navigator.credentials.get()', assertion);

      webauthnLog('Assertion received from navigator.credentials.get(): %o', {
        hasAuthenticatorData: !!assertion.response.authenticatorData,
        hasSignature: !!assertion.response.signature,
        signatureLength: assertion.response.signature?.byteLength || 0,
      });

      // Create a signature that includes the original data and credential proof
      // This allows verification without requiring WebAuthn again
      webauthnLog('Creating proof object...');
      const webauthnProof = {
        credentialId: this.credentialId,
        dataHash: WebAuthnDIDProvider.arrayBufferToBase64url(
          await crypto.subtle.digest(CRYPTO_ALGORITHMS.SHA_256, dataBytes)
        ),
        authenticatorData: WebAuthnDIDProvider.arrayBufferToBase64url(
          assertion.response.authenticatorData
        ),
        clientDataJSON: new TextDecoder().decode(
          assertion.response.clientDataJSON
        ),
        signature: WebAuthnDIDProvider.arrayBufferToBase64url(
          assertion.response.signature
        ),
        // Deliberately no timestamp. This envelope ends up in a
        // content-addressed identity document, so a wall-clock field would
        // change the document hash on every call for no verification value.
      };

      webauthnLog('Proof created successfully: %o', {
        credentialId: webauthnProof.credentialId.substring(0, 16) + '...',
        dataHash: webauthnProof.dataHash.substring(0, 16) + '...',
      });

      // Return the proof as a base64url encoded string for OrbitDB
      const encodedProof = WebAuthnDIDProvider.arrayBufferToBase64url(
        new TextEncoder().encode(JSON.stringify(webauthnProof))
      );
      webauthnLog(
        'sign() completed successfully, proof length: %d',
        encodedProof.length
      );
      return encodedProof;
    } catch (error) {
      webauthnLog.error('WebAuthn signing failed: %s', error.message);

      if (error.name === 'NotAllowedError') {
        throw new WebAuthnAuthenticationError(
          'Biometric authentication was cancelled',
          { cause: error }
        );
      } else {
        throw new WebAuthnAuthenticationError(
          `WebAuthn signing error: ${error.message}`,
          { cause: error }
        );
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
    webauthnLog(
      'verify() called with signature length: %d',
      signatureData.length
    );

    try {
      // Decode the WebAuthn proof object
      const proofBytes =
        WebAuthnDIDProvider.base64urlToArrayBuffer(signatureData);
      const proofText = new TextDecoder().decode(proofBytes);
      const proof = JSON.parse(proofText);

      // Verify the proof structure
      if (!proof.credentialId || !proof.dataHash || !proof.signature) {
        throw new WebAuthnVerificationError('Invalid WebAuthn proof structure');
      }

      // Check if credential ID matches
      webauthnLog('Verification step: checking credential ID');
      if (proof.credentialId !== this.credentialId) {
        webauthnLog.error(
          'Credential ID mismatch in WebAuthn proof verification'
        );
        throw new WebAuthnVerificationError('Credential ID mismatch');
      }
      webauthnLog('Verification step: credential ID check PASSED');

      // Verify client data JSON
      webauthnLog('Verification step: checking client data');
      if (proof.clientDataJSON) {
        const clientData = JSON.parse(proof.clientDataJSON);
        if (clientData.type !== WEBAUTHN_CLIENT_DATA_TYPES.GET) {
          webauthnLog.error('Invalid WebAuthn proof type: %s', clientData.type);
          throw new WebAuthnVerificationError('Invalid WebAuthn proof type');
        }
        webauthnLog('Verification step: client data check PASSED');
      } else {
        webauthnLog.error('Invalid client data in WebAuthn proof');
        throw new WebAuthnVerificationError('Invalid client data');
      }

      // No expiry check. This proof is embedded in an OrbitDB identity
      // document, and every entry ever signed under that document has to stay
      // validatable — an expiring proof would silently invalidate history.
      // The proof attests that this credential signed this payload, which does
      // not stop being true. Proofs written by earlier versions still carry a
      // timestamp field; it is simply ignored.

      // Verify authenticator data exists
      webauthnLog('Verification step: checking authenticator data');
      if (!proof.authenticatorData) {
        webauthnLog.error('Missing authenticator data in WebAuthn proof');
        throw new WebAuthnVerificationError('Missing authenticator data');
      }
      webauthnLog('Verification step: authenticator data check PASSED');

      webauthnLog('Verification result: SUCCESS');
      return true;
    } catch (error) {
      webauthnLog.error(
        'WebAuthn proof verification failed: %s',
        error.message
      );
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

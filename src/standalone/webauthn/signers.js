import { WebAuthnVarsigProvider } from '../../varsig/provider.js';
import { createWebAuthnVarsigCredential } from '../../varsig/credential.js';

const wrapQueuedSign = (signer) => {
  let pending = Promise.resolve();
  const queued = Object.create(signer);
  queued.sign = async (data) => {
    const run = pending.then(() => signer.sign(data), () => signer.sign(data));
    pending = run.then(() => undefined, () => undefined);
    return run;
  };
  return queued;
};

const UCAN_SIGNATURE_CODES = {
  EdDSA: 0xd0ed,
  ES256: 0xd01200
};

function normalizeCredentialId(credentialId) {
  if (credentialId instanceof Uint8Array) return credentialId;
  if (credentialId instanceof ArrayBuffer) return new Uint8Array(credentialId);
  if (ArrayBuffer.isView(credentialId)) {
    return new Uint8Array(credentialId.buffer, credentialId.byteOffset, credentialId.byteLength);
  }
  if (Array.isArray(credentialId)) return new Uint8Array(credentialId);
  throw new Error('Unsupported credentialId type');
}

/**
 * Standalone WebAuthn varsig signer wrapper.
 */
export class StandaloneWebAuthnVarsigSigner {
  constructor(credential) {
    this.credential = {
      ...credential,
      credentialId: normalizeCredentialId(credential.credentialId)
    };
    this.did = credential.did;
    this.publicKey = credential.publicKey;
    this.algorithm = credential.algorithm;
    this.type = 'webauthn-varsig';
    this.provider = new WebAuthnVarsigProvider(this.credential);
  }

  getDid() {
    return this.did;
  }

  getCredentialId() {
    return this.credential.credentialId;
  }

  /**
   * Sign bytes or string data with WebAuthn varsig.
   * @param {string|Uint8Array} data
   * @param {string} [domainLabel]
   * @returns {Promise<Uint8Array>}
   */
  async sign(data, domainLabel) {
    return this.provider.sign(data, domainLabel);
  }

  /**
   * Verify varsig for bytes or string data.
   * @param {Uint8Array} signature
   * @param {string|Uint8Array} data
   * @param {string} [domainLabel]
   * @returns {Promise<boolean>}
   */
  async verify(signature, data, domainLabel) {
    return this.provider.verify(signature, this.credential.publicKey, data, domainLabel);
  }

  /**
   * Create an object with UCAN signer-compatible surface.
   * This mirrors the upload-wall signer contract.
   */
  toUcantoSigner() {
    const signatureAlgorithm = this.algorithm === 'Ed25519' ? 'EdDSA' : 'ES256';
    const signatureCode =
      signatureAlgorithm === 'EdDSA'
        ? UCAN_SIGNATURE_CODES.EdDSA
        : UCAN_SIGNATURE_CODES.ES256;

    const getSignatureParams = async () => {
      const DagUcanSignature = await import('@ipld/dag-ucan/signature');
      return {
        signatureAlgorithm,
        signatureCode,
        signatureCreate: DagUcanSignature.create
      };
    };

    const signer = {
      sign: async (payload) => {
        const varsig = await this.sign(payload);
        const { signatureCode, signatureCreate } = await getSignatureParams();
        return signatureCreate(signatureCode, varsig);
      },
      did: () => this.did,
      toDIDKey: () => this.did,
      signatureAlgorithm,
      signatureCode,
      encode: () => this.publicKey,
      toArchive: () => ({
        id: this.did,
        keys: {
          [this.did]: this.publicKey
        }
      }),
      export: () => {
        throw new Error('Cannot export WebAuthn hardware-backed keys');
      }
    };

    return wrapQueuedSign(signer);
  }
}

export class WebAuthnEd25519Signer extends StandaloneWebAuthnVarsigSigner {
  constructor(credentialId, did, publicKey) {
    super({
      credentialId: normalizeCredentialId(credentialId),
      did,
      publicKey,
      algorithm: 'Ed25519',
      cose: null
    });
  }
}

export class WebAuthnP256Signer extends StandaloneWebAuthnVarsigSigner {
  constructor(credentialId, did, publicKey) {
    super({
      credentialId: normalizeCredentialId(credentialId),
      did,
      publicKey,
      algorithm: 'P-256',
      cose: null
    });
  }
}

/**
 * Create a standalone WebAuthn varsig signer (Ed25519 preferred, P-256 fallback).
 * @param {Object} [options]
 * @returns {Promise<StandaloneWebAuthnVarsigSigner>}
 */
export async function createWebAuthnSigner(options = {}) {
  const credential = await createWebAuthnVarsigCredential(options);
  return new StandaloneWebAuthnVarsigSigner(credential);
}

/**
 * Create a standalone WebAuthn varsig signer and require Ed25519.
 * @param {Object} [options]
 * @returns {Promise<StandaloneWebAuthnVarsigSigner>}
 */
export async function createWebAuthnEd25519Signer(options = {}) {
  const signer = await createWebAuthnSigner(options);
  if (signer.algorithm !== 'Ed25519') {
    throw new Error(`Expected Ed25519 credential, received ${signer.algorithm}`);
  }
  return signer;
}

/**
 * Create a standalone WebAuthn varsig signer and require P-256.
 * @param {Object} [options]
 * @returns {Promise<StandaloneWebAuthnVarsigSigner>}
 */
export async function createWebAuthnP256Signer(options = {}) {
  const signer = await createWebAuthnSigner(options);
  if (signer.algorithm !== 'P-256') {
    throw new Error(`Expected P-256 credential, received ${signer.algorithm}`);
  }
  return signer;
}

/**
 * Upload-wall compatibility helper. Returns Ed25519 signer or P-256 fallback signer.
 * @param {string} userId
 * @param {string} displayName
 * @param {{authenticatorType?: 'platform' | 'cross-platform' | 'any'}} [options]
 * @returns {Promise<StandaloneWebAuthnVarsigSigner|null>}
 */
export async function createWebAuthnEd25519Credential(userId, displayName, options = {}) {
  try {
    const forceP256Hardware =
      typeof window !== 'undefined' &&
      Boolean(window.__FORCE_P256_HARDWARE__);
    return createWebAuthnSigner({
      userId,
      displayName,
      authenticatorType: options.authenticatorType || 'any',
      forceP256: forceP256Hardware
    });
  } catch {
    return null;
  }
}

/**
 * Upload-wall compatibility helper.
 * @returns {Promise<boolean>}
 */
export async function checkEd25519Support() {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) return false;
  return Boolean(navigator.credentials?.create);
}

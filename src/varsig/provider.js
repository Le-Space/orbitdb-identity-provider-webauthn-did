/**
 * WebAuthn varsig identity provider.
 *
 * Uses passkey assertions for each signature and encodes them into a varsig
 * envelope for OrbitDB identity verification.
 */
import { DEFAULT_DOMAIN_LABELS } from './domain.js';
import { buildVarsigOutput, runWebAuthnAssertionForPayload, verifyVarsigForPayload, toBytes } from './assertion.js';
import { createWebAuthnVarsigCredential } from './credential.js';

export class WebAuthnVarsigProvider {
  /**
   * @param {Object} credentialInfo - Varsig credential info (public key, algorithm, credentialId)
   */
  constructor(credentialInfo) {
    this.credential = credentialInfo;
    this.type = 'webauthn-varsig';
  }

  /**
   * @returns {boolean} True if WebAuthn is available in this environment.
   */
  static isSupported() {
    return Boolean(window.PublicKeyCredential);
  }

  /**
   * Create a WebAuthn varsig credential.
   * @param {Object} [options] - WebAuthn creation options.
   * @returns {Promise<Object>} Credential info with public key and DID.
   */
  static async createCredential(options = {}) {
    return createWebAuthnVarsigCredential(options);
  }

  /**
   * Sign raw bytes using WebAuthn and return a varsig envelope.
   * @param {Uint8Array} payloadBytes - Data to sign.
   * @param {string} [domainLabel] - Domain label for the challenge.
   * @returns {Promise<Uint8Array>} Varsig signature.
   */
  async signPayload(payloadBytes, domainLabel = DEFAULT_DOMAIN_LABELS.entry) {
    const assertion = await runWebAuthnAssertionForPayload(
      this.credential,
      payloadBytes,
      domainLabel
    );
    const output = await buildVarsigOutput(assertion);
    return output.varsig;
  }

  /**
   * Sign data (string or bytes) and return a varsig envelope.
   * @param {string|Uint8Array} data - Data to sign.
   * @param {string} [domainLabel] - Domain label for the challenge.
   * @returns {Promise<Uint8Array>} Varsig signature.
   */
  async sign(data, domainLabel = DEFAULT_DOMAIN_LABELS.entry) {
    return this.signPayload(toBytes(data), domainLabel);
  }

  /**
   * Verify a varsig signature for a payload.
   * @param {Uint8Array} signature - Varsig signature.
   * @param {Uint8Array} publicKey - Public key for verification.
   * @param {string|Uint8Array} data - Payload data.
   * @param {string} [domainLabel] - Domain label for the challenge.
   * @returns {Promise<boolean>} True if valid.
   */
  async verify(signature, publicKey, data, domainLabel = DEFAULT_DOMAIN_LABELS.entry) {
    return verifyVarsigForPayload(
      signature,
      publicKey,
      toBytes(data),
      domainLabel
    );
  }
}

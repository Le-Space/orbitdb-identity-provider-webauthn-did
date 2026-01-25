import { DEFAULT_DOMAIN_LABELS } from './domain.js';
import { buildVarsigOutput, runWebAuthnAssertionForPayload, verifyVarsigForPayload, toBytes } from './assertion.js';
import { createWebAuthnVarsigCredential } from './credential.js';

export class WebAuthnVarsigProvider {
  constructor(credentialInfo) {
    this.credential = credentialInfo;
    this.type = 'webauthn-varsig';
  }

  static isSupported() {
    return Boolean(window.PublicKeyCredential);
  }

  static async createCredential(options = {}) {
    return createWebAuthnVarsigCredential(options);
  }

  async signPayload(payloadBytes, domainLabel = DEFAULT_DOMAIN_LABELS.entry) {
    const assertion = await runWebAuthnAssertionForPayload(
      this.credential,
      payloadBytes,
      domainLabel
    );
    const output = await buildVarsigOutput(assertion);
    return output.varsig;
  }

  async sign(data, domainLabel = DEFAULT_DOMAIN_LABELS.entry) {
    return this.signPayload(toBytes(data), domainLabel);
  }

  async verify(signature, publicKey, data, domainLabel = DEFAULT_DOMAIN_LABELS.entry) {
    return verifyVarsigForPayload(
      signature,
      publicKey,
      toBytes(data),
      domainLabel
    );
  }
}

/**
 * WebAuthn varsig credential creation and parsing utilities.
 */
import { DIDKey } from 'iso-did';
import { parseAttestationObject } from 'iso-passkeys';
import { toArrayBuffer } from './utils.js';

/**
 * Extract public key info from a WebAuthn attestation object.
 * @param {Uint8Array} attestationObject - Raw attestation object bytes.
 * @returns {{algorithm: string|null, publicKey: Uint8Array|null, kty: number, alg: number, crv: number}}
 */
function extractCredentialInfo(attestationObject) {
  const parsed = parseAttestationObject(toArrayBuffer(attestationObject));
  const coseKey = parsed.authData.credentialPublicKey;

  if (!coseKey) {
    throw new Error('Credential public key missing from attestation');
  }

  const getValue = (key) =>
    coseKey instanceof Map ? coseKey.get(key) : coseKey[key];

  const kty = getValue(1);
  const alg = getValue(3);
  const crv = getValue(-1);

  if (kty === 1 && (alg === -50 || alg === -8) && crv === 6) {
    const publicKeyBytes = new Uint8Array(getValue(-2));
    if (publicKeyBytes.length !== 32) {
      throw new Error(`Invalid Ed25519 public key length: ${publicKeyBytes.length}`);
    }
    return { algorithm: 'Ed25519', publicKey: publicKeyBytes, kty, alg, crv };
  }

  if (kty === 2 && alg === -7 && crv === 1) {
    const x = new Uint8Array(getValue(-2));
    const y = new Uint8Array(getValue(-3));
    if (x.length !== 32 || y.length !== 32) {
      throw new Error(`Invalid P-256 coordinate length: x=${x.length} y=${y.length}`);
    }
    const publicKeyBytes = new Uint8Array(65);
    publicKeyBytes[0] = 0x04;
    publicKeyBytes.set(x, 1);
    publicKeyBytes.set(y, 33);
    return { algorithm: 'P-256', publicKey: publicKeyBytes, kty, alg, crv };
  }

  return { algorithm: null, publicKey: null, kty, alg, crv };
}

/**
 * Create a WebAuthn credential for varsig usage.
 * @param {Object} [options] - WebAuthn creation options.
 * @param {string} [options.userId] - User identifier.
 * @param {string} [options.displayName] - Display name.
 * @param {string} [options.domain] - RP ID / domain.
 * @returns {Promise<Object>} Credential info including public key and DID.
 */
async function createWebAuthnVarsigCredential(options = {}) {
  const {
    userId,
    displayName,
    domain
  } = {
    userId: `orbitdb-user-${Date.now()}`,
    displayName: 'OrbitDB Varsig User',
    domain: window.location.hostname,
    ...options
  };

  const publicKey = {
    rp: { name: 'OrbitDB Varsig Identity', id: domain },
    user: {
      id: crypto.getRandomValues(new Uint8Array(16)),
      name: userId,
      displayName
    },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [
      { type: 'public-key', alg: -50 },
      { type: 'public-key', alg: -8 },
      { type: 'public-key', alg: -7 }
    ],
    attestation: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred'
    }
  };

  const credential = await navigator.credentials.create({ publicKey });
  if (!credential) {
    throw new Error('Passkey registration failed.');
  }

  const response = credential.response;
  const {
    algorithm,
    publicKey: publicKeyBytes,
    kty,
    alg,
    crv
  } = extractCredentialInfo(new Uint8Array(response.attestationObject));

  if (!publicKeyBytes || !algorithm) {
    throw new Error('No supported credential returned (expected Ed25519 or P-256).');
  }

  const credentialId = new Uint8Array(credential.rawId);
  const did = DIDKey.fromPublicKey(algorithm, publicKeyBytes).did;

  return {
    credentialId,
    publicKey: publicKeyBytes,
    did,
    algorithm,
    cose: { kty, alg, crv }
  };
}

export {
  createWebAuthnVarsigCredential
};

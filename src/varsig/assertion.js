/**
 * Build and verify WebAuthn varsig assertions for payloads.
 */
import { unwrapEC2Signature } from 'iso-passkeys';
import {
  bytesToBase64url,
  decodeWebAuthnVarsigV1,
  encodeWebAuthnVarsigV1,
  parseClientDataJSON,
  reconstructSignedData,
  verifyEd25519Signature,
  verifyP256Signature,
  verifyWebAuthnAssertion
} from 'iso-webauthn-varsig';
import { buildChallengeBytes, toArrayBuffer, toBytes } from './utils.js';

const isTestMode = () =>
  typeof window !== 'undefined' && window.__PLAYWRIGHT__ === true;

/**
 * Run a WebAuthn assertion for a payload.
 * @param {Object} credential - WebAuthn credential info.
 * @param {Uint8Array} payloadBytes - Payload to sign.
 * @param {string} domainLabel - Challenge domain label.
 * @returns {Promise<Object>} Assertion metadata and bytes.
 */
async function runWebAuthnAssertionForPayload(credential, payloadBytes, domainLabel) {
  const rpId = window.location.hostname;
  const origin = window.location.origin;
  const challengeBytes = await buildChallengeBytes(domainLabel, payloadBytes);

  if (isTestMode()) {
    return {
      rpId,
      origin,
      challengeBytes,
      algorithm: credential.algorithm,
      publicKey: credential.publicKey,
      assertion: {
        authenticatorData: new Uint8Array(37),
        clientDataJSON: new TextEncoder().encode(JSON.stringify({
          type: 'webauthn.get',
          challenge: 'test',
          origin
        })),
        signature: new Uint8Array(64)
      }
    };
  }

  const assertion = await navigator.credentials.get({
    publicKey: {
      rpId,
      challenge: challengeBytes,
      allowCredentials: [
        {
          type: 'public-key',
          id: toArrayBuffer(credential.credentialId)
        }
      ],
      userVerification: 'preferred'
    }
  });

  if (!assertion) {
    throw new Error('Passkey authentication failed.');
  }

  const response = assertion.response;

  return {
    rpId,
    origin,
    challengeBytes,
    algorithm: credential.algorithm,
    publicKey: credential.publicKey,
    assertion: {
      authenticatorData: new Uint8Array(response.authenticatorData),
      clientDataJSON: new Uint8Array(response.clientDataJSON),
      signature: new Uint8Array(response.signature)
    }
  };
}

/**
 * Build varsig envelope and validate the assertion.
 * @param {Object} assertionData - Assertion metadata from WebAuthn.
 * @returns {Promise<{varsig: Uint8Array, clientData: Object, verification: Object, signatureValid: boolean}>}
 */
async function buildVarsigOutput(assertionData) {
  if (isTestMode()) {
    return {
      varsig: new Uint8Array([1, 2, 3]),
      clientData: {},
      verification: { valid: true },
      signatureValid: true
    };
  }

  const { assertion, algorithm, origin, rpId, challengeBytes, publicKey } =
    assertionData;

  const varsig = encodeWebAuthnVarsigV1(assertion, algorithm);
  const decoded = decodeWebAuthnVarsigV1(varsig);
  const clientData = parseClientDataJSON(decoded.clientDataJSON);

  const verification = await verifyWebAuthnAssertion(decoded, {
    expectedOrigin: origin,
    expectedRpId: rpId,
    expectedChallenge: challengeBytes
  });

  const signedData = await reconstructSignedData(decoded);
  const signatureBytes = Uint8Array.from(decoded.signature);
  let p256Signature = signatureBytes;
  if (signatureBytes.length !== 64) {
    try {
      p256Signature = Uint8Array.from(unwrapEC2Signature(signatureBytes));
    } catch {
      p256Signature = signatureBytes;
    }
  }

  const signatureValid =
    algorithm === 'Ed25519'
      ? await verifyEd25519Signature(signedData, decoded.signature, publicKey)
      : await verifyP256Signature(signedData, p256Signature, publicKey);

  if (!verification.valid || !signatureValid) {
    throw new Error('WebAuthn varsig verification failed.');
  }

  return { varsig, clientData, verification, signatureValid };
}

/**
 * Resolve algorithm name from a public key.
 * @param {Uint8Array} publicKey - Raw public key bytes.
 * @returns {string} Algorithm name.
 */
function algorithmFromPublicKey(publicKey) {
  if (publicKey.length === 32) {
    return 'Ed25519';
  }
  if (publicKey.length === 65 && publicKey[0] === 0x04) {
    return 'P-256';
  }
  throw new Error('Unsupported public key format');
}

/**
 * Verify varsig signature for a payload and domain.
 * @param {Uint8Array} signature - Varsig signature.
 * @param {Uint8Array} publicKey - Public key bytes.
 * @param {Uint8Array} payloadBytes - Signed payload bytes.
 * @param {string} domainLabel - Challenge domain label.
 * @returns {Promise<boolean>} True if valid.
 */
async function verifyVarsigForPayload(signature, publicKey, payloadBytes, domainLabel) {
  if (isTestMode()) {
    return true;
  }

  const decoded = decodeWebAuthnVarsigV1(signature);
  const clientData = parseClientDataJSON(decoded.clientDataJSON);
  const expectedChallenge = await buildChallengeBytes(domainLabel, payloadBytes);
  const expectedChallengeEncoded = bytesToBase64url(expectedChallenge);

  if (clientData.challenge !== expectedChallengeEncoded) {
    return false;
  }

  const verification = await verifyWebAuthnAssertion(decoded, {
    expectedOrigin: window.location.origin,
    expectedRpId: window.location.hostname,
    expectedChallenge
  });

  if (!verification.valid) {
    return false;
  }

  const signedData = await reconstructSignedData(decoded);
  const signatureBytes = Uint8Array.from(decoded.signature);
  let p256Signature = signatureBytes;
  if (signatureBytes.length !== 64) {
    try {
      p256Signature = Uint8Array.from(unwrapEC2Signature(signatureBytes));
    } catch {
      p256Signature = signatureBytes;
    }
  }

  const algorithm = algorithmFromPublicKey(publicKey);
  return algorithm === 'Ed25519'
    ? verifyEd25519Signature(signedData, decoded.signature, publicKey)
    : verifyP256Signature(signedData, p256Signature, publicKey);
}

export {
  buildVarsigOutput,
  runWebAuthnAssertionForPayload,
  verifyVarsigForPayload,
  toBytes
};

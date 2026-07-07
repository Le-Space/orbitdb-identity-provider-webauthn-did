/**
 * LocalStorage helpers for varsig credential persistence.
 */
import { base64urlToBytes, bytesToBase64url } from 'iso-webauthn-varsig';
import { STORAGE_KEYS } from '../constants.js';

/**
 * Persist varsig credential to localStorage.
 * @param {Object} credential - Varsig credential info.
 * @param {string} [key] - Storage key.
 */
export function storeWebAuthnVarsigCredential(
  credential,
  key = STORAGE_KEYS.WEBAUTHN_VARSIG_CREDENTIAL
) {
  const payload = {
    credentialId: bytesToBase64url(credential.credentialId),
    publicKey: bytesToBase64url(credential.publicKey),
    did: credential.did,
    algorithm: credential.algorithm,
    cose: credential.cose || null,
  };
  localStorage.setItem(key, JSON.stringify(payload));
}

/**
 * Load varsig credential from localStorage.
 * @param {string} [key] - Storage key.
 * @returns {Object|null} Credential info or null.
 */
export function loadWebAuthnVarsigCredential(
  key = STORAGE_KEYS.WEBAUTHN_VARSIG_CREDENTIAL
) {
  const stored = localStorage.getItem(key);
  if (!stored) return null;
  const parsed = JSON.parse(stored);
  return {
    credentialId: base64urlToBytes(parsed.credentialId),
    publicKey: base64urlToBytes(parsed.publicKey),
    did: parsed.did,
    algorithm: parsed.algorithm,
    cose: parsed.cose || null,
  };
}

/**
 * Remove varsig credential from localStorage.
 * @param {string} [key] - Storage key.
 */
export function clearWebAuthnVarsigCredential(
  key = STORAGE_KEYS.WEBAUTHN_VARSIG_CREDENTIAL
) {
  localStorage.removeItem(key);
}

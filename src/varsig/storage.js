import { base64urlToBytes, bytesToBase64url } from 'iso-webauthn-varsig';

export function storeWebAuthnVarsigCredential(credential, key = 'webauthn-varsig-credential') {
  const payload = {
    credentialId: bytesToBase64url(credential.credentialId),
    publicKey: bytesToBase64url(credential.publicKey),
    did: credential.did,
    algorithm: credential.algorithm,
    cose: credential.cose || null
  };
  localStorage.setItem(key, JSON.stringify(payload));
}

export function loadWebAuthnVarsigCredential(key = 'webauthn-varsig-credential') {
  const stored = localStorage.getItem(key);
  if (!stored) return null;
  const parsed = JSON.parse(stored);
  return {
    credentialId: base64urlToBytes(parsed.credentialId),
    publicKey: base64urlToBytes(parsed.publicKey),
    did: parsed.did,
    algorithm: parsed.algorithm,
    cose: parsed.cose || null
  };
}

export function clearWebAuthnVarsigCredential(key = 'webauthn-varsig-credential') {
  localStorage.removeItem(key);
}

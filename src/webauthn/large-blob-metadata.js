import { buildCredentialRequestOptions } from './config.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64url(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlToBytes(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  const binary = atob(padded);
  const output = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    output[i] = binary.charCodeAt(i);
  }
  return output;
}

function encodePayload(payload) {
  return encoder.encode(JSON.stringify(payload));
}

function decodePayload(bytes) {
  return JSON.parse(decoder.decode(bytes));
}

export function createDidLargeBlobPayload(credential, did) {
  return encodePayload({
    version: 1,
    type: 'webauthn-did',
    credentialId: credential.credentialId,
    did: did || null,
    publicKey: {
      algorithm: credential.publicKey.algorithm,
      keyType: credential.publicKey.keyType,
      curve: credential.publicKey.curve,
      x: bytesToBase64url(credential.publicKey.x),
      y: bytesToBase64url(credential.publicKey.y),
    },
  });
}

export function parseDidLargeBlobPayload(bytes) {
  const payload = decodePayload(bytes);
  if (payload.type !== 'webauthn-did') {
    throw new Error(`Unexpected largeBlob payload type: ${payload.type}`);
  }
  const rawCredentialId = base64urlToBytes(payload.credentialId);
  return {
    credentialId: payload.credentialId,
    rawCredentialId,
    publicKey: {
      algorithm: payload.publicKey.algorithm,
      keyType: payload.publicKey.keyType,
      curve: payload.publicKey.curve,
      x: base64urlToBytes(payload.publicKey.x),
      y: base64urlToBytes(payload.publicKey.y),
    },
    did: payload.did || null,
  };
}

export function createVarsigLargeBlobPayload(credential) {
  return encodePayload({
    version: 1,
    type: 'webauthn-varsig',
    credentialId: bytesToBase64url(credential.credentialId),
    did: credential.did || null,
    algorithm: credential.algorithm,
    publicKey: bytesToBase64url(credential.publicKey),
    cose: credential.cose || null,
  });
}

export function parseVarsigLargeBlobPayload(bytes) {
  const payload = decodePayload(bytes);
  if (payload.type !== 'webauthn-varsig') {
    throw new Error(`Unexpected largeBlob payload type: ${payload.type}`);
  }
  return {
    credentialId: base64urlToBytes(payload.credentialId),
    publicKey: base64urlToBytes(payload.publicKey),
    did: payload.did || null,
    algorithm: payload.algorithm,
    cose: payload.cose || null,
  };
}

export async function writeLargeBlobMetadata({
  credentialId,
  rpId,
  payload,
  discoverableCredentials = false,
  userVerification = 'required',
}) {
  const assertion = await navigator.credentials.get(
    buildCredentialRequestOptions({
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      credentialId,
      rpId,
      userVerification,
      discoverableCredentials,
      extensions: {
        largeBlob: {
          write: payload,
        },
      },
    })
  );

  return {
    assertion,
    extensionResults: assertion?.getClientExtensionResults?.() || {},
  };
}

export async function readLargeBlobMetadata({
  rpId,
  credentialId,
  discoverableCredentials = true,
  userVerification = 'required',
}) {
  const assertion = await navigator.credentials.get(
    buildCredentialRequestOptions({
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      credentialId,
      rpId,
      userVerification,
      discoverableCredentials,
      extensions: {
        largeBlob: {
          read: true,
        },
      },
    })
  );

  const extensionResults = assertion?.getClientExtensionResults?.() || {};
  const blob = extensionResults.largeBlob?.blob
    ? new Uint8Array(extensionResults.largeBlob.blob)
    : null;

  return {
    assertion,
    extensionResults,
    blob,
  };
}

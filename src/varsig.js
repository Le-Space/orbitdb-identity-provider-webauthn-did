import { DIDKey } from 'iso-did';
import { parseAttestationObject, unwrapEC2Signature } from 'iso-passkeys';
import {
  base64urlToBytes,
  bytesToBase64url,
  concat,
  decodeWebAuthnVarsigV1,
  encodeWebAuthnVarsigV1,
  parseClientDataJSON,
  reconstructSignedData,
  verifyEd25519Signature,
  verifyP256Signature,
  verifyWebAuthnAssertion
} from 'iso-webauthn-varsig';
import * as Block from 'multiformats/block';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { base58btc } from 'multiformats/bases/base58';

const encoder = new TextEncoder();
const IDENTITY_CODEC = dagCbor;
const IDENTITY_HASHER = sha256;
const IDENTITY_HASH_ENCODING = base58btc;

const DEFAULT_DOMAIN_LABELS = {
  id: 'orbitdb-id:',
  publicKey: 'orbitdb-pubkey:',
  entry: 'orbitdb-entry:'
};

function toArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function toBytes(data) {
  return typeof data === 'string' ? encoder.encode(data) : data;
}

async function buildChallengeBytes(domainLabel, payloadBytes) {
  const domain = encoder.encode(domainLabel);
  const hash = await crypto.subtle.digest('SHA-256', concat([domain, payloadBytes]));
  return new Uint8Array(hash);
}

async function runWebAuthnAssertionForPayload(credential, payloadBytes, domainLabel) {
  const rpId = window.location.hostname;
  const origin = window.location.origin;
  const challengeBytes = await buildChallengeBytes(domainLabel, payloadBytes);

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

async function buildVarsigOutput(assertionData) {
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

function algorithmFromPublicKey(publicKey) {
  if (publicKey.length === 32) {
    return 'Ed25519';
  }
  if (publicKey.length === 65 && publicKey[0] === 0x04) {
    return 'P-256';
  }
  throw new Error('Unsupported public key format');
}

async function verifyVarsigForPayload(signature, publicKey, payloadBytes, domainLabel) {
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

async function encodeIdentityValue(value) {
  const { cid, bytes } = await Block.encode({
    value,
    codec: IDENTITY_CODEC,
    hasher: IDENTITY_HASHER
  });
  return {
    hash: cid.toString(IDENTITY_HASH_ENCODING),
    bytes: Uint8Array.from(bytes)
  };
}

export class WebAuthnVarsigProvider {
  constructor(credentialInfo) {
    this.credential = credentialInfo;
    this.type = 'webauthn-varsig';
  }

  static isSupported() {
    return Boolean(window.PublicKeyCredential);
  }

  static async createCredential(options = {}) {
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

export async function createWebAuthnVarsigIdentity({ credential, domainLabels = {} }) {
  const labels = { ...DEFAULT_DOMAIN_LABELS, ...domainLabels };
  const provider = new WebAuthnVarsigProvider(credential);
  const id = credential.did || DIDKey.fromPublicKey(credential.algorithm, credential.publicKey).did;
  const idBytes = encoder.encode(id);

  const idSignature = await provider.signPayload(idBytes, labels.id);
  const publicKeyPayload = concat([credential.publicKey, idSignature]);
  const publicKeySignature = await provider.signPayload(publicKeyPayload, labels.publicKey);

  const identity = {
    id,
    publicKey: credential.publicKey,
    signatures: {
      id: idSignature,
      publicKey: publicKeySignature
    },
    type: 'webauthn-varsig',
    sign: (identityInstance, data) => provider.sign(data, labels.entry),
    verify: (signature, data) =>
      provider.verify(signature, credential.publicKey, data, labels.entry)
  };

  const { hash, bytes } = await encodeIdentityValue({
    id: identity.id,
    publicKey: identity.publicKey,
    signatures: identity.signatures,
    type: identity.type
  });
  identity.hash = hash;
  identity.bytes = bytes;

  return identity;
}

export function createWebAuthnVarsigIdentities(identity, domainLabels = {}) {
  const labels = { ...DEFAULT_DOMAIN_LABELS, ...domainLabels };
  const identityByHash = new Map([[identity.hash, identity]]);

  const verify = (signature, publicKey, data) =>
    verifyVarsigForPayload(signature, publicKey, toBytes(data), labels.entry);

  const verifyIdentity = async (identityToVerify) => {
    if (!identityToVerify) return false;

    const idBytes = encoder.encode(identityToVerify.id);
    const idValid = await verifyVarsigForPayload(
      identityToVerify.signatures.id,
      identityToVerify.publicKey,
      idBytes,
      labels.id
    );
    if (!idValid) return false;

    const publicKeyPayload = concat([
      identityToVerify.publicKey,
      identityToVerify.signatures.id
    ]);

    return verifyVarsigForPayload(
      identityToVerify.signatures.publicKey,
      identityToVerify.publicKey,
      publicKeyPayload,
      labels.publicKey
    );
  };

  const getIdentity = async (hash) => identityByHash.get(hash) ?? null;

  return {
    createIdentity: async () => identity,
    verifyIdentity,
    getIdentity,
    sign: (identityInstance, data) => identityInstance.sign(identityInstance, data),
    verify,
    keystore: null
  };
}

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

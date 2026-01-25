import * as Block from 'multiformats/block';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { base58btc } from 'multiformats/bases/base58';
import { DIDKey } from 'iso-did';
import { concat } from 'iso-webauthn-varsig';
import { DEFAULT_DOMAIN_LABELS } from './domain.js';
import { encoder, toBytes } from './utils.js';
import { verifyVarsigForPayload } from './assertion.js';
import { WebAuthnVarsigProvider } from './provider.js';

const IDENTITY_CODEC = dagCbor;
const IDENTITY_HASHER = sha256;
const IDENTITY_HASH_ENCODING = base58btc;

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

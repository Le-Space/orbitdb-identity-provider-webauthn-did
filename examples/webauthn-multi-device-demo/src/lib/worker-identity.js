import * as Block from 'multiformats/block';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { base58btc } from 'multiformats/bases/base58';
import { publicKeyFromRaw } from '@libp2p/crypto/keys';

const IDENTITY_CODEC = dagCbor;
const IDENTITY_HASHER = sha256;
const IDENTITY_HASH_ENCODING = base58btc;
const encoder = new TextEncoder();

function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (typeof data === 'string') return encoder.encode(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  throw new Error('Unsupported data type for worker identity');
}

function concatBytes(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function encodeIdentityValue(value) {
  const { cid, bytes } = await Block.encode({
    value,
    codec: IDENTITY_CODEC,
    hasher: IDENTITY_HASHER,
  });

  return {
    hash: cid.toString(IDENTITY_HASH_ENCODING),
    bytes: Uint8Array.from(bytes),
  };
}

async function verifyEd25519Signature(publicKeyBytes, data, signature) {
  const publicKey = publicKeyFromRaw(publicKeyBytes);
  return publicKey.verify(toBytes(data), toBytes(signature));
}

export async function createWorkerEd25519Identity({ did, publicKey, sign }) {
  const didBytes = encoder.encode(did);
  const idSignature = await sign(didBytes);
  const publicKeyPayload = concatBytes([publicKey, idSignature]);
  const publicKeySignature = await sign(publicKeyPayload);

  const identity = {
    id: did,
    publicKey,
    signatures: {
      id: idSignature,
      publicKey: publicKeySignature,
    },
    type: 'worker-ed25519',
    sign: (_identity, data) => sign(toBytes(data)),
    verify: (signature, data) =>
      verifyEd25519Signature(publicKey, data, signature),
  };

  const { hash, bytes } = await encodeIdentityValue({
    id: identity.id,
    publicKey: identity.publicKey,
    signatures: identity.signatures,
    type: identity.type,
  });

  identity.hash = hash;
  identity.bytes = bytes;

  return identity;
}

export function createWorkerEd25519Identities(identity, storage = null) {
  const identityByHash = new Map([[identity.hash, identity]]);

  if (storage?.put) {
    storage.put(identity.hash, identity.bytes);
  }

  const verify = async (signature, publicKey, data) =>
    verifyEd25519Signature(publicKey, data, signature);

  const verifyIdentity = async (identityToVerify) => {
    if (!identityToVerify?.publicKey || !identityToVerify?.signatures) {
      return false;
    }

    const didBytes = encoder.encode(identityToVerify.id);
    const idValid = await verifyEd25519Signature(
      identityToVerify.publicKey,
      didBytes,
      identityToVerify.signatures.id
    );

    if (!idValid) return false;

    const publicKeyPayload = concatBytes([
      identityToVerify.publicKey,
      identityToVerify.signatures.id,
    ]);

    return verifyEd25519Signature(
      identityToVerify.publicKey,
      publicKeyPayload,
      identityToVerify.signatures.publicKey
    );
  };

  const getIdentity = async (hash) => {
    const cached = identityByHash.get(hash);
    if (cached) return cached;
    if (!storage?.get) return null;

    const bytes = await storage.get(hash);
    if (!bytes) return null;

    const { value } = await Block.decode({
      bytes,
      codec: IDENTITY_CODEC,
      hasher: IDENTITY_HASHER,
    });

    const decoded = {
      id: value.id,
      publicKey: value.publicKey,
      signatures: value.signatures,
      type: value.type,
      bytes,
      hash,
      sign: async () => {
        throw new Error('Remote worker identity cannot sign');
      },
      verify: (signature, data) =>
        verifyEd25519Signature(value.publicKey, data, signature),
    };

    identityByHash.set(hash, decoded);
    return decoded;
  };

  return {
    createIdentity: async () => identity,
    verifyIdentity,
    getIdentity,
    sign: (identityInstance, data) => identityInstance.sign(identityInstance, data),
    verify,
    keystore: null,
  };
}

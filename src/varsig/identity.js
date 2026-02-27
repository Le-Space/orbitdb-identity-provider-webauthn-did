/**
 * Identity creation helpers for WebAuthn varsig.
 */
import * as Block from 'multiformats/block';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { base58btc } from 'multiformats/bases/base58';
import { CID } from 'multiformats/cid';
import { DIDKey } from 'iso-did';
import { concat } from 'iso-webauthn-varsig';
import { DEFAULT_DOMAIN_LABELS } from './domain.js';
import { encoder, toBytes } from './utils.js';
import { verifyVarsigForPayload } from './assertion.js';
import { WebAuthnVarsigProvider } from './provider.js';

const IDENTITY_CODEC = dagCbor;
const IDENTITY_HASHER = sha256;
const IDENTITY_HASH_ENCODING = base58btc;

/**
 * Encode an identity value as CBOR and compute its CID hash.
 * @param {Object} value - Identity payload.
 * @returns {Promise<{hash: string, bytes: Uint8Array}>}
 */
export async function encodeIdentityValue(value) {
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

/**
 * Create a WebAuthn varsig identity.
 * @param {Object} params - Identity inputs.
 * @param {Object} params.credential - WebAuthn varsig credential info.
 * @param {Object} [params.domainLabels] - Domain label overrides.
 * @param {'required'|'preferred'|'discouraged'} [params.userVerification='preferred'] - WebAuthn assertion user verification behavior.
 * @returns {Promise<Object>} OrbitDB identity object.
 */
export async function createWebAuthnVarsigIdentity({
  credential,
  domainLabels = {},
  userVerification = 'preferred',
  mediation,
}) {
  const labels = { ...DEFAULT_DOMAIN_LABELS, ...domainLabels };
  const provider = new WebAuthnVarsigProvider(credential, {
    userVerification,
    mediation,
  });
  const id =
    credential.did ||
    DIDKey.fromPublicKey(credential.algorithm, credential.publicKey).did;
  const idBytes = encoder.encode(id);

  const idSignature = await provider.signPayload(idBytes, labels.id);
  const publicKeyPayload = concat([credential.publicKey, idSignature]);
  const publicKeySignature = await provider.signPayload(
    publicKeyPayload,
    labels.publicKey
  );

  const identity = {
    id,
    publicKey: credential.publicKey,
    signatures: {
      id: idSignature,
      publicKey: publicKeySignature,
    },
    type: 'webauthn-varsig',
    sign: (identityInstance, data) => provider.sign(data, labels.entry),
    verify: (signature, data) =>
      provider.verify(signature, credential.publicKey, data, labels.entry),
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

/**
 * Build an OrbitDB identities interface for varsig.
 * @param {Object} identity - Local identity instance.
 * @param {Object} [domainLabels] - Domain label overrides.
 * @param {Object} [storage] - Optional storage adapter.
 * @returns {Object} Identities-compatible API.
 */
export function createWebAuthnVarsigIdentities(identity, domainLabels = {}) {
  const labels = { ...DEFAULT_DOMAIN_LABELS, ...domainLabels };
  const identityByHash = new Map([[identity.hash, identity]]);
  const storage = arguments.length > 2 ? arguments[2] : null;

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
      identityToVerify.signatures.id,
    ]);

    return verifyVarsigForPayload(
      identityToVerify.signatures.publicKey,
      identityToVerify.publicKey,
      publicKeyPayload,
      labels.publicKey
    );
  };

  const getIdentity = async (hash) => {
    const cached = identityByHash.get(hash);
    if (cached) return cached;
    if (!storage || !storage.get) return null;
    const bytes = await storage.get(hash);
    if (!bytes) return null;
    const { value } = await Block.decode({
      bytes,
      codec: IDENTITY_CODEC,
      hasher: IDENTITY_HASHER,
    });
    const decoded = value;
    const { hash: decodedHash } = await encodeIdentityValue({
      id: decoded.id,
      publicKey: decoded.publicKey,
      signatures: decoded.signatures,
      type: decoded.type,
    });
    const storedIdentity = {
      id: decoded.id,
      publicKey: decoded.publicKey,
      signatures: decoded.signatures,
      type: decoded.type,
      hash: decodedHash,
      bytes,
      sign: async () => {
        throw new Error('Remote identity cannot sign');
      },
      verify: (signature, data) =>
        verifyVarsigForPayload(
          signature,
          decoded.publicKey,
          toBytes(data),
          labels.entry
        ),
    };
    identityByHash.set(decodedHash, storedIdentity);
    return storedIdentity;
  };

  if (storage && storage.put) {
    storage.put(identity.hash, identity.bytes);
  }

  return {
    createIdentity: async () => identity,
    verifyIdentity,
    getIdentity,
    sign: (identityInstance, data) =>
      identityInstance.sign(identityInstance, data),
    verify,
    keystore: null,
  };
}

/**
 * Decode a varsig identity from CBOR-encoded bytes.
 * Returns an identity object suitable for verification (cannot sign).
 * @param {Uint8Array} bytes - CBOR-encoded identity bytes.
 * @param {Object} [domainLabels] - Domain label overrides.
 * @returns {Promise<Object>} Decoded identity with verify method.
 */
export async function decodeVarsigIdentityFromBytes(bytes, domainLabels = {}) {
  const labels = { ...DEFAULT_DOMAIN_LABELS, ...domainLabels };
  const { value } = await Block.decode({
    bytes,
    codec: IDENTITY_CODEC,
    hasher: IDENTITY_HASHER,
  });
  const decoded = value;
  const { hash: decodedHash } = await encodeIdentityValue({
    id: decoded.id,
    publicKey: decoded.publicKey,
    signatures: decoded.signatures,
    type: decoded.type,
  });
  return {
    id: decoded.id,
    publicKey: decoded.publicKey,
    signatures: decoded.signatures,
    type: decoded.type,
    hash: decodedHash,
    bytes,
    sign: async () => {
      throw new Error('Remote identity cannot sign');
    },
    verify: (signature, data) =>
      verifyVarsigForPayload(
        signature,
        decoded.publicKey,
        toBytes(data),
        labels.entry
      ),
  };
}

/**
 * Verify a varsig identity's signatures without needing the credential.
 * Uses only the public key embedded in the identity.
 * @param {Object} identity - Identity object with id, publicKey, signatures.
 * @param {Object} [domainLabels] - Domain label overrides.
 * @returns {Promise<boolean>} True if the identity is valid.
 */
export async function verifyVarsigIdentity(identity, domainLabels = {}) {
  if (!identity || !identity.publicKey || !identity.signatures) return false;
  const labels = { ...DEFAULT_DOMAIN_LABELS, ...domainLabels };

  const idBytes = encoder.encode(identity.id);
  const idValid = await verifyVarsigForPayload(
    identity.signatures.id,
    identity.publicKey,
    idBytes,
    labels.id
  );
  if (!idValid) return false;

  const publicKeyPayload = concat([identity.publicKey, identity.signatures.id]);
  return verifyVarsigForPayload(
    identity.signatures.publicKey,
    identity.publicKey,
    publicKeyPayload,
    labels.publicKey
  );
}

/**
 * Create an IPFS blockstore adapter for identity storage.
 * @param {Object} ipfs - Helia/IPFS instance with a blockstore.
 * @returns {Object|null} Storage adapter with get/put methods, or null.
 */
export function createIpfsIdentityStorage(ipfs) {
  if (!ipfs || !ipfs.blockstore) return null;
  return {
    get: async (hash) => {
      try {
        const cid = CID.parse(hash);
        return await ipfs.blockstore.get(cid);
      } catch {
        return undefined;
      }
    },
    put: async (hash, bytes) => {
      const cid = CID.parse(hash);
      await ipfs.blockstore.put(cid, bytes);
    },
  };
}

/**
 * Wraps a default OrbitDB identities object with varsig verification fallback.
 * This allows any OrbitDB instance to verify entries signed by varsig identities,
 * even without having the signer's WebAuthn credential.
 * @param {Object} defaultIdentities - The default Identities instance from OrbitDB.
 * @param {Object} ipfs - Helia/IPFS instance (for fetching identity blocks).
 * @param {Object} [domainLabels] - Domain label overrides.
 * @returns {Object} A wrapped identities object that handles both default and varsig verification.
 */
export function wrapWithVarsigVerification(
  defaultIdentities,
  ipfs,
  domainLabels = {}
) {
  const labels = { ...DEFAULT_DOMAIN_LABELS, ...domainLabels };
  const ipfsStorage = createIpfsIdentityStorage(ipfs);
  const varsigIdentityCache = new Map();

  // Hybrid verify: tries default keystore verification, then varsig verification
  const hybridVerify = async (signature, publicKey, data) => {
    // Try default keystore verification first
    try {
      const result = await defaultIdentities.verify(signature, publicKey, data);
      if (result) return true;
    } catch {
      // Default verification failed, try varsig
    }

    // Try varsig verification (varsig uses Uint8Array public keys)
    if (publicKey instanceof Uint8Array) {
      try {
        return await verifyVarsigForPayload(
          signature,
          publicKey,
          toBytes(data),
          labels.entry
        );
      } catch {
        // Varsig verification also failed
      }
    }

    return false;
  };

  return {
    ...defaultIdentities,

    getIdentity: async (hash) => {
      // Try default identities storage first
      try {
        const defaultId = await defaultIdentities.getIdentity(hash);
        if (defaultId) return defaultId;
      } catch {
        // Default lookup failed
      }

      // Try varsig identity cache
      const cached = varsigIdentityCache.get(hash);
      if (cached) return cached;

      // Try IPFS blockstore for varsig identities stored by remote peers
      if (ipfsStorage) {
        try {
          const bytes = await ipfsStorage.get(hash);
          if (bytes) {
            const decoded = await decodeVarsigIdentityFromBytes(
              bytes,
              domainLabels
            );
            varsigIdentityCache.set(decoded.hash, decoded);
            return decoded;
          }
        } catch {
          // IPFS lookup failed
        }
      }

      return undefined;
    },

    verifyIdentity: async (identity) => {
      if (!identity) return false;

      // Try default verification first
      try {
        const result = await defaultIdentities.verifyIdentity(identity);
        if (result) return true;
      } catch {
        // Default verification failed
      }

      // Try varsig verification for webauthn-varsig type
      if (identity.type === 'webauthn-varsig') {
        try {
          return await verifyVarsigIdentity(identity, domainLabels);
        } catch {
          return false;
        }
      }

      return false;
    },

    verify: hybridVerify,

    createIdentity: async (options) => {
      const identity = await defaultIdentities.createIdentity(options);
      // Patch the identity's verify to be varsig-aware so that
      // Entry.verify(identity, entry) can verify varsig entries
      identity.verify = hybridVerify;
      return identity;
    },
  };
}

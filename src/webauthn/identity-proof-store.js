/**
 * @module IdentityProofStore
 * @description
 * Persists the WebAuthn proof that becomes `signatures.publicKey` in an
 * OrbitDB identity document.
 *
 * OrbitDB content-addresses the identity document, so its hash is only stable
 * if every field is. A WebAuthn assertion is deliberately non-deterministic —
 * randomised ECDSA, an incrementing signature counter — so re-signing on every
 * page load mints a new document each time, and peers reject entries signed
 * under any document but the first one they verified.
 *
 * The proof attests that this credential signed this exact payload. That
 * statement does not change between page loads, so the proof is stored under
 * the payload it covers and reused. The assertion still happens once, when the
 * identity is first established.
 *
 * See issue #18.
 */
import { logger } from '@libp2p/logger';

const log = logger('orbitdb-identity-provider-webauthn-did:identity-proof');

const STORAGE_PREFIX = 'webauthn-identity-proof:';

// Used when no Web Storage is available (Node, SSR, private-mode failures).
// Process-lifetime only, which still keeps a single run self-consistent.
const memoryStore = new Map();

/**
 * The Storage to use, or null when none is usable.
 * @returns {Storage|null} A Web Storage implementation.
 */
function getStorage() {
  try {
    const storage = globalThis.localStorage;
    if (!storage) return null;
    // Safari in private mode throws on write rather than on access.
    const probe = `${STORAGE_PREFIX}probe`;
    storage.setItem(probe, '1');
    storage.removeItem(probe);
    return storage;
  } catch {
    return null;
  }
}

function toBase64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Derive the storage key for a proof.
 *
 * Keyed by credential and payload together, so a different passkey on the same
 * origin cannot pick up another credential's proof.
 *
 * @param {string} credentialId - Base64url credential id.
 * @param {string|Uint8Array} data - Payload passed to signIdentity().
 * @returns {Promise<string>} Storage key.
 */
export async function identityProofKey(credentialId, data) {
  const payload =
    typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const credential = new TextEncoder().encode(String(credentialId));

  const combined = new Uint8Array(credential.length + 1 + payload.length);
  combined.set(credential, 0);
  combined[credential.length] = 0x1f; // separator, so the join is unambiguous
  combined.set(payload, credential.length + 1);

  const digest = await crypto.subtle.digest('SHA-256', combined);
  return STORAGE_PREFIX + toBase64url(new Uint8Array(digest));
}

/**
 * Look up a previously stored proof.
 * @param {string} key - Key from identityProofKey().
 * @returns {string|null} The proof, or null.
 */
export function loadIdentityProof(key) {
  const storage = getStorage();
  if (storage) {
    const value = storage.getItem(key);
    if (value) return value;
  }
  return memoryStore.get(key) ?? null;
}

/**
 * Store a proof for reuse on later loads.
 * @param {string} key - Key from identityProofKey().
 * @param {string} proof - The proof envelope.
 */
export function storeIdentityProof(key, proof) {
  memoryStore.set(key, proof);

  const storage = getStorage();
  if (!storage) {
    log(
      'no Web Storage available; identity proof kept in memory only, so the identity document will change after a reload'
    );
    return;
  }

  try {
    storage.setItem(key, proof);
  } catch (error) {
    log.error('failed to persist identity proof: %s', error.message);
  }
}

/**
 * Drop every stored proof. Intended for logout and for tests.
 */
export function clearIdentityProofs() {
  memoryStore.clear();

  const storage = getStorage();
  if (!storage) return;

  const keys = [];
  for (let i = 0; i < storage.length; i++) {
    const key = storage.key(i);
    if (key?.startsWith(STORAGE_PREFIX)) keys.push(key);
  }
  for (const key of keys) storage.removeItem(key);
}

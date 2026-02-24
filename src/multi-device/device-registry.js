/**
 * Multi-Device Registry for OrbitDB WebAuthn
 *
 * Manages a KV store of registered devices using OrbitDBAccessController
 * so write access can be dynamically granted to new devices.
 */

import { OrbitDBAccessController } from '@orbitdb/core';

/**
 * Convert P-256 x/y byte arrays from a WebAuthn attestation into JWK format.
 * @param {Uint8Array} x - 32-byte x coordinate
 * @param {Uint8Array} y - 32-byte y coordinate
 * @returns {Object} JWK object
 */
export function coseToJwk(x, y) {
  const toBase64url = (bytes) =>
    btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

  return {
    kty: 'EC',
    crv: 'P-256',
    x: toBase64url(x),
    y: toBase64url(y),
  };
}

/**
 * Hash a credential ID string to a 64-char lowercase hex key for DB storage.
 * @param {string} credentialId - base64url credential ID
 * @returns {Promise<string>} 64-char hex string
 */
export async function hashCredentialId(credentialId) {
  const bytes = new TextEncoder().encode(credentialId);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Open (or create) the multi-device registry KV database.
 *
 * @param {Object} orbitdb - OrbitDB instance
 * @param {string} ownerIdentityId - Ed25519 DID of the device creating the registry
 * @param {string} [address] - Existing DB address to reopen (for Device B)
 * @returns {Promise<Object>} Opened OrbitDB KeyValue database
 */
export async function openDeviceRegistry(orbitdb, ownerIdentityId, address = null) {
  if (address) {
    // Reopen existing registry (Device B after pairing)
    return await orbitdb.open(address, {
      type: 'keyvalue',
      sync: true,
    });
  }

  // Create new registry (Device A — first device)
  return await orbitdb.open('multi-device-registry', {
    type: 'keyvalue',
    sync: true,
    AccessController: OrbitDBAccessController({ write: [ownerIdentityId] }),
  });
}

/**
 * Register a device entry in the registry.
 *
 * Entry shape:
 * {
 *   credential_id: string,       // base64url
 *   public_key: JWK | null,      // P-256 JWK (null when public key unavailable)
 *   device_label: string,
 *   created_at: number,          // Unix ms
 *   status: 'active' | 'revoked',
 *   ed25519_did: string          // did:key:z6Mk...
 * }
 *
 * @param {Object} db - OrbitDB KV database
 * @param {Object} entry - Device entry
 * @returns {Promise<void>}
 */
export async function registerDevice(db, entry) {
  const key = await hashCredentialId(entry.credential_id);
  const existing = await db.get(key);
  if (existing) return; // Already registered — skip to avoid duplicate log entries
  await db.put(key, entry);
}

/**
 * List all registered devices from the registry.
 * @param {Object} db - OrbitDB KV database
 * @returns {Promise<Array>} Array of device entry objects
 */
export async function listDevices(db) {
  const all = await db.all();
  return all.map((e) => e.value);
}

/**
 * Look up a device by its credential ID.
 * @param {Object} db - OrbitDB KV database
 * @param {string} credentialId - base64url credential ID
 * @returns {Promise<Object|null>} Device entry or null if not found
 */
export async function getDeviceByCredentialId(db, credentialId) {
  const key = await hashCredentialId(credentialId);
  return (await db.get(key)) || null;
}

/**
 * Grant write access to a new device DID via OrbitDBAccessController.
 * @param {Object} db - OrbitDB KV database (must use OrbitDBAccessController)
 * @param {string} did - Ed25519 DID of the new device
 * @returns {Promise<void>}
 */
export async function grantDeviceWriteAccess(db, did) {
  await db.access.grant('write', did);
}

/**
 * Revoke write access from a device DID.
 * @param {Object} db - OrbitDB KV database
 * @param {string} did - Ed25519 DID to revoke
 * @returns {Promise<void>}
 */
export async function revokeDeviceAccess(db, did) {
  await db.access.revoke('write', did);
}

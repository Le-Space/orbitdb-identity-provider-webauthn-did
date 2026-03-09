/**
 * Device Registry Database helpers for the multi-device demo.
 */

import {
  openDeviceRegistry,
  registerDevice,
  listDevices,
  coseToJwk,
} from '@le-space/orbitdb-identity-provider-webauthn-did';

/**
 * Open (or reconnect to) the devices KV database.
 * @param {Object} orbitdb - OrbitDB instance
 * @param {Object} identity - OrbitDB identity
 * @param {string} [existingAddress] - Existing DB address (for Device B)
 * @returns {Promise<Object>} OrbitDB KV database
 */
export async function openDevicesDB(orbitdb, identity, existingAddress = null) {
  return await openDeviceRegistry(orbitdb, identity.id, existingAddress);
}

/**
 * Register the current device (self) in the registry.
 * Called by Device A after setup.
 * @param {Object} db - Device registry database
 * @param {Object} credential - WebAuthn credential from createCredential()
 * @param {Object} identity - OrbitDB identity
 * @param {string} [label] - Human-readable device label
 */
export async function registerCurrentDevice(db, credential, identity, label = 'This Device') {
  const publicKey =
    credential.publicKey?.x && credential.publicKey?.y
      ? coseToJwk(credential.publicKey.x, credential.publicKey.y)
      : null;

  await registerDevice(db, {
    credential_id: credential.credentialId,
    public_key: publicKey,
    device_label: label,
    created_at: Date.now(),
    status: 'active',
    ed25519_did: identity.id,
  });
}

/**
 * Register a new device that has just been paired (called on Device A).
 * @param {Object} db - Device registry database
 * @param {Object} entry - Entry as received from the pairing request
 */
export async function onboardNewDevice(db, entry) {
  await registerDevice(db, {
    credential_id: entry.credentialId,
    public_key: entry.publicKey || null,
    device_label: entry.deviceLabel || 'New Device',
    created_at: Date.now(),
    status: 'active',
    ed25519_did: entry.id,
  });
}

/**
 * Load all devices from the registry database.
 * @param {Object} db - Device registry database
 * @returns {Promise<Array>}
 */
export async function loadDevices(db) {
  if (!db) return [];
  return await listDevices(db);
}

const DB_ADDRESS_STORAGE_KEY_PREFIX = 'orbitdb-multi-device-db-address';

function getStorageKey(mode = 'default') {
  return `${DB_ADDRESS_STORAGE_KEY_PREFIX}:${mode}`;
}

export function saveDbAddress(address, mode = 'default') {
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(getStorageKey(mode), address);
  }
}

export function getDbAddress(mode = 'default') {
  if (typeof localStorage !== 'undefined') {
    return localStorage.getItem(getStorageKey(mode));
  }
  return null;
}

export function clearDbAddress(mode = 'default') {
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(getStorageKey(mode));
  }
}

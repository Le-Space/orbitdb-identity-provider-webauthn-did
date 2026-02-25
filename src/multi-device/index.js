/**
 * Multi-Device Linking & Recovery
 *
 * Exports the device registry and pairing protocol for multi-device OrbitDB identities.
 */

export {
  openDeviceRegistry,
  registerDevice,
  listDevices,
  getDeviceByCredentialId,
  getDeviceByDID,
  grantDeviceWriteAccess,
  revokeDeviceAccess,
  hashCredentialId,
  coseToJwk,
} from './device-registry.js';

export {
  LINK_DEVICE_PROTOCOL,
  registerLinkDeviceHandler,
  unregisterLinkDeviceHandler,
  sendPairingRequest,
  detectDeviceLabel,
} from './pairing-protocol.js';

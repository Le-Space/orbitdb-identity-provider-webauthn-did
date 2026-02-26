/**
 * MultiDeviceManager - Unified class for multi-device OrbitDB with WebAuthn
 */

import {
  openDeviceRegistry,
  registerDevice,
  listDevices,
  getDeviceByCredentialId,
  grantDeviceWriteAccess,
  revokeDeviceAccess,
  detectDeviceLabel,
  sendPairingRequest,
  registerLinkDeviceHandler,
  unregisterLinkDeviceHandler,
} from './index.js';

import { WebAuthnDIDProvider } from '../webauthn/provider.js';

export class MultiDeviceManager {
  constructor() {
    this._credential = null;
    this._orbitdb = null;
    this._ipfs = null;
    this._libp2p = null;
    this._identity = null;
    this._devicesDb = null;
    this._dbAddress = null;
    this._onPairingRequest = null;
  }

  static async create(config) {
    const manager = new MultiDeviceManager();
    await manager._init(config);
    return manager;
  }

  async _init(config) {
    if (!config.credential) {
      throw new Error('credential is required');
    }
    this._credential = config.credential;
    this._onPairingRequest = config.onPairingRequest || null;
  }
}

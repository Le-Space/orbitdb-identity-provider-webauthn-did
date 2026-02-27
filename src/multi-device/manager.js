/**
 * MultiDeviceManager - Unified class for multi-device OrbitDB with WebAuthn
 */

import {
  openDeviceRegistry,
  registerDevice,
  listDevices,
  getDeviceByCredentialId,
  getDeviceByDID,
  grantDeviceWriteAccess,
  revokeDeviceAccess,
  coseToJwk,
  detectDeviceLabel,
  sendPairingRequest,
  registerLinkDeviceHandler,
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
    this._onDeviceLinked = null;
    this._onDeviceJoined = null;
  }

  static async create(config) {
    const manager = new MultiDeviceManager();
    await manager._init(config);
    return manager;
  }

  static async createFromExisting(config) {
    const manager = new MultiDeviceManager();
    manager._credential = config.credential;
    manager._orbitdb = config.orbitdb;
    manager._ipfs = config.ipfs;
    manager._libp2p = config.libp2p;
    manager._identity = config.identity;
    manager._onPairingRequest = config.onPairingRequest || null;
    manager._onDeviceLinked = config.onDeviceLinked || null;
    manager._onDeviceJoined = config.onDeviceJoined || null;
    return manager;
  }

  async _init(config) {
    if (!config.credential) throw new Error('credential is required');
    this._credential = config.credential;
    this._onPairingRequest = config.onPairingRequest || null;
    this._onDeviceLinked = config.onDeviceLinked || null;
    this._onDeviceJoined = config.onDeviceJoined || null;
    if (config.orbitdb) this._orbitdb = config.orbitdb;
    if (config.ipfs) this._ipfs = config.ipfs;
    if (config.libp2p) this._libp2p = config.libp2p;
    if (config.identity) this._identity = config.identity;
  }

  /** Build a JWK from the credential's P-256 public key, or null if unavailable. */
  _getPublicKey() {
    const { x, y } = this._credential.publicKey || {};
    return x && y ? coseToJwk(x, y) : null;
  }

  /** Attach sync listeners and register the pairing handler (if configured). */
  async _finalizeDb() {
    await this._setupSyncListeners();
    if (this._onPairingRequest) {
      await registerLinkDeviceHandler(
        this._libp2p, this._devicesDb, this._onPairingRequest, this._onDeviceLinked
      );
    }
  }

  async createNew() {
    if (!this._credential) {
      this._credential = await WebAuthnDIDProvider.createCredential({
        userId: `device-${Date.now()}`,
        displayName: 'Multi-Device User',
        encryptKeystore: true,
        keystoreEncryptionMethod: 'prf',
      });
    }

    if (!this._orbitdb) {
      throw new Error('orbitdb not provided. Pass orbitdb, ipfs, libp2p, identity in config, or use createFromExisting().');
    }

    this._devicesDb = await openDeviceRegistry(this._orbitdb, this._identity.id);
    this._dbAddress = this._devicesDb.address;

    await registerDevice(this._devicesDb, {
      credential_id: this._credential.credentialId,
      public_key: this._getPublicKey(),
      device_label: detectDeviceLabel(),
      created_at: Date.now(),
      status: 'active',
      ed25519_did: this._identity.id,
    });

    await this.syncDevices();
    await this._finalizeDb();

    return { dbAddress: this._dbAddress, identity: this._identity };
  }

  async _setupSyncListeners() {
    if (!this._devicesDb) return;

    if (this._onDeviceJoined) {
      this._devicesDb.events.on('join', (peerId, details) => {
        this._onDeviceJoined(peerId.toString(), details);
      });
    }

    this._devicesDb.events.on('update', async (_entry) => {
      if (this._onDeviceLinked) {
        const devices = await listDevices(this._devicesDb);
        const myDid = this._identity?.id;
        for (const device of devices) {
          if (device.ed25519_did !== myDid && device.status === 'active') {
            this._onDeviceLinked(device);
          }
        }
      }
    });
  }

  async restore() {
    const result = await WebAuthnDIDProvider.detectExistingCredential();
    if (result.hasCredentials && result.credential) {
      this._credential = {
        credentialId: WebAuthnDIDProvider.arrayBufferToBase64url(result.credential.rawId),
        rawCredentialId: new Uint8Array(result.credential.rawId),
      };
      return { needsChoice: true };
    }
    throw new Error('No credentials found and orbitdb not provided. Pass orbitdb, ipfs, libp2p, identity in config to create new.');
  }

  async openExistingDb(dbAddress) {
    if (!this._orbitdb) {
      throw new Error('orbitdb not provided. Pass orbitdb, ipfs, libp2p, identity in config.');
    }
    this._devicesDb = await openDeviceRegistry(this._orbitdb, this._identity.id, dbAddress);
    this._dbAddress = this._devicesDb.address;
    await this._finalizeDb();
    return { dbAddress: this._dbAddress, identity: this._identity };
  }

  async linkToDevice(qrPayload) {
    if (!this._orbitdb) {
      throw new Error('orbitdb not provided. Pass orbitdb, ipfs, libp2p, identity in config.');
    }

    const result = await sendPairingRequest(
      this._libp2p,
      qrPayload.peerId,
      {
        id: this._identity.id,
        credentialId: this._credential.credentialId,
        publicKey: null,
        deviceLabel: detectDeviceLabel(),
      },
      qrPayload.multiaddrs || []
    );

    if (result.type === 'rejected') return result;

    this._devicesDb = await openDeviceRegistry(this._orbitdb, this._identity.id, result.orbitdbAddress);
    this._dbAddress = this._devicesDb.address;

    await registerDevice(this._devicesDb, {
      credential_id: this._credential.credentialId,
      public_key: this._getPublicKey(),
      device_label: detectDeviceLabel(),
      created_at: Date.now(),
      status: 'active',
      ed25519_did: this._identity.id,
    });

    await this.syncDevices();
    await this._finalizeDb();

    return { type: 'granted', dbAddress: this._dbAddress };
  }

  getPeerInfo() {
    if (!this._libp2p) throw new Error('Libp2p not initialized');
    const peerId = this._libp2p.peerId.toString();
    const filteredMultiaddrs = this._libp2p.getMultiaddrs()
      .map((ma) => ma.toString())
      .filter((ma) => {
        const lower = ma.toLowerCase();
        return (lower.includes('/ws/') || lower.includes('/wss/') || lower.includes('/webtransport'))
          && !lower.includes('/ip4/127.') && !lower.includes('/ip4/localhost') && !lower.includes('/ip6/::1');
      });
    return { peerId, multiaddrs: filteredMultiaddrs };
  }

  async listDevices() {
    if (!this._devicesDb) return [];
    await this.syncDevices();
    return listDevices(this._devicesDb);
  }

  async syncDevices() {
    // OrbitDB syncs automatically with connected peers (sync: true in openDeviceRegistry).
    // db.sync is a Sync controller object, not a callable — there is no force-sync API.
  }

  async revokeDevice(did) {
    if (!this._devicesDb) throw new Error('Device registry not initialized');
    await revokeDeviceAccess(this._devicesDb, did);
  }

  /**
   * Process an incoming pairing request programmatically (no libp2p transport).
   * Mirrors the logic of registerLinkDeviceHandler. Used by the test API and
   * by applications that want to handle pairing without raw libp2p streams.
   *
   * @param {Object} requestMsg - { type: 'request', identity: { id, credentialId, deviceLabel, publicKey } }
   * @returns {Promise<{type: 'granted', orbitdbAddress: string}|{type: 'rejected', reason: string}>}
   */
  async processIncomingPairingRequest(requestMsg) {
    if (!this._devicesDb) throw new Error('Device registry not initialized');
    const { identity } = requestMsg;

    const isKnown =
      (await getDeviceByCredentialId(this._devicesDb, identity.credentialId)) ||
      (await getDeviceByDID(this._devicesDb, identity.id));

    if (isKnown) {
      return { type: 'granted', orbitdbAddress: this._dbAddress };
    }

    const decision = this._onPairingRequest
      ? await this._onPairingRequest(requestMsg)
      : 'granted';

    if (decision === 'granted') {
      await grantDeviceWriteAccess(this._devicesDb, identity.id);
      await registerDevice(this._devicesDb, {
        credential_id: identity.credentialId,
        public_key: identity.publicKey || null,
        device_label: identity.deviceLabel || 'Unknown Device',
        created_at: Date.now(),
        status: 'active',
        ed25519_did: identity.id,
      });
      return { type: 'granted', orbitdbAddress: this._dbAddress };
    }
    return { type: 'rejected', reason: 'User cancelled' };
  }

  async close() {
    try {
      if (this._devicesDb) await this._devicesDb.close();
      if (this._orbitdb) await this._orbitdb.stop();
      if (this._ipfs) await this._ipfs.stop();
    } catch (error) {
      console.warn('Error during cleanup:', error);
    }
  }
}

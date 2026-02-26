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

    if (config.orbitdb) {
      this._orbitdb = config.orbitdb;
    }
    if (config.ipfs) {
      this._ipfs = config.ipfs;
    }
    if (config.libp2p) {
      this._libp2p = config.libp2p;
    }
    if (config.identity) {
      this._identity = config.identity;
    }
  }

  async _setupOrbitDB() {
    if (this._orbitdb && this._identity) {
      return;
    }

    const { createLibp2p } = await import('libp2p');
    const { createHelia } = await import('helia');
    const { LevelBlockstore } = await import('blockstore-level');
    const { LevelDatastore } = await import('datastore-level');
    const { createOrbitDB, Identities, useIdentityProvider } = await import('@orbitdb/core');
    const { OrbitDBWebAuthnIdentityProviderFunction } = await import('../webauthn/provider.js');

    const libp2p = await createLibp2p({
      addresses: {
        listen: ['/p2p-circuit', '/webrtc'],
      },
      transports: [
        (await import('@libp2p/websockets')).webSockets(),
        (await import('@libp2p/webtransport')).webTransport(),
        (await import('@libp2p/webrtc')).webRTC(),
        (await import('@libp2p/circuit-relay-v2')).circuitRelayTransport(),
      ],
      connectionEncrypters: [(await import('@chainsafe/libp2p-noise')).noise()],
      streamMuxers: [(await import('@chainsafe/libp2p-yamux')).yamux()],
      connectionGater: {
        denyDialMultiaddr: async () => false,
      },
      peerDiscovery: [
        (await import('@libp2p/bootstrap')).bootstrap({
          list: ['/dns4/acc1-2405-201-8012-40d2-4c6-6344-379d-d7e1.ngrok-free.app/tcp/443/wss/p2p/12D3KooWJkH5Xo1Y4gh4ufNfp9BivkC6ynNx7qMn74Mt4JE4ij7T'],
        }),
      ],
    });

    const ipfs = await createHelia({
      libp2p,
      blockstore: new LevelBlockstore('./orbitdb/blocks'),
      datastore: new LevelDatastore('./orbitdb/data'),
    });

    useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);

    const identities = await Identities({ ipfs });

    const identity = await identities.createIdentity({
      provider: OrbitDBWebAuthnIdentityProviderFunction({
        webauthnCredential: this._credential,
        useKeystoreDID: true,
        keystore: identities.keystore,
        keystoreKeyType: 'Ed25519',
        encryptKeystore: true,
        keystoreEncryptionMethod: 'prf',
      }),
    });

    const orbitdb = await createOrbitDB({ ipfs, identities, identity });

    this._libp2p = libp2p;
    this._ipfs = ipfs;
    this._orbitdb = orbitdb;
    this._identity = identity;
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

    await this._setupOrbitDB();

    this._devicesDb = await openDeviceRegistry(this._orbitdb, this._identity.id);
    this._dbAddress = this._devicesDb.address;

    const publicKey = this._credential.publicKey?.x && this._credential.publicKey?.y
      ? this._convertCoseToJwk(this._credential.publicKey.x, this._credential.publicKey.y)
      : null;

    await registerDevice(this._devicesDb, {
      credential_id: this._credential.credentialId,
      public_key: publicKey,
      device_label: detectDeviceLabel(),
      created_at: Date.now(),
      status: 'active',
      ed25519_did: this._identity.id,
    });

    if (this._onPairingRequest) {
      await registerLinkDeviceHandler(this._libp2p, this._devicesDb, this._onPairingRequest);
    }

    return {
      dbAddress: this._dbAddress,
      identity: this._identity,
    };
  }

  _convertCoseToJwk(x, y) {
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
}

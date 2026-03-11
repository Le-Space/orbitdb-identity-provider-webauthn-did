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
    this._onDeviceLinked = null;
    this._onDeviceJoined = null;
    this._onPairingEvent = null;
    this._listenersSetup = false;
    this._pairingHandlerRegistered = false;
    this._pubsubListeners = null;
    this._dbEventListeners = [];
    this._replicationObserver = null;
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
    manager._onPairingEvent = config.onPairingEvent || null;
    return manager;
  }

  async _init(config) {
    if (!config.credential) throw new Error('credential is required');
    this._credential = config.credential;
    this._onPairingRequest = config.onPairingRequest || null;
    this._onDeviceLinked = config.onDeviceLinked || null;
    this._onDeviceJoined = config.onDeviceJoined || null;
    this._onPairingEvent = config.onPairingEvent || null;
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

  _emitPairingEvent(event) {
    if (!this._onPairingEvent) return;
    this._onPairingEvent({
      timestamp: Date.now(),
      scope: 'manager',
      identityId: this._identity?.id || null,
      dbAddress: this._dbAddress?.toString?.() || this._dbAddress || this._devicesDb?.address?.toString?.() || null,
      ...event,
    });
  }

  async _getAccessSnapshot() {
    if (!this._devicesDb) {
      return {
        rootWritePermissions: [],
        writePermissions: [],
        adminPermissions: [],
        accessControllerHeadCount: 0,
        accessControllerHeadHashes: [],
        currentIdentityIsRootWriter: false,
        currentIdentityCanWrite: false,
        currentIdentityIsAdmin: false,
      };
    }

    const identityId = this._identity?.id || null;
    let rootWritePermissions = [];
    let writePermissions = [];
    let adminPermissions = [];
    let accessControllerHeadCount = 0;
    let accessControllerHeadHashes = [];

    try {
      const raw = this._devicesDb.access?.write;
      if (Array.isArray(raw)) {
        rootWritePermissions = raw;
      }
    } catch {}

    try {
      if (typeof this._devicesDb.access?.get === 'function') {
        writePermissions = Array.from(await this._devicesDb.access.get('write'));
        adminPermissions = Array.from(await this._devicesDb.access.get('admin'));
      }
    } catch {}

    try {
      if (this._devicesDb.access?.debugDb?.log?.heads) {
        const heads = await this._devicesDb.access.debugDb.log.heads();
        accessControllerHeadCount = heads.length;
        accessControllerHeadHashes = heads.map((entry) => entry?.hash).filter(Boolean);
      }
    } catch {}

    return {
      rootWritePermissions,
      writePermissions,
      adminPermissions,
      accessControllerHeadCount,
      accessControllerHeadHashes,
      currentIdentityIsRootWriter: Boolean(identityId && rootWritePermissions.includes(identityId)),
      currentIdentityCanWrite: Boolean(identityId && (writePermissions.includes(identityId) || writePermissions.includes('*'))),
      currentIdentityIsAdmin: Boolean(identityId && (adminPermissions.includes(identityId) || adminPermissions.includes('*'))),
    };
  }

  async _getIdentityReplicationSnapshot() {
    if (!this._devicesDb || !this._orbitdb?.identities) {
      return {
        identityReferencesTotal: 0,
        identitiesResolvedCount: 0,
        identitiesVerifiedCount: 0,
        identityReplicationComplete: false,
        identityMissingHashes: [],
        identityInvalidHashes: [],
        identityReplicationDetails: [],
      };
    }

    const identities = this._orbitdb.identities;
    const seen = new Map();

    const collectFromLog = async (scope, log) => {
      if (!log?.iterator) return;

      for await (const entry of log.iterator()) {
        const hash = entry?.identity;
        if (!hash) continue;

        if (!seen.has(hash)) {
          seen.set(hash, {
            hash,
            scopes: new Set(),
            id: null,
            resolved: false,
            verified: false,
          });
        }

        const record = seen.get(hash);
        record.scopes.add(scope);

        if (record.resolved) continue;

        try {
          const identity = await identities.getIdentity(hash);
          if (!identity) continue;

          record.resolved = true;
          record.id = identity.id || null;

          try {
            record.verified = await identities.verifyIdentity(identity);
          } catch {
            record.verified = false;
          }
        } catch {
          // ignore identity lookup failures, surfaced through unresolved count
        }
      }
    };

    await collectFromLog('registry', this._devicesDb?.log);
    await collectFromLog('acl', this._devicesDb?.access?.debugDb?.log);

    const records = Array.from(seen.values());
    const identityMissingHashes = records.filter((record) => !record.resolved).map((record) => record.hash);
    const identityInvalidHashes = records
      .filter((record) => record.resolved && !record.verified)
      .map((record) => record.hash);

    return {
      identityReferencesTotal: records.length,
      identitiesResolvedCount: records.filter((record) => record.resolved).length,
      identitiesVerifiedCount: records.filter((record) => record.verified).length,
      identityReplicationComplete:
        records.length > 0 &&
        identityMissingHashes.length === 0 &&
        identityInvalidHashes.length === 0,
      identityMissingHashes,
      identityInvalidHashes,
      identityReplicationDetails: records.map((record) => {
        const scopes = Array.from(record.scopes).sort().join('+');
        const status = record.verified
          ? 'verified'
          : record.resolved
            ? 'resolved-unverified'
            : 'missing';
        return `${scopes}: ${record.hash} -> ${record.id || 'unresolved'} [${status}]`;
      }),
    };
  }

  async _emitLocalStateSnapshot(role, stage, detail, extra = {}) {
    const access = await this._getAccessSnapshot();
    const identities = await this._getIdentityReplicationSnapshot();
    let deviceCount = 0;
    let registryHeadCount = 0;
    let accessAddress = null;
    let registryPeerCount = 0;
    let aclPeerCount = 0;
    let registryHeadHashes = [];
    try {
      deviceCount = this._devicesDb ? (await listDevices(this._devicesDb)).length : 0;
    } catch {}
    try {
      if (this._devicesDb?.log) {
        const heads = await this._devicesDb.log.heads();
        registryHeadCount = heads.length;
        registryHeadHashes = heads.map((entry) => entry.hash);
      }
    } catch {}
    try {
      accessAddress = this._devicesDb?.access?.address || null;
    } catch {}
    try {
      registryPeerCount = this._devicesDb?.peers?.size || 0;
    } catch {}
    try {
      aclPeerCount = this._devicesDb?.access?.events ? 1 : 0;
    } catch {}

    this._emitPairingEvent({
      role,
      stage,
      detail,
      level: extra.level || 'info',
      deviceCount,
      rootWritePermissions: access.rootWritePermissions,
      writePermissions: access.writePermissions,
      adminPermissions: access.adminPermissions,
      accessControllerHeadCount: access.accessControllerHeadCount,
      accessControllerHeadHashes: access.accessControllerHeadHashes,
      currentIdentityIsRootWriter: access.currentIdentityIsRootWriter,
      currentIdentityCanWrite: access.currentIdentityCanWrite,
      currentIdentityIsAdmin: access.currentIdentityIsAdmin,
      identityReferencesTotal: identities.identityReferencesTotal,
      identitiesResolvedCount: identities.identitiesResolvedCount,
      identitiesVerifiedCount: identities.identitiesVerifiedCount,
      identityReplicationComplete: identities.identityReplicationComplete,
      identityMissingHashes: identities.identityMissingHashes,
      identityInvalidHashes: identities.identityInvalidHashes,
      identityReplicationDetails: identities.identityReplicationDetails,
      registryHeadCount,
      registryHeadHashes,
      accessAddress,
      registryPeerCount,
      aclPeerCount,
      ...extra,
    });
  }

  _attachPubsubDebugListeners() {
    if (this._pubsubListeners || !this._ipfs?.libp2p?.services?.pubsub || !this._devicesDb) {
      return;
    }

    const pubsub = this._ipfs.libp2p.services.pubsub;
    const registryTopic = this._devicesDb.address?.toString?.() || this._devicesDb.address;
    const aclTopic = this._devicesDb.access?.address || null;

    const onSubscriptionChange = (event) => {
      const { peerId, subscriptions } = event.detail || {};
      const relevant = (subscriptions || []).filter((subscription) =>
        subscription?.topic === registryTopic || subscription?.topic === aclTopic
      );

      if (relevant.length === 0) return;

      for (const subscription of relevant) {
        this._emitPairingEvent({
          role: 'sync',
          stage: 'pubsub-subscription-change',
          level: 'info',
          detail: `Observed pubsub subscription ${subscription.subscribe ? 'join' : 'leave'} for ${subscription.topic === registryTopic ? 'registry' : 'access-controller'} topic`,
          remotePeerId: peerId?.toString?.() || null,
          orbitdbAddress: subscription.topic === registryTopic ? registryTopic : null,
          accessAddress: subscription.topic === aclTopic ? aclTopic : null,
        });
      }
    };

    const onPubsubMessage = (event) => {
      const { topic, from } = event.detail || {};
      if (topic !== registryTopic && topic !== aclTopic) return;
      this._emitPairingEvent({
        role: 'sync',
        stage: 'pubsub-message',
        level: 'info',
        detail: `Observed pubsub message on ${topic === registryTopic ? 'registry' : 'access-controller'} topic`,
        remotePeerId: from?.toString?.() || null,
        orbitdbAddress: topic === registryTopic ? registryTopic : null,
        accessAddress: topic === aclTopic ? aclTopic : null,
      });
    };

    pubsub.addEventListener('subscription-change', onSubscriptionChange);
    pubsub.addEventListener('message', onPubsubMessage);
    this._pubsubListeners = { pubsub, onSubscriptionChange, onPubsubMessage };
  }

  _trackDbListener(target, event, handler) {
    if (!target?.on) return;
    target.on(event, handler);
    this._dbEventListeners.push({ target, event, handler });
  }

  _detachDbListeners() {
    for (const listener of this._dbEventListeners) {
      listener.target?.removeListener?.(listener.event, listener.handler);
      listener.target?.off?.(listener.event, listener.handler);
    }
    this._dbEventListeners = [];
    this._listenersSetup = false;
  }

  _detachPubsubListeners() {
    if (this._pubsubListeners?.pubsub) {
      this._pubsubListeners.pubsub.removeEventListener(
        'subscription-change',
        this._pubsubListeners.onSubscriptionChange
      );
      this._pubsubListeners.pubsub.removeEventListener(
        'message',
        this._pubsubListeners.onPubsubMessage
      );
    }
    this._pubsubListeners = null;
  }

  async _evaluateReplicationObserver() {
    const observer = this._replicationObserver;
    if (!observer || !this._devicesDb) return;

    const entries = await listDevices(this._devicesDb);
    const access = await this._getAccessSnapshot();
    const registryHeadCount = this._devicesDb?.log ? (await this._devicesDb.log.heads()).length : 0;
    const registryPeerCount = this._devicesDb?.peers?.size || 0;

    if (!observer.registryVisible && entries.length > 0) {
      observer.registryVisible = true;
      this._emitPairingEvent({
        role: 'device-b',
        stage: 'registry-visible',
        level: 'success',
        detail: `Registry entries became visible after ${Date.now() - observer.start}ms`,
        deviceCount: entries.length,
        rootWritePermissions: access.rootWritePermissions,
        writePermissions: access.writePermissions,
        adminPermissions: access.adminPermissions,
        currentIdentityIsRootWriter: access.currentIdentityIsRootWriter,
        currentIdentityCanWrite: access.currentIdentityCanWrite,
        currentIdentityIsAdmin: access.currentIdentityIsAdmin,
        registryHeadCount,
        registryPeerCount,
      });
    }

    if (!observer.writeVisible && access.currentIdentityCanWrite) {
      observer.writeVisible = true;
      this._emitPairingEvent({
        role: 'device-b',
        stage: 'acl-write-visible',
        level: 'success',
        detail: `ACL write permission for Device B became visible after ${Date.now() - observer.start}ms`,
        deviceCount: entries.length,
        rootWritePermissions: access.rootWritePermissions,
        writePermissions: access.writePermissions,
        adminPermissions: access.adminPermissions,
        currentIdentityIsRootWriter: access.currentIdentityIsRootWriter,
        currentIdentityCanWrite: access.currentIdentityCanWrite,
        currentIdentityIsAdmin: access.currentIdentityIsAdmin,
        registryHeadCount,
        registryPeerCount,
      });
    }

    if (!observer.adminStateVisible && access.adminPermissions.length > 0) {
      observer.adminStateVisible = true;
      this._emitPairingEvent({
        role: 'device-b',
        stage: 'acl-admin-visible',
        level: 'info',
        detail: `ACL admin set became visible after ${Date.now() - observer.start}ms`,
        deviceCount: entries.length,
        rootWritePermissions: access.rootWritePermissions,
        writePermissions: access.writePermissions,
        adminPermissions: access.adminPermissions,
        currentIdentityIsRootWriter: access.currentIdentityIsRootWriter,
        currentIdentityCanWrite: access.currentIdentityCanWrite,
        currentIdentityIsAdmin: access.currentIdentityIsAdmin,
        registryHeadCount,
        registryPeerCount,
      });
    }

    observer.snapshot = {
      devices: entries,
      access,
      registryVisible: observer.registryVisible,
      writeVisible: observer.writeVisible,
      adminStateVisible: observer.adminStateVisible,
    };

    if (!observer.settled && entries.length > 0) {
      observer.settled = true;
      clearTimeout(observer.timeoutId);
      observer.resolve({
        timedOut: false,
        ...observer.snapshot,
      });
      this._replicationObserver = null;
    }
  }

  _scheduleReplicationEvaluation() {
    if (!this._replicationObserver || this._replicationObserver.scheduled) return;
    this._replicationObserver.scheduled = true;
    queueMicrotask(async () => {
      const observer = this._replicationObserver;
      if (!observer) return;
      observer.scheduled = false;
      await this._evaluateReplicationObserver();
    });
  }

  _scheduleAclHeadProbe(durationMs = 20000, intervalMs = 2000) {
    if (!this._devicesDb?.access?.debugDb?.log?.heads) return;

    const startedAt = Date.now();
    const tick = async () => {
      if (!this._devicesDb?.access?.debugDb?.log?.heads) return;

      try {
        const heads = await this._devicesDb.access.debugDb.log.heads();
        this._emitPairingEvent({
          role: 'sync',
          stage: 'acl-head-probe',
          level: 'info',
          detail: `ACL head probe at ${Date.now() - startedAt}ms`,
          accessAddress: this._devicesDb?.access?.address || null,
          accessControllerHeadCount: heads.length,
          accessControllerHeadHashes: heads.map((entry) => entry?.hash).filter(Boolean),
        });
      } catch (error) {
        this._emitPairingEvent({
          role: 'sync',
          stage: 'acl-head-probe-error',
          level: 'warning',
          detail: `ACL head probe failed: ${error?.message || error}`,
          accessAddress: this._devicesDb?.access?.address || null,
        });
      }

      if (Date.now() - startedAt + intervalMs <= durationMs) {
        setTimeout(() => {
          void tick();
        }, intervalMs);
      }
    };

    void tick();
  }

  _awaitReplicationEvents(timeoutMs = 15000) {
    if (this._replicationObserver?.timeoutId) {
      clearTimeout(this._replicationObserver.timeoutId);
    }

    return new Promise((resolve) => {
      const observer = {
        start: Date.now(),
        resolve,
        settled: false,
        scheduled: false,
        registryVisible: false,
        writeVisible: false,
        adminStateVisible: false,
        snapshot: {
          devices: [],
          access: {
            rootWritePermissions: [],
            writePermissions: [],
            adminPermissions: [],
            currentIdentityIsRootWriter: false,
            currentIdentityCanWrite: false,
            currentIdentityIsAdmin: false,
          },
          registryVisible: false,
          writeVisible: false,
          adminStateVisible: false,
        },
        timeoutId: setTimeout(async () => {
          await this._evaluateReplicationObserver();
          if (observer.settled) return;
          observer.settled = true;
          resolve({
            timedOut: true,
            ...observer.snapshot,
          });
          if (this._replicationObserver === observer) {
            this._replicationObserver = null;
          }
        }, timeoutMs),
      };

      this._replicationObserver = observer;
      this._scheduleReplicationEvaluation();
    });
  }

  _beginReplicationWatchdog(timeoutMs = 15000) {
    void this._awaitReplicationEvents(timeoutMs).then((replication) => {
      const devices = replication.devices;
      const access = replication.access;
      this._emitPairingEvent({
        role: 'device-b',
        stage: 'replication-visible',
        level: devices.length > 0 ? 'success' : 'warning',
        detail: devices.length > 0
          ? 'Replicated registry entries are now visible locally'
          : 'Timed out waiting for replicated registry entries',
        deviceCount: devices.length,
        replicationSummary: `registry=${replication.registryVisible ? 'yes' : 'no'}, aclWrite=${replication.writeVisible ? 'yes' : 'no'}, aclAdmin=${replication.adminStateVisible ? 'yes' : 'no'}`,
        rootWritePermissions: access.rootWritePermissions,
        writePermissions: access.writePermissions,
        adminPermissions: access.adminPermissions,
        currentIdentityIsRootWriter: access.currentIdentityIsRootWriter,
        currentIdentityCanWrite: access.currentIdentityCanWrite,
        currentIdentityIsAdmin: access.currentIdentityIsAdmin,
      });
    });
  }

  async _waitForAclWriteVisibility(timeoutMs = 10000) {
    if (!this._devicesDb?.access?.events?.on || !this._devicesDb?.access?.events?.off) {
      return { visible: false, timedOut: false, access: await this._getAccessSnapshot() };
    }

    const current = await this._getAccessSnapshot();
    if (current.currentIdentityCanWrite) {
      return { visible: true, timedOut: false, access: current };
    }

    return await new Promise((resolve) => {
      let settled = false;

      const finalize = async (timedOut) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        this._devicesDb?.access?.events?.off?.('update', onActivity);
        this._devicesDb?.access?.events?.off?.('join', onActivity);
        const access = await this._getAccessSnapshot();
        resolve({
          visible: access.currentIdentityCanWrite,
          timedOut,
          access,
        });
      };

      const onActivity = async () => {
        const access = await this._getAccessSnapshot();
        if (access.currentIdentityCanWrite) {
          await finalize(false);
        }
      };

      const timeoutId = setTimeout(() => {
        void finalize(true);
      }, timeoutMs);

      this._devicesDb.access.events.on('update', onActivity);
      this._devicesDb.access.events.on('join', onActivity);
    });
  }

  /** Attach sync listeners and optionally register the pairing handler. */
  async _finalizeDb({ registerPairingHandler = false } = {}) {
    await this._setupSyncListeners();
    if (registerPairingHandler && this._onPairingRequest && !this._pairingHandlerRegistered) {
      console.log('[manager] Registering link device handler for peer:', this._libp2p?.peerId?.toString());
      await registerLinkDeviceHandler(
        this._libp2p, this._devicesDb, this._onPairingRequest, this._onDeviceLinked, this._onPairingEvent
      );
      console.log('[manager] Link device handler registered');
      this._pairingHandlerRegistered = true;
      this._emitPairingEvent({
        role: 'device-a',
        stage: 'handler-registered',
        level: 'info',
        detail: 'Device A pairing handler registered',
      });
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
    this._detachDbListeners();
    this._detachPubsubListeners();
    this._emitPairingEvent({
      role: 'device-a',
      stage: 'db-created',
      level: 'success',
      detail: 'Created shared device registry database',
    });

    await registerDevice(this._devicesDb, {
      credential_id: this._credential.credentialId,
      public_key: this._getPublicKey(),
      device_label: detectDeviceLabel(),
      created_at: Date.now(),
      status: 'active',
      ed25519_did: this._identity.id,
    });
    const selfEntry = await getDeviceByDID(this._devicesDb, this._identity.id);
    const access = await this._getAccessSnapshot();
    this._emitPairingEvent({
      role: 'device-a',
      stage: 'self-registered',
      level: selfEntry ? 'success' : 'warning',
      detail: selfEntry
        ? 'Registered this device as the first authorized device'
        : 'Attempted to register the first device, but the self entry is not readable back from the local registry',
      rootWritePermissions: access.rootWritePermissions,
      writePermissions: access.writePermissions,
      adminPermissions: access.adminPermissions,
      accessControllerHeadCount: access.accessControllerHeadCount,
      accessControllerHeadHashes: access.accessControllerHeadHashes,
      currentIdentityIsRootWriter: access.currentIdentityIsRootWriter,
      currentIdentityCanWrite: access.currentIdentityCanWrite,
      currentIdentityIsAdmin: access.currentIdentityIsAdmin,
      deviceCount: selfEntry ? 1 : 0,
    });

    if (!selfEntry) {
      throw new Error('Created the device registry, but the first device entry was not readable back from the local database.');
    }

    await this._emitLocalStateSnapshot(
      'device-a',
      'registry-heads-local',
      'Local registry heads after first-device registration'
    );

    await this.syncDevices();
    await this._finalizeDb({ registerPairingHandler: true });

    return { dbAddress: this._dbAddress, identity: this._identity };
  }

  async _setupSyncListeners() {
    if (this._listenersSetup || !this._devicesDb) {
      console.log('[manager] _setupSyncListeners: skipping (already set up or no db)');
      return;
    }
    this._listenersSetup = true;
    this._attachPubsubDebugListeners();

    console.log('[manager] Setting up sync listeners for DB:', this._devicesDb.address?.toString());

    if (this._onDeviceJoined) {
      console.log('[manager] Subscribing to join events');
      this._trackDbListener(this._devicesDb.events, 'join', async (peerId, details) => {
        console.log('[manager] JOIN event fired:', peerId.toString(), details);
        if (this._onDeviceJoined) {
          this._onDeviceJoined(peerId.toString(), details);
        }
        this._emitPairingEvent({
          role: 'sync',
          stage: 'peer-joined',
          level: 'info',
          detail: `Replication peer joined: ${peerId.toString()}`,
          remotePeerId: peerId.toString(),
          registryHeadCount: Array.isArray(details) ? details.length : 0,
          registryHeadHashes: Array.isArray(details) ? details.map((entry) => entry?.hash).filter(Boolean) : [],
        });
        this._scheduleReplicationEvaluation();
        // Also refresh device list on join to show all devices
        if (this._onDeviceLinked) {
          const devices = await listDevices(this._devicesDb);
          console.log('[manager] JOIN: Refreshing device list, found:', devices.length);
          for (const device of devices) {
            this._onDeviceLinked(device);
          }
        }
      });
    }

    this._trackDbListener(this._devicesDb.events, 'error', async (error) => {
      console.error('[manager] DB error event:', error);
      this._emitPairingEvent({
        role: 'sync',
        stage: 'db-error',
        level: 'error',
        detail: `Registry sync/database error: ${error?.message || error}`,
        error: error?.message || String(error),
      });
    });

    this._trackDbListener(this._devicesDb.events, 'leave', async (peerId) => {
      console.warn('[manager] LEAVE event fired:', peerId.toString());
      this._emitPairingEvent({
        role: 'sync',
        stage: 'peer-left',
        level: 'warning',
        detail: `Replication peer left: ${peerId.toString()}`,
        remotePeerId: peerId.toString(),
      });
    });

      this._trackDbListener(this._devicesDb.events, 'update', async (_entry) => {
        console.log('[manager] UPDATE event fired, _onDeviceLinked:', !!this._onDeviceLinked);
        const devices = await listDevices(this._devicesDb);
      const heads = this._devicesDb?.log ? await this._devicesDb.log.heads() : [];
      console.log('[manager] DB UPDATE snapshot:', {
        dbAddress: this._devicesDb?.address?.toString?.() || null,
        deviceCount: devices.length,
        headCount: heads.length,
        headHashes: heads.map((entry) => entry?.hash).filter(Boolean),
        peerCount: this._devicesDb?.peers?.size || 0,
      });
      this._emitPairingEvent({
        role: 'sync',
        stage: 'db-update',
        level: 'info',
        detail: `Registry update observed; ${devices.length} device entr${devices.length === 1 ? 'y' : 'ies'} now visible locally`,
        deviceCount: devices.length,
      });
      if (this._onDeviceLinked) {
        console.log('[manager] UPDATE: Devices found:', devices.length);
        // Trigger callback for all devices to refresh the list
        for (const device of devices) {
          console.log('[manager] UPDATE: Triggering callback for device:', device.device_label, device.ed25519_did, 'status:', device.status);
          this._onDeviceLinked(device);
        }
      }
      this._scheduleReplicationEvaluation();
    });

    if (this._devicesDb.access?.events?.on) {
      this._trackDbListener(this._devicesDb.access.events, 'update', async () => {
        console.log('[manager] ACL UPDATE event fired');
        await this._emitLocalStateSnapshot(
          'sync',
          'acl-update',
          'Access controller update observed locally'
        );
        this._scheduleAclHeadProbe(10000, 2000);
        this._scheduleReplicationEvaluation();
      });

      this._trackDbListener(this._devicesDb.access.events, 'join', async (peerId) => {
        console.log('[manager] ACL JOIN event fired:', peerId.toString());
        await this._emitLocalStateSnapshot(
          'sync',
          'acl-peer-joined',
          `Access controller peer joined: ${peerId.toString()}`,
          { remotePeerId: peerId.toString() }
        );
        this._scheduleAclHeadProbe(10000, 2000);
        this._scheduleReplicationEvaluation();
      });

      this._trackDbListener(this._devicesDb.access.events, 'error', async (error) => {
        console.error('[manager] ACL error event:', error);
        this._emitPairingEvent({
          role: 'sync',
          stage: 'acl-error',
          level: 'error',
          detail: `Access-controller sync/database error: ${error?.message || error}`,
          error: error?.message || String(error),
          accessAddress: this._devicesDb?.access?.address || null,
        });
      });

      this._trackDbListener(this._devicesDb.access.events, 'leave', async (peerId) => {
        console.warn('[manager] ACL LEAVE event fired:', peerId.toString());
        this._emitPairingEvent({
          role: 'sync',
          stage: 'acl-peer-left',
          level: 'warning',
          detail: `Access controller peer left: ${peerId.toString()}`,
          remotePeerId: peerId.toString(),
          accessAddress: this._devicesDb?.access?.address || null,
        });
      });
    }
    console.log('[manager] Sync listeners setup complete');
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

  async openExistingDb(dbAddress, { registerPairingHandler = true } = {}) {
    if (!this._orbitdb) {
      throw new Error('orbitdb not provided. Pass orbitdb, ipfs, libp2p, identity in config.');
    }
    this._detachDbListeners();
    this._detachPubsubListeners();
    this._devicesDb = await openDeviceRegistry(this._orbitdb, this._identity.id, dbAddress);
    this._dbAddress = this._devicesDb.address;
    const access = await this._getAccessSnapshot();
    const identities = await this._getIdentityReplicationSnapshot();
    this._emitPairingEvent({
      role: 'device-b',
      stage: 'db-opened',
      level: 'success',
      detail: 'Opened existing shared device registry',
      registryHeadCount: this._devicesDb?.log ? (await this._devicesDb.log.heads()).length : 0,
      registryPeerCount: this._devicesDb?.peers?.size || 0,
      accessAddress: this._devicesDb?.access?.address || null,
      rootWritePermissions: access.rootWritePermissions,
      writePermissions: access.writePermissions,
      adminPermissions: access.adminPermissions,
      currentIdentityIsRootWriter: access.currentIdentityIsRootWriter,
      currentIdentityCanWrite: access.currentIdentityCanWrite,
      currentIdentityIsAdmin: access.currentIdentityIsAdmin,
      identityReferencesTotal: identities.identityReferencesTotal,
      identitiesResolvedCount: identities.identitiesResolvedCount,
      identitiesVerifiedCount: identities.identitiesVerifiedCount,
      identityReplicationComplete: identities.identityReplicationComplete,
      identityMissingHashes: identities.identityMissingHashes,
      identityInvalidHashes: identities.identityInvalidHashes,
      identityReplicationDetails: identities.identityReplicationDetails,
    });
    this._scheduleAclHeadProbe();
    const aclStatus = await this._waitForAclWriteVisibility();
    this._emitPairingEvent({
      role: 'device-b',
      stage: aclStatus.visible ? 'acl-ready-before-finalize' : 'acl-pending-before-finalize',
      level: aclStatus.visible ? 'success' : (aclStatus.timedOut ? 'warning' : 'info'),
      detail: aclStatus.visible
        ? 'ACL write permission became visible before continuing'
        : 'ACL write permission is still not visible before continuing',
      accessAddress: this._devicesDb?.access?.address || null,
      rootWritePermissions: aclStatus.access.rootWritePermissions,
      writePermissions: aclStatus.access.writePermissions,
      adminPermissions: aclStatus.access.adminPermissions,
      accessControllerHeadCount: aclStatus.access.accessControllerHeadCount,
      accessControllerHeadHashes: aclStatus.access.accessControllerHeadHashes,
      currentIdentityIsRootWriter: aclStatus.access.currentIdentityIsRootWriter,
      currentIdentityCanWrite: aclStatus.access.currentIdentityCanWrite,
      currentIdentityIsAdmin: aclStatus.access.currentIdentityIsAdmin,
    });
    await this._finalizeDb({ registerPairingHandler });
    return { dbAddress: this._dbAddress, identity: this._identity };
  }

  async linkToDevice(qrPayload) {
    if (!this._orbitdb) {
      throw new Error('orbitdb not provided. Pass orbitdb, ipfs, libp2p, identity in config.');
    }

    console.log('[linkToDevice] QR payload:', JSON.stringify(qrPayload));
    console.log('[linkToDevice] My peerId:', this._libp2p?.peerId?.toString());
    this._emitPairingEvent({
      role: 'device-b',
      stage: 'pairing-start',
      level: 'info',
      detail: 'Starting pairing flow from QR payload',
      targetPeerId: qrPayload.peerId,
    });

    const result = await sendPairingRequest(
      this._libp2p,
      qrPayload.peerId,
      {
        id: this._identity.id,
        credentialId: this._credential.credentialId,
        publicKey: null,
        deviceLabel: detectDeviceLabel(),
      },
      qrPayload.multiaddrs || [],
      (event) => this._emitPairingEvent(event)
    );

    if (result.type === 'rejected') return result;

    console.log('[linkToDevice] Got granted, opening database...');
    this._emitPairingEvent({
      role: 'device-b',
      stage: 'grant-received',
      level: 'success',
      detail: 'Received granted database address from Device A',
      orbitdbAddress: result.orbitdbAddress,
    });
    this._detachDbListeners();
    this._detachPubsubListeners();
    this._devicesDb = await openDeviceRegistry(this._orbitdb, this._identity.id, result.orbitdbAddress);
    this._dbAddress = this._devicesDb.address;
    const identities = await this._getIdentityReplicationSnapshot();
    console.log('[linkToDevice] Database opened, waiting for Device A entries to sync...');
    this._emitPairingEvent({
      role: 'device-b',
      stage: 'db-opened',
      level: 'success',
      detail: 'Opened shared registry and waiting for replication',
      registryHeadCount: this._devicesDb?.log ? (await this._devicesDb.log.heads()).length : 0,
      registryPeerCount: this._devicesDb?.peers?.size || 0,
      accessAddress: this._devicesDb?.access?.address || null,
      identityReferencesTotal: identities.identityReferencesTotal,
      identitiesResolvedCount: identities.identitiesResolvedCount,
      identitiesVerifiedCount: identities.identitiesVerifiedCount,
      identityReplicationComplete: identities.identityReplicationComplete,
      identityMissingHashes: identities.identityMissingHashes,
      identityInvalidHashes: identities.identityInvalidHashes,
      identityReplicationDetails: identities.identityReplicationDetails,
    });

    // Register listeners immediately so we catch update events during the delay below
    this._listenersSetup = false;
    await this._setupSyncListeners();
    this._beginReplicationWatchdog(15000);

    const aclStatus = await this._waitForAclWriteVisibility();
    this._emitPairingEvent({
      role: 'device-b',
      stage: aclStatus.visible ? 'acl-ready-before-use' : 'acl-pending-before-use',
      level: aclStatus.visible ? 'success' : (aclStatus.timedOut ? 'warning' : 'info'),
      detail: aclStatus.visible
        ? 'ACL write permission became visible before using the shared registry'
        : 'ACL write permission is still not visible before using the shared registry',
      accessAddress: this._devicesDb?.access?.address || null,
      rootWritePermissions: aclStatus.access.rootWritePermissions,
      writePermissions: aclStatus.access.writePermissions,
      adminPermissions: aclStatus.access.adminPermissions,
      currentIdentityIsRootWriter: aclStatus.access.currentIdentityIsRootWriter,
      currentIdentityCanWrite: aclStatus.access.currentIdentityCanWrite,
      currentIdentityIsAdmin: aclStatus.access.currentIdentityIsAdmin,
    });

    await this._finalizeDb({ registerPairingHandler: false });

    return { type: 'granted', dbAddress: this._dbAddress };
  }

  getPeerInfo() {
    if (!this._libp2p) throw new Error('Libp2p not initialized');
    const peerId = this._libp2p.peerId.toString();
    const filteredMultiaddrs = this._libp2p.getMultiaddrs()
      .map((ma) => ma.toString())
      .filter((ma) => {
        const lower = ma.toLowerCase();
        return (lower.includes('/ws/') || lower.includes('/wss/') || lower.includes('/webtransport') || lower.includes('/p2p-circuit'))
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
    this._emitPairingEvent({
      role: 'device-a',
      stage: 'request-received',
      level: 'info',
      detail: 'Processing incoming pairing request via direct API',
      requesterDid: identity.id,
      credentialId: identity.credentialId,
    });

    const isKnown =
      (await getDeviceByCredentialId(this._devicesDb, identity.credentialId)) ||
      (await getDeviceByDID(this._devicesDb, identity.id));

    if (isKnown) {
      this._emitPairingEvent({
        role: 'device-a',
        stage: 'known-device',
        level: 'success',
        detail: 'Known device detected; returning existing database address',
        requesterDid: identity.id,
      });
      return { type: 'granted', orbitdbAddress: this._dbAddress };
    }

    const decision = this._onPairingRequest
      ? await this._onPairingRequest(requestMsg)
      : 'granted';

    if (decision === 'granted') {
      const beforeGrant = await this._getAccessSnapshot();
      this._emitPairingEvent({
        role: 'device-a',
        stage: 'access-check',
        level: beforeGrant.currentIdentityIsAdmin || beforeGrant.currentIdentityIsRootWriter ? 'info' : 'warning',
        detail: beforeGrant.currentIdentityIsAdmin || beforeGrant.currentIdentityIsRootWriter
          ? 'Current Device A identity appears authorized to mutate access control'
          : 'Current Device A identity does not appear in the access controller admin/root-writer set',
        requesterDid: identity.id,
        rootWritePermissions: beforeGrant.rootWritePermissions,
        writePermissions: beforeGrant.writePermissions,
        adminPermissions: beforeGrant.adminPermissions,
        currentIdentityIsRootWriter: beforeGrant.currentIdentityIsRootWriter,
        currentIdentityCanWrite: beforeGrant.currentIdentityCanWrite,
        currentIdentityIsAdmin: beforeGrant.currentIdentityIsAdmin,
      });
      this._emitPairingEvent({
        role: 'device-a',
        stage: 'grant-start',
        level: 'info',
        detail: 'Granting write access in OrbitDB access controller',
        requesterDid: identity.id,
      });
      await grantDeviceWriteAccess(this._devicesDb, identity.id);
      const afterGrant = await this._getAccessSnapshot();
      this._emitPairingEvent({
        role: 'device-a',
        stage: 'grant-complete',
        level: 'success',
        detail: 'Write access grant completed',
        requesterDid: identity.id,
        rootWritePermissions: afterGrant.rootWritePermissions,
        writePermissions: afterGrant.writePermissions,
        adminPermissions: afterGrant.adminPermissions,
        currentIdentityIsRootWriter: afterGrant.currentIdentityIsRootWriter,
        currentIdentityCanWrite: afterGrant.currentIdentityCanWrite,
        currentIdentityIsAdmin: afterGrant.currentIdentityIsAdmin,
      });
      await registerDevice(this._devicesDb, {
        credential_id: identity.credentialId,
        public_key: identity.publicKey || null,
        device_label: identity.deviceLabel || 'Unknown Device',
        created_at: Date.now(),
        status: 'active',
        ed25519_did: identity.id,
      });
      const devices = await listDevices(this._devicesDb);
      this._emitPairingEvent({
        role: 'device-a',
        stage: 'registry-write-complete',
        level: 'success',
        detail: 'New device registered in shared registry',
        requesterDid: identity.id,
        deviceCount: devices.length,
      });
      return { type: 'granted', orbitdbAddress: this._dbAddress };
    }
    return { type: 'rejected', reason: 'User cancelled' };
  }

  async close() {
    try {
      if (this._pubsubListeners?.pubsub) {
        this._pubsubListeners.pubsub.removeEventListener(
          'subscription-change',
          this._pubsubListeners.onSubscriptionChange
        );
        this._pubsubListeners.pubsub.removeEventListener(
          'message',
          this._pubsubListeners.onPubsubMessage
        );
      }
      this._pubsubListeners = null;
      if (this._pairingHandlerRegistered && this._libp2p) {
        await unregisterLinkDeviceHandler(this._libp2p);
        this._pairingHandlerRegistered = false;
      }
      if (this._devicesDb) await this._devicesDb.close();
      if (this._orbitdb) await this._orbitdb.stop();
      if (this._ipfs) await this._ipfs.stop();
    } catch (error) {
      console.warn('Error during cleanup:', error);
    }
  }
}

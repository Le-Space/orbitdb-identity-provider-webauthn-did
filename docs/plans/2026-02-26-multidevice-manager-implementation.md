# MultiDeviceManager Class Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a `MultiDeviceManager` class that encapsulates all multi-device logic, hiding device registries, pairing protocols, and access controllers from consumers.

**Architecture:** Single monolithic class that owns orbitdb/ipfs/libp2p/identity/devicesDb. Uses existing functional primitives internally. Factory pattern with `create()` instead of constructor.

**Tech Stack:** OrbitDB, Helia, libp2p, WebAuthn

---

## Pre-requisites

Before starting, ensure you understand the existing code:
- Read `src/multi-device/device-registry.js` - device registry primitives
- Read `src/multi-device/pairing-protocol.js` - pairing protocol
- Read `src/webauthn/provider.js` - WebAuthn DID provider
- Read `examples/webauthn-multi-device-demo/src/lib/MultiDeviceApp.svelte` - current flow

---

### Task 1: Create MultiDeviceManager Class Skeleton

**Files:**
- Create: `src/multi-device/manager.js`

**Step 1: Create the file with class skeleton**

```js
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
```

**Step 2: Commit**

```bash
git add src/multi-device/manager.js
git commit -m "feat(multi-device): add MultiDeviceManager class skeleton"
```

---

### Task 2: Implement _setupOrbitDB Internal Method

**Files:**
- Modify: `src/multi-device/manager.js`

**Step 1: Add _setupOrbitDB method**

Add this method after `_init`:

```js
  async _setupOrbitDB() {
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
```

**Step 2: Commit**

```bash
git add src/multi-device/manager.js
git commit -m "feat(multi-device): add _setupOrbitDB method to manager"
```

---

### Task 3: Implement createNew Method

**Files:**
- Modify: `src/multi-device/manager.js`

**Step 1: Add createNew method**

Add after `_setupOrbitDB`:

```js
  async createNew() {
    // Create new credential if not exists
    if (!this._credential) {
      this._credential = await WebAuthnDIDProvider.createCredential({
        userId: `device-${Date.now()}`,
        displayName: 'Multi-Device User',
        encryptKeystore: true,
        keystoreEncryptionMethod: 'prf',
      });
    }

    // Setup OrbitDB
    await this._setupOrbitDB();

    // Create device registry (first device)
    this._devicesDb = await openDeviceRegistry(this._orbitdb, this._identity.id);
    this._dbAddress = this._devicesDb.address;

    // Register self
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

    // Register pairing handler
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
```

**Step 2: Commit**

```bash
git add src/multi-device/manager.js
git commit -m "feat(multi-device): add createNew method"
```

---

### Task 4: Implement restore Method

**Files:**
- Modify: `src/multi-device/manager.js`

**Step 1: Add restore method**

Add after `createNew`:

```js
  async restore() {
    // Check for existing credential
    const result = await WebAuthnDIDProvider.detectExistingCredential();

    if (result.hasCredentials && result.credential) {
      // Normalize credential
      this._credential = {
        credentialId: WebAuthnDIDProvider.arrayBufferToBase64url(result.credential.rawId),
        rawCredentialId: new Uint8Array(result.credential.rawId),
      };

      // Return "link-or-create" state - caller decides
      return { needsChoice: true };
    }

    // No credential - create new
    return await this.createNew();
  }

  async openExistingDb(dbAddress) {
    // Setup OrbitDB if not already
    if (!this._orbitdb) {
      await this._setupOrbitDB();
    }

    // Open existing DB
    this._devicesDb = await openDeviceRegistry(this._orbitdb, this._identity.id, dbAddress);
    this._dbAddress = this._devicesDb.address;

    // Register pairing handler
    if (this._onPairingRequest) {
      await registerLinkDeviceHandler(this._libp2p, this._devicesDb, this._onPairingRequest);
    }

    return {
      dbAddress: this._dbAddress,
      identity: this._identity,
    };
  }
```

**Step 2: Commit**

```bash
git add src/multi-device/manager.js
git commit -m "feat(multi-device): add restore and openExistingDb methods"
```

---

### Task 5: Implement linkToDevice and getPeerInfo Methods

**Files:**
- Modify: `src/multi-device/manager.js`

**Step 1: Add linkToDevice and getPeerInfo methods**

```js
  async linkToDevice(qrPayload) {
    // Ensure orbitdb/identity ready
    if (!this._orbitdb) {
      await this._setupOrbitDB();
    }

    const identityPayload = {
      id: this._identity.id,
      credentialId: this._credential.credentialId,
      publicKey: null,
      deviceLabel: detectDeviceLabel(),
    };

    const result = await sendPairingRequest(
      this._libp2p,
      qrPayload.peerId,
      identityPayload,
      qrPayload.multiaddrs || []
    );

    if (result.type === 'rejected') {
      return result;
    }

    // Open shared DB
    this._devicesDb = await openDeviceRegistry(
      this._orbitdb,
      this._identity.id,
      result.orbitdbAddress
    );
    this._dbAddress = this._devicesDb.address;

    // Register pairing handler to accept more devices
    if (this._onPairingRequest) {
      await registerLinkDeviceHandler(this._libp2p, this._devicesDb, this._onPairingRequest);
    }

    return {
      type: 'granted',
      dbAddress: this._dbAddress,
    };
  }

  getPeerInfo() {
    if (!this._libp2p) {
      throw new Error('Libp2p not initialized');
    }

    const peerId = this._libp2p.peerId.toString();

    const filteredMultiaddrs = this._libp2p.getMultiaddrs()
      .map((ma) => ma.toString())
      .filter((ma) => {
        const maStr = ma.toLowerCase();
        const hasWebsocketOrTransport = 
          maStr.includes('/ws/') || 
          maStr.includes('/wss/') ||
          maStr.includes('/webtransport');
        const isLoopback = 
          maStr.includes('/ip4/127.') ||
          maStr.includes('/ip4/localhost') ||
          maStr.includes('/ip6/::1');
        return hasWebsocketOrTransport && !isLoopback;
      });

    return { peerId, multiaddrs: filteredMultiaddrs };
  }
```

**Step 2: Commit**

```bash
git add src/multi-device/manager.js
git commit -m "feat(multi-device): add linkToDevice and getPeerInfo methods"
```

---

### Task 6: Implement listDevices, revokeDevice, and close Methods

**Files:**
- Modify: `src/multi-device/manager.js`

**Step 1: Add remaining methods**

```js
  async listDevices() {
    if (!this._devicesDb) {
      return [];
    }
    return await listDevices(this._devicesDb);
  }

  async revokeDevice(did) {
    if (!this._devicesDb) {
      throw new Error('Device registry not initialized');
    }
    await revokeDeviceAccess(this._devicesDb, did);
  }

  async close() {
    try {
      if (this._devicesDb) {
        await this._devicesDb.close();
      }
      if (this._orbitdb) {
        await this._orbitdb.stop();
      }
      if (this._ipfs) {
        await this._ipfs.stop();
      }
    } catch (error) {
      console.warn('Error during cleanup:', error);
    }
  }
```

**Step 2: Commit**

```bash
git add src/multi-device/manager.js
git commit -m "feat(multi-device): add listDevices, revokeDevice, and close methods"
```

---

### Task 7: Export MultiDeviceManager from index.js

**Files:**
- Modify: `src/multi-device/index.js`

**Step 1: Add export**

Add at the end of the file:

```js
export { MultiDeviceManager } from './manager.js';
```

**Step 2: Commit**

```bash
git add src/multi-device/index.js
git commit -m "feat(multi-device): export MultiDeviceManager"
```

---

### Task 8: Run Lint and Tests

**Step 1: Run lint**

```bash
pnpm run lint
```

**Step 2: Run existing tests**

```bash
pnpm run test:unit
```

---

### Task 9: Refactor Demo to Use MultiDeviceManager

**Files:**
- Modify: `examples/webauthn-multi-device-demo/src/lib/MultiDeviceApp.svelte`

**Step 1: Replace imports**

Replace:
```js
import {
  WebAuthnDIDProvider,
  checkWebAuthnSupport,
  grantDeviceWriteAccess,
  registerDevice,
  listDevices,
  getDeviceByCredentialId,
  sendPairingRequest,
  detectDeviceLabel,
} from '@le-space/orbitdb-identity-provider-webauthn-did';
import { setupOrbitDB, registerPairingHandler, getQRPayload, cleanup } from '$lib/libp2p.js';
import { openDevicesDB, registerCurrentDevice, loadDevices, saveDbAddress, getDbAddress } from '$lib/database.js';
```

With:
```js
import { MultiDeviceManager } from '@le-space/orbitdb-identity-provider-webauthn-did';
import { checkWebAuthnSupport } from '@le-space/orbitdb-identity-provider-webauthn-did';
```

**Step 2: Replace state management**

Replace all the manual orbitdb/ipfs/libp2p/identity state with:
```js
let manager = null;

// Use manager.create() with credential and onPairingRequest callback
// Replace all manager. calls: restore(), createNew(), linkToDevice(), getPeerInfo(), listDevices(), revokeDevice(), close()
```

**Step 3: Commit**

```bash
git add examples/webauthn-multi-device-demo/src/lib/MultiDeviceApp.svelte
git commit -m "refactor(demo): use MultiDeviceManager class"
```

---

### Task 10: Refactor E2E Test to Use MultiDeviceManager

**Files:**
- Modify: `tests/webauthn-multi-device-e2e.test.js`

**Step 1: Update test approach**

The E2E tests should now:
1. Import `MultiDeviceManager` into the page context
2. Use `manager.createNew()` for first device setup
3. Use `manager.linkToDevice()` for device linking
4. Use `manager.listDevices()` for verification

**Step 2: Run E2E tests**

```bash
pnpm run test:e2e
```

**Step 3: Commit**

```bash
git add tests/webauthn-multi-device-e2e.test.js
git commit -m "refactor(test): use MultiDeviceManager in E2E tests"
```

---

### Task 11: Final Verification

**Step 1: Run all tests**

```bash
pnpm run test:unit
pnpm run test:integration
pnpm run test:e2e
```

**Step 2: Run lint**

```bash
pnpm run lint
```

**Step 3: Commit**

```bash
git commit -m "fix: final verification passing"
```

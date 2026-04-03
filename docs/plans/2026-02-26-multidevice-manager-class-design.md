# MultiDeviceManager Class Design

**Date:** 2026-02-26
**Status:** Approved

## Overview

Refactor `src/multi-device/` from functional primitives to a unified class API (`MultiDeviceManager`). Consumers call methods without knowing about device registries, pairing protocols, access controllers, etc.

## Architecture

Single class `MultiDeviceManager` that encapsulates all multi-device logic. Uses existing functional primitives internally.

### File Location

- New class in `src/multi-device/manager.js`
- Export from `src/multi-device/index.js`
- Keep existing `device-registry.js` and `pairing-protocol.js` exports as-is for backward compatibility

## Public API

```js
// Factory (not constructor - async setup)
const manager = await MultiDeviceManager.create({
  credential,           // WebAuthn credential (required)
  orbitdb,              // OrbitDB instance (optional - creates if nil)
  ipfs,                 // Helia IPFS instance (optional - creates if nil)
  libp2p,               // libp2p instance (optional - creates if nil)
  identity,             // OrbitDB identity (optional - creates if nil)
  onPairingRequest: async (request) => 'granted' | 'rejected',  // required for Device A
});

// Methods
await manager.restore();                    // Auto-detect: login → link-or-create → new
await manager.createNew();                  // Create new credential + fresh setup (first device)
await manager.linkToDevice(qrPayload);     // Link as Device B to existing device

manager.getPeerInfo();                      // Returns { peerId, multiaddrs } for QR rendering
await manager.listDevices();                // Get registered devices
await manager.revokeDevice(did);            // Revoke device access

manager.onPairingRequest = async (req) => 'granted' | 'rejected';  // Set/update callback

await manager.close();                       // Cleanup all resources
```

## Internal Structure

```
MultiDeviceManager
├── _credential          // WebAuthn credential
├── _orbitdb             // OrbitDB instance  
├── _ipfs                // Helia IPFS instance
├── _libp2p              // libp2p instance
├── _identity            // OrbitDB identity
├── _devicesDb           // Device registry KV database
├── _dbAddress           // Stored for restoration
├── _onPairingRequest    // Callback for incoming pairing requests
│
├── create()             // Factory - initializes or uses provided instances
├── _setupOrbitDB()      // Internal: create orbitdb/ipfs/libp2p/identity
├── _initAsFirstDevice() // Internal: create new registry (Device A)
├── _initAsLinking()     // Internal: setup for linking to existing
├── restore()            // Auto-detect flow: login → link-or-create → new
├── createNew()          // Create fresh setup (new credential)
├── linkToDevice()       // Connect to Device A via QR payload
├── getPeerInfo()        // Expose peer info for QR
├── listDevices()        // Delegate to device-registry
├── revokeDevice()       // Delegate to device-registry
└── close()              // Cleanup all resources
```

## Data Flow

### `create()` flow
1. Store credential
2. If orbitdb/ipfs/libp2p/identity provided → use them
3. If nil → call `_setupOrbitDB()` to create all
4. Register pairing handler if `onPairingRequest` callback provided
5. Return manager instance

### `restore()` flow
1. Call `WebAuthnDIDProvider.detectExistingCredential()`
2. **If has credential + local DB exists:**
   - Setup orbitdb (will prompt biometric)
   - Open existing DB by address
   - Register pairing handler
   - Return ready state
3. **If has credential + no local DB:**
   - Return state indicating "link-or-create" choice needed
   - Caller decides → call `createNew()` or wait for user to scan
4. **If no credential:**
   - Call `createNew()` automatically

### `createNew()` flow
1. Call `WebAuthnDIDProvider.createCredential()`
2. Setup orbitdb with new credential
3. Create device registry (`openDeviceRegistry`)
4. Register self as device
5. Register pairing handler
6. Save state for restoration

### `linkToDevice(qrPayload)` flow
1. Ensure orbitdb/identity ready
2. Call `sendPairingRequest(libp2p, qrPayload.peerId, identity, qrPayload.multiaddrs)`
3. If granted → open shared DB by returned address
4. Register pairing handler to accept more devices

## Error Handling

### At `create()` time
- Missing `credential` → throw `'credential is required'`
- Missing `onPairingRequest` for Device A → allow (warn), but pairing won't work

### At `restore()`/`createNew()` time
- WebAuthn not supported → throw with descriptive message
- Biometric prompt cancelled → throw `'Authentication cancelled'`
- DB open fails → throw `'Failed to open database: {error}'`
- Network/connection fails → throw `'Connection failed: {error}'`

### At `linkToDevice()` time
- Pairing rejected → return `{ type: 'rejected', reason: '...' }` (not throw)
- Connection timeout → throw `'Connection timeout'`
- Invalid QR payload → throw `'Invalid QR payload'`

### General
- All resources cleanup on `close()` - don't throw if already closed
- Log errors internally, expose to caller via thrown errors

## Testing & Backward Compatibility

### Testing
- Unit tests for class methods (mock OrbitDB, libp2p)
- Integration tests with actual demo flow
- Existing functional exports still testable

### Backward Compatibility
- Keep existing `device-registry.js` and `pairing-protocol.js` exports as-is
- Add class as new export alongside existing functions
- Demo refactors to use class (but can keep working version as reference)

## Test Refactor

The existing E2E test `tests/webauthn-multi-device-e2e.test.js` will be refactored to use `MultiDeviceManager` class instead of the current test API approach.

### Current approach (to be replaced)
- Uses `window.__multiDevice` test API exposed by component
- Direct calls to `getState()`, `listDevices()`, `simulateIncomingRequest()`, etc.

### New approach
- Import `MultiDeviceManager` in test context
- Use class methods directly: `manager.restore()`, `manager.createNew()`, `manager.listDevices()`, etc.
- Simpler, more direct testing

### Test scenarios remain the same
- Scenario A: First device setup
- Scenario B: Device linking  
- Scenario C: Recovery (known credential)

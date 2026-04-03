# Plan: WebAuthn Multi-Device Linking & Recovery

## Context

The repository currently supports single-device WebAuthn-based OrbitDB identities with credentials in `localStorage`. This plan implements the full multi-device architecture described in the proposal: a `devices` KV store with `OrbitDBAccessController`, a libp2p pairing protocol (`/orbitdb/link-device/1.0.0`), QR-based device linking, WebAuthn challenge-response mutual verification via SubtleCrypto, and a recovery path via discoverable credentials.

Three deliverables:
1. **Library module** `src/multi-device/` — reusable, framework-agnostic
2. **Demo app** `examples/webauthn-multi-device-demo/` — SvelteKit, same stack as existing demos
3. **E2E tests** `tests/webauthn-multi-device-e2e.test.js` — Playwright, two-context test strategy

---

## Architecture Decisions

**Identity provider:** `OrbitDBWebAuthnIdentityProvider` with `useKeystoreDID: true, keystoreKeyType: 'Ed25519', encryptKeystore: true, keystoreEncryptionMethod: 'prf'` — matches the encrypted keystore demo. Each device gets an Ed25519 DID for fast OrbitDB writes. The WebAuthn P-256 credential's public key (JWK) is stored separately in the devices DB for assertion verification during pairing.

**Access control:** `OrbitDBAccessController` (not `IPFSAccessController`) for dynamic `grant()`/`revoke()`. After pairing, Device A calls `db.access.grant('write', deviceBIdentityId)` before sending the DB address.

**Pairing transport:** libp2p custom stream protocol `/orbitdb/link-device/1.0.0` using `it-length-prefixed-stream@2.0.4` (already in the lockfile as a transitive dep of libp2p). libp2p instance accessed via `helia.libp2p` — no need to change `setupOrbitDB()` return signature.

**Test strategy:** Two Playwright chromium contexts on the same `localhost:5173`. The libp2p pairing transport is bypassed in tests via a `window.__multiDevice` test API exposed when `window.__testMode === true`. This exercises all protocol logic (challenge generation, assertion verification, access granting, DB sync) without requiring a relay node in CI.

**QR code library:** `qrcode` npm package. In `window.__testMode`, QR data is also written to a `data-testid` attribute for Playwright extraction without camera access.

**ECDSA signature format:** WebAuthn authenticators return DER-encoded signatures; SubtleCrypto expects raw r||s (64 bytes for P-256). A `derToRawEcdsaSignature()` converter is included. The mock authenticator returns flat `Uint8Array(64)`, so a guard checks `bytes[0] === 0x30` before converting.

---

## Pairing Protocol Messages (JSON over LP stream)

```
Device B → Device A: { type: 'challenge', nonce: '<base64url 32B>', timestamp: <ms> }
Device A → Device B: { type: 'assertion', authenticatorData, clientDataJSON, signature, credentialId, identity: { id: '<ed25519 did>', publicKey } }
Device B → Device A: { type: 'granted', orbitdbAddress: '/orbitdb/...' }
              OR:    { type: 'rejected', reason: '...' }
```

**Roles:**
- **Device B** (new device) dials Device A, sends challenge, receives assertion, verifies via SubtleCrypto, calls `db.access.grant()`, sends address
- **Device A** (existing device) handles incoming stream, performs WebAuthn assertion with Device B's nonce as challenge, sends result, waits for grant/reject

**Device discovery:** Device A's peerId is embedded in the QR payload; libp2p's `identify` service populates the peer store so `libp2p.dialProtocol(deviceAPeerId, PROTOCOL)` resolves routing automatically.

---

## Files to Create

### Library: `src/multi-device/`

| File | Purpose |
|------|---------|
| `src/multi-device/challenge.js` | `generateChallenge(peerId)`, `encodeQRPayload()`, `parseAndValidateQRPayload()` with 60s TTL |
| `src/multi-device/assertion-verifier.js` | `verifyWebAuthnAssertion(assertion, nonce, jwk)`, `coseToJwk(x, y)`, `derToRawEcdsaSignature(bytes)` — SubtleCrypto only |
| `src/multi-device/device-registry.js` | `openDeviceRegistry(orbitdb, ownerIdentityId, address?)`, `registerDevice(db, entry)`, `listDevices(db)`, `getDeviceByCredentialId(db, credId)`, `grantDeviceWriteAccess(db, did)`, `revokeDeviceAccess(db, did)`, `hashCredentialId(credId)` |
| `src/multi-device/pairing-protocol.js` | `LINK_DEVICE_PROTOCOL`, `registerLinkDeviceHandler(libp2p, db, onPairingRequest, onPairingResult)`, `unregisterLinkDeviceHandler(libp2p)`, `initiatePairing(libp2p, deviceAPeerId, nonce, db, onGranted, onRejected)` |
| `src/multi-device/index.js` | Re-export barrel |

**Key implementation notes:**

`device-registry.js` — Device entry shape:
```json
{
  "credential_id": "<base64url>",
  "public_key": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "device_label": "Chrome Mac",
  "created_at": 1234567890,
  "status": "active",
  "ed25519_did": "did:key:z6Mk..."
}
```
DB key: `SHA-256(credentialId)` as 64-char lowercase hex. `OrbitDBAccessController` import and usage:
```js
import { OrbitDBAccessController } from '@orbitdb/core';
const db = await orbitdb.open('multi-device-registry', {
  type: 'keyvalue',
  AccessController: OrbitDBAccessController({ write: [ownerIdentityId] })
});
// ⚠️ Verify exact casing of AccessController option key during implementation
// against @orbitdb/core 3.x source — existing demos use lowercase `accessController`
// for IPFSAccessController but OrbitDBAccessController docs use capital A
await db.access.grant('write', newDeviceEd25519Did);
```

`assertion-verifier.js` — Signing input per WebAuthn spec §7.2:
```js
signingInput = authData || SHA-256(clientDataJSON)
// Note: signature from real authenticator is DER-encoded, must convert to raw r||s for SubtleCrypto
const rawSig = bytes[0] === 0x30 ? derToRawEcdsaSignature(bytes) : bytes;
```

`pairing-protocol.js` — Stream serialization using `it-length-prefixed-stream`:
```js
import lpStream from 'it-length-prefixed-stream';
const lp = lpStream(stream);
const bytes = await lp.read();
const msg = JSON.parse(new TextDecoder().decode(bytes.subarray())); // .subarray() needed for Uint8ArrayList
await lp.write(new TextEncoder().encode(JSON.stringify(msg)));
```
Challenge TTL (60s) validated in the handler when Device A receives the challenge message.

### Demo: `examples/webauthn-multi-device-demo/`

Scaffold from `examples/ed25519-encrypted-keystore-demo/`. Key structural files to copy verbatim: `svelte.config.js`, `vite.config.js`, `jsconfig.json`, `src/app.html`, `src/app.css`, `src/routes/+layout.js`, `src/routes/+layout.svelte`.

| New file | Purpose |
|----------|---------|
| `package.json` | Copy from encrypted-keystore-demo; add `"it-length-prefixed-stream": "^2.0.4"` and `"qrcode": "^1.5.4"` to dependencies |
| `src/lib/libp2p.js` | Copy from encrypted-keystore-demo; add `registerPairingHandler(libp2p, db, onRequest, onResult)` and `unregisterPairingHandler(libp2p)` wrappers |
| `src/lib/database.js` | New: `openDevicesDB(orbitdb, identity, existingAddress?)`, `registerCurrentDevice(db, credential, identity, label)`, `onboardNewDevice(db, entry)` using `OrbitDBAccessController` |
| `src/lib/MultiDeviceApp.svelte` | Top-level orchestrator; three views via Svelte store; exposes `window.__multiDevice` when `window.__testMode` |
| `src/lib/components/SetupView.svelte` | Scenario A: create credential → init DB → register self → show as Device A with QR |
| `src/lib/components/PairView.svelte` | Scenario B: Device B creates credential → shows "waiting to pair" → processes injected pairing or QR scan result |
| `src/lib/components/RecoverView.svelte` | Scenario C: discoverable credential auth → enter DB address → open existing DB |
| `src/lib/components/DeviceList.svelte` | Display devices from DB with labels, DIDs, status |
| `src/lib/components/QRCode.svelte` | Show QR via `qrcode` lib; also expose `data-testid="qr-payload"` with JSON string for Playwright |
| `src/routes/+page.svelte` | Thin shell embedding `<MultiDeviceApp />` |

**`window.__multiDevice` test API** (exposed in `onMount` when `window.__testMode === true`):
```js
window.__multiDevice = {
  getState(),                          // { view, peerId, devicesDbAddress, deviceCount, identity }
  simulatePairingRequest(challengeMsg), // Device A: performs WebAuthn get → returns assertionResult
  simulateVerifyAssertion(assertion, nonce, jwk), // runs verifyWebAuthnAssertion()
  getDevicesDbAddress(),
  injectGrantedResult(orbitdbAddress, deviceEntry), // calls onboardNewDevice on Device B
  listDevices(),
  openByAddress(address),              // recovery test helper
}
```

**`database.js` key pattern:**
```js
// The `setupOrbitDB` return value does NOT include libp2p.
// Access via helia.libp2p:
const { orbitdb, ipfs, identity } = await setupOrbitDB(credential, options);
const libp2p = ipfs.libp2p;  // helia exposes libp2p instance
```

### Test: `tests/webauthn-multi-device-e2e.test.js`

Two browser contexts (both Chromium). WebAuthn mocked via `context.addInitScript()` with different deterministic credential seeds. `crypto.subtle.verify` mocked to return `true` for ECDSA in test mode (mock signatures are random bytes, not verifiable). P2P transport bypassed via `window.__multiDevice` API.

**Test scenarios:**

*Scenario A — First device setup:*
1. Navigate to demo, click "Set up as first device"
2. Mock WebAuthn create + authenticate
3. Assert via `window.__multiDevice.getState()`: `devicesDbAddress` matches `/^\/orbitdb\//`, `deviceCount === 1`
4. Assert via `window.__multiDevice.listDevices()`: device has `credential_id`, `public_key: {kty:'EC', crv:'P-256'}`, `ed25519_did: /^did:key:z6Mk/`, `status: 'active'`

*Scenario B — Device linking (transport-bypassed):*
1. Context A: full first-device setup
2. Context B: navigate to demo, click "Link to existing device", create credential, authenticate
3. Test generates a nonce; injects challenge into Context A via `simulatePairingRequest()`
4. Context A returns assertion; test passes assertion to Context B via `simulateVerifyAssertion()`
5. Test calls `injectGrantedResult()` on Context A to simulate Device B granting access and sending address
6. Assert Context A's `listDevices()` returns 2 entries

*Scenario C — Recovery:*
1. Full first-device setup → get `devicesDbAddress`
2. Call `window.__multiDevice.openByAddress(address)` → assert address matches

**WebAuthn mock patterns (two different credential IDs):**
```js
// Context A mock: credentialId bytes = [1..16]
// Context B mock: credentialId bytes = [17..32]
// credentials.get() stores the challenge from options.publicKey.challenge in
// window.__lastChallenge so clientDataJSON can reference it
```

---

## Files to Modify

### `src/index.js`
Add at the bottom:
```js
export * from './multi-device/index.js';
```
And add `"./multi-device": "./src/multi-device/index.js"` to the exports map in `package.json` if consumers need direct import path.

### `package.json`
Add to `scripts`:
```json
"test:multi-device": "USE_MULTI_DEVICE_DEMO=true playwright test tests/webauthn-multi-device-e2e.test.js --project=chromium --reporter=line",
"test:multi-device-headed": "USE_MULTI_DEVICE_DEMO=true playwright test tests/webauthn-multi-device-e2e.test.js --headed --project=chromium",
"demo:multi-device": "cd examples/webauthn-multi-device-demo && npm run dev",
"demo:multi-device-setup": "cd examples/webauthn-multi-device-demo && npm ci && npm run build"
```

### `playwright.config.js`
Extend the `demoDir` IIFE with a `useMultiDeviceDemo` branch:
```js
const useMultiDeviceDemo = testFile.includes('multi-device') ||
  cliArgs.includes('multi-device') ||
  process.env.USE_MULTI_DEVICE_DEMO === 'true';

const demoDir = useEncryptedDemo
  ? 'examples/ed25519-encrypted-keystore-demo'
  : useVarsigDemo
    ? 'examples/webauthn-varsig-demo'
    : useMultiDeviceDemo
      ? 'examples/webauthn-multi-device-demo'
      : 'examples/webauthn-todo-demo';
```

---

## Implementation Order

1. `src/multi-device/challenge.js` — pure functions, no deps, start here
2. `src/multi-device/assertion-verifier.js` — SubtleCrypto only, includes DER converter
3. `src/multi-device/device-registry.js` — verify exact `OrbitDBAccessController` API against source
4. `src/multi-device/pairing-protocol.js` — libp2p stream protocol
5. `src/multi-device/index.js` — barrel export
6. Modify `src/index.js` — add multi-device re-exports
7. Create `examples/webauthn-multi-device-demo/` skeleton (scaffold from encrypted-keystore-demo)
8. `src/lib/libp2p.js` and `src/lib/database.js` in demo
9. UI components: `DeviceList`, `QRCode`, `SetupView`, `PairView`, `RecoverView`
10. `MultiDeviceApp.svelte` with `window.__multiDevice` test API
11. `+page.svelte` and routes
12. Modify `package.json` and `playwright.config.js`
13. `tests/webauthn-multi-device-e2e.test.js`
14. `pnpm install` in demo dir, run `pnpm run test:multi-device`

---

## Critical Reference Files

- `examples/ed25519-encrypted-keystore-demo/src/lib/libp2p.js` — `setupOrbitDB()` pattern to extend; note that `helia.libp2p` accesses the libp2p instance without changing return signature
- `examples/ed25519-encrypted-keystore-demo/package.json` — copy as base for new demo's `package.json`
- `playwright.config.js` — exact IIFE pattern to extend with `useMultiDeviceDemo` branch
- `tests/ed25519-encrypted-keystore-e2e.test.js` — `addInitScript` WebAuthn mock pattern reference
- `src/webauthn/provider.js` — `extractPublicKey()` shows how x/y coordinates are extracted from attestation for `coseToJwk()`

---

## Verification Plan

**Unit verification (in browser console after `pnpm run demo:multi-device`):**
- First device setup completes with no errors
- `devicesDbAddress` in the UI starts with `/orbitdb/`
- Device entry shows in `DeviceList` with correct label and status

**Pairing verification (two browser windows):**
- Window 1: fully set up (Device A)
- Window 2: click "Link to existing device", create credential
- Window 2: shows QR code and pairing data
- Window 1: reads QR, enters pairing mode
- Pairing completes: Device A shows 2 entries; Device B opens same DB

**Recovery verification:**
- After setup, note the DB address
- Reload page (clears libp2p state)
- Click "Recover", enter address
- Same device list reappears

**Playwright E2E (`pnpm run test:multi-device`):**
- Scenario A assertions: `devicesDbAddress`, `deviceCount`, `public_key.kty === 'EC'`, `ed25519_did` format
- Scenario B assertions: 2 devices after pairing, Device B's DID in registry
- Scenario C assertion: `openByAddress()` returns correct address

**Known implementation risk:** The exact option key for `OrbitDBAccessController` in `orbitdb.open()` (`accessController` lowercase vs. `AccessController` capital A) must be verified against `@orbitdb/core@3.0.2` source before coding `device-registry.js`. Both forms appear in different versions of the docs.

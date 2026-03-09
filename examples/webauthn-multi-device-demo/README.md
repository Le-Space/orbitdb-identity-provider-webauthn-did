# WebAuthn Multi-Device Demo

This demo shows multi-device linking and recovery for a shared OrbitDB device registry, with explicit identity/signing modes.

## Identity Modes

- `Ed25519 keystore`
  Uses `OrbitDBWebAuthnIdentityProvider` with `useKeystoreDID: true` and `keystoreKeyType: 'Ed25519'`.

- `Worker Ed25519`
  Uses a worker-backed Ed25519 signer for OrbitDB identity signing. The demo stores an encrypted worker archive in browser storage and restores it with a WebAuthn-derived seed.

- `Varsig Ed25519`
  Uses `WebAuthn varsig` identity/signing with an Ed25519 passkey credential.

- `Varsig P-256`
  Uses `WebAuthn varsig` identity/signing with a `P-256` passkey credential.

## Security Notes

- `Ed25519 keystore` keeps signing in browser-managed software keys after unlock.
- `Worker Ed25519` reduces direct main-thread exposure during signing, but it is still browser-resident software key management rather than authenticator-resident signing.
- `Varsig Ed25519` and `Varsig P-256` keep signing anchored in the authenticator by using WebAuthn assertions for protocol-level signatures.
- The device registry still stores device metadata, DIDs, and access-control state in OrbitDB.

## Running the Demo

Install dependencies from the repo root and the demo directory:

```bash
pnpm install
cd examples/webauthn-multi-device-demo
pnpm install
```

Start the dev server:

```bash
pnpm run dev
```

The demo typically serves at `http://localhost:5173`.

## Running the E2E Suite

From the repo root:

```bash
npm run test:multi-device
```

This suite covers:

- first-device setup
- device linking
- recovery
- revocation
- three-device registry state
- explicit backend checks for:
  - `worker-ed25519`
  - `varsig-ed25519`
  - `varsig-p256`

## Test API

In Playwright mode the demo exposes `window.__multiDevice`, including:

- `getState()`
- `setupAsDeviceA()`
- `simulateIncomingRequest()`
- `listDevices()`
- `setIdentityMode(mode)`

The state includes the active:

- `identityMode`
- `signingBackend`
- `didAlgorithm`
- `identityType`
- worker metadata when worker mode is active

## Notes

- The worker mode requires Vite to serve the linked worker source from the repo root; the demo’s `vite.config.js` is configured for that.
- The Playwright file currently runs serially to avoid dev-server dependency-optimization reloads during first-touch of worker and varsig paths.

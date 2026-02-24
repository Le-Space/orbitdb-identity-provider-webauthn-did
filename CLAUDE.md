# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

This project uses `pnpm` as the package manager.

```bash
# Install dependencies
pnpm install

# Lint
pnpm run lint
pnpm run lint:fix

# Run tests (Playwright)
pnpm run test:unit          # Unit tests
pnpm run test:integration   # Integration tests
pnpm run test:verification  # Verification tests (used in CI)
pnpm run test:focused       # Core WebAuthn credential flow tests
pnpm run test:encrypted-keystore  # Encrypted keystore E2E tests
pnpm run test:varsig-e2e    # Hardware-signed varsig E2E tests
pnpm run test:ui            # Interactive test UI runner

# Run a single test file
pnpx playwright test tests/webauthn-focused.test.js --project=chromium
pnpx playwright test tests/webauthn-focused.test.js --project=chromium --headed

# Start the main demo app
pnpm run demo:setup && pnpm run demo

# Validate npm package contents
pnpm run validate-package
```

Tests require a running demo app (Playwright auto-starts one via `webServer` config in `playwright.config.js`). The demo served depends on which test suite is running.

## Architecture

This library provides three ways to integrate WebAuthn biometric authentication with OrbitDB:

### 1. WebAuthn DID Provider (`src/webauthn/provider.js`)
Creates P-256 DIDs directly from WebAuthn credentials. The credential's COSE public key is extracted and encoded as a `did:key`. Used as a signing identity for OrbitDB entries.

### 2. Keystore-based Identity Provider (`src/keystore/provider.js`)
The main OrbitDB identity provider. Creates an Ed25519 or secp256k1 keypair stored in a browser keystore, optionally encrypted using the WebAuthn credential as a key source. Faster than varsig (single prompt per session, not per write).

**Keystore encryption** (`src/keystore/encryption.js`) wraps the private key with AES-GCM using a secret derived from the WebAuthn authenticator via one of three extension methods:
- **PRF** (preferred — most authenticators)
- **largeBlob** (stores secret on authenticator)
- **hmac-secret** (legacy fallback)

### 3. Varsig Provider (`src/varsig/`)
Hardware-backed signing where each OrbitDB write triggers a WebAuthn assertion. The private key never leaves the authenticator. Uses a varsig envelope format from `src/varsig/assertion.js`. Most secure but prompts the user on every write.

### Standalone Toolkit (`src/standalone/`)
An OrbitDB-independent export surface (`createWebAuthnSigner`, `WebAuthnHardwareSignerService`, `createWorkerKeystoreClient`). Supports a Web Worker-based keystore (`src/standalone/worker/`) so signing doesn't block the main thread.

### Entry Point
`src/index.js` is the main export. `verification.js` (published as `./verification` export) contains DID validation and database update verification utilities.

### Demo Apps
Three Vite-based demo apps in `examples/` are used both as end-user samples and as the test harnesses for Playwright:
- `examples/webauthn-todo-demo/` — default demo (keystore flow)
- `examples/ed25519-encrypted-keystore-demo/` — encrypted keystore flow
- `examples/webauthn-varsig-demo/` — varsig flow

`playwright.config.js` selects which demo to start based on the test file being run.

### Domain Labels
`src/varsig/domain.js` defines domain label constants that differentiate OrbitDB vs. UCAN signing contexts — this matters for replay protection.

## Patching
The project uses `patch-package` to modify `@orbitdb/core` to support Ed25519 keys. Patches are in `patches/`. Run `pnpm install` to apply them automatically via the `postinstall` hook.

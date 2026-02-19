# Standalone WebAuthn Toolkit API Plan

Status: Phase 0 (initial contract)
Issue: #13
Depends on: #11 (chainagnostik varsig 1.0 alignment)
Implementation branch: `feat/issue-13-standalone-webauthn-toolkit`

## Objective
Add a standalone API surface to this package so projects can use WebAuthn/varsig/worker-keystore flows without OrbitDB identity provider wiring, while preserving all existing OrbitDB provider capabilities.

## Non-negotiable compatibility requirements
- Existing OrbitDB provider features must remain intact.
- Existing exports from `src/index.js` must keep working.
- Standalone modules are additive and independently importable.
- Varsig behavior must remain aligned with #11.

## Proposed exports

### New package subpath
- `orbitdb-identity-provider-webauthn-did/standalone`

### Proposed named exports from `./standalone`
- `createWebAuthnHardwareSigner`
- `loadWebAuthnHardwareSigner`
- `storeWebAuthnHardwareSigner`
- `getStoredWebAuthnHardwareSignerInfo`
- `createWebAuthnEd25519Signer`
- `createWebAuthnP256Signer`
- `initWorkerEd25519Keystore`
- `generateWorkerEd25519Identity`
- `encryptWorkerArchive`
- `decryptWorkerArchive`
- `workerSign`
- `workerVerify`
- `storeWebAuthnCredentialSafe`
- `loadWebAuthnCredentialSafe`
- `clearWebAuthnCredentialSafe`

## Proposed module layout
- `src/standalone/index.js`
- `src/standalone/webauthn/signers.js`
- `src/standalone/webauthn/hardware-service.js`
- `src/standalone/worker/client.js`
- `src/standalone/worker/ed25519-keystore.worker.js`
- `src/standalone/storage/credential.js`
- `src/standalone/storage/hardware-signer.js`
- `src/standalone/storage/archive.js`

## Behavioral contract

### Hardware mode
- Ed25519 first, P-256 fallback.
- WebAuthn prompt required on signing.
- Varsig v1 envelopes produced and verified.
- Signer metadata storable/restorable from localStorage.

### Worker mode
- WebAuthn PRF-derived seed input (never persisted as raw seed).
- Worker holds Ed25519 keypair and AES key in worker memory.
- Archive encryption/decryption available for persistence.

### Fallback order
- Hardware Ed25519 -> Hardware P-256 -> Worker mode.

## Upload-wall migration map

### Replace local modules with package imports
- `web/src/lib/webauthn-ed25519-signer.ts` -> `./standalone/webauthn/signers`
- `web/src/lib/hardware-ucan-service.ts` -> `./standalone/webauthn/hardware-service`
- `web/src/lib/secure-ed25519-did.ts` -> `./standalone/worker/client`
- `web/src/workers/ed25519-keystore.worker.ts` -> packaged worker module

### Keep app-specific logic in upload-wall
- UCAN business rules and delegation orchestration in upload-wall.
- Service-specific environment and UX logic.

## Tests to port/add in this repo
- Signer tests: Ed25519 varsig and P-256 varsig parity.
- Hardware storage rehydration tests.
- Worker protocol tests: init/generate/encrypt/decrypt/sign/verify.
- Fallback selection tests (hardware->worker).

## Sequenced implementation steps
1. Add `./standalone` export and minimal module skeletons.
2. Port worker module + client bridge + tests.
3. Port hardware signers + tests.
4. Port hardware service/storage helpers + tests.
5. Add integration tests that mimic upload-wall mode behavior.
6. Migrate upload-wall imports in a separate PR.

## Open questions
- Worker distribution strategy for non-Vite consumers (documented constraint vs generic worker loader).
- Exact storage key defaults in standalone modules (preserve upload-wall keys or provide configurable keys with defaults).
- Whether to expose low-level varsig helpers directly or keep focused high-level API only.

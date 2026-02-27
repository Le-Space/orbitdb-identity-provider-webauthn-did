# Standalone WebAuthn Toolkit API Status

Status: Implemented (initial public surface)
Issue: #13
Depends on: #11 (chainagnostik varsig 1.0 alignment)

## Objective

Provide a standalone API surface so consumers can use WebAuthn signer and worker-keystore flows without OrbitDB identity provider wiring.

## Package Subpath

- `@le-space/orbitdb-identity-provider-webauthn-did/standalone`

## Implemented Exports

The current exports are defined in `src/standalone/index.js`.

### WebAuthn signer exports

- `StandaloneWebAuthnVarsigSigner`
- `WebAuthnEd25519Signer`
- `WebAuthnP256Signer`
- `createWebAuthnSigner`
- `createWebAuthnEd25519Credential`
- `createWebAuthnEd25519Signer`
- `createWebAuthnP256Signer`
- `checkEd25519Support`

### Hardware service exports

- `WebAuthnHardwareSignerService`
- `getStoredWebAuthnHardwareSignerInfo`

### Credential-safe exports

- `storeWebAuthnCredentialSafe`
- `loadWebAuthnCredentialSafe`
- `clearWebAuthnCredentialSafe`
- `extractPrfSeedFromCredential`

### Worker client exports

- `createWorkerKeystoreClient`
- `isWorkerKeystoreAvailable`
- `createEd25519DidFromPublicKey`
- `getDefaultWorkerKeystoreClient`
- `resetDefaultWorkerKeystoreClient`
- `initEd25519KeystoreWithPrfSeed`
- `generateWorkerEd25519DID`
- `loadWorkerEd25519Archive`
- `keystoreEncrypt`
- `keystoreDecrypt`
- `keystoreSign`
- `keystoreVerify`
- `encryptArchive`
- `decryptArchive`

## Notes

- Export naming differs from the early proposal in this file's previous version. Treat `src/standalone/index.js` as the source of truth.
- Worker and hardware flows are additive and do not remove existing OrbitDB provider APIs.
- The upload-wall migration should map against implemented names above.

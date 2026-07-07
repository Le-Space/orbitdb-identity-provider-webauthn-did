# API Reference

This package is JavaScript-first and ships TypeScript declarations for the
public API surface:

- root export: `@le-space/orbitdb-identity-provider-webauthn-did`
- standalone export: `@le-space/orbitdb-identity-provider-webauthn-did/standalone`
- keystore export: `@le-space/orbitdb-identity-provider-webauthn-did/keystore`
- verification export: `@le-space/orbitdb-identity-provider-webauthn-did/verification`

## Root Export

```js
import {
  WebAuthnDIDProvider,
  OrbitDBWebAuthnIdentityProviderFunction,
  WebAuthnVarsigProvider,
  createWebAuthnVarsigIdentity,
  configureWebAuthn,
  KEYSTORE_ENCRYPTION_METHODS,
  WebAuthnAuthenticationError,
  generateSecretKey,
  encryptWithAESGCM,
} from '@le-space/orbitdb-identity-provider-webauthn-did';
```

### WebAuthnDIDProvider

Creates and uses WebAuthn-backed DID credentials.

#### `WebAuthnDIDProvider.isSupported()`

Returns `true` when the current browser exposes the WebAuthn APIs required by
this package.

```js
if (!WebAuthnDIDProvider.isSupported()) {
  throw new Error('WebAuthn is not available');
}
```

#### `WebAuthnDIDProvider.isPlatformAuthenticatorAvailable()`

Checks whether a platform authenticator such as Face ID, Touch ID, or Windows
Hello appears to be available.

```js
const available = await WebAuthnDIDProvider.isPlatformAuthenticatorAvailable();
```

#### `WebAuthnDIDProvider.createCredential(options)`

Creates a WebAuthn credential and extracts the public key from registration
attestation.

Options:

- `userId?: string`
- `displayName?: string`
- `domain?: string`
- `encryptKeystore?: boolean`
- `keystoreEncryptionMethod?: 'prf' | 'largeBlob' | 'hmac-secret'`
- `discoverableCredentials?: boolean`
- `authenticatorType?: 'platform' | 'cross-platform' | 'any'`

```js
const credential = await WebAuthnDIDProvider.createCredential({
  userId: 'alice@example.com',
  displayName: 'Alice',
  encryptKeystore: true,
  keystoreEncryptionMethod: KEYSTORE_ENCRYPTION_METHODS.PRF,
});
```

Returns a credential info object containing:

- `credentialId`
- `rawCredentialId`
- `publicKey`
- `userId`
- `displayName`
- `attestationObject`
- optional `prfInput`

### Constants And Errors

Shared constants are exported for storage keys, identity types, key types,
WebAuthn client-data types, cryptographic algorithm names, and keystore
encryption methods:

- `IDENTITY_TYPES`
- `KEY_TYPES`
- `KEYSTORE_ENCRYPTION_METHODS`
- `STORAGE_KEYS`
- `WEBAUTHN_CLIENT_DATA_TYPES`
- `CRYPTO_ALGORITHMS`
- `DID_KEY_PREFIX`
- `ERROR_CODES`

Catchable error classes extend `WebAuthnIdentityError` and expose a `code`
property:

- `WebAuthnNotSupportedError`
- `WebAuthnCredentialError`
- `WebAuthnAuthenticationError`
- `WebAuthnVerificationError`
- `KeystoreEncryptionError`
- `VarsigVerificationError`

```js
try {
  await WebAuthnDIDProvider.createCredential();
} catch (error) {
  if (error instanceof WebAuthnAuthenticationError) {
    // User cancelled or authenticator authentication failed.
  }
}
```

#### `WebAuthnDIDProvider.createDID(credentialInfo)`

Creates a `did:key` DID from a WebAuthn P-256 public key.

```js
const did = await WebAuthnDIDProvider.createDID(credential);
```

#### `new WebAuthnDIDProvider(credentialInfo)`

Creates a signer instance from credential metadata.

```js
const provider = new WebAuthnDIDProvider(credential);
const signature = await provider.sign(new TextEncoder().encode('hello'));
const valid = await provider.verify(signature);
```

### OrbitDB Identity Provider

#### `registerWebAuthnProvider()`

Registers the WebAuthn identity provider with OrbitDB.

```js
registerWebAuthnProvider();
```

#### `OrbitDBWebAuthnIdentityProviderFunction(options)`

Creates an OrbitDB identity provider instance.

```js
const identity = await identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
  }),
});
```

Common options:

- `webauthnCredential`
- `encryptKeystore`
- `keystoreEncryptionMethod`
- `keyType`
- `usePersistentKey`

### WebAuthn Configuration

#### `configureWebAuthn(config)`

Sets global WebAuthn request policy.

```js
configureWebAuthn({
  discoverableCredentials: true,
  userVerification: 'required',
});
```

#### `getWebAuthnConfig()`

Returns the current WebAuthn config.

#### `resetWebAuthnConfig()`

Restores default WebAuthn config.

### largeBlob Metadata Helpers

These helpers encode and recover identity metadata used by the demo recovery
flows.

- `createDidLargeBlobPayload(credentialInfo)`
- `parseDidLargeBlobPayload(payload)`
- `createVarsigLargeBlobPayload(credentialInfo)`
- `parseVarsigLargeBlobPayload(payload)`
- `readLargeBlobMetadata(options)`
- `writeLargeBlobMetadata(credentialId, payload, options)`

Discoverable passkeys can identify a credential later, but WebAuthn assertions
do not reliably return the public key after registration. Persisted metadata is
therefore still required to reconstruct an OrbitDB identity.

### Credential Storage Helpers

Legacy storage helpers:

- `storeWebAuthnCredential(credential, key?)`
- `loadWebAuthnCredential(key?)`
- `clearWebAuthnCredential(key?)`

Safer storage helpers:

- `storeWebAuthnCredentialSafe(credential, key?)`
- `loadWebAuthnCredentialSafe(key?)`
- `clearWebAuthnCredentialSafe(key?)`
- `extractPrfSeedFromCredential(credential)`

### Keystore Encryption Helpers

These helpers are exported from the root package and from the dedicated
`./keystore` subpath:

```js
import {
  generateSecretKey,
  encryptWithAESGCM,
  OrbitDBWebAuthnIdentityProviderFunction,
} from '@le-space/orbitdb-identity-provider-webauthn-did/keystore';
```

- `generateSecretKey()`
- `encryptWithAESGCM(data, sk)`
- `decryptWithAESGCM(ciphertext, sk, iv)`
- `addLargeBlobToCredentialOptions(credentialOptions, sk)`
- `addPRFToCredentialOptions(credentialOptions, prfInput?)`
- `retrieveSKFromLargeBlob(credentialId, rpId)`
- `addHmacSecretToCredentialOptions(credentialOptions)`
- `wrapSKWithHmacSecret(credentialId, sk, rpId)`
- `wrapSKWithPRF(credentialId, sk, rpId, prfInput?)`
- `unwrapSKWithHmacSecret(credentialId, wrappedSK, wrappingIV, salt, rpId)`
- `unwrapSKWithPRF(credentialId, wrappedSK, wrappingIV, salt, rpId)`
- `storeEncryptedKeystore(data, credentialId)`
- `loadEncryptedKeystore(credentialId)`
- `clearEncryptedKeystore(credentialId)`
- `checkExtensionSupport()`

Example:

```js
const sk = generateSecretKey();
const encrypted = await encryptWithAESGCM(
  new TextEncoder().encode('secret'),
  sk
);
const plaintext = await decryptWithAESGCM(
  encrypted.ciphertext,
  sk,
  encrypted.iv
);
```

### Varsig Provider

Varsig is the preferred high-security signing path. Each write can be signed by
a WebAuthn assertion, so private key material remains in the authenticator.

Key exports:

- `WebAuthnVarsigProvider`
- `createWebAuthnVarsigIdentity(options)`
- `createWebAuthnVarsigIdentities(options)`
- `encodeIdentityValue(identity)`
- `decodeVarsigIdentityFromBytes(bytes)`
- `verifyVarsigIdentity(identity)`
- `createIpfsIdentityStorage(options)`
- `wrapWithVarsigVerification(value)`
- `DEFAULT_DOMAIN_LABELS`
- `storeWebAuthnVarsigCredential(credential, key?)`
- `loadWebAuthnVarsigCredential(key?)`
- `clearWebAuthnVarsigCredential(key?)`
- `isUnsupportedVarsigEnvelopeError(error)`

Example:

```js
const credential = await WebAuthnVarsigProvider.createCredential({
  userId: 'alice@example.com',
  displayName: 'Alice',
});

const identity = await createWebAuthnVarsigIdentity({ credential });
```

## Standalone Export

Use the standalone export when you want WebAuthn signing and worker-keystore
features without OrbitDB identity provider wiring.

```js
import {
  createWebAuthnSigner,
  createWorkerKeystoreClient,
} from '@le-space/orbitdb-identity-provider-webauthn-did/standalone';
```

### WebAuthn Signers

- `StandaloneWebAuthnVarsigSigner`
- `WebAuthnEd25519Signer`
- `WebAuthnP256Signer`
- `createWebAuthnSigner(options?)`
- `createWebAuthnEd25519Signer(options?)`
- `createWebAuthnP256Signer(options?)`
- `createWebAuthnEd25519Credential(userId, displayName, options?)`
- `checkEd25519Support()`

```js
const signer = await createWebAuthnSigner({
  userId: 'alice@example.com',
  displayName: 'Alice',
});

const signature = await signer.sign(new Uint8Array([1, 2, 3]));
const ok = await signer.verify(signature, new Uint8Array([1, 2, 3]));
```

#### `signer.toUcantoSigner(options?)`

Returns a UCAN signer-compatible surface.

```js
const ucanSigner = signer.toUcantoSigner({
  domainLabel: 'ucan-webauthn-v1:',
});
```

### Hardware Signer Service

- `WebAuthnHardwareSignerService`
- `getStoredWebAuthnHardwareSignerInfo(key?)`

### Credential-safe Helpers

- `storeWebAuthnCredentialSafe(credential, key?)`
- `loadWebAuthnCredentialSafe(key?)`
- `clearWebAuthnCredentialSafe(key?)`
- `extractPrfSeedFromCredential(credential)`

### Worker Keystore Client

- `createWorkerKeystoreClient(options?)`
- `isWorkerKeystoreAvailable()`
- `createEd25519DidFromPublicKey(publicKeyBytes)`
- `getDefaultWorkerKeystoreClient(options?)`
- `resetDefaultWorkerKeystoreClient()`
- `initEd25519KeystoreWithPrfSeed(prfSeed, options?)`
- `generateWorkerEd25519DID(options?)`
- `loadWorkerEd25519Archive(archive, options?)`
- `keystoreEncrypt(plaintext, options?)`
- `keystoreDecrypt(ciphertext, iv, options?)`
- `keystoreSign(data, options?)`
- `keystoreVerify(data, signature, options?)`
- `encryptArchive(archive, options?)`
- `decryptArchive(ciphertext, iv, options?)`

Example:

```js
const client = createWorkerKeystoreClient();
await client.initWithPrfSeed(prfSeed);

const { did, publicKey, archive } = await client.generateEd25519Identity();
const signature = await client.sign(new TextEncoder().encode('entry'));
```

## Verification Export

```js
import {
  verifyDatabaseUpdate,
  verifyIdentityStorage,
  verifyDataEntries,
  isValidWebAuthnDID,
} from '@le-space/orbitdb-identity-provider-webauthn-did/verification';
```

### Helpers

- `verifyDatabaseUpdate(database, identityHash, expectedWebAuthnDID)`
- `verifyIdentityStorage(identities, identity, timeoutMs?)`
- `verifyDataEntries(database, dataEntries, expectedWebAuthnDID, options?)`
- `isValidWebAuthnDID(did)`
- `extractWebAuthnDIDSuffix(did)`
- `compareWebAuthnDIDs(did1, did2)`
- `createVerificationResult(success, details?)`

These helpers are pragmatic application-level checks for demos and integration
tests. They are not a replacement for protocol-level signature verification.

## TypeScript

The package publishes declaration files:

- `types/index.d.ts`
- `types/keystore.d.ts`
- `types/standalone.d.ts`
- `types/verification.d.ts`

They are connected through `package.json` `exports.types`, so TypeScript
consumers can import from the public package paths directly.

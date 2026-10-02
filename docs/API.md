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
- `authenticatorType?: 'platform' | 'cross-platform' | 'any'` — which
  authenticators the browser offers: the device's own (Touch ID, Windows
  Hello, a phone's screen lock), a security key or another phone, or every
  kind. `'any'` is the default and names none in the request.
- `authenticatorAttachment?: 'platform' | 'cross-platform'` — the WebAuthn name
  for the same choice. Giving both with different values, or a value neither
  knows, throws a `TypeError` before anyone is asked.

Before 0.9.1 both were listed here and neither reached the browser: the request
named no attachment, so every kind of authenticator was offered — a YubiKey as
much as the device's own. That is still the default.

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
- `rpId` (the relying party the credential is registered under)
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
  - `PrfUnavailableError` (`PRF_UNAVAILABLE`) — the authenticator answered
    without a PRF output
  - `VaultError` — a vault refused; see [Vaults](#vaults)
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
const valid = await provider.verify(signature, data, credential.publicKey);
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
- `prfOutput` — a PRF output already read with `readPrfOutput`, so the signing
  key costs no second touch; see
  [One touch for the data and the identity](#one-touch-for-the-data-and-the-identity)

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

### Identity Restore

#### `restoreIdentityFromAuthenticator(options?)`

Reconstructs an identity on a device that has stored nothing — a second device,
or the same one after its profile was cleared. Two touches of the same passkey:
the first is asked with the relying party's fixed PRF input, the second signs
another challenge, and the two signatures together give back the credential's
public key, which a single assertion does not carry. The DID follows from that
key, and the signing key from the PRF output with the DID mixed in.

```js
import { restoreIdentityFromAuthenticator } from '@le-space/orbitdb-identity-provider-webauthn-did';

const restored = await restoreIdentityFromAuthenticator({
  onTouch: ({ touch, of }) => setStatus(`Touch ${touch} of ${of}`),
});

const identity = await identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: restored.credential,
  }),
});
```

Options, all optional:

- `rpId` — relying party id; the current host by default.
- `timeout` — per touch, in ms; `120000`. Generous on purpose: an NFC key has to
  be found, held and read.
- `signingKeyType` — `'secp256k1'` by default, as the keystore wants it. Pass
  the same type the identity was created with.
- `onTouch({ touch, of })` — called before each ceremony, so an application can
  say which touch this is rather than leaving a person wondering why they are
  asked twice.

Returns `{ did, publicKey: { x, y }, credentialId, rawCredentialId, signingKey,
prfInput, credential }`. `credential` is what
`OrbitDBWebAuthnIdentityProviderFunction({ webauthnCredential })` takes;
`credentialId` is base64url text and `rawCredentialId` the bytes (before 0.7.0,
`credentialId` was the bytes).

Putting `signingKey` into the keystore under the DID before OrbitDB builds the
identity spares one further touch: the provider would otherwise read the PRF
output a second time to derive the very same key.

Throws rather than substituting anything:

- `WebAuthnIdentityError` (`WEBAUTHN_NOT_SUPPORTED`) where WebAuthn is absent,
  and when no credential is offered for this relying party.
- `PrfUnavailableError` when the authenticator cannot evaluate PRF. Nothing
  stands in for it: an identity derived from something else is a different
  identity that looks like success.

Since 0.6.0. Measured on hardware across two phones sharing one YubiKey, and
used in [the recovery example](https://github.com/NiKrause/orbitdb-storage-bridge/tree/main/examples/svelte/recovery);
the database half of the same problem is in
[orbitdb-storage-bridge](https://github.com/NiKrause/orbitdb-storage-bridge/blob/main/docs/RECOVERY-ON-A-SECOND-DEVICE.md).

### PRF Keys and Vaults

Since 0.9.0. Applications that keep data under keys from the passkey used to
write their own HKDF over the PRF output, read it once per key, and had no way
for a second security key to open what the first one sealed. These functions
replace that: one read, any number of keys derived from it, and a vault any
registered authenticator opens.

#### `readPrfOutput(credential, options?)`

One assertion — one touch — returning the credential's PRF output, 32 bytes.
It always asks the same question: `options.prfInput`, else the input the
credential was registered with, else `prfInputForRelyingParty(rpId)`, which
every device computes alike. It never draws a random input, which would give
bytes that never come back.

- `rpId` — the current host by default.
- `prfInput` — overrides the credential's. Leave it out when the output also
  goes to the identity provider, which asks with the credential's.

Throws `PrfUnavailableError` when the authenticator answers without a PRF
output. A refused prompt stays the browser's `NotAllowedError`, so "the user
said no" and "this authenticator has no PRF" can be told apart.

#### `deriveSubkey(prfOutput, info, { length = 32 })`

HKDF-SHA-256 with an empty salt, 1 to 8160 bytes. `info` is part of the data
format: the same output and `info` always give the same bytes, and a different
`info` gives unrelated ones. Name it after the application and the purpose, and
version it — `invoice/db-key/v1`; bumping the version rotates the key and makes
everything sealed under the old one unreadable.

The derivations Le-Space/belege, Le-Space/invoice and simple-todo's escrow01
wrote for themselves give the same bytes through it, and so does this
package's own signing key; `tests/prf-keys.test.js` holds vectors from each.

#### `deriveAesKey(prfOutput, info)`

The same derivation as a non-extractable AES-GCM-256 `CryptoKey`: it encrypts
and decrypts, and no script can read its bytes.

#### One touch for the data and the identity

Hand the output to the identity provider as `prfOutput`, and it derives the
OrbitDB signing key from it instead of asking the passkey again:

```js
const prfOutput = await readPrfOutput(credential);

const { payload } = await openVault(vault, {
  slotKey: await deriveAesKey(prfOutput, 'invoice/vault-slot/v1'),
  rawCredentialId: credential.rawCredentialId,
});

const identity = await identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
    prfOutput,
  }),
});
```

It is the same key the provider would have derived by asking itself, so a
device where nobody hands it over arrives at the same identity document. The
provider instance drops its reference once the key is in the keystore and
never alters the bytes; the options object passed to
`OrbitDBWebAuthnIdentityProviderFunction` still holds them for as long as the
application keeps it. `encryptKeystore` still asks on its own.

#### Vaults

A key derived from a passkey exists only where that passkey is. A second
security key has its own PRF secret, so it derives different keys and cannot
open what the first one sealed. A vault holds what must be the same for every
key — a database key, database names, a peer seed — sealed under a random
vault key, and gives each registered authenticator a slot: the vault key,
sealed under that authenticator's
`deriveAesKey(prfOutput, '<app>/vault-slot/v1')`. Any slot opens the vault.

- `createVault(payload, { slotKey, rawCredentialId })` → `{ vault, vaultKey }`.
  The creating authenticator's slot comes with it: a vault without one could
  never be opened.
- `openVault(vault, { slotKey, rawCredentialId })` → `{ payload, vaultKey }`.
- `addSlot(vault, vaultKey, { slotKey, rawCredentialId })` → a new record with
  the new authenticator's slot. It needs the vault open and the new key
  touched, so in practice both keys are at one computer.
- `removeSlot(vault, rawCredentialId)` → a new record without that slot. It
  needs no key: whoever may write the record may shorten it, so guard the
  record where it is stored.
- `replacePayload(vault, vaultKey, payload)` → a new record with a new
  payload, the same vault key and the same slots.
- `slotIdFor(rawCredentialId)` → the id a slot is filed under, the SHA-256 of
  the raw credential id; the id itself is never written into the record.

Each function returns a new record and leaves the one passed in unchanged. The
record is plain JSON with nothing secret in the clear (format version 1, in
`src/keystore/vault.js`), so it can be stored anywhere, replicated, and backed
up in public. Every ciphertext in it is bound to the vault's id, and every slot
also to its authenticator, so neither can be moved to another vault or
relabelled to another authenticator.

Refusals are `VaultError`, with `code`:

- `VAULT_MALFORMED` — not a version-1 vault
- `VAULT_NO_SLOT` — this authenticator has no slot
- `VAULT_LOCKED` — the key does not open it, or the record was altered
- `VAULT_SLOT_EXISTS` — the authenticator already has a slot
- `VAULT_LAST_SLOT` — the last slot cannot go

What a vault does not do:

- **Removing a slot revokes nothing already opened.** An authenticator that
  opened the vault has seen the vault key, and older copies of the record still
  carry its slot. Against a stolen key, make a new vault with a new key and move
  what the old one protected.
- **It cannot tell the current record from an earlier copy of itself.** Where a
  rollback matters, the place the record is stored has to say which is current.
- **It does not make two keys one person.** Each authenticator keeps its own DID
  and signing key; who may write to a database is its access controller's
  decision.

`tests/vault-two-authenticators.test.js` runs this in Chromium with two virtual
authenticators, each with its own PRF secret as two YubiKeys have.

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
do not reliably return the public key after registration. Persisted metadata was
therefore the only way to reconstruct an identity until 0.6.0; since then
`restoreIdentityFromAuthenticator()` does it from two signatures instead, and a
stored copy only spares the touches. `largeBlob` is the less dependable place to
keep one: Android Chrome writes the blob and does not return it on read, while
desktop Chrome reads it
([#48](https://github.com/Le-Space/orbitdb-identity-provider-webauthn-did/issues/48)).

### Credential Storage Helpers

Legacy storage helpers:

- `storeWebAuthnCredential(credential, key?)`
- `loadWebAuthnCredential(key?)`
- `clearWebAuthnCredential(key?)`

Safer storage helpers:

- `storeWebAuthnCredentialSafe(credential, key?)`
- `loadWebAuthnCredentialSafe(key?)`
- `clearWebAuthnCredentialSafe(key?)`
- `extractPrfSeedFromCredential(credential, options?)` →
  `{ seed, source: 'prf' }`, or `{ seed: null, source: 'none' }` without PRF.
  Without a `prfInput` — in `options` or on the credential — it asks a random
  question, so the seed never comes back and nothing derived from it survives
  the page; it says so on the console. Prefer `readPrfOutput`.

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

`WebAuthnVarsigProvider.createCredential(options)` takes `userId`,
`displayName`, `domain`, `discoverableCredentials`, `forceP256` (offer only
P-256), and `authenticatorType` / `authenticatorAttachment` as
`WebAuthnDIDProvider.createCredential` does. Before 0.9.1 it dropped the choice
of authenticator the same way and offered every kind.

It always requires user verification, whatever the options say. A varsig
signature without the UV flag is refused, when it is made and when it is
verified, so a credential registered without user verification could never
sign.

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

The `create…Signer` functions register as
`WebAuthnVarsigProvider.createCredential` does and take its options;
`createWebAuthnEd25519Credential` passes on `options.authenticatorType` alone.

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
- `extractPrfSeedFromCredential(credential, options?)` — see
  [Credential Storage Helpers](#credential-storage-helpers)

### PRF Keys and Vaults (standalone)

The same functions as the root export, without OrbitDB: `readPrfOutput`,
`deriveSubkey`, `deriveAesKey`, `createVault`, `openVault`, `addSlot`,
`removeSlot`, `replacePayload`, `slotIdFor`, `PrfUnavailableError` and
`VaultError`. See [PRF Keys and Vaults](#prf-keys-and-vaults).

### P-256 Wallet Primitives

For smart accounts that verify P-256 WebAuthn signatures (for example Calibur
with webauthn-sol). See the README section "Passkeys for smart accounts".

- `getP256CredentialDescriptor(credential)` →
  `{ credentialId, rawCredentialId, x, y, rpId, userVerification: 'required' }`
  or `null` (RS256, Ed25519, placeholder or unreadable key). `x` and `y` are
  32-byte big-endian `Uint8Array`s.
- `signP256Challenge(descriptor, challenge)` → `Promise` of
  `{ authenticatorData, clientDataJSON, challengeIndex, typeIndex, r, s }`.
  `challenge` must be exactly 32 bytes. `allowCredentials` is pinned to the
  descriptor, user verification is required, an assertion from another
  credential is refused. `r` and `s` are 32 bytes with `s` low; the indices
  are UTF-8 byte offsets in `clientDataJSON`.

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

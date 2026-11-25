# Ed25519 Keystore DID Feature

## Overview

This feature adds support for creating **Ed25519 DIDs from the OrbitDB keystore** instead of P-256 DIDs from WebAuthn credentials. This provides better integration with UCAN and ensures the DID is derived from the same key that signs database operations.

## Motivation

### The Problem

In the default implementation:

- **Identity DID**: Derived from WebAuthn P-256 public key (hardware-backed)
- **Database operations**: Signed by OrbitDB Ed25519 keystore (software key)

This creates a **key mismatch**:

- The DID represents one key (P-256 from WebAuthn)
- Database entries are signed by a different key (Ed25519 from keystore)
- Two separate cryptographic identities for one user

### The Solution

With the `useKeystoreDID` flag:

- **Identity DID**: Derived from Ed25519 keystore public key
- **Database operations**: Signed by the same Ed25519 keystore key
- **WebAuthn**: Still used for authentication and session establishment
- **Unified identity**: One key for both DID and database operations

## Usage

### Basic Usage

```javascript
import {
  WebAuthnDIDProvider,
  OrbitDBWebAuthnIdentityProviderFunction,
} from '@le-space/orbitdb-identity-provider-webauthn-did';
import { createOrbitDB } from '@orbitdb/core';

// Create WebAuthn credential (for authentication)
const credential = await WebAuthnDIDProvider.createCredential({
  userId: 'user@example.com',
  displayName: 'User Name',
});

// Initialize OrbitDB
const orbitdb = await createOrbitDB({ ipfs });

// Create identity with Ed25519 keystore DID
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
    useKeystoreDID: true, // 🎯 Enable Ed25519 keystore DID
    keystore: orbitdb.keystore, // 🎯 Pass keystore instance
  }),
});

console.log(`Ed25519 DID: ${identity.id}`);
// Output: did:key:z6Mk... (Ed25519-based DID)
```

### Comparison with Default Behavior

#### Default (P-256 DID from WebAuthn)

```javascript
// Without the flag - uses P-256 from WebAuthn
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
  }),
});

// DID: did:key:zDna... (P-256-based, starts with 'zDna')
```

#### New Feature (Ed25519 DID from Keystore)

```javascript
// With the flag - uses Ed25519 from keystore
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
    useKeystoreDID: true,
    keystore: orbitdb.keystore,
  }),
});

// DID: did:key:z6Mk... (Ed25519-based, starts with 'z6Mk')
```

## API Reference

### OrbitDBWebAuthnIdentityProviderFunction Options

```typescript
interface Options {
  // WebAuthn credential for authentication (required)
  webauthnCredential: WebAuthnCredential;

  // If true, creates Ed25519 DID from keystore instead of P-256 DID from WebAuthn
  // Default: false
  useKeystoreDID?: boolean;

  // OrbitDB keystore instance (required if useKeystoreDID is true)
  keystore?: KeyStore;
}
```

### OrbitDBWebAuthnIdentityProvider Constructor

```typescript
class OrbitDBWebAuthnIdentityProvider {
  constructor(options: {
    webauthnCredential: WebAuthnCredential;
    useKeystoreDID?: boolean;
    keystore?: KeyStore;
  });
}
```

### New Method: createEd25519DIDFromKeystore

```typescript
class OrbitDBWebAuthnIdentityProvider {
  /**
   * Create Ed25519 DID from OrbitDB keystore
   * This uses the keystore's Ed25519 key to create a did:key DID
   * @throws {Error} If keystore is not provided
   * @returns {Promise<string>} Ed25519-based did:key DID
   */
  async createEd25519DIDFromKeystore(): Promise<string>;
}
```

## Technical Details

### DID Format

#### Ed25519 DID (with `useKeystoreDID: true`)

```
did:key:z6Mk... (Ed25519 multicodec prefix: 0xed)
```

**Structure:**

1. Multicodec prefix: `0xed` (Ed25519 public key)
2. Public key bytes: 32 bytes from keystore
3. Encoded as base58btc
4. Prefixed with `did:key:`

#### P-256 DID (default)

```
did:key:zDna... (P-256 multicodec prefix: 0x1200)
```

**Structure:**

1. Multicodec prefix: `0x1200` (P-256 public key)
2. Compressed public key: 33 bytes from WebAuthn
3. Encoded as base58btc
4. Prefixed with `did:key:`

### Key Generation Flow

#### With `useKeystoreDID: false` (default)

```
WebAuthn Credential
  ↓
P-256 Public Key (x, y coordinates)
  ↓
Compress to 33 bytes
  ↓
Add P-256 multicodec (0x1200)
  ↓
Base58btc encode
  ↓
did:key:zDna...
```

#### With `useKeystoreDID: true`

```
WebAuthn Credential (for auth)
  ↓
Get/Create Ed25519 key in keystore
  ↓
Ed25519 Public Key (32 bytes)
  ↓
Add Ed25519 multicodec (0xed)
  ↓
Base58btc encode
  ↓
did:key:z6Mk...
```

## Benefits

### 1. Unified Key Management

✅ **Single key for identity and operations**

- DID derived from Ed25519 keystore key
- Database entries signed by same Ed25519 key
- No key mismatch between identity and operations

### 2. Better UCAN Compatibility

✅ **Ed25519 is widely supported in UCAN**

- Most UCAN implementations prefer Ed25519
- Better interoperability with IPFS/Filecoin ecosystem
- Simplified delegation chains

### 3. Simplified Security Model

✅ **Clear separation of concerns**

- WebAuthn: Authentication and session establishment
- Ed25519 Keystore: Identity and database operations
- Easier to reason about security properties

### 4. Backward Compatible

✅ **Opt-in feature**

- Default behavior unchanged (P-256 from WebAuthn)
- Existing applications continue to work
- Can be enabled with a single flag

## Security Considerations

### WebAuthn Still Required

⚠️ **WebAuthn is still mandatory** even with `useKeystoreDID: true`

The WebAuthn credential is used for:

- User authentication
- Session establishment
- Proving user presence
- Hardware-backed security

### Keystore Security

⚠️ **Keystore is stored in browser/filesystem**

The Ed25519 keystore key is:

- Stored in IndexedDB (browser) or filesystem (Node.js)
- **Currently unencrypted** (OrbitDB limitation)
- Vulnerable to XSS, malicious extensions, physical access

**Recommendation:**

- Use WebAuthn-encrypted keystore (future enhancement)
- See [WebAuthn-Encrypted Keystore Integration](./WEBAUTHN-ENCRYPTED-KEYSTORE-INTEGRATION.md)

### Identity Trust Model

With `useKeystoreDID: true`:

- ✅ Identity is tied to keystore key
- ✅ Database operations provably from same key
- ⚠️ Keystore key is software-based (not hardware-backed)
- ⚠️ WebAuthn provides authentication, not identity key protection

## Migration Guide

### From P-256 to Ed25519 DID

If you have existing applications using P-256 DIDs and want to switch:

#### Step 1: Update Identity Creation

```javascript
// Before
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
  }),
});

// After
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
    useKeystoreDID: true, // Add this
    keystore: orbitdb.keystore, // Add this
  }),
});
```

#### Step 2: Handle DID Change

⚠️ **Important:** The DID will change when switching from P-256 to Ed25519

- Old DID: `did:key:zDna...` (P-256)
- New DID: `did:key:z6Mk...` (Ed25519)

This means:

- New identity in OrbitDB
- Databases need to be re-permissioned
- Cannot access old databases without P-256 DID

#### Step 3: Update Access Control

```javascript
// Grant access to new Ed25519 DID
await db.access.grant('write', newEd25519DID);

// Remove old P-256 DID (optional)
await db.access.revoke('write', oldP256DID);
```

## Examples

See [`examples/ed25519-encrypted-keystore-demo` (identity module: `examples/shared/lib/options/encrypted-keystore.js`)](../`examples/ed25519-encrypted-keystore-demo` 'identity module: `examples/shared/lib/options/encrypted-keystore.js`') for complete working examples:

- Example 1: Default P-256 DID from WebAuthn
- Example 2: Ed25519 DID from keystore
- Example 3: Full workflow with Ed25519 keystore DID
- Example 4: Comparison between P-256 and Ed25519

## Testing

The feature includes comprehensive tests. Run them with:

```bash
npm test
```

## Keys that change, and keys that do not

This section used to promise an encrypted keystore and `identity.rotateKey({ preserveDID: true })`. The first exists: `encryptKeystore: true`, described in [WEBAUTHN-ENCRYPTED-KEYSTORE-INTEGRATION.md](./WEBAUTHN-ENCRYPTED-KEYSTORE-INTEGRATION.md). The second will not come in that form: a `did:key` _is_ its public key, so no change of key can keep the DID. What can change, and how:

| Key                                                            | Can it change?                    | How                                                                                                                                   |
| -------------------------------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| The passkey (P-256 DID, `did:key:zDna…`)                       | Only by becoming another identity | A new passkey is a new DID. Grant the new DID write access and revoke the old one (below).                                            |
| The Ed25519 keystore key (`useKeystoreDID`, `did:key:z6Mk…`)   | Only by becoming another identity | The same: a new key is a new DID.                                                                                                     |
| The signing key derived from the PRF output (the default path) | For all identities at once        | It is fixed per passkey. The derivation is versioned, and changing the version is a breaking change for every identity.               |
| Keys an application derives (`deriveSubkey`, `deriveAesKey`)   | Yes                               | Put a version in `info` (`invoice/db-key/v1`) and raise it. Everything sealed under the old key has to be re-encrypted.               |
| A vault's key                                                  | Yes                               | `renew` on the vault keeper makes a new vault key without the slots of removed authenticators.                                        |
| A books identity from a vault secret (`createSecretSigner`)    | Only by moving the data           | It is the root of its databases and cannot be revoked; against a stolen secret, make a new vault with a new secret and move the data. |

**Replacing a passkey.** Register a second passkey before one is lost: as a slot of the vault (`addPasskey`), and as a writer of the databases. When one is lost or stolen:

- **Access control.** Revoke its DID: `await db.access.revoke('write', oldDID)`. This works with the `OrbitDBAccessController` only. The `IPFSAccessController`'s write list is fixed when the database is created, so a database that has to outlive a passkey needs the former — or a books identity (`createSecretSigner`) as its root, which the passkeys open through the vault instead of writing as themselves.
- **Vault.** `renew` with the stolen authenticator in `removed`. Removing a slot revokes nothing that was already opened: an authenticator that opened the vault has seen its contents, root included. Renew with a new `payload` where it may hold them, and replace what the old contents protected.

**What no step here can do.** An OrbitDB identity document does not expire, and peers accept a writer by its DID. A signing key that leaked stays usable for that DID wherever the DID may write, until the DID is revoked. The answer is the one above: revoke the DID and continue under a new identity.

### Hardware-backed Ed25519

`createCredential` asks for ES256 (P-256), with RS256 as a fallback, and not for Ed25519. Some security keys can sign with Ed25519 (COSE `EdDSA`), but this package does not request it: an Ed25519 identity is the keystore DID above, not the passkey's own key.

## FAQ

### Q: Why not use P-256 for everything?

**A:** UCAN and many Web3 tools prefer Ed25519. Using Ed25519 for the keystore (which signs operations) and the DID provides better ecosystem compatibility.

### Q: Is WebAuthn still secure with this feature?

**A:** Yes! WebAuthn is still used for authentication and session establishment. The only change is where the DID comes from (keystore instead of WebAuthn credential).

### Q: Can I switch between P-256 and Ed25519 DIDs?

**A:** Yes, but it creates a new identity. The DIDs are different, so you'll need to re-permission databases.

### Q: Is the Ed25519 keystore encrypted?

**A:** Currently no (OrbitDB limitation). This is a known issue. See [WebAuthn-Encrypted Keystore Integration](./WEBAUTHN-ENCRYPTED-KEYSTORE-INTEGRATION.md) for details and future solutions.

### Q: Which should I use: P-256 or Ed25519 DID?

**A:**

- **P-256 (default)**: If you want hardware-backed DID and don't need UCAN
- **Ed25519 (new)**: If you need UCAN compatibility or want unified key management

## References

- [WebAuthn-Encrypted Keystore Integration](./WEBAUTHN-ENCRYPTED-KEYSTORE-INTEGRATION.md)
- [UCAN Specification](https://github.com/ucan-wg/spec)
- [DID Key Format](https://w3c-ccg.github.io/did-method-key/)
- [Multicodec Table](https://github.com/multiformats/multicodec/blob/master/table.csv)
- [OrbitDB Documentation](https://orbitdb.org/)

## License

MIT License - see LICENSE file for details.

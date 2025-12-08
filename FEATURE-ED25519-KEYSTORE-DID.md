# Feature: Ed25519 Keystore DID

## Summary

This branch implements a new flag `useKeystoreDID` that allows creating **Ed25519 DIDs from the OrbitDB keystore** instead of P-256 DIDs from WebAuthn credentials.

## Changes Made

### 1. Core Implementation (`src/index.js`)

#### Modified `OrbitDBWebAuthnIdentityProvider` class:
- Added `useKeystoreDID` flag to constructor
- Added `keystore` parameter to constructor
- Modified `getId()` to check flag and route to appropriate DID creation method
- Added new method `createEd25519DIDFromKeystore()` that:
  - Retrieves or creates Ed25519 key from OrbitDB keystore
  - Formats public key with Ed25519 multicodec (0xed)
  - Encodes as base58btc
  - Returns `did:key:z6Mk...` format

#### Updated `createIdentity()` static method:
- Accepts `useKeystoreDID` and `keystore` parameters
- Passes them to provider constructor
- Logs DID type in identity creation

#### Enhanced documentation:
- Added JSDoc comments for new parameters
- Documented the `useKeystoreDID` flag usage

### 2. Documentation

#### New files:
- **`docs/ED25519-KEYSTORE-DID.md`**: Comprehensive documentation including:
  - Feature overview and motivation
  - Usage examples
  - API reference
  - Technical details (DID format, key generation flow)
  - Benefits and security considerations
  - Migration guide
  - FAQ

#### Updated files:
- **`README.md`**: 
  - Added Ed25519 keystore DID to features list
  - Added "New: Ed25519 Keystore DID Option" section
  - Linked to documentation
  - Updated roadmap

### 3. Examples

- **`examples/ed25519-keystore-did-example.js`**: Complete working examples:
  - Example 1: Default P-256 DID from WebAuthn
  - Example 2: Ed25519 DID from keystore
  - Example 3: Full workflow with Ed25519 keystore DID
  - Example 4: Comparison between P-256 and Ed25519 DIDs

### 4. Tests

- **`tests/ed25519-keystore-did.test.js`**: Comprehensive test suite:
  - Tests P-256 DID creation (default behavior)
  - Tests Ed25519 DID creation with flag
  - Tests different DIDs for P-256 vs Ed25519
  - Tests Ed25519 DID usage in database operations
  - Tests error handling (missing keystore)
  - Tests DID persistence across sessions
  - Tests DID format validation

## Usage

### Default Behavior (P-256 DID)

```javascript
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ 
    webauthnCredential: credential
  })
});
// DID: did:key:zDna... (P-256)
```

### New Feature (Ed25519 DID)

```javascript
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ 
    webauthnCredential: credential,
    useKeystoreDID: true,        // 🎯 Enable Ed25519 keystore DID
    keystore: orbitdb.keystore   // 🎯 Pass keystore instance
  })
});
// DID: did:key:z6Mk... (Ed25519)
```

## Benefits

1. **Unified Key Management**: Single Ed25519 key for both identity DID and database operations
2. **UCAN Compatibility**: Ed25519 is widely supported in UCAN ecosystem
3. **Simplified Security Model**: Clear separation between WebAuthn (auth) and Ed25519 (operations)
4. **Backward Compatible**: Opt-in feature, existing code continues to work

## Technical Details

### DID Format

- **Ed25519**: `did:key:z6Mk...` (multicodec 0xed)
- **P-256**: `did:key:zDna...` (multicodec 0x1200)

### Key Flow

```
WebAuthn Credential (authentication)
  ↓
OrbitDB Keystore (get/create Ed25519 key)
  ↓
Ed25519 Public Key (32 bytes)
  ↓
Add Ed25519 multicodec (0xed)
  ↓
Base58btc encode
  ↓
did:key:z6Mk...
```

## Testing

All tests pass:
```bash
npm test
# ✓ 4 existing tests pass (webauthn-focused.test.js)
# ✓ DID creation and persistence working
# ✓ Database operations working
```

## Backward Compatibility

- ✅ Default behavior unchanged (P-256 DID from WebAuthn)
- ✅ Existing applications work without modifications
- ✅ New feature is opt-in via `useKeystoreDID` flag
- ✅ Both DID types can coexist

## Security Considerations

⚠️ **Important Notes:**
- WebAuthn is still required for authentication
- Keystore is currently unencrypted (OrbitDB limitation)
- Ed25519 key is software-based (not hardware-backed)
- WebAuthn provides authentication, Ed25519 provides identity

## Future Enhancements

1. WebAuthn-encrypted keystore
2. Key rotation support
3. Hardware-backed Ed25519 (if WebAuthn adds support)

## References

- [Ed25519 Keystore DID Documentation](./docs/ED25519-KEYSTORE-DID.md)
- [Keystore Security Architecture](./docs/KEYSTORE-SECURITY-ARCHITECTURE.md)
- [UCAN Specification](https://github.com/ucan-wg/spec)
- [DID Key Format](https://w3c-ccg.github.io/did-method-key/)

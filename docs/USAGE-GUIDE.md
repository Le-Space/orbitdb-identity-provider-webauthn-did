# Usage Guide

Complete guide for using OrbitDB WebAuthn DID Identity Provider.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Advanced Configuration](#advanced-configuration)
- [Credential Management](#credential-management)
- [Verification Utilities](#verification-utilities)
- [Error Handling](#error-handling)
- [API Reference](#api-reference)

## Installation

```bash
npm install orbitdb-identity-provider-webauthn-did
```

## Basic Usage

### Quick Start

```javascript
import { createOrbitDB, Identities, IPFSAccessController } from '@orbitdb/core'
import { createHelia } from 'helia'
import { 
  WebAuthnDIDProvider,
  OrbitDBWebAuthnIdentityProviderFunction,
  registerWebAuthnProvider,
  checkWebAuthnSupport,
  storeWebAuthnCredential,
  loadWebAuthnCredential
} from 'orbitdb-identity-provider-webauthn-did'

// Check WebAuthn support
const support = await checkWebAuthnSupport()
if (!support.supported) {
  console.error('WebAuthn not supported:', support.message)
  return
}

// Create or load WebAuthn credential
let credential = loadWebAuthnCredential()

if (!credential) {
  // Create new WebAuthn credential (triggers biometric prompt)
  credential = await WebAuthnDIDProvider.createCredential({
    userId: 'alice@example.com',
    displayName: 'Alice Smith'
  })
  
  // Store credential for future use
  storeWebAuthnCredential(credential)
}

// Register the WebAuthn provider
registerWebAuthnProvider()

// Create identities instance
const identities = await Identities()

// Create WebAuthn identity
const identity = await identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ webauthnCredential: credential })
})

// Create IPFS instance - see OrbitDB Liftoff example for full libp2p configuration:
// https://github.com/orbitdb/orbitdb/tree/main/examples/liftoff
const ipfs = await createHelia()

// Create OrbitDB instance with WebAuthn identity
const orbitdb = await createOrbitDB({
  ipfs,
  identities,
  identity
})

// Create a database
const db = await orbitdb.open('my-secure-database', {
  type: 'keyvalue',
  accessController: IPFSAccessController({
    write: [identity.id] // Only this WebAuthn identity can write
  })
})

// Add data (may trigger biometric prompt for identity verification)
await db.put('greeting', 'Hello, secure world!')
```

## Advanced Configuration

### LibP2P and IPFS Setup

For production deployments, you'll need a proper libp2p configuration. See the [OrbitDB Liftoff example](https://github.com/orbitdb/liftoff) for complete setup including:
- WebRTC and WebSocket transports
- Circuit relay configuration
- Connection management
- Persistent storage

### Credential Creation Options

```javascript
const credential = await WebAuthnDIDProvider.createCredential({
  userId: 'unique-user-identifier',      // Required: Unique user ID
  displayName: 'User Display Name',      // Required: Display name
  domain: 'your-app-domain.com',         // Optional: Defaults to current hostname
  timeout: 60000                         // Optional: Authentication timeout in ms
})
```

### Identity Provider Configuration

#### Manual Setup

```javascript
import { OrbitDBWebAuthnIdentityProviderFunction } from 'orbitdb-identity-provider-webauthn-did'

const identityProvider = OrbitDBWebAuthnIdentityProviderFunction({
  webauthnCredential: credential
})

const orbitdb = await createOrbitDB({
  ipfs,
  identities,
  identity: {
    provider: identityProvider
  }
})
```

### WebAuthn Support Detection

```javascript
import { checkWebAuthnSupport, WebAuthnDIDProvider } from 'orbitdb-identity-provider-webauthn-did'

// Comprehensive support check
const support = await checkWebAuthnSupport()
console.log({
  supported: support.supported,
  platformAuthenticator: support.platformAuthenticator,
  message: support.message
})

// Quick checks
const isSupported = WebAuthnDIDProvider.isSupported()
const hasBiometric = await WebAuthnDIDProvider.isPlatformAuthenticatorAvailable()
```

## Credential Management

### Credential Storage Utilities

The library provides utility functions for properly storing and loading WebAuthn credentials:

```javascript
import { 
  storeWebAuthnCredential, 
  loadWebAuthnCredential, 
  clearWebAuthnCredential 
} from 'orbitdb-identity-provider-webauthn-did'

// Store credential (handles Uint8Array serialization automatically)
storeWebAuthnCredential(credential)

// Load credential (handles Uint8Array deserialization automatically)  
const credential = loadWebAuthnCredential()

// Clear stored credential
clearWebAuthnCredential()

// Use custom storage keys
storeWebAuthnCredential(credential, 'my-custom-key')
const credential = loadWebAuthnCredential('my-custom-key')
```

**Why we provide these utilities**: WebAuthn credentials contain `Uint8Array` objects that don't serialize properly with `JSON.stringify()`. Without proper serialization, the public key coordinates become empty arrays after loading from localStorage, causing DID generation to fail. Our utility functions handle this complexity automatically and ensure proper `did:key` format generation.

## Verification Utilities

The library provides comprehensive verification utilities to validate database operations and identity storage:

```javascript
import { 
  verifyDatabaseUpdate,
  verifyIdentityStorage,
  verifyDataEntries,
  isValidWebAuthnDID
} from 'orbitdb-identity-provider-webauthn-did'

// Verify database update events
const updateResult = await verifyDatabaseUpdate(database, identityHash, expectedWebAuthnDID)
if (updateResult.success) {
  console.log('✅ Database update verified')
} else {
  console.log('❌ Verification failed:', updateResult.error)
}

// Verify identity is properly stored
const storageResult = await verifyIdentityStorage(identities, identity)
console.log('Identity stored correctly:', storageResult.success)

// Verify generic data entries with custom matching
const dataResults = await verifyDataEntries(database, dataItems, expectedWebAuthnDID, {
  matchFn: (dbItem, expectedItem) => dbItem.id === expectedItem.id,
  checkLog: true
})

// DID format validation
if (isValidWebAuthnDID(identity.id)) {
  console.log('Valid WebAuthn DID format')
}
```

### Verification Features

- **Database-centric verification**: Uses local database state instead of unreliable IPFS gateway calls
- **Access control validation**: Verifies write permissions and database ownership  
- **Identity storage checking**: Confirms identities are properly stored in OrbitDB's identity store
- **Generic data verification**: Flexible verification system that works with any data structure
- **DID format validation**: Utility functions for WebAuthn DID validation and parsing
- **Pragmatic fallback**: Provides fallback verification when network resources are unavailable

## Error Handling

The library provides detailed error handling for common WebAuthn scenarios:

```javascript
try {
  const credential = await WebAuthnDIDProvider.createCredential()
} catch (error) {
  switch (error.message) {
    case 'Biometric authentication was cancelled or failed':
      // User cancelled or biometric failed
      break
    case 'WebAuthn is not supported on this device':
      // Device/browser doesn't support WebAuthn
      break
    case 'A credential with this ID already exists':
      // Credential already registered for this user
      break
    default:
      console.error('WebAuthn error:', error.message)
  }
}
```

## API Reference

### WebAuthnDIDProvider

Core class for WebAuthn DID operations.

#### Static Methods

- `isSupported()` - Check if WebAuthn is supported
- `isPlatformAuthenticatorAvailable()` - Check for biometric authenticators
- `createCredential(options)` - Create new WebAuthn credential
- `createDID(credentialInfo)` - Generate DID from credential
- `extractPublicKey(credential)` - Extract public key from WebAuthn credential

#### Instance Methods

- `sign(data)` - Sign data using WebAuthn (triggers biometric prompt)
- `verify(signature, data, publicKey)` - Verify WebAuthn signature

### OrbitDBWebAuthnIdentityProvider

OrbitDB-compatible identity provider.

#### Methods

- `getId()` - Get the DID identifier
- `signIdentity(data, options)` - Sign identity data
- `verifyIdentity(signature, data, publicKey)` - Verify identity signature

### Utility Functions

- `registerWebAuthnProvider()` - Register provider with OrbitDB
- `checkWebAuthnSupport()` - Comprehensive support detection
- `OrbitDBWebAuthnIdentityProviderFunction(options)` - Provider factory function
- `storeWebAuthnCredential(credential, key?)` - Store credential to localStorage with proper serialization
- `loadWebAuthnCredential(key?)` - Load credential from localStorage with proper deserialization
- `clearWebAuthnCredential(key?)` - Clear stored credential from localStorage

## Examples

See the `test/` directory for comprehensive usage examples including:

- Basic credential creation and authentication
- Multi-platform compatibility testing
- Error handling scenarios
- Integration with OrbitDB databases

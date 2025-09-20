# OrbitDB WebAuthn DID Identity Provider

A hardware-secured identity provider for OrbitDB using WebAuthn biometric authentication. This provider enables quantum-resistant, biometric-secured database access where private keys never leave the secure hardware element.

## Features

- 🔐 **Hardware-secured authentication** - Uses WebAuthn with platform authenticators (Face ID, Touch ID, Windows Hello)
- 🚫 **Private keys never leave hardware** - Keys are generated and stored in secure elements
- 🌐 **Cross-platform compatibility** - Works across modern browsers and platforms
- 📱 **Biometric authentication** - Seamless user experience with fingerprint, face recognition, or PIN
- 🔒 **Quantum-resistant** - P-256 elliptic curve cryptography with hardware backing
- 🆔 **DID-based identity** - Generates deterministic DIDs based on WebAuthn credentials

## Installation

```bash
npm install orbitdb-identity-provider-webauthn-did
```

## Basic Usage

```javascript
import { createOrbitDB, Identities, useIdentityProvider, IPFSAccessController } from '@orbitdb/core'
import { createHelia } from 'helia'
import { createLibp2p } from 'libp2p'
import { 
  WebAuthnDIDProvider,
  OrbitDBWebAuthnIdentityProviderFunction,
  registerWebAuthnProvider,
  checkWebAuthnSupport 
} from 'orbitdb-identity-provider-webauthn-did'

// Check WebAuthn support
const support = await checkWebAuthnSupport()
if (!support.supported) {
  console.error('WebAuthn not supported:', support.message)
  return
}

// Create or load WebAuthn credential
let credential = null

// Check if we have stored credentials
const storedCredential = localStorage.getItem('webauthn-credential')
if (storedCredential) {
  const parsed = JSON.parse(storedCredential)
  // IMPORTANT: Properly deserialize Uint8Arrays
  credential = {
    ...parsed,
    rawCredentialId: new Uint8Array(parsed.rawCredentialId),
    attestationObject: new Uint8Array(parsed.attestationObject),
    publicKey: {
      ...parsed.publicKey,
      x: new Uint8Array(parsed.publicKey.x),
      y: new Uint8Array(parsed.publicKey.y)
    }
  }
} else {
  // Create new WebAuthn credential (triggers biometric prompt)
  credential = await WebAuthnDIDProvider.createCredential({
    userId: 'alice@example.com',
    displayName: 'Alice Smith'
  })
  
  // Store credential with proper serialization
  const serializedCredential = {
    ...credential,
    rawCredentialId: Array.from(credential.rawCredentialId),
    attestationObject: Array.from(credential.attestationObject),
    publicKey: {
      ...credential.publicKey,
      x: Array.from(credential.publicKey.x),
      y: Array.from(credential.publicKey.y)
    }
  }
  localStorage.setItem('webauthn-credential', JSON.stringify(serializedCredential))
}

// Register the WebAuthn provider
useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction)

// Create identities instance
const identities = await Identities()

// Create WebAuthn identity
const identity = await identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ webauthnCredential: credential })
})

// Create libp2p and IPFS instances (browser-compatible)
const libp2p = await createLibp2p({
  addresses: {
    listen: ['/p2p-circuit', '/webrtc']
  },
  transports: [
    webSockets({ filter: all }),
    webRTC(),
    circuitRelayTransport()
  ],
  connectionEncryption: [noise()],
  streamMuxers: [yamux()],
  services: {
    identify: identify(),
    pubsub: gossipsub({ emitSelf: true, allowPublishToZeroTopicPeers: true })
  }
})

const ipfs = await createHelia({ 
  libp2p,
  blockstore: new MemoryBlockstore(),
  datastore: new MemoryDatastore()
})

// Create OrbitDB instance with WebAuthn identity
const orbitdb = await createOrbitDB({
  ipfs,
  identities,
  identity
})

// Create a database - will require biometric authentication for each write
const db = await orbitdb.open('my-secure-database', {
  type: 'keyvalue',
  accessController: IPFSAccessController({
    write: [identity.id] // Only this WebAuthn identity can write
  })
})

// Adding data will trigger biometric prompt
await db.put('greeting', 'Hello, secure world!')
```

## Advanced Configuration

### Credential Creation Options

```javascript
const credential = await WebAuthnDIDProvider.createCredential({
  userId: 'unique-user-identifier',
  displayName: 'User Display Name',
  domain: 'your-app-domain.com', // Defaults to current hostname
  timeout: 60000 // Authentication timeout in milliseconds
})
```

### Identity Provider Configuration

```javascript
// Manual identity provider setup
import { OrbitDBWebAuthnIdentityProviderFunction } from 'orbitdb-identity-provider-webauthn-did'

const identityProvider = OrbitDBWebAuthnIdentityProviderFunction({
  webauthnCredential: credential
})

const orbitdb = await createOrbitDB({
  identity: {
    provider: identityProvider
  }
})
```

## WebAuthn Support Detection

The library provides utilities to check WebAuthn compatibility:

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

## Browser Compatibility

| Browser | Version | Face ID | Touch ID | Windows Hello |
|---------|---------|---------|----------|---------------|
| Chrome  | 67+     | ✅      | ✅       | ✅            |
| Firefox | 60+     | ✅      | ✅       | ✅            |
| Safari  | 14+     | ✅      | ✅       | ✅            |
| Edge    | 18+     | ✅      | ✅       | ✅            |

## Platform Support

- **macOS**: Face ID, Touch ID
- **iOS**: Face ID, Touch ID  
- **Windows**: Windows Hello (face, fingerprint, PIN)
- **Android**: Fingerprint, face unlock, screen lock
- **Linux**: FIDO2 security keys, fingerprint readers

## Important: localStorage Serialization

⚠️ **CRITICAL**: When storing WebAuthn credentials in localStorage, you must properly serialize and deserialize `Uint8Array` objects, including the public key coordinates.

### Correct Storage:
```javascript
// Store credential with proper serialization
const serializedCredential = {
  ...credential,
  rawCredentialId: Array.from(credential.rawCredentialId),
  attestationObject: Array.from(credential.attestationObject),
  publicKey: {
    ...credential.publicKey,
    x: Array.from(credential.publicKey.x),  // Convert to regular array
    y: Array.from(credential.publicKey.y)   // Convert to regular array
  }
}
localStorage.setItem('webauthn-credential', JSON.stringify(serializedCredential))
```

### Correct Loading:
```javascript
const storedCredential = localStorage.getItem('webauthn-credential')
if (storedCredential) {
  const parsed = JSON.parse(storedCredential)
  credential = {
    ...parsed,
    rawCredentialId: new Uint8Array(parsed.rawCredentialId),
    attestationObject: new Uint8Array(parsed.attestationObject),
    publicKey: {
      ...parsed.publicKey,
      x: new Uint8Array(parsed.publicKey.x),  // Restore to Uint8Array
      y: new Uint8Array(parsed.publicKey.y)   // Restore to Uint8Array
    }
  }
}
```

**Why this matters**: Without proper serialization, the public key coordinates will be empty arrays after loading from localStorage, causing DID generation to fail with `did:webauthn:` (missing identifier).

## Security Considerations

### Private Key Security
- Private keys are generated within the secure hardware element
- Keys cannot be extracted, cloned, or compromised through software attacks
- Each authentication requires user presence and verification

### DID Generation
- DIDs are deterministically generated from the WebAuthn public key
- Same credential always produces the same DID
- Format: `did:webauthn:{32-char-hex-identifier}`

### Authentication Flow
1. User attempts database operation
2. WebAuthn biometric prompt appears
3. User provides biometric authentication
4. Hardware element signs the operation
5. OrbitDB verifies the signature

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

## Development

### Building

```bash
npm run build
```

### Testing

```bash
npm test
```

The test suite includes both unit tests and browser integration tests that verify WebAuthn functionality across different platforms.

### Dependencies

- `@orbitdb/core` - OrbitDB core functionality
- `cbor-web` - CBOR decoding for WebAuthn attestation objects

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

## Examples

See the `test/` directory for comprehensive usage examples including:

- Basic credential creation and authentication
- Multi-platform compatibility testing
- Error handling scenarios
- Integration with OrbitDB databases

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## License

MIT License - see LICENSE file for details.

## Security Disclosures

For security vulnerabilities, please email security@your-domain.com instead of using the issue tracker.
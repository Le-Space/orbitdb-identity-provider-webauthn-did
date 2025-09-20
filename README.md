# OrbitDB WebAuthn DID Identity Provider

[![Tests](https://github.com/le-space/orbitdb-identity-provider-webauthn-did/workflows/Tests/badge.svg)](https://github.com/le-space/orbitdb-identity-provider-webauthn-did/actions/workflows/test.yml) [![CI/CD](https://github.com/le-space/orbitdb-identity-provider-webauthn-did/workflows/CI%2FCD%20-%20Test%20and%20Publish/badge.svg)](https://github.com/le-space/orbitdb-identity-provider-webauthn-did/actions/workflows/ci-cd.yml)

🚀 **[Try the Live Demo](https://bafybeida2cdlt3yie4hh67fwm2q4gvi23s53klo4rb2en2inhu33zzmmqa.ipfs.w3s.link/)** - Interactive WebAuthn demo with biometric authentication

A hardware-secured identity provider for OrbitDB using WebAuthn authentication. This provider enables hardware -secured database access (Ledger, Yubikey etc.) where private keys never leave the secure hardware element 
and biometric authentication via Passkey.

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

### LibP2P and IPFS Setup

For an example libp2p configuration. See the [OrbitDB Liftoff example](https://github.com/orbitdb/liftoff) for example libp2p setup including:

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

## Credential Storage Utilities

The library provides utility functions for properly storing and loading WebAuthn credentials:

### Using the Built-in Utilities:

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

**Why we provide these utilities**: WebAuthn credentials contain `Uint8Array` objects that don't serialize properly with `JSON.stringify()`. Without proper serialization, the public key coordinates become empty arrays after loading from localStorage, causing DID generation to fail with `did:webauthn:` (missing identifier). Our utility functions handle this complexity automatically.

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
2. WebAuthn prompt appears
3. User provides authentication
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
- `storeWebAuthnCredential(credential, key?)` - Store credential to localStorage with proper serialization
- `loadWebAuthnCredential(key?)` - Load credential from localStorage with proper deserialization
- `clearWebAuthnCredential(key?)` - Clear stored credential from localStorage

## Examples

See the `test/` directory for comprehensive usage examples including:

- Basic credential creation and authentication
- Multi-platform compatibility testing
- Error handling scenarios
- Integration with OrbitDB databases

## Reference Documentation

### Core Technologies

#### OrbitDB
- [OrbitDB Documentation](https://orbitdb.org/docs/) - Peer-to-peer database for the decentralized web
- [OrbitDB GitHub](https://github.com/orbitdb/orbitdb) - Source code and examples
- [OrbitDB Liftoff Example](https://github.com/orbitdb/orbitdb/tree/main/examples/liftoff) - Complete setup guide

#### IPFS & Helia
- [Helia Documentation](https://helia.io/) - Lean, modular, and modern implementation of IPFS for JavaScript
- [Helia GitHub](https://github.com/ipfs/helia) - Source code and examples
- [IPFS Documentation](https://docs.ipfs.tech/) - InterPlanetary File System docs

#### libp2p
- [libp2p Documentation](https://docs.libp2p.io/) - Modular network stack for peer-to-peer applications
- [libp2p JavaScript](https://github.com/libp2p/js-libp2p) - JavaScript implementation
- [libp2p Browser Examples](https://github.com/libp2p/js-libp2p/tree/main/examples) - Browser-specific configurations

### WebAuthn & Authentication

#### WebAuthn Standard
- [WebAuthn W3C Specification](https://w3c.github.io/webauthn/) - Official WebAuthn standard
- [WebAuthn Guide](https://webauthn.guide/) - Comprehensive WebAuthn tutorial
- [MDN WebAuthn API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) - Browser API documentation

#### Passkeys
- [Passkeys.dev](https://passkeys.dev/) - Complete guide to implementing passkeys
- [Apple Passkeys](https://developer.apple.com/passkeys/) - iOS/macOS passkey implementation
- [Google Passkeys](https://developers.google.com/identity/passkeys) - Android/Chrome passkey support
- [Microsoft Passkeys](https://docs.microsoft.com/en-us/microsoft-edge/web-platform/passkeys) - Windows Hello integration

#### Hardware Security Keys

##### Ledger WebAuthn
- [Ledger WebAuthn Support](https://support.ledger.com/hc/en-us/articles/115005198545-FIDO-U2F) - FIDO U2F and WebAuthn on Ledger devices
- [Ledger Developer Portal](https://developers.ledger.com/) - Building apps for Ledger hardware wallets
- [Ledger WebAuthn Example](https://github.com/LedgerHQ/ledger-live/tree/develop/apps/ledger-live-desktop/src/renderer/families/ethereum/WebAuthnModal) - Implementation examples

##### YubiKey WebAuthn
- [YubiKey WebAuthn Guide](https://developers.yubico.com/WebAuthn/) - Complete WebAuthn implementation guide
- [YubiKey Developer Program](https://developers.yubico.com/) - SDKs, libraries, and documentation
- [YubiKey WebAuthn Examples](https://github.com/Yubico/java-webauthn-server) - Server-side WebAuthn implementation
- [YubiKey JavaScript Library](https://github.com/Yubico/yubikit-web) - Web integration tools

#### Browser Compatibility
- [Can I Use WebAuthn](https://caniuse.com/webauthn) - Browser support matrix
- [WebAuthn Awesome List](https://github.com/herrjemand/awesome-webauthn) - Curated WebAuthn resources
- [FIDO Alliance](https://fidoalliance.org/) - Industry standards and certification

### Cryptography & DIDs

#### Decentralized Identifiers (DIDs)
- [DID W3C Specification](https://w3c.github.io/did-core/) - Official DID standard
- [DID Method Registry](https://w3c.github.io/did-spec-registries/) - Registered DID methods
- [DID Primer](https://github.com/WebOfTrustInfo/rwot5-boston/blob/master/topics-and-advance-readings/did-primer.md) - Introduction to DIDs

#### P-256 Elliptic Curve Cryptography
- [RFC 6090 - ECC Algorithms](https://tools.ietf.org/html/rfc6090) - Fundamental ECC operations
- [NIST P-256 Curve](https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf) - Technical specifications
- [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) - Browser cryptography APIs

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## License

MIT License - see LICENSE file for details.

## Security Disclosures

For security vulnerabilities, please email security@le-space.de instead of using the issue tracker.
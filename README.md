# OrbitDB WebAuthn DID Identity Provider

[![Tests](https://github.com/le-space/orbitdb-identity-provider-webauthn-did/workflows/Tests/badge.svg)](https://github.com/le-space/orbitdb-identity-provider-webauthn-did/actions/workflows/test.yml) [![CI/CD](https://github.com/le-space/orbitdb-identity-provider-webauthn-did/workflows/CI%2FCD%20-%20Test%20and%20Publish/badge.svg)](https://github.com/le-space/orbitdb-identity-provider-webauthn-did/actions/workflows/ci-cd.yml)

⚠️ **SECURITY AUDIT WARNING**: This library has not undergone a formal security audit. While it implements industry-standard WebAuthn and cryptographic protocols, use in production environments is at your own risk. We recommend thorough testing and security review before deploying in critical applications.

🚀 **[Try the Live Demo](https://w3s.link/ipfs/bafybeibrrqn27xgvq6kzxwlyrfdomgfvlsoojfg3odba755f3pezwqpdza)** - Interactive WebAuthn demo with biometric authentication
A hardware-secured identity provider for OrbitDB using WebAuthn authentication. This provider enables hardware-secured database access (Ledger, Yubikey, etc.) where private keys never leave the secure hardware element and biometric authentication via Passkey.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Browser & Platform Support](#browser--platform-support)
- [Architecture & Security](#architecture--security)
- [Documentation](#documentation)
- [Development](#development)
- [Credits](#credits)
- [License](#license)

## Features

- 🔐 **Hardware-secured authentication** - Uses WebAuthn with platform authenticators (Face ID, Touch ID, Windows Hello)
- 🚫 **Private keys never leave hardware** - Keys are generated and stored in secure elements
- 🌐 **Cross-platform compatibility** - Works across modern browsers and platforms
- 📱 **Biometric authentication** - Seamless user experience with fingerprint, face recognition, or PIN
- 🔒 **Quantum-resistant** - P-256 elliptic curve cryptography with hardware backing
- 🆔 **Flexible DID options** - P-256 DIDs from WebAuthn OR Ed25519 DIDs from keystore
- 🔑 **UCAN-compatible** - Ed25519 keystore DID option for better UCAN integration

## Installation

```bash
npm install orbitdb-identity-provider-webauthn-did
```

## Quick Start

```javascript
import { WebAuthnDIDProvider, OrbitDBWebAuthnIdentityProviderFunction } from 'orbitdb-identity-provider-webauthn-did'

// Create WebAuthn credential (triggers biometric prompt)
const credential = await WebAuthnDIDProvider.createCredential({
  userId: 'alice@example.com',
  displayName: 'Alice'
})

// Create OrbitDB identity with WebAuthn
const identity = await identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ webauthnCredential: credential })
})

// Use with OrbitDB
const orbitdb = await createOrbitDB({ ipfs, identities, identity })
const db = await orbitdb.open('my-database')
```

📖 **See [Usage Guide](./docs/USAGE-GUIDE.md) for complete examples and API reference.**

## Browser & Platform Support

**Browsers**: Chrome 67+, Firefox 60+, Safari 14+, Edge 18+

**Platforms**:
- **macOS/iOS**: Face ID, Touch ID
- **Windows**: Windows Hello (face, fingerprint, PIN)
- **Android**: Fingerprint, face unlock, screen lock
- **Linux**: FIDO2 security keys, fingerprint readers

**Hardware Keys**: Ledger, YubiKey, and other FIDO2-compliant devices


## Architecture & Security

### Current Architecture

**DID Generation**: DIDs are deterministically generated from WebAuthn P-256 public key
- Format: `did:key:{base58btc-encoded-multikey}`
- Implementation: `src/index.js` lines 222-296

**OrbitDB Keystore**: Separate keystore (secp256k1) signs database operations
- Location: `./orbitdb/keystore/` (IndexedDB)
- ⚠️ **Currently unencrypted** - vulnerable to XSS/extensions
- WebAuthn signs identity (once), keystore signs operations (fast)

### Security Features

✅ **Hardware-backed authentication** - Private keys never leave secure element  
✅ **Biometric verification** - Each WebAuthn operation requires user presence  
⚠️ **Keystore encryption needed** - See roadmap below

### New: Ed25519 Keystore DID Option

✅ **Now available!** Create Ed25519 DIDs from OrbitDB keystore for better UCAN compatibility:

```javascript
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ 
    webauthnCredential: credential,
    useKeystoreDID: true,        // Enable Ed25519 keystore DID
    keystore: orbitdb.keystore
  })
});
```

📖 **See [Ed25519 Keystore DID Documentation](./docs/ED25519-KEYSTORE-DID.md) for details**

### New: WebAuthn-Encrypted Keystore

✅ **Now available!** Protect your keystore with WebAuthn hardware security:

```javascript
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ 
    webauthnCredential: credential,
    useKeystoreDID: true,              // Ed25519 DID from keystore
    keystore: orbitdb.keystore,
    encryptKeystore: true,             // 🔐 Encrypt keystore
    keystoreEncryptionMethod: 'largeBlob'  // or 'hmac-secret'
  })
});
```

**Benefits:**
- 🔐 Keystore encrypted with AES-GCM 256-bit
- 🔑 Secret key protected by WebAuthn hardware
- 🛡️ Protected from XSS, malicious extensions, theft
- 👆 One biometric prompt per session

📖 **See [WebAuthn-Encrypted Keystore Integration](./docs/WEBAUTHN-ENCRYPTED-KEYSTORE-INTEGRATION.md) for details**

### Future Roadmap

1. **WebAuthn-encrypted keystore**: One biometric prompt per session
2. **Offline-first encryption**: No centralized dependencies
3. **Key rotation support**: Seamless key updates

📖 **See [Keystore Security Architecture](./docs/KEYSTORE-SECURITY-ARCHITECTURE.md) for detailed analysis**

## Documentation

### Getting Started
- [Usage Guide](./docs/USAGE-GUIDE.md) - Complete examples and API reference
- [Passkey Authentication Architecture](./docs/PASSKEY-KEYSTORE-ARCHITECTURE.md) - How WebAuthn integrates with OrbitDB

### Security & Architecture
- [Ed25519 Keystore DID](./docs/ED25519-KEYSTORE-DID.md) - **NEW!** Create Ed25519 DIDs from keystore
- [Keystore Security Architecture](./docs/KEYSTORE-SECURITY-ARCHITECTURE.md) - Vulnerability analysis and solutions
- [PWA & Capacitor Keystore Encryption](./docs/PWA-CAPACITOR-KEYSTORE-ENCRYPTION.md) - Encryption strategies
- [Lit Protocol Integration](./docs/LIT-PROTOCOL-INTEGRATION.md) - Decentralized key management option
- [WebAuthn DID and OrbitDB Identity](./docs/WEBAUTHN-DID-AND-ORBITDB-IDENTITY.md) - DID/identity relationship

### Examples
- `test/` directory - Unit and integration tests
- `examples/` directory - Working demo applications

## Development

```bash
npm install      # Install dependencies
npm run build    # Build the library
npm test         # Run test suite
```

Tests include unit tests and browser integration tests for WebAuthn across different platforms.

## Credits

This project builds upon:
- [OrbitDB DID Identity Provider](https://github.com/orbitdb/orbitdb-identity-provider-did) - Foundational DID implementation
- [OpenFort EIP-7702 WebAuthn Sample](https://github.com/openfort-xyz/sample-7702-WebAuthn/) - WebAuthn reference implementation
- [Passkey Wallet Demo](https://www.passkey-wallet.com/) - Passkey wallet patterns

## Contributing

Contributions welcome! Please ensure all tests pass before submitting PRs.

## License

MIT License - see LICENSE file for details.

**Security Disclosures**: For security issues, email security@le-space.de (not GitHub issues).

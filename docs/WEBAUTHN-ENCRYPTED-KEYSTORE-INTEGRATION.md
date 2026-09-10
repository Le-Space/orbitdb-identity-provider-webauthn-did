# WebAuthn-Encrypted Keystore

Seal the OrbitDB keystore key with the passkey: PRF by default, `largeBlob` or `hmac-secret` where the authenticator offers them. Only meaningful together with `useKeystoreDID` (the keystore key is the identity) and a keystore that forgets — see below.

## Architecture

### Without Encryption

```
┌─────────────────────────────────────────────────────────┐
│ IDENTITY LAYER (WebAuthn - Hardware)                    │
│  • Creates P-256 or Ed25519 DID                         │
│  • One-time authentication                              │
│  • Hardware-secured credential                          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ OPERATIONS LAYER (OrbitDB Keystore - Unencrypted)      │
│  • Ed25519 private key in plaintext                     │
│  • Stored in IndexedDB                                  │
│  • ⚠️ VULNERABLE to XSS, extensions, theft              │
│  • Signs all database operations                        │
└─────────────────────────────────────────────────────────┘
```

### With Encryption (Implemented)

```
┌─────────────────────────────────────────────────────────┐
│ IDENTITY LAYER (WebAuthn Passkey)                       │
│  • Biometric/PIN authentication                         │
│  • Protects secret key (SK) via largeBlob/hmac-secret  │
│  • Hardware-backed                                       │
└─────────────────────────────────────────────────────────┘
                          ↓
              Releases SK after authentication
                          ↓
┌─────────────────────────────────────────────────────────┐
│ ENCRYPTION LAYER (AES-GCM with SK)                      │
│  • SK decrypts OrbitDB private key                      │
│  • AES-GCM 256-bit encryption                           │
│  • IV stored locally with ciphertext                    │
└─────────────────────────────────────────────────────────┘
                          ↓
              OrbitDB private key unlocked
                          ↓
┌─────────────────────────────────────────────────────────┐
│ OPERATIONS LAYER (OrbitDB Keystore - Encrypted)        │
│  • Ed25519 private key encrypted at rest               │
│  • ✅ Protected from XSS, extensions, theft             │
│  • Decrypted in memory during session                   │
│  • Signs all database operations                        │
└─────────────────────────────────────────────────────────┘
```

## Usage

### Basic Usage

```javascript
import { OrbitDBWebAuthnIdentityProviderFunction } from '@le-space/orbitdb-identity-provider-webauthn-did';

// Create identity with encrypted keystore
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
    useKeystoreDID: true, // Use Ed25519 keystore DID
    keystoreKeyType: 'Ed25519', // 'Ed25519' or 'secp256k1'
    keystore, // from createSessionKeystore(): OrbitDB's default keystore
    //          persists the unlocked key unencrypted
    encryptKeystore: true, // Enable encryption
    keystoreEncryptionMethod: 'prf', // 'prf' (default), 'largeBlob' or 'hmac-secret'
  }),
});
```

### Database Content Encryption

The keystore seal and database content encryption are separate keys. There
is no `secretKey` option on the provider — it generates and seals its own —
so content encryption needs a key of its own, wrapped the same way if you
want the passkey to guard it:

```javascript
import SimpleEncryption from '@orbitdb/simple-encryption';
import { generateSecretKey } from '@le-space/orbitdb-identity-provider-webauthn-did';

const sk = generateSecretKey(); // seal it with wrapSKWithPRF() to persist it

const password = btoa(String.fromCharCode(...sk));
const encryption = {
  data: await SimpleEncryption({ password }),
  replication: await SimpleEncryption({ password }),
};

const db = await orbitdb.open('encrypted-db', { encryption });
```

`tests/simple-encryption-integration.test.js` runs this combination end to end.

## Implementation Details

### WebAuthn Extensions

#### largeBlob Extension

```javascript
/**
 * Store secret key in WebAuthn largeBlob
 */
async function storeSKInLargeBlob(credential, sk) {
  // Create credential with largeBlob support
  const credentialWithBlob = await navigator.credentials.create({
    publicKey: {
      // ... existing WebAuthn options
      extensions: {
        largeBlob: {
          support: 'required',
          write: sk, // Store SK in authenticator
        },
      },
    },
  });

  return credentialWithBlob;
}

/**
 * Retrieve secret key from WebAuthn largeBlob
 */
async function retrieveSKFromLargeBlob(credential) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          id: credential.rawCredentialId,
          type: 'public-key',
        },
      ],
      extensions: {
        largeBlob: {
          read: true, // Request SK from authenticator
        },
      },
    },
  });

  return assertion.getClientExtensionResults().largeBlob.blob;
}
```

#### hmac-secret Extension

```javascript
/**
 * Wrap secret key using hmac-secret
 */
async function wrapSKWithHmacSecret(credential, sk) {
  const salt = crypto.getRandomValues(new Uint8Array(32));

  const credentialWithHmac = await navigator.credentials.create({
    publicKey: {
      // ... existing WebAuthn options
      extensions: {
        hmacCreateSecret: true,
      },
    },
  });

  // Derive wrapping key from HMAC
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          id: credentialWithHmac.rawId,
          type: 'public-key',
        },
      ],
      extensions: {
        hmacGetSecret: {
          salt1: salt,
        },
      },
    },
  });

  const hmacOutput =
    assertion.getClientExtensionResults().hmacGetSecret.output1;

  // Wrap SK with HMAC-derived key
  const wrappedSK = await wrapKey(sk, hmacOutput);

  // Store wrapped SK and salt locally
  await storeWrappedSK({
    wrappedSK,
    salt,
    credentialId: credentialWithHmac.id,
  });

  return credentialWithHmac;
}

/**
 * Unwrap secret key using hmac-secret
 */
async function unwrapSKWithHmacSecret(credential) {
  const { wrappedSK, salt } = await loadWrappedSK(credential.credentialId);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          id: credential.rawCredentialId,
          type: 'public-key',
        },
      ],
      extensions: {
        hmacGetSecret: {
          salt1: salt,
        },
      },
    },
  });

  const hmacOutput =
    assertion.getClientExtensionResults().hmacGetSecret.output1;

  // Unwrap SK with HMAC-derived key
  const sk = await unwrapKey(wrappedSK, hmacOutput);

  return sk;
}
```

### AES-GCM Encryption

```javascript
/**
 * Encrypt private key with AES-GCM
 */
async function encryptPrivateKey(privateKey, sk) {
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    sk,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    privateKey
  );

  return { ciphertext: new Uint8Array(ciphertext), iv };
}

/**
 * Decrypt private key with AES-GCM
 */
async function decryptPrivateKey(ciphertext, sk, iv) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    sk,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const privateKey = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertext
  );

  return new Uint8Array(privateKey);
}
```

The complete implementation is available in `src/keystore/encryption.js` with the following exported utilities:

```javascript
import {
  generateSecretKey,
  encryptWithAESGCM,
  decryptWithAESGCM,
  storeEncryptedKeystore,
  loadEncryptedKeystore,
  clearEncryptedKeystore,
  checkExtensionSupport,
} from '@le-space/orbitdb-identity-provider-webauthn-did/keystore';
```

## Ed25519/secp256k1 Keystore DIDs

```javascript
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
    useKeystoreDID: true,
    keystoreKeyType: 'Ed25519', // or 'secp256k1'
    keystore: orbitdb.keystore,
    encryptKeystore: true,
    keystoreEncryptionMethod: 'largeBlob',
  }),
});
```

## Browser Support

**largeBlob**: Chrome 106+, Edge 106+  
**hmac-secret**: Chrome, Firefox, Edge (with CTAP2)

## Security

**Without encryption**: the keystore key sits in IndexedDB in clear.

**With encryption, on a session keystore**:

- A copy of the keystore key sealed with AES-GCM-256, the wrapping key from
  the passkey's PRF output; nothing else at rest
- Unlocked once per session into memory; during the session the key is in
  page memory like any other software key — script running in the page can
  use it. The worker signer (`createWorkerSigner`) is the option that keeps
  it out of the page
- Without PRF nothing is sealed: `provider.encryptionState` reports
  `{ enabled: false, reason: 'prf-unavailable' }`

## Status

**Implemented**: AES-GCM sealing, PRF/largeBlob/hmac-secret unwrap, Ed25519/secp256k1 keystore DIDs, the session keystore, the worker signer

**Future**: Session timeout, multi-device sync, recovery flows

## Compatibility

Encryption is opt-in. Existing code without `encryptKeystore` continues to work.

## Testing

The node suite (`pnpm run test:node`) covers the seal, the session keystore and the signer; `tests/ed25519-encrypted-keystore-e2e.test.js` drives the demo through a virtual authenticator.

```bash
npm run test:encrypted-keystore
npm test
```

# WebAuthn-Encrypted Keystore Integration Plan

## Overview

This document outlines the integration of **Passkey-Protected OrbitDB Identity** into the existing WebAuthn DID provider. This implements the architecture described in the keystore encryption solution using WebAuthn `largeBlob` or `hmac-secret` extensions.

## Current vs Proposed Architecture

### Current Architecture (What We Have)

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

### Proposed Architecture (With Encryption)

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

## Integration Points

### 1. Update `OrbitDBWebAuthnIdentityProvider` Constructor

```javascript
export class OrbitDBWebAuthnIdentityProvider {
  constructor({ 
    webauthnCredential, 
    useKeystoreDID = false, 
    keystore = null,
    // NEW: Enable encrypted keystore
    encryptKeystore = false,
    // NEW: WebAuthn extension to use (largeBlob or hmac-secret)
    keystoreEncryptionMethod = 'largeBlob'
  }) {
    this.credential = webauthnCredential;
    this.webauthnProvider = new WebAuthnDIDProvider(webauthnCredential);
    this.type = 'webauthn';
    this.useKeystoreDID = useKeystoreDID;
    this.keystore = keystore;
    
    // NEW: Encrypted keystore options
    this.encryptKeystore = encryptKeystore;
    this.keystoreEncryptionMethod = keystoreEncryptionMethod;
  }
}
```

### 2. Add Encryption/Decryption Methods

```javascript
/**
 * Generate and encrypt OrbitDB keystore using WebAuthn-protected secret
 */
async function createEncryptedKeystore(webauthnCredential, keystoreEncryptionMethod) {
  // 1. Generate Ed25519 keypair for OrbitDB
  const keypair = await generateEd25519Keypair();
  
  // 2. Generate random AES-GCM 256-bit secret key (SK)
  const sk = crypto.getRandomValues(new Uint8Array(32));
  
  // 3. Encrypt the OrbitDB private key with SK
  const { ciphertext, iv } = await encryptPrivateKey(keypair.privateKey, sk);
  
  // 4. Store SK in WebAuthn credential
  if (keystoreEncryptionMethod === 'largeBlob') {
    await storeSKInLargeBlob(webauthnCredential, sk);
  } else if (keystoreEncryptionMethod === 'hmac-secret') {
    await wrapSKWithHmacSecret(webauthnCredential, sk);
  }
  
  // 5. Store encrypted data locally
  await storeEncryptedKeystore({
    ciphertext,
    iv,
    credentialId: webauthnCredential.credentialId,
    publicKey: keypair.publicKey
  });
  
  return keypair.publicKey;
}

/**
 * Unlock encrypted keystore using WebAuthn authentication
 */
async function unlockEncryptedKeystore(webauthnCredential, keystoreEncryptionMethod) {
  // 1. Load encrypted keystore from IndexedDB
  const encrypted = await loadEncryptedKeystore(webauthnCredential.credentialId);
  
  // 2. Authenticate with WebAuthn to get SK
  let sk;
  if (keystoreEncryptionMethod === 'largeBlob') {
    sk = await retrieveSKFromLargeBlob(webauthnCredential);
  } else if (keystoreEncryptionMethod === 'hmac-secret') {
    sk = await unwrapSKWithHmacSecret(webauthnCredential);
  }
  
  // 3. Decrypt OrbitDB private key
  const privateKey = await decryptPrivateKey(encrypted.ciphertext, sk, encrypted.iv);
  
  // 4. Return decrypted keypair
  return {
    privateKey,
    publicKey: encrypted.publicKey
  };
}
```

### 3. Implement WebAuthn Extensions

#### Option A: largeBlob Extension

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
          write: sk  // Store SK in authenticator
        }
      }
    }
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
      allowCredentials: [{
        id: credential.rawCredentialId,
        type: 'public-key'
      }],
      extensions: {
        largeBlob: {
          read: true  // Request SK from authenticator
        }
      }
    }
  });
  
  return assertion.getClientExtensionResults().largeBlob.blob;
}
```

#### Option B: hmac-secret Extension

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
        hmacCreateSecret: true
      }
    }
  });
  
  // Derive wrapping key from HMAC
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{
        id: credentialWithHmac.rawId,
        type: 'public-key'
      }],
      extensions: {
        hmacGetSecret: {
          salt1: salt
        }
      }
    }
  });
  
  const hmacOutput = assertion.getClientExtensionResults().hmacGetSecret.output1;
  
  // Wrap SK with HMAC-derived key
  const wrappedSK = await wrapKey(sk, hmacOutput);
  
  // Store wrapped SK and salt locally
  await storeWrappedSK({ wrappedSK, salt, credentialId: credentialWithHmac.id });
  
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
      allowCredentials: [{
        id: credential.rawCredentialId,
        type: 'public-key'
      }],
      extensions: {
        hmacGetSecret: {
          salt1: salt
        }
      }
    }
  });
  
  const hmacOutput = assertion.getClientExtensionResults().hmacGetSecret.output1;
  
  // Unwrap SK with HMAC-derived key
  const sk = await unwrapKey(wrappedSK, hmacOutput);
  
  return sk;
}
```

### 4. AES-GCM Encryption Utilities

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

### 5. Update Identity Creation Flow

```javascript
static async createIdentity(options) {
  const { 
    webauthnCredential, 
    useKeystoreDID = false, 
    keystore = null,
    encryptKeystore = false,
    keystoreEncryptionMethod = 'largeBlob'
  } = options;

  identityLog('createIdentity() called with encryption: %s', encryptKeystore);

  // If encryption is enabled, create and encrypt keystore
  if (encryptKeystore) {
    identityLog('Creating encrypted keystore with method: %s', keystoreEncryptionMethod);
    
    // Create encrypted keystore
    const publicKey = await createEncryptedKeystore(
      webauthnCredential, 
      keystoreEncryptionMethod
    );
    
    // Unlock it immediately for this session
    const unlockedKeypair = await unlockEncryptedKeystore(
      webauthnCredential,
      keystoreEncryptionMethod
    );
    
    // Store unlocked keypair in session memory
    sessionStorage.unlockedKeypair = unlockedKeypair;
  }

  const provider = new OrbitDBWebAuthnIdentityProvider({ 
    webauthnCredential, 
    useKeystoreDID,
    keystore,
    encryptKeystore,
    keystoreEncryptionMethod
  });
  
  const id = await provider.getId();

  return {
    id,
    publicKey: webauthnCredential.publicKey,
    type: 'webauthn',
    sign: (identity, data) => {
      // Use unlocked keystore if encrypted
      if (encryptKeystore && sessionStorage.unlockedKeypair) {
        return signWithUnlockedKey(sessionStorage.unlockedKeypair, data);
      }
      return provider.signIdentity(data);
    },
    verify: (signature, data) => {
      return provider.verifyIdentity(signature, data, webauthnCredential.publicKey);
    }
  };
}
```

## Integration with Existing Ed25519 Keystore DID Feature

The encrypted keystore works **perfectly** with the Ed25519 DID feature we just implemented:

```javascript
// Use Ed25519 DID from ENCRYPTED keystore
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ 
    webauthnCredential: credential,
    useKeystoreDID: true,              // ✅ Use Ed25519 keystore DID
    keystore: orbitdb.keystore,
    encryptKeystore: true,             // ✅ NEW: Encrypt the keystore
    keystoreEncryptionMethod: 'largeBlob'  // ✅ NEW: Use WebAuthn largeBlob
  })
});
```

**Result:**
- ✅ Identity DID derived from Ed25519 keystore key
- ✅ Keystore private key encrypted with AES-GCM
- ✅ Encryption key (SK) protected by WebAuthn hardware
- ✅ One biometric prompt per session to unlock
- ✅ Database operations use decrypted key from memory

## Browser Support

### largeBlob Extension
- ✅ Chrome 106+
- ✅ Edge 106+
- ❌ Safari (not yet)
- ❌ Firefox (not yet)

### hmac-secret Extension
- ✅ Chrome (with CTAP2)
- ✅ Firefox (with CTAP2)
- ⚠️ Safari (limited)
- ✅ Edge (with CTAP2)

**Recommendation:** Start with `largeBlob` for Chrome/Edge, fallback to `hmac-secret` for broader support.

## Security Benefits

### Current Issues (Unencrypted)
- ❌ Keystore in plaintext in IndexedDB
- ❌ Vulnerable to XSS attacks
- ❌ Vulnerable to malicious extensions
- ❌ Vulnerable to device theft
- ❌ No protection if IndexedDB copied

### With Encryption
- ✅ Keystore encrypted at rest
- ✅ Protected from XSS (SK not in memory)
- ✅ Protected from extensions (SK in hardware)
- ✅ Protected from device theft (biometric required)
- ✅ IndexedDB theft useless (ciphertext only)
- ✅ One biometric prompt per session (good UX)

## Implementation Phases

### Phase 1: Core Encryption (Current Branch Extension)
- Implement AES-GCM encryption/decryption
- Add `encryptKeystore` flag
- Add largeBlob integration
- Add local storage for encrypted data

### Phase 2: Session Management
- Implement session keystore unlock
- Add session timeout handling
- Add keystore re-lock on timeout
- Add secure memory clearing

### Phase 3: Multi-Device Support
- Add passkey sync detection
- Handle multiple enrolled authenticators
- Implement recovery flows
- Add backup/restore mechanisms

### Phase 4: hmac-secret Fallback
- Implement hmac-secret extension
- Add automatic method detection
- Graceful degradation for unsupported browsers

## Compatibility with Existing Code

✅ **Fully backward compatible**

```javascript
// Existing code (no encryption) - still works
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ 
    webauthnCredential: credential
  })
});

// New code (with encryption) - opt-in
const identity = await orbitdb.identities.createIdentity({
  provider: OrbitDBWebAuthnIdentityProviderFunction({ 
    webauthnCredential: credential,
    encryptKeystore: true
  })
});
```

## Next Steps

1. **Extend current branch** with encryption implementation
2. **Add largeBlob support** to `WebAuthnDIDProvider.createCredential()`
3. **Implement encryption utilities** (AES-GCM)
4. **Add session management** for unlocked keystore
5. **Test with Chrome/Edge** (largeBlob support)
6. **Update documentation** with encryption options
7. **Add examples** showing encrypted keystore usage

## Conclusion

This solution:
- ✅ Directly addresses the keystore security vulnerability
- ✅ Integrates seamlessly with existing Ed25519 DID feature
- ✅ Maintains backward compatibility
- ✅ Uses standard WebAuthn extensions
- ✅ Provides excellent UX (one prompt per session)
- ✅ Achieves hardware-backed protection

**This is the natural next evolution of the architecture we've built.**

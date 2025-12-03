# PWA & Capacitor Keystore Encryption Strategies

## Executive Summary

This document outlines two practical approaches for securing the OrbitDB keystore in a cross-platform application:

1. **Option 1: Pure PWA** - Web Crypto API with WebAuthn-derived encryption (no native wrapper)
2. **Option 2: Capacitor Hybrid** - Progressive enhancement with OS Keychain on native platforms

Both approaches avoid centralized dependencies (like Lit Protocol) while providing strong security guarantees appropriate to each platform's capabilities.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Option 1: Pure PWA Approach](#option-1-pure-pwa-approach)
3. [Option 2: Capacitor Hybrid Approach](#option-2-capacitor-hybrid-approach)
4. [WebAuthn Signature Deep Dive](#webauthn-signature-deep-dive)
5. [Security Analysis](#security-analysis)
6. [Implementation Guide](#implementation-guide)
7. [Migration Path](#migration-path)
8. [Comparison Matrix](#comparison-matrix)

---

## Architecture Overview

### The Challenge

OrbitDB stores its keystore **unencrypted** at `./orbitdb/keystore/`:
- Browser: IndexedDB (via LevelDB)
- Node.js: Filesystem

**Security requirements:**
- ✅ Protect keystore from XSS attacks
- ✅ Protect from malicious browser extensions
- ✅ Enable biometric authentication where possible
- ✅ Work offline after initial setup
- ✅ No centralized dependencies

### Platform Capabilities

```
┌─────────────────────────────────────────────────────────┐
│ PWA (Browser/Mobile Web)                                │
│ • Web Crypto API (AES-256 encryption)                   │
│ • WebAuthn (biometric authentication)                   │
│ • IndexedDB (encrypted storage)                         │
│ • Offline-capable                                       │
│ ❌ No OS Keychain access                                │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ Capacitor Native (iOS/Android)                          │
│ • iOS Keychain (Secure Enclave)                         │
│ • Android Keystore (TEE/hardware)                       │
│ • Native biometric APIs                                 │
│ • Hardware-backed encryption                            │
│ ✅ OS-level security                                     │
└─────────────────────────────────────────────────────────┘
```

---

## Option 1: Pure PWA Approach

### Architecture

```
User Authentication (WebAuthn)
         ↓
   Sign Challenge
         ↓
   Derive AES Key from Signature
         ↓
   Encrypt OrbitDB Keystore
         ↓
   Store in IndexedDB (encrypted)
         ↓
   Cached in Memory During Session
```

### Key Derivation Strategy

**Challenge: WebAuthn signatures are PUBLIC**

WebAuthn signatures can be observed by:
- Network sniffers (if sent to server)
- Browser extensions
- JavaScript code on the page

**Solution: Use deterministic challenge + key stretching**

```javascript
// What we sign: A deterministic challenge unique to this keystore
const KEYSTORE_DERIVATION_CHALLENGE = 'orbitdb-keystore-encryption-v1';

// The signature is deterministic for the same challenge
const signature = await webauthn.sign(KEYSTORE_DERIVATION_CHALLENGE);

// Apply key stretching to make rainbow table attacks harder
const encryptionKey = await deriveKeyWithPBKDF2(signature, iterations=100000);
```

### WebAuthn Signature Contents

**What gets signed:**

```javascript
// WebAuthn creates a signature over:
{
  challenge: Uint8Array,           // Your deterministic value
  origin: "https://yourapp.com",   // Browser origin
  rpId: "yourapp.com",             // Relying Party ID
  flags: {
    userPresent: true,             // User confirmed action
    userVerified: true,            // Biometric verified
  },
  counter: 42,                     // Signature counter (prevents replay)
  clientDataJSON: "...",           // JSON of above data
}

// Signature is created by:
signature = privateKey.sign(authenticatorData + hash(clientDataJSON))
```

**Key properties:**
1. **Deterministic** - Same challenge → Same signature (for given credential)
2. **Unique per credential** - Different WebAuthn keys = different signatures
3. **Cannot be forged** - Private key never leaves device
4. **User presence required** - Biometric/PIN needed each time

### Implementation

```javascript
// pwa-keystore-manager.js
import { logger } from '@libp2p/logger';

const log = logger('orbitdb-webauthn:pwa-keystore');

export class PWAKeystoreManager {
  constructor() {
    this.DERIVATION_CHALLENGE = new TextEncoder().encode(
      'orbitdb-keystore-encryption-v1'
    );
    this.encryptedKeystoreCache = null;
    this.decryptedKeystore = null;
  }

  // ═══════════════════════════════════════════════════════════
  // ENCRYPTION KEY DERIVATION
  // ═══════════════════════════════════════════════════════════

  /**
   * Derives an AES-256 encryption key from WebAuthn signature
   * 
   * @param {PublicKeyCredential} credential - WebAuthn credential
   * @returns {Promise<CryptoKey>} AES-256 encryption key
   */
  async deriveEncryptionKey(credential) {
    log('🔑 Deriving encryption key from WebAuthn signature...');

    // 1. Get WebAuthn signature over deterministic challenge
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: this.DERIVATION_CHALLENGE,
        rpId: window.location.hostname,
        allowCredentials: [{
          id: credential.rawId,
          type: 'public-key',
        }],
        userVerification: 'required', // Force biometric
        timeout: 60000,
      },
    });

    log('✅ WebAuthn signature obtained');

    // 2. Extract signature bytes
    const signatureBytes = new Uint8Array(assertion.response.signature);
    
    // IMPORTANT: Signatures are not secret!
    // We use PBKDF2 to make brute-force attacks harder
    
    // 3. Import signature as base key material
    const baseKeyMaterial = await crypto.subtle.importKey(
      'raw',
      signatureBytes,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    // 4. Derive AES-256 key with key stretching
    // Use credential ID as salt (deterministic but unique per credential)
    const salt = new Uint8Array(credential.rawId);
    
    const encryptionKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000, // Key stretching (protects against rainbow tables)
        hash: 'SHA-256',
      },
      baseKeyMaterial,
      { name: 'AES-GCM', length: 256 },
      false, // Non-extractable
      ['encrypt', 'decrypt']
    );

    log('✅ AES-256 encryption key derived');

    return encryptionKey;
  }

  // ═══════════════════════════════════════════════════════════
  // KEYSTORE ENCRYPTION
  // ═══════════════════════════════════════════════════════════

  /**
   * Encrypts OrbitDB keystore with WebAuthn-derived key
   * 
   * @param {Object} keystoreData - OrbitDB keystore to encrypt
   * @param {PublicKeyCredential} credential - WebAuthn credential
   */
  async encryptKeystore(keystoreData, credential) {
    log('🔐 Encrypting OrbitDB keystore...');

    // 1. Derive encryption key
    const encryptionKey = await this.deriveEncryptionKey(credential);

    // 2. Generate random IV (Initialization Vector)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 3. Encrypt keystore data
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(JSON.stringify(keystoreData));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      encryptionKey,
      plaintextBytes
    );

    log('✅ Keystore encrypted');

    // 4. Prepare storage object
    const encryptedData = {
      version: 1,
      credentialId: Array.from(new Uint8Array(credential.rawId)),
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(ciphertext)),
      timestamp: Date.now(),
    };

    // 5. Store encrypted keystore in IndexedDB
    await this.saveToIndexedDB('orbitdb-encrypted-keystore', encryptedData);

    log('✅ Encrypted keystore stored in IndexedDB');

    this.encryptedKeystoreCache = encryptedData;

    return encryptedData;
  }

  /**
   * Decrypts OrbitDB keystore with WebAuthn authentication
   * 
   * @param {PublicKeyCredential} credential - WebAuthn credential
   * @returns {Promise<Object>} Decrypted keystore data
   */
  async decryptKeystore(credential) {
    log('🔓 Decrypting OrbitDB keystore...');

    // 1. Load encrypted keystore
    const encryptedData = this.encryptedKeystoreCache || 
      await this.loadFromIndexedDB('orbitdb-encrypted-keystore');

    if (!encryptedData) {
      throw new Error('No encrypted keystore found');
    }

    // 2. Derive decryption key (requires biometric!)
    const decryptionKey = await this.deriveEncryptionKey(credential);

    // 3. Decrypt keystore
    const iv = new Uint8Array(encryptedData.iv);
    const ciphertext = new Uint8Array(encryptedData.ciphertext);

    const plaintextBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      decryptionKey,
      ciphertext
    );

    const decoder = new TextDecoder();
    const keystoreData = JSON.parse(decoder.decode(plaintextBytes));

    log('✅ Keystore decrypted');

    return keystoreData;
  }

  // ═══════════════════════════════════════════════════════════
  // SESSION MANAGEMENT
  // ═══════════════════════════════════════════════════════════

  /**
   * Starts a session with decrypted keystore in memory
   * 
   * @param {PublicKeyCredential} credential - WebAuthn credential
   * @returns {Promise<Object>} Decrypted keystore (in memory only)
   */
  async startSession(credential) {
    log('🚀 Starting session...');

    // Decrypt keystore (requires biometric)
    this.decryptedKeystore = await this.decryptKeystore(credential);

    // Set session timeout (30 minutes)
    this.sessionTimeoutId = setTimeout(() => {
      this.endSession();
    }, 30 * 60 * 1000);

    log('✅ Session started (keystore in memory)');

    return this.decryptedKeystore;
  }

  /**
   * Ends session and clears keystore from memory
   */
  async endSession() {
    log('🔒 Ending session...');

    // Clear keystore from memory
    if (this.decryptedKeystore) {
      // Overwrite sensitive data
      Object.keys(this.decryptedKeystore).forEach(key => {
        delete this.decryptedKeystore[key];
      });
      this.decryptedKeystore = null;
    }

    // Clear timeout
    if (this.sessionTimeoutId) {
      clearTimeout(this.sessionTimeoutId);
      this.sessionTimeoutId = null;
    }

    log('✅ Session ended (keystore cleared from memory)');
  }

  /**
   * Gets current decrypted keystore (if session active)
   */
  getKeystore() {
    if (!this.decryptedKeystore) {
      throw new Error('No active session. Call startSession() first.');
    }
    return this.decryptedKeystore;
  }

  // ═══════════════════════════════════════════════════════════
  // INDEXEDDB HELPERS
  // ═══════════════════════════════════════════════════════════

  async saveToIndexedDB(key, value) {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('OrbitDBSecureStorage', 1);

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('keystore')) {
          db.createObjectStore('keystore');
        }
      };

      request.onsuccess = (event) => {
        const db = event.target.result;
        const transaction = db.transaction(['keystore'], 'readwrite');
        const store = transaction.objectStore('keystore');
        store.put(value, key);

        transaction.oncomplete = () => {
          db.close();
          resolve();
        };

        transaction.onerror = () => {
          db.close();
          reject(transaction.error);
        };
      };

      request.onerror = () => reject(request.error);
    });
  }

  async loadFromIndexedDB(key) {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('OrbitDBSecureStorage', 1);

      request.onsuccess = (event) => {
        const db = event.target.result;
        const transaction = db.transaction(['keystore'], 'readonly');
        const store = transaction.objectStore('keystore');
        const getRequest = store.get(key);

        getRequest.onsuccess = () => {
          db.close();
          resolve(getRequest.result);
        };

        getRequest.onerror = () => {
          db.close();
          reject(getRequest.error);
        };
      };

      request.onerror = () => reject(request.error);
    });
  }
}
```

### Usage Example

```javascript
import { PWAKeystoreManager } from './pwa-keystore-manager.js';
import { createOrbitDB, KeyStore } from '@orbitdb/core';

// ═══════════════════════════════════════════════════════════
// SETUP: First Time User
// ═══════════════════════════════════════════════════════════

const manager = new PWAKeystoreManager();

// 1. Register WebAuthn credential (with biometric)
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: 'OrbitDB App', id: window.location.hostname },
    user: {
      id: crypto.getRandomValues(new Uint8Array(16)),
      name: 'user@example.com',
      displayName: 'User',
    },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
    },
  },
});

console.log('✅ WebAuthn credential registered');

// 2. Create OrbitDB keystore
const tempKeystore = await KeyStore({ path: './temp-keystore' });
await tempKeystore.createKey('user-identity');

// 3. Export keystore data
const keystoreData = {
  // Export implementation depends on KeyStore internals
  keys: {}, // ... exported keys
};

// 4. Encrypt and store keystore
await manager.encryptKeystore(keystoreData, credential);

console.log('✅ Setup complete - keystore encrypted');

// ═══════════════════════════════════════════════════════════
// SESSION: Returning User
// ═══════════════════════════════════════════════════════════

// 1. Authenticate with WebAuthn (biometric prompt)
const authCredential = await navigator.credentials.get({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: window.location.hostname,
    userVerification: 'required',
  },
});

// 2. Start session (decrypts keystore into memory)
const keystoreData = await manager.startSession(authCredential);

// 3. Load keystore into OrbitDB
const keystore = await KeyStore({
  storage: createMemoryStorage(keystoreData),
});

// 4. Use OrbitDB normally (fast, no additional prompts)
const orbitdb = await createOrbitDB({ ipfs, identities, identity, keystore });
const db = await orbitdb.open('todos');

await db.put('todo-1', { text: 'Buy milk' });    // ✅ No prompt
await db.put('todo-2', { text: 'Walk dog' });    // ✅ No prompt
await db.put('todo-3', { text: 'Call mom' });    // ✅ No prompt

// 5. End session when done
await manager.endSession();
console.log('✅ Session ended, keystore cleared from memory');
```

---

## Option 2: Capacitor Hybrid Approach

### Architecture

```
Platform Detection
         ↓
    ┌─────────┴─────────┐
    ↓                   ↓
Native Platform     Web Platform
    ↓                   ↓
OS Keychain        Web Crypto
(Secure Enclave)    (IndexedDB)
    ↓                   ↓
Hardware-backed    Software-backed
Encryption         Encryption
```

### Setup

```bash
# Install Capacitor
npm install @capacitor/core @capacitor/cli
npx cap init

# Add platforms
npx cap add ios
npx cap add android

# Install secure storage plugin
npm install @aparajita/capacitor-secure-storage
```

### Implementation

```javascript
// hybrid-keystore-manager.js
import { Capacitor } from '@capacitor/core';
import { SecureStorage } from '@aparajita/capacitor-secure-storage';
import { PWAKeystoreManager } from './pwa-keystore-manager.js';
import { logger } from '@libp2p/logger';

const log = logger('orbitdb-webauthn:hybrid-keystore');

export class HybridKeystoreManager {
  constructor() {
    this.isNative = Capacitor.isNativePlatform();
    this.pwaManager = new PWAKeystoreManager();
    
    log(`Platform: ${this.isNative ? 'Native' : 'Web'}`);
  }

  // ═══════════════════════════════════════════════════════════
  // PLATFORM-AWARE STORAGE
  // ═══════════════════════════════════════════════════════════

  /**
   * Encrypts and stores keystore (platform-aware)
   * 
   * @param {Object} keystoreData - OrbitDB keystore to encrypt
   * @param {PublicKeyCredential} credential - WebAuthn credential (web only)
   */
  async encryptKeystore(keystoreData, credential = null) {
    if (this.isNative) {
      return await this.encryptKeystoreNative(keystoreData);
    } else {
      if (!credential) {
        throw new Error('WebAuthn credential required for web platform');
      }
      return await this.pwaManager.encryptKeystore(keystoreData, credential);
    }
  }

  /**
   * Decrypts keystore (platform-aware)
   * 
   * @param {PublicKeyCredential} credential - WebAuthn credential (web only)
   * @returns {Promise<Object>} Decrypted keystore data
   */
  async decryptKeystore(credential = null) {
    if (this.isNative) {
      return await this.decryptKeystoreNative();
    } else {
      if (!credential) {
        throw new Error('WebAuthn credential required for web platform');
      }
      return await this.pwaManager.decryptKeystore(credential);
    }
  }

  // ═══════════════════════════════════════════════════════════
  // NATIVE PLATFORM (iOS/Android)
  // ═══════════════════════════════════════════════════════════

  /**
   * Stores keystore in native OS Keychain
   * 
   * Uses:
   * - iOS: Secure Enclave (hardware-backed)
   * - Android: Keystore (TEE/hardware)
   * 
   * @param {Object} keystoreData - OrbitDB keystore
   */
  async encryptKeystoreNative(keystoreData) {
    log('🔐 Storing keystore in native OS Keychain...');

    try {
      await SecureStorage.set({
        key: 'orbitdb-keystore',
        value: JSON.stringify(keystoreData),
      });

      log('✅ Keystore stored in OS Keychain (hardware-backed)');

      return {
        platform: 'native',
        storage: Capacitor.getPlatform(), // 'ios' or 'android'
        encrypted: true,
        hardwareBacked: true,
      };
    } catch (error) {
      log('❌ Failed to store in OS Keychain:', error);
      throw error;
    }
  }

  /**
   * Retrieves keystore from native OS Keychain
   * 
   * Requires biometric authentication (enforced by OS)
   * 
   * @returns {Promise<Object>} Decrypted keystore data
   */
  async decryptKeystoreNative() {
    log('🔓 Retrieving keystore from OS Keychain...');

    try {
      const result = await SecureStorage.get({
        key: 'orbitdb-keystore',
      });

      log('✅ Keystore retrieved from OS Keychain');

      return JSON.parse(result.value);
    } catch (error) {
      if (error.message.includes('NotFound')) {
        log('⚠️ No keystore found in OS Keychain');
        return null;
      }
      log('❌ Failed to retrieve from OS Keychain:', error);
      throw error;
    }
  }

  // ═══════════════════════════════════════════════════════════
  // SESSION MANAGEMENT (Unified)
  // ═══════════════════════════════════════════════════════════

  /**
   * Starts a session with decrypted keystore
   * 
   * @param {PublicKeyCredential} credential - WebAuthn credential (web only)
   * @returns {Promise<Object>} Decrypted keystore (in memory)
   */
  async startSession(credential = null) {
    log('🚀 Starting session...');

    if (this.isNative) {
      // Native: OS Keychain (biometric enforced by OS)
      this.decryptedKeystore = await this.decryptKeystoreNative();
    } else {
      // Web: PWA manager (WebAuthn biometric)
      this.decryptedKeystore = await this.pwaManager.startSession(credential);
    }

    log('✅ Session started');

    return this.decryptedKeystore;
  }

  /**
   * Ends session and clears keystore from memory
   */
  async endSession() {
    log('🔒 Ending session...');

    if (this.isNative) {
      // Clear from memory
      if (this.decryptedKeystore) {
        Object.keys(this.decryptedKeystore).forEach(key => {
          delete this.decryptedKeystore[key];
        });
        this.decryptedKeystore = null;
      }
    } else {
      // Use PWA manager's session end
      await this.pwaManager.endSession();
    }

    log('✅ Session ended');
  }

  /**
   * Gets current platform information
   */
  getPlatformInfo() {
    return {
      isNative: this.isNative,
      platform: Capacitor.getPlatform(),
      storage: this.isNative ? 'os-keychain' : 'indexeddb-encrypted',
      hardwareBacked: this.isNative,
    };
  }
}
```

### Platform-Specific Configuration

#### iOS (Capacitor)

```json
// ios/App/App/Info.plist
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access your OrbitDB keystore</string>

<key>NSBiometricAuthenticationUsageDescription</key>
<string>Use biometric authentication to unlock your keystore</string>
```

#### Android (Capacitor)

```xml
<!-- android/app/src/main/AndroidManifest.xml -->
<manifest>
  <uses-permission android:name="android.permission.USE_BIOMETRIC" />
  <uses-permission android:name="android.permission.USE_FINGERPRINT" />
</manifest>
```

### Usage Example

```javascript
import { HybridKeystoreManager } from './hybrid-keystore-manager.js';

const manager = new HybridKeystoreManager();

// Check platform
const platformInfo = manager.getPlatformInfo();
console.log('Platform:', platformInfo);
// {
//   isNative: true,
//   platform: 'ios',
//   storage: 'os-keychain',
//   hardwareBacked: true
// }

// ═══════════════════════════════════════════════════════════
// NATIVE PLATFORM (iOS/Android)
// ═══════════════════════════════════════════════════════════

if (platformInfo.isNative) {
  // 1. Create and encrypt keystore (no WebAuthn needed!)
  const keystoreData = { /* ... */ };
  await manager.encryptKeystore(keystoreData);
  // ✅ Stored in Secure Enclave (iOS) / Keystore (Android)

  // 2. Start session (OS biometric prompt)
  const keystore = await manager.startSession();
  // 📱 Native biometric prompt appears
  // ✅ Keystore decrypted and loaded

  // 3. Use OrbitDB
  const orbitdb = await createOrbitDB({ /* ... */ keystore });
  // ✅ All operations work offline

  // 4. End session
  await manager.endSession();
}

// ═══════════════════════════════════════════════════════════
// WEB PLATFORM (Browser/PWA)
// ═══════════════════════════════════════════════════════════

if (!platformInfo.isNative) {
  // 1. Register WebAuthn credential
  const credential = await navigator.credentials.create({ /* ... */ });

  // 2. Encrypt keystore with WebAuthn
  const keystoreData = { /* ... */ };
  await manager.encryptKeystore(keystoreData, credential);
  // ✅ Encrypted and stored in IndexedDB

  // 3. Start session (WebAuthn prompt)
  const authCredential = await navigator.credentials.get({ /* ... */ });
  const keystore = await manager.startSession(authCredential);
  // 🖐️ Browser biometric prompt appears
  // ✅ Keystore decrypted and loaded

  // 4. Use OrbitDB
  const orbitdb = await createOrbitDB({ /* ... */ keystore });
  // ✅ All operations work offline

  // 5. End session
  await manager.endSession();
}
```

---

## WebAuthn Signature Deep Dive

### What Gets Signed

When you call `navigator.credentials.get()`, here's what happens:

```javascript
// 1. You provide a challenge
const challenge = new TextEncoder().encode('orbitdb-keystore-encryption-v1');

// 2. Browser collects authentication data
const authenticatorData = {
  rpIdHash: SHA256(window.location.hostname),     // "example.com"
  flags: {
    userPresent: true,        // User clicked/touched
    userVerified: true,       // Biometric verified
  },
  counter: 42,                // Signature counter (anti-replay)
};

// 3. Browser creates client data JSON
const clientDataJSON = {
  type: 'webauthn.get',
  challenge: base64url(challenge),
  origin: 'https://example.com',
  crossOrigin: false,
};

// 4. Private key signs concatenation
const dataToSign = authenticatorData + SHA256(clientDataJSON);
const signature = privateKey.sign(dataToSign);  // ECDSA P-256

// 5. Browser returns signature
return {
  signature: signature,              // The actual signature bytes
  authenticatorData: authenticatorData,
  clientDataJSON: JSON.stringify(clientDataJSON),
};
```

### Signature Properties

**1. Deterministic for Same Challenge**

```javascript
// Same credential + same challenge = same signature
const sig1 = await sign('orbitdb-keystore-encryption-v1');
const sig2 = await sign('orbitdb-keystore-encryption-v1');
// sig1 === sig2 ✅ (for ECDSA with deterministic nonce - RFC 6979)
```

**2. Unique per Credential**

```javascript
// Different WebAuthn credentials = different signatures
const credential1 = await createCredential('user1');
const credential2 = await createCredential('user2');

const sig1 = await sign(credential1, 'challenge');
const sig2 = await sign(credential2, 'challenge');
// sig1 !== sig2 ✅
```

**3. Includes Context**

```javascript
// Signature binds to:
- origin: "https://example.com"     // Can't be used on different domain
- rpId: "example.com"                 // Can't be used for different RP
- counter: incrementing value         // Prevents replay attacks
```

### Security Considerations

**✅ What's Safe:**

1. **Using signature for key derivation**
   ```javascript
   // Safe: Signature is deterministic for this user+device
   const encryptionKey = deriveKey(signature);
   const encrypted = encrypt(data, encryptionKey);
   ```

2. **Storing encrypted data publicly**
   ```javascript
   // Safe: Only user with WebAuthn credential can decrypt
   await ipfs.add(encryptedData);  // Public IPFS
   ```

**⚠️ What's Risky:**

1. **Using signature directly as key (without stretching)**
   ```javascript
   // Risky: Signature is only ~256 bits
   const key = signature.slice(0, 32);  // ❌ No key stretching
   const encrypted = encrypt(data, key);
   ```
   **Fix:** Use PBKDF2 with 100,000+ iterations

2. **Assuming signature is secret**
   ```javascript
   // Wrong assumption: Signatures are PUBLIC
   sendToServer(signature);  // ❌ Anyone can see this
   ```
   **Reality:** Signatures can be observed, use for key derivation only

3. **Not including origin/RP checks**
   ```javascript
   // Risky: Signature from evil.com could decrypt data
   const signature = await getSignatureFromAnywhere();  // ❌
   ```
   **Fix:** WebAuthn enforces origin/RP checks automatically

### Why This Works for Keystore Encryption

**The Security Model:**

```
User's Device
┌────────────────────────────────────┐
│ Secure Enclave / TPM               │
│ • WebAuthn private key (P-256)     │
│ • Signs challenge                  │
│ • Private key NEVER leaves         │
└────────────────────────────────────┘
         ↓ signature (public)
┌────────────────────────────────────┐
│ Key Derivation (PBKDF2)            │
│ • Input: signature + salt          │
│ • 100,000 iterations               │
│ • Output: AES-256 key              │
└────────────────────────────────────┘
         ↓ encryption key
┌────────────────────────────────────┐
│ Encrypted Keystore                 │
│ • Stored in IndexedDB               │
│ • Safe to expose publicly          │
│ • Can only be decrypted by user    │
└────────────────────────────────────┘
```

**Why it's secure:**

1. ✅ **Biometric required** - Can't get signature without user's finger/face
2. ✅ **Device-bound** - Private key in hardware, can't export
3. ✅ **Deterministic** - Same signature every time (for key derivation)
4. ✅ **Key stretching** - PBKDF2 makes brute-force impractical
5. ✅ **Origin-bound** - Signature tied to your domain

**What an attacker would need:**

To decrypt the keystore, an attacker needs:
1. Physical access to the device AND
2. User's biometric (fingerprint/face) OR device PIN AND
3. Access to the encrypted keystore data

Without all three, the keystore remains secure.

---

## Security Analysis

### Threat Model

| Threat | PWA Impact | Capacitor Native Impact |
|--------|-----------|------------------------|
| **XSS Attack** | 🟡 Medium - Can observe signatures | 🟢 Low - No web context |
| **Malicious Extension** | 🟡 Medium - Can read IndexedDB | 🟢 None - No extensions |
| **Physical Device Loss** | 🟢 Low - Requires biometric | 🟢 Low - Requires biometric |
| **Device Unlocked + Malware** | 🟡 Medium - IndexedDB accessible | 🟢 Low - OS-protected |
| **Cloud Backup Exposure** | 🟡 Medium - IndexedDB in backup | 🟡 Medium - Keychain in backup |
| **Network Eavesdropping** | 🟢 None - Offline operation | 🟢 None - Offline operation |

### Security Levels

**PWA (Web Crypto + WebAuthn):**
- 🟢 **Strong** against remote attacks (XSS, network)
- 🟡 **Medium** against local attacks (requires device access + biometric)
- ✅ Better than unencrypted
- ✅ Good enough for most use cases

**Capacitor Native (OS Keychain):**
- 🟢 **Very Strong** against remote attacks
- 🟢 **Strong** against local attacks (hardware-backed)
- ✅ Same security as banking apps
- ✅ Best available on mobile

### Attack Scenarios

#### Scenario 1: XSS Attack

**PWA:**
```javascript
// Malicious script injected on page
console.log(localStorage);  // Can read encrypted data
// But cannot decrypt without user's biometric
// ✅ Keystore remains secure
```

**Capacitor:**
```javascript
// XSS in web view
console.log(localStorage);  // Nothing sensitive here
// Keystore in OS Keychain, inaccessible from web context
// ✅ Keystore remains secure
```

#### Scenario 2: Physical Device Access

**PWA:**
```
Attacker has unlocked device
  ↓
Can open DevTools
  ↓
Can read IndexedDB (encrypted keystore)
  ↓
Cannot decrypt (no biometric)
  ✅ Keystore remains secure
```

**Capacitor:**
```
Attacker has unlocked device
  ↓
Can debug app
  ↓
Cannot access OS Keychain without biometric
  ✅ Keystore remains secure
```

#### Scenario 3: Malware on Device

**PWA:**
```
Malware running in browser
  ↓
Can inject script into page
  ↓
Can observe WebAuthn signatures (public)
  ↓
Cannot decrypt (PBKDF2 key stretching)
  🟡 Theoretically vulnerable with sufficient compute
```

**Capacitor:**
```
Malware on device
  ↓
Cannot access other app's Keychain data (OS sandboxing)
  ✅ Keystore remains secure
```

---

## Implementation Guide

### Step 1: Choose Your Approach

**Start with PWA if:**
- ✅ You want fastest time to market
- ✅ You don't need app store distribution
- ✅ Web-only deployment is acceptable
- ✅ Users have WebAuthn-capable browsers

**Start with Capacitor if:**
- ✅ You want native app experience
- ✅ You need maximum security
- ✅ App store distribution is desired
- ✅ You want OS Keychain access

**Use Hybrid (Recommended) if:**
- ✅ You want both web and native versions
- ✅ You want progressive enhancement
- ✅ You want to start PWA, add native later

### Step 2: Install Dependencies

#### PWA Only

```bash
# No additional dependencies needed
# Uses built-in Web Crypto API
```

#### Capacitor Hybrid

```bash
# Install Capacitor
npm install @capacitor/core @capacitor/cli

# Initialize
npx cap init

# Add platforms
npx cap add ios
npx cap add android

# Install secure storage
npm install @aparajita/capacitor-secure-storage

# Sync changes
npx cap sync
```

### Step 3: Integrate with OrbitDB

```javascript
// orbitdb-integration.js
import { createOrbitDB, KeyStore, Identities } from '@orbitdb/core';
import { HybridKeystoreManager } from './hybrid-keystore-manager.js';

export class SecureOrbitDB {
  constructor() {
    this.keystoreManager = new HybridKeystoreManager();
    this.orbitdb = null;
    this.session = null;
  }

  async initialize(ipfs, webauthnCredential = null) {
    // 1. Start secure session
    const keystoreData = await this.keystoreManager.startSession(
      webauthnCredential
    );

    // 2. Create KeyStore from decrypted data
    const keystore = await this.createKeystoreFromData(keystoreData);

    // 3. Create Identities with keystore
    const identities = await Identities({ ipfs, keystore });

    // 4. Create identity
    const identity = await identities.createIdentity({ id: 'user-id' });

    // 5. Create OrbitDB instance
    this.orbitdb = await createOrbitDB({
      ipfs,
      identities,
      identity,
      keystore,
    });

    this.session = { keystore, identities, identity };

    return this.orbitdb;
  }

  async createKeystoreFromData(keystoreData) {
    // Implementation depends on KeyStore internals
    // Create in-memory keystore from decrypted data
    return await KeyStore({
      storage: createMemoryStorage(keystoreData),
    });
  }

  async shutdown() {
    if (this.orbitdb) {
      await this.orbitdb.stop();
    }
    
    await this.keystoreManager.endSession();
  }
}

// Usage
const secureOrbitDB = new SecureOrbitDB();

// Web: requires WebAuthn credential
const credential = await navigator.credentials.get({ /* ... */ });
const orbitdb = await secureOrbitDB.initialize(ipfs, credential);

// Native: no credential needed (OS handles biometric)
const orbitdb = await secureOrbitDB.initialize(ipfs);

// Use OrbitDB
const db = await orbitdb.open('todos');
await db.put('todo-1', { text: 'Hello World' });

// Cleanup
await secureOrbitDB.shutdown();
```

---

## Migration Path

### Phase 1: PWA with Unencrypted Keystore (Current)

```javascript
// Current implementation
const keystore = await KeyStore({ path: './orbitdb/keystore' });
// ❌ Stored unencrypted in IndexedDB
```

### Phase 2: Add Encryption (PWA Manager)

```javascript
// Add PWA encryption
const manager = new PWAKeystoreManager();

// Detect existing unencrypted keystore
const existingKeystore = await loadUnencryptedKeystore();

if (existingKeystore) {
  console.log('⚠️ Migrating unencrypted keystore...');
  
  // Prompt user to set up WebAuthn
  const credential = await registerWebAuthn();
  
  // Encrypt existing keystore
  await manager.encryptKeystore(existingKeystore, credential);
  
  // Delete unencrypted version
  await deleteUnencryptedKeystore();
  
  console.log('✅ Migration complete');
}
```

### Phase 3: Add Native Support (Capacitor)

```javascript
// Upgrade to hybrid manager
const manager = new HybridKeystoreManager();

// Existing encrypted keystore (from PWA) still works on web
// New native installs use OS Keychain automatically

if (manager.isNative && hasEncryptedPWAKeystore()) {
  // Optional: Migrate PWA keystore to native
  const keystoreData = await manager.pwaManager.decryptKeystore(credential);
  await manager.encryptKeystoreNative(keystoreData);
  
  console.log('✅ Migrated to native OS Keychain');
}
```

---

## Comparison Matrix

| Feature | Pure PWA | Capacitor Hybrid |
|---------|----------|------------------|
| **Deployment** | Website only | App stores + Web |
| **Installation** | Add to Home Screen | Native app install |
| **Storage** | IndexedDB (encrypted) | OS Keychain + IndexedDB |
| **Encryption** | Web Crypto (AES-256) | Hardware + Web Crypto |
| **Biometric Auth** | WebAuthn | Native + WebAuthn |
| **Offline** | ✅ Yes | ✅ Yes |
| **Security Level** | 🟢 High | 🟢 Very High |
| **Development Complexity** | 🟢 Low | 🟡 Medium |
| **Maintenance** | 🟢 Single codebase | 🟡 Native + Web |
| **Updates** | Instant (web) | App store review |
| **Platform Support** | All modern browsers | iOS, Android, Web |
| **Native Features** | ❌ Limited | ✅ Full access |
| **App Store Presence** | ❌ No | ✅ Yes |
| **Cross-Device Sync** | Manual (IPFS backup) | Manual (IPFS backup) |

---

## Recommendations

### For Your OrbitDB Project

**Start with: Pure PWA (Option 1)**

**Reasons:**
1. ✅ Fastest time to market
2. ✅ Single codebase
3. ✅ No app store hassle
4. ✅ Instant updates
5. ✅ Good security (Web Crypto + WebAuthn)
6. ✅ Works offline
7. ✅ Easy to upgrade to Capacitor later

**When to Add Capacitor (Option 2):**
- User demand for native app
- Need for app store presence
- Want maximum security (OS Keychain)
- Building other native features

### Security Best Practices

**For PWA:**
1. ✅ Always use PBKDF2 with 100,000+ iterations
2. ✅ Use deterministic challenge for key derivation
3. ✅ Clear keystore from memory on session end
4. ✅ Implement session timeouts (30 minutes)
5. ✅ Store encrypted backups on IPFS

**For Capacitor:**
1. ✅ Let OS handle biometric authentication
2. ✅ Use `WHEN_UNLOCKED_THIS_DEVICE_ONLY` accessibility
3. ✅ Don't store sensitive data in web storage
4. ✅ Use native APIs for keystore access
5. ✅ Test on real devices (not just simulators)

---

## Conclusion

Both options provide strong security for OrbitDB keystore protection:

**Pure PWA:**
- ✅ Good security with Web Crypto + WebAuthn
- ✅ Simple implementation
- ✅ No native dependencies
- ✅ Perfect for web-first projects

**Capacitor Hybrid:**
- ✅ Maximum security with OS Keychain
- ✅ Native app experience
- ✅ Progressive enhancement
- ✅ Best of both worlds

**Recommended Path:**
1. Start with PWA (Option 1)
2. Ship fast, iterate
3. Add Capacitor (Option 2) when needed
4. Use hybrid manager for seamless transition

Both are vastly superior to unencrypted keystore storage and avoid centralized dependencies like Lit Protocol while maintaining offline capability.

---

## References

- Web Crypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
- WebAuthn Spec: https://www.w3.org/TR/webauthn-2/
- Capacitor: https://capacitorjs.com/
- Secure Storage Plugin: https://github.com/aparajita/capacitor-secure-storage
- OrbitDB KeyStore: `@orbitdb/core/src/key-store.js`
- Our WebAuthn DID Implementation: `src/index.js`

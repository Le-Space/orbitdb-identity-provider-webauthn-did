# Keystore Security Architecture: WebAuthn & OrbitDB

## Executive Summary

This document explains the security architecture of using WebAuthn with OrbitDB, the trade-offs between different keystore approaches, and why certain design decisions were made.

**Key Insight**: WebAuthn provides hardware-secured authentication, but OrbitDB requires fast, frequent signing operations. This creates a fundamental UX vs. security trade-off that must be carefully balanced.

## Table of Contents

1. [The Core Problem](#the-core-problem)
2. [WebAuthn Capabilities & Limitations](#webauthn-capabilities--limitations)
3. [Architecture Options](#architecture-options)
4. [Security Analysis](#security-analysis)
5. [Recommended Architecture](#recommended-architecture)
6. [Implementation Guide](#implementation-guide)
7. [Comparison with Other Systems](#comparison-with-other-systems)

---

## The Core Problem

### OrbitDB Keystore Storage Location

**Current Implementation:**

OrbitDB stores its keystore persistently using **LevelDB**:

- **Default path**: `./orbitdb/keystore/` (relative to the OrbitDB `directory` parameter)
- **Storage backend**: 
  - **Browser**: LevelDB uses IndexedDB internally (via the `level` npm package)
  - **Node.js**: LevelDB uses filesystem storage
- **Key format**: Keys are stored with prefix `private_<identity-id>`
- **Encryption**: Keys are stored **UNENCRYPTED** as raw bytes

**Code References:**
```javascript
// @orbitdb/core/src/key-store.js:106
const defaultPath = './keystore'

// @orbitdb/core/src/key-store.js:125
storage = storage || await ComposedStorage(
  await LRUStorage({ size: 1000 }), 
  await LevelStorage({ path: path || defaultPath })
)

// @orbitdb/core/src/orbitdb.js:52
keystore = await KeyStore({ path: pathJoin(directory, './keystore') })
// Results in: ./orbitdb/keystore/

// @orbitdb/core/src/key-store.js:193
await storage.put('private_' + id, privateKey)
```

**Security Status:**
- ❌ Keys stored **unencrypted** in IndexedDB (browser) or filesystem (Node.js)
- ❌ Vulnerable to XSS attacks (malicious scripts can read IndexedDB)
- ❌ Vulnerable to malicious browser extensions
- ❌ Vulnerable to physical access to device
- ❌ Keys lost **permanently** if browser data/IndexedDB cleared
- ❌ No backup/recovery mechanism by default
- ❌ Keys are raw secp256k1 private keys in memory during operations

**Why This Matters:**

The current architecture stores cryptographic keys with NO encryption layer, making them vulnerable to:
1. **Browser-based attacks**: Any script with IndexedDB access can steal keys
2. **Extension malware**: Browser extensions can read IndexedDB
3. **Physical access**: Anyone with device access can extract keys from IndexedDB
4. **Accidental loss**: Users clearing browser data lose keys permanently

**This document explores three architecture options to secure this vulnerable keystore.**

---

### OrbitDB's Requirement
OrbitDB signs **every database operation** to ensure:
- Data integrity
- Provable authorship
- Access control enforcement
- Tamper detection

For a typical session, this means:
- Adding 100 TODOs = 100 signatures
- Editing 50 entries = 50 signatures
- Deleting 20 items = 20 signatures
- **Total: 170+ signing operations per session**

### WebAuthn's Design
WebAuthn is designed for **authentication**, not continuous signing:
- Private key **never leaves** secure hardware
- Each signature requires **user interaction** (biometric/PIN)
- Optimized for **infrequent, high-value operations**

### The Conflict
```
OrbitDB needs: Fast, frequent, automatic signing
WebAuthn provides: Slow, prompted, secure signing

170 biometric prompts per session = Unusable UX
```

---

## WebAuthn Capabilities & Limitations

### What WebAuthn CAN Do ✅

1. **Hardware-Secured Authentication**
   - Private key stored in TPM/Secure Enclave
   - Resistant to extraction/cloning
   - Biometric or PIN verification

2. **Sign Challenges**
   - Can sign arbitrary data
   - Returns cryptographic proof
   - User must approve each signature

3. **Provide Public Key**
   - P-256 elliptic curve coordinates (x, y)
   - Safe to publish
   - Used for verification

### What WebAuthn CANNOT Do ❌

1. **Silent Signing**
   - Cannot sign without user interaction
   - Browser enforces user gesture requirement
   - No way to "pre-approve" signatures

2. **Key Extraction**
   - Cannot export private key
   - Cannot derive secrets from private key
   - Hardware-enforced isolation

3. **Deterministic Derivation**
   - Public key is public (not a secret)
   - Deriving keys from public data = insecure
   - No way to create deterministic private keys

---

## Architecture Options

### Option 1: Pure WebAuthn Signing (Hardware-Only)

```
Every db.put() → WebAuthn sign() → Biometric prompt → Entry signed
```

#### Flow
```javascript
async function addTodo(database, text) {
  // User clicks "Add TODO"
  await database.put(todoId, todo);
  // ↓
  // identity.sign() called
  // ↓
  // navigator.credentials.get() invoked
  // ↓
  // 🔐 BIOMETRIC PROMPT APPEARS 🔐
  // ↓
  // User authenticates
  // ↓
  // Entry signed and added
}
```

#### Characteristics

**Pros:**
- ✅ Maximum security - every entry hardware-signed
- ✅ Private key never in memory
- ✅ True end-to-end hardware security
- ✅ No key storage/encryption needed

**Cons:**
- ❌ **Biometric prompt for EVERY operation**
- ❌ Terrible UX (100+ prompts per session)
- ❌ Slow (500-2000ms per operation)
- ❌ User fatigue and frustration
- ❌ Unusable for real applications

**When to Use:**
- Legal document signing
- Financial transactions
- Infrequent, high-value operations
- User expects security friction

**Example Use Case:**
```javascript
// Signing a contract - acceptable UX
async function signContract(contractData) {
  // User expects to authenticate for this
  const signature = await webauthn.sign(contractData);
  return signature; // ✅ Worth the prompt
}
```

---

### Option 2: Separate Software Keystore (Two-Tier Security)

```
Session start → WebAuthn (ONCE) → Decrypt software keystore
Every db.put() → Software key signs → NO prompt
```

#### Architecture Diagram
```
┌─────────────────────────────────────────────────────────┐
│ IDENTITY LAYER (WebAuthn - Hardware)                    │
│  • Proves ownership of DID                              │
│  • Hardware-secured private key                         │
│  • Used at session establishment                        │
└─────────────────────────────────────────────────────────┘
                          ↓
              One biometric prompt per session
                          ↓
┌─────────────────────────────────────────────────────────┐
│ SESSION LAYER (WebAuthn Signature)                      │
│  • Sign known challenge                                 │
│  • Derive decryption key from signature                 │
│  • Unlock operational keystore                          │
└─────────────────────────────────────────────────────────┘
                          ↓
                   Keystore unlocked
                          ↓
┌─────────────────────────────────────────────────────────┐
│ OPERATIONS LAYER (P-256/Ed25519 - Software)            │
│  • Signs all database entries                           │
│  • Fast, no user interaction                            │
│  • Cached in memory during session                      │
│  • Cleared on logout/timeout                            │
└─────────────────────────────────────────────────────────┘
```

#### Flow
```javascript
// ═══════════════════════════════════════════════════════
// SESSION ESTABLISHMENT (Once per session)
// ═══════════════════════════════════════════════════════

async function establishSession(webauthnCredential) {
  console.log('🔐 Session establishment starting...');
  
  // 1. User provides WebAuthn credential
  const identity = await createWebAuthnIdentity(webauthnCredential);
  console.log('✅ WebAuthn identity created');
  
  // 2. Sign a known challenge to decrypt keystore
  const KEYSTORE_CHALLENGE = 'orbitdb-keystore-unlock-v1';
  console.log('🔐 Requesting WebAuthn signature...');
  
  // ** BIOMETRIC PROMPT HAPPENS HERE ** (ONLY ONCE!)
  const unlockSignature = await identity.sign(KEYSTORE_CHALLENGE);
  console.log('✅ Biometric authentication successful');
  
  // 3. Derive decryption key from WebAuthn signature
  const decryptionKey = await deriveKey(unlockSignature);
  
  // 4. Decrypt and load operational keystore
  const encryptedKeystore = await loadEncryptedKeystore();
  const p256Keystore = await decryptKeystore(encryptedKeystore, decryptionKey);
  console.log('✅ Operational keystore unlocked');
  
  // 5. Cache keystore in memory for session
  sessionStorage.keystore = p256Keystore;
  sessionStorage.expiresAt = Date.now() + (60 * 60 * 1000); // 1 hour
  
  console.log('✅ Session established - no more prompts needed!');
  
  return {
    identity,        // WebAuthn identity
    keystore: p256Keystore,  // Unlocked operational keystore
    orbitdb: await createOrbitDB({ identity, keystore: p256Keystore })
  };
}

// ═══════════════════════════════════════════════════════
// NORMAL OPERATIONS (Fast, no prompts)
// ═══════════════════════════════════════════════════════

async function addTodo(database, text) {
  // No WebAuthn involved - uses cached keystore
  await database.put(todoId, todo);
  // ↓
  // identity.sign() called
  // ↓
  // Uses P-256 keystore from memory
  // ↓
  // Signs in ~1ms (no prompt!)
  // ✅ Entry added
}

// Add 100 TODOs - NO additional prompts!
for (let i = 0; i < 100; i++) {
  await addTodo(db, `TODO ${i}`); // Fast, silent
}

// ═══════════════════════════════════════════════════════
// SESSION CLEANUP
// ═══════════════════════════════════════════════════════

function endSession() {
  // Clear keystore from memory
  delete sessionStorage.keystore;
  console.log('🔒 Session ended - keystore cleared');
}
```

#### Characteristics

**Pros:**
- ✅ **One biometric prompt per session**
- ✅ Fast operations (1-5ms per signature)
- ✅ Good UX - no friction during use
- ✅ WebAuthn secures session establishment
- ✅ Practical for real applications

**Cons:**
- ⚠️ Database entries signed with SOFTWARE key
- ⚠️ Keystore in memory during session
- ⚠️ If memory dumped, keystore exposed
- ⚠️ Not pure hardware security

**Security Model:**
```
Identity: Hardware-secured (WebAuthn proves "this is me")
Session: Hardware-secured (WebAuthn unlocks keystore)
Operations: Software-secured (P-256 signs entries)

Risk Window: During active session (keystore in RAM)
Mitigation: Session timeout, secure memory handling
```

**When to Use:**
- ✅ Collaborative editing
- ✅ Chat applications
- ✅ TODO/note apps
- ✅ Any high-frequency operations
- ✅ Normal web applications

---

### Option 3: Hybrid - Session Keys with Rotation

```
Session start → WebAuthn → Generate ephemeral session key
Every db.put() → Session key signs → NO prompt
Session expires (e.g., 1 hour) → Need new WebAuthn auth
```

#### Flow
```javascript
async function establishSession(webauthnCredential) {
  // 1. Authenticate with WebAuthn (ONE prompt)
  const identity = await createWebAuthnIdentity(webauthnCredential);
  const unlockSig = await identity.sign('session-' + Date.now());
  
  // 2. Generate ephemeral P-256 key pair (random, not stored)
  const sessionKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // Non-extractable - can't be exported
    ['sign', 'verify']
  );
  
  // 3. Create session certificate signed by WebAuthn identity
  const sessionCertificate = await identity.sign({
    sessionPublicKey: await exportPublicKey(sessionKeyPair.publicKey),
    validFrom: Date.now(),
    validUntil: Date.now() + (60 * 60 * 1000), // 1 hour
  });
  
  // 4. Use session key for all operations
  sessionStorage.ephemeralKey = sessionKeyPair;
  sessionStorage.certificate = sessionCertificate;
  
  return sessionKeyPair;
}

// Operations use ephemeral key (fast, no prompts)
// After timeout: session key expired, need new WebAuthn auth
```

#### Characteristics

**Pros:**
- ✅ One prompt per session
- ✅ Time-limited exposure
- ✅ Session key can't be backed up/stolen
- ✅ Non-extractable crypto keys

**Cons:**
- ⚠️ Still software key during session
- ⚠️ Adds complexity (session management)
- ⚠️ Requires certificate verification
- ⚠️ Need to handle session expiry UX

---

## Security Analysis

### Attack Scenarios & Mitigations

#### Scenario 1: Attacker Steals Encrypted Keystore
```
Attacker action: Downloads encrypted keystore from browser storage
Risk: None - keystore is encrypted
Requirement: Need WebAuthn signature to decrypt
Mitigation: ✅ Encryption key derived from WebAuthn signature
```

#### Scenario 2: Memory Dump During Session
```
Attacker action: Dumps process memory while session active
Risk: High - P-256 keystore in plaintext memory
Impact: Can sign entries until session ends
Mitigation: 
  - ⚠️ Session timeout (limit exposure window)
  - ⚠️ Secure memory handling (OS-dependent)
  - ⚠️ Detect debugging/memory access attempts
```

#### Scenario 3: XSS Attack
```
Attacker action: Injects malicious JavaScript
Risk: Critical - Can call sessionStorage.keystore
Impact: Full access to keystore during session
Mitigation:
  - ✅ CSP headers (prevent script injection)
  - ✅ Input sanitization
  - ✅ SameSite cookies
  - ⚠️ Cannot fully prevent if XSS succeeds
```

#### Scenario 4: Derive Keys from Public Data
```
Attacker action: Attempts to derive keystore from WebAuthn public key
Risk: None - mathematically impossible
Mitigation: ✅ Public key cryptography is secure
```

#### Scenario 5: Phishing WebAuthn Credential
```
Attacker action: Tricks user to authenticate on fake site
Risk: Limited - WebAuthn checks origin
Mitigation: ✅ WebAuthn origin binding (automatic)
Note: Even if phished, attacker only gets ONE signature, not keystore
```

### Threat Model Summary

| Threat | Pure WebAuthn (Option 1) | Software Keystore (Option 2) |
|--------|-------------------------|------------------------------|
| Encrypted storage theft | ✅ N/A | ✅ Encrypted |
| Memory dump | ✅ No key in memory | ⚠️ Key in memory during session |
| XSS attack | ✅ Limited (per-operation) | ⚠️ Full session access |
| Key derivation attack | ✅ Impossible | ✅ Impossible |
| Phishing | ✅ One signature only | ⚠️ Can unlock session |
| User fatigue | ❌ 100+ prompts | ✅ One prompt |
| Usability | ❌ Unusable | ✅ Excellent |

---

## Recommended Architecture

### For OrbitDB Applications: **Option 2 (Separate Software Keystore)**

This provides the best balance of security and usability for applications requiring frequent operations.

### Implementation Strategy

```
1. WebAuthn Identity Layer (Hardware)
   └─> Proves ownership of DID
   └─> Used to establish session

2. Encrypted Keystore Storage
   └─> P-256 operational keys
   └─> Encrypted at rest
   └─> Decrypted with WebAuthn signature

3. Session Management
   └─> One unlock per session
   └─> Timeout after inactivity
   └─> Clear on logout

4. Backup & Recovery
   └─> Export encrypted keystore
   └─> Require password or second WebAuthn device
   └─> Support multi-device sync
```

---

## Implementation Guide

### Phase 1: Generate Operational Keystore

```javascript
/**
 * Generate a P-256 keystore for signing OrbitDB entries
 */
async function generateOperationalKeystore() {
  // Generate P-256 key pair
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true, // Extractable (for backup)
    ['sign', 'verify']
  );
  
  // Export for storage
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  
  return {
    privateKey: privateKeyJwk,
    publicKey: publicKeyJwk,
    created: Date.now(),
    id: await generateKeyId(publicKeyJwk)
  };
}
```

### Phase 2: Encrypt Keystore with WebAuthn

```javascript
/**
 * Encrypt keystore using WebAuthn signature as key
 */
async function encryptKeystore(keystore, webauthnIdentity) {
  // 1. Sign a known challenge with WebAuthn
  const ENCRYPTION_CHALLENGE = 'orbitdb-keystore-encryption-v1';
  const webauthnSignature = await webauthnIdentity.sign(ENCRYPTION_CHALLENGE);
  
  // 2. Derive AES key from WebAuthn signature
  const aesKey = await deriveAESKey(webauthnSignature);
  
  // 3. Encrypt keystore
  const keystoreBytes = new TextEncoder().encode(JSON.stringify(keystore));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    keystoreBytes
  );
  
  // 4. Store encrypted keystore + IV
  return {
    ciphertext: new Uint8Array(encrypted),
    iv,
    algorithm: 'AES-GCM',
    challenge: ENCRYPTION_CHALLENGE
  };
}

/**
 * Decrypt keystore using WebAuthn signature
 */
async function decryptKeystore(encryptedKeystore, webauthnIdentity) {
  // 1. Get WebAuthn signature (BIOMETRIC PROMPT)
  const webauthnSignature = await webauthnIdentity.sign(
    encryptedKeystore.challenge
  );
  
  // 2. Derive same AES key
  const aesKey = await deriveAESKey(webauthnSignature);
  
  // 3. Decrypt
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: encryptedKeystore.iv },
    aesKey,
    encryptedKeystore.ciphertext
  );
  
  // 4. Parse and return keystore
  const keystoreJson = new TextDecoder().decode(decrypted);
  return JSON.parse(keystoreJson);
}

/**
 * Derive AES key from WebAuthn signature
 */
async function deriveAESKey(webauthnSignature) {
  // Extract signature bytes from WebAuthn proof
  const sigBytes = extractSignatureBytes(webauthnSignature);
  
  // Hash to create AES key material
  const keyMaterial = await crypto.subtle.digest('SHA-256', sigBytes);
  
  // Import as AES key
  return await crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}
```

### Phase 3: Session Management

```javascript
/**
 * Session manager for operational keystore
 */
class KeystoreSession {
  constructor() {
    this.keystore = null;
    this.expiresAt = null;
    this.timeout = 60 * 60 * 1000; // 1 hour
  }
  
  async establish(webauthnIdentity) {
    // Load encrypted keystore from storage
    const encrypted = await this.loadEncrypted();
    
    // Decrypt with WebAuthn (ONE BIOMETRIC PROMPT)
    this.keystore = await decryptKeystore(encrypted, webauthnIdentity);
    
    // Set expiration
    this.expiresAt = Date.now() + this.timeout;
    
    // Auto-cleanup on expiry
    setTimeout(() => this.end(), this.timeout);
    
    console.log('✅ Session established - keystore unlocked');
  }
  
  isActive() {
    return this.keystore !== null && Date.now() < this.expiresAt;
  }
  
  async sign(data) {
    if (!this.isActive()) {
      throw new Error('Session expired - re-authentication required');
    }
    
    // Sign with cached keystore (FAST, NO PROMPT)
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      this.keystore.privateKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      typeof data === 'string' ? new TextEncoder().encode(data) : data
    );
    
    return new Uint8Array(signature);
  }
  
  end() {
    // Clear keystore from memory
    this.keystore = null;
    this.expiresAt = null;
    console.log('🔒 Session ended - keystore cleared');
  }
  
  async loadEncrypted() {
    // Load from IndexedDB or localStorage
    const stored = localStorage.getItem('encrypted-keystore');
    return stored ? JSON.parse(stored) : null;
  }
}
```

### Phase 4: OrbitDB Integration

```javascript
/**
 * Create OrbitDB instance with session-based keystore
 */
async function createOrbitDBWithSession(webauthnCredential) {
  // 1. Create WebAuthn identity
  registerWebAuthnProvider();
  const identities = await Identities();
  const identity = await identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential
    })
  });
  
  // 2. Establish keystore session (ONE PROMPT)
  const session = new KeystoreSession();
  await session.establish(identity);
  
  // 3. Create custom identity that uses session keystore
  const sessionIdentity = {
    ...identity,
    sign: async (data) => {
      // Use session keystore instead of WebAuthn
      return session.sign(data);
    }
  };
  
  // 4. Create OrbitDB with session identity
  const ipfs = await createHelia();
  const orbitdb = await createOrbitDB({
    ipfs,
    identities,
    identity: sessionIdentity
  });
  
  return {
    orbitdb,
    identity: sessionIdentity,
    session
  };
}

// Usage
const { orbitdb, session } = await createOrbitDBWithSession(credential);

// Open database
const db = await orbitdb.open('my-database');

// Add entries - NO MORE PROMPTS!
await db.put('key1', 'value1'); // Fast
await db.put('key2', 'value2'); // Fast
await db.put('key3', 'value3'); // Fast

// After 1 hour or on logout
session.end();
```

---

## Comparison with Other Systems

### Signal/WhatsApp
- **Approach**: One unlock per session
- **Storage**: Encrypted message history
- **Signing**: Software keys for messages
- **Session**: Persists until explicit logout

### Password Managers (1Password, Bitwarden)
- **Approach**: One master password/biometric
- **Storage**: Encrypted vault
- **Decryption**: Unlocks entire vault to memory
- **Session**: Timeout after inactivity

### Ethereum Wallets (MetaMask)
- **Approach**: Prompt for EVERY transaction
- **Reasoning**: Financial value justifies friction
- **User Expectation**: Security > UX
- **Frequency**: Low (few transactions per day)

### Email Clients (Gmail, Outlook)
- **Approach**: OAuth token per session
- **Storage**: Token in memory
- **Refresh**: Silent refresh until revoked
- **Session**: Days/weeks without re-auth

### OrbitDB (This Implementation)
- **Approach**: Hybrid (WebAuthn + session keystore)
- **Storage**: Encrypted operational keystore
- **Signing**: P-256 session key
- **Session**: 1 hour timeout (configurable)
- **Balance**: Security + UX for collaborative apps

---

## Conclusion

### Key Takeaways

1. **Pure WebAuthn signing is impractical** for high-frequency operations like OrbitDB
2. **Separate software keystore** provides best balance of security and UX
3. **Session-based approach** matches user expectations from other apps
4. **Encryption with WebAuthn signature** maintains hardware security for session establishment
5. **Clear session boundaries** (timeout/logout) limit exposure window

### Security Recommendations

✅ **DO:**
- Use WebAuthn for session establishment
- Encrypt keystore with WebAuthn-derived key
- Implement session timeouts
- Clear keystore from memory on logout
- Provide backup/export functionality
- Use CSP and input sanitization

❌ **DON'T:**
- Derive keystore from public WebAuthn key (insecure!)
- Store unencrypted keystore
- Keep sessions active indefinitely
- Ignore XSS prevention
- Prompt user for every operation

### Future Enhancements

1. **Multi-device sync**: Encrypted keystore sync across devices
2. **Key rotation**: Periodic rotation of operational keys
3. **Hardware session keys**: Use WebCrypto non-extractable keys
4. **Biometric re-prompt**: Optional re-auth for sensitive operations
5. **Audit logging**: Track all signing operations

---

## References

- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [OrbitDB Documentation](https://orbitdb.org)
- [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
- [NIST P-256 (secp256r1)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)

---

**Document Version**: 1.0  
**Last Updated**: 2025-12-03  
**Authors**: OrbitDB WebAuthn Identity Provider Team

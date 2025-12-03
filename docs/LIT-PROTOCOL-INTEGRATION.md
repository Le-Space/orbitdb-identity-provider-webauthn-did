# Lit Protocol Integration for Secure Keystore Management

## Executive Summary

<cite index="11-4">Lit Protocol uses an identity-based encryption scheme, which means that decryption is only permitted to those who satisfy a certain pre-determined identity parameter.</cite> This makes it an excellent solution for encrypting the OrbitDB keystore based on WebAuthn authentication.

**Key Solution**: Use Lit Protocol to encrypt the OrbitDB keystore, with WebAuthn credentials as the access control condition. This provides:
- ✅ **Hardware-backed encryption**: Only users with valid WebAuthn credentials can decrypt the keystore
- ✅ **Decentralized**: No centralized key management server
- ✅ **One biometric prompt per session**: Good UX balance
- ✅ **Cross-device support**: PKPs enable wallet-like functionality tied to WebAuthn

---

## The Problem We're Solving

From our analysis in `KEYSTORE-SECURITY-ARCHITECTURE.md`, OrbitDB stores its keystore **unencrypted** in LevelDB/IndexedDB at `./orbitdb/keystore/`:

- ❌ Keys stored in plaintext
- ❌ Vulnerable to XSS, malicious extensions, physical access
- ❌ Keys lost if browser data cleared
- ❌ No backup/recovery mechanism

**Current architecture**:
```
WebAuthn (P-256) → Signs identity object ONCE
OrbitDB KeyStore (secp256k1) → Signs ALL database operations (UNENCRYPTED storage)
```

---

## How Lit Protocol Works

<cite index="6-5,6-6,6-7">Lit Protocol generates Programmable Key Pairs (PKPs) using Distributed Key Generation (DKG), where no single node has access to the entire private key. The private key is stored in shares across the network, making each PKP functionally a wallet where the private key lives across the Lit Network.</cite>

### Core Capabilities

1. **Identity-Based Encryption**
   <cite index="11-8,11-9">Encryption is entirely a client-side operation, with only one round of network interactivity required for decryption to request signature shares and assemble a decryption key.</cite>

2. **Access Control Conditions**
   <cite index="11-12,11-13">Users create Access Control Conditions combined with private data to construct an identity parameter, then encrypt using the public key of the shared Lit BLS key.</cite>

3. **WebAuthn Integration**
   <cite index="1-6,1-7">WebAuthn enables users to authenticate with web apps using biometrics or passkeys. Authentication data can mint or fetch PKPs associated with the verified WebAuthn credential.</cite>

4. **Session Signatures**
   <cite index="1-2,1-3">After authenticating, session signatures can be generated, which take in an AuthMethod object and PKP public key, allowing operations without repeated authentication.</cite>

---

## Proposed Architecture: Lit Protocol + WebAuthn + OrbitDB

### Option 1: Encrypt OrbitDB Keystore with Lit (Recommended)

```
┌──────────────────────────────────────────────────────────┐
│ 1. SESSION ESTABLISHMENT (WebAuthn)                      │
│    User authenticates with WebAuthn → One biometric      │
│    prompt → Mint/fetch Lit PKP tied to WebAuthn cred     │
└──────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────┐
│ 2. LIT PROTOCOL DECRYPTION                               │
│    • PKP generates session signatures                    │
│    • Access Control Condition: WebAuthn credential ID    │
│    • Lit network verifies WebAuthn auth                  │
│    • Decrypts OrbitDB keystore from encrypted storage    │
└──────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────┐
│ 3. ORBITDB OPERATIONS (Cached Keystore)                 │
│    • OrbitDB keystore loaded into memory (session only)  │
│    • All db.put() operations use cached keystore         │
│    • Fast, no additional prompts                         │
│    • Keystore cleared on logout/timeout                  │
└──────────────────────────────────────────────────────────┘
```

### Flow Details

#### Initial Setup (First Time User)
```javascript
import { LitNodeClient } from '@lit-protocol/lit-node-client';
import { WebAuthnProvider } from '@lit-protocol/providers';
import { LitRelay } from '@lit-protocol/lit-auth-client';

// 1. User registers WebAuthn credential
const webauthnCredential = await navigator.credentials.create({
  publicKey: { /* WebAuthn options */ }
});

// 2. Mint PKP tied to WebAuthn credential
const litNodeClient = new LitNodeClient({
  litNetwork: 'datil-dev',
  debug: true,
});
await litNodeClient.connect();

const litRelay = new LitRelay({
  relayUrl: LitRelay.getRelayUrl('datil-dev'),
  relayApiKey: 'your-api-key',
});

const webAuthnProvider = new WebAuthnProvider({ 
  relay: litRelay, 
  litNodeClient 
});

// Register and mint PKP through relay
const options = await webAuthnProvider.register();
const txHash = await webAuthnProvider.verifyAndMintPKPThroughRelayer(options);
const response = await litRelay.pollRequestUntilTerminalState(txHash);

const pkpPublicKey = response.pkpPublicKey;
console.log('✅ PKP minted:', pkpPublicKey);

// 3. Generate OrbitDB keystore
const orbitdbKeystore = await KeyStore({ /* ... */ });

// 4. Encrypt keystore with Lit
// Access Control: Only this WebAuthn credential can decrypt
const accessControlConditions = [
  {
    contractAddress: '',
    standardContractType: '',
    chain: 'ethereum',
    method: '',
    parameters: [':currentActionIpfsId'],
    returnValueTest: {
      comparator: '=',
      value: webauthnCredential.id, // WebAuthn credential ID
    },
  }
];

const keystoreJson = JSON.stringify(orbitdbKeystore);
const { ciphertext, dataToEncryptHash } = await LitJsSdk.encryptString(
  {
    accessControlConditions,
    sessionSigs: {}, // session signatures from PKP
    chain: 'ethereum',
    dataToEncrypt: keystoreJson,
  },
  litNodeClient
);

// 5. Store encrypted keystore (IndexedDB, IPFS, etc.)
await storeEncryptedKeystore({
  pkpPublicKey,
  ciphertext,
  dataToEncryptHash,
  accessControlConditions,
  webauthnCredentialId: webauthnCredential.id,
});
```

#### Session Start (Returning User)
```javascript
// 1. User authenticates with WebAuthn
const webauthnCredential = await navigator.credentials.get({
  publicKey: { /* options */ }
});

// 2. Authenticate with Lit and get PKP
const authMethod = await webAuthnProvider.authenticate(webauthnCredential);

// 3. Generate session signatures
const sessionSigs = await webAuthnProvider.getSessionSigs({
  authMethod,
  pkpPublicKey: storedPkpPublicKey,
  sessionSigsParams: {
    chain: 'ethereum',
    resourceAbilityRequests: [{
      resource: litResource,
      ability: LIT_ABILITY.AccessControlConditionDecryption,
    }],
  },
});

// 4. Decrypt OrbitDB keystore
const encryptedData = await loadEncryptedKeystore();

const decryptedKeystore = await LitJsSdk.decryptToString(
  {
    accessControlConditions: encryptedData.accessControlConditions,
    chain: 'ethereum',
    ciphertext: encryptedData.ciphertext,
    dataToEncryptHash: encryptedData.dataToEncryptHash,
    sessionSigs,
  },
  litNodeClient
);

// 5. Load keystore into OrbitDB (memory only, session-scoped)
const keystore = await KeyStore({ 
  storage: MemoryStorage(JSON.parse(decryptedKeystore))
});

// 6. Use OrbitDB normally - all operations use decrypted keystore
const orbitdb = await createOrbitDB({ ipfs, identities, identity, keystore });
const db = await orbitdb.open('todos');
await db.put(todoId, todo); // ✅ No additional prompts!
```

#### Session End
```javascript
// 1. Clear keystore from memory
await keystore.clear();

// 2. Disconnect from Lit
await litNodeClient.disconnect();

// Encrypted keystore remains safely in storage
```

---

### Option 2: Use Lit PKP as Primary Signing Key (Alternative)

Instead of encrypting the OrbitDB keystore, **replace** it entirely with a Lit PKP:

```
┌──────────────────────────────────────────────────────────┐
│ WebAuthn → Lit PKP (Distributed ECDSA Key)              │
│  • PKP acts as the OrbitDB signing key                   │
│  • DID generated from PKP public key                     │
│  • All signatures requested from Lit network             │
│  • Session signatures enable fast signing                │
└──────────────────────────────────────────────────────────┘
```

**Pros:**
- ✅ No local keystore to protect
- ✅ True distributed key management
- ✅ Built-in key recovery via WebAuthn credential
- ✅ Hardware-backed authentication

**Cons:**
- ❌ Network latency for every signature (~100-300ms)
- ❌ Requires Lit network availability
- ❌ Requires Capacity Credits (paid)
- ❌ More complex integration with OrbitDB

---

## Security Comparison

### Current State (No Encryption)
| Threat | Impact | Mitigation |
|--------|--------|------------|
| XSS Attack | 🔴 **CRITICAL** - Keys stolen | None |
| Malicious Extension | 🔴 **CRITICAL** - Keys stolen | None |
| Physical Access | 🔴 **CRITICAL** - Keys stolen | None |
| Accidental Deletion | 🔴 **CRITICAL** - Keys lost forever | None |

### With Lit Protocol Encryption (Option 1)
| Threat | Impact | Mitigation |
|--------|--------|------------|
| XSS Attack | 🟡 **LOW** - Only encrypted data exposed | Requires WebAuthn auth to decrypt |
| Malicious Extension | 🟡 **LOW** - Only encrypted data exposed | Requires WebAuthn auth to decrypt |
| Physical Access | 🟡 **LOW** - Only encrypted data exposed | Requires biometric to decrypt |
| Accidental Deletion | 🟢 **NONE** - Encrypted backup exists | Can restore from storage |
| Session Hijacking | 🟡 **MEDIUM** - Keys in memory during session | Session timeout, clear on logout |

### With Lit PKP as Primary Key (Option 2)
| Threat | Impact | Mitigation |
|--------|--------|------------|
| XSS Attack | 🟢 **NONE** - No keys in browser | Keys distributed across Lit network |
| Malicious Extension | 🟢 **NONE** - No keys in browser | Keys distributed across Lit network |
| Physical Access | 🟢 **NONE** - No keys on device | Requires WebAuthn hardware auth |
| Accidental Deletion | 🟢 **NONE** - Keys never local | Keys exist on Lit network |
| Network Outage | 🔴 **CRITICAL** - Cannot sign | Requires Lit network availability |

---

## Implementation Recommendations

### Recommended Approach: Hybrid (Option 1 + Backup)

1. **Primary**: Encrypt OrbitDB keystore with Lit Protocol (Option 1)
   - One WebAuthn prompt per session
   - Fast operation performance
   - Good UX

2. **Backup**: Store encrypted keystore on IPFS/Arweave
   - User can recover keys on new device
   - WebAuthn + Lit PKP enables decryption anywhere
   - No dependency on localStorage/IndexedDB

3. **Optional Enhancement**: Lit PKP as secondary identity layer
   - Generate DID from Lit PKP (not WebAuthn P-256)
   - Enables cross-device identity portability
   - WebAuthn → Lit PKP → OrbitDB KeyStore

### Migration Path

**Phase 1: Encrypt Existing Keystore**
```javascript
// Detect unencrypted keystore
const unencryptedKeystore = await loadKeystoreFromLevelDB('./orbitdb/keystore');

if (unencryptedKeystore && !isEncrypted(unencryptedKeystore)) {
  console.warn('⚠️ Unencrypted keystore detected. Migrating...');
  
  // Prompt user to set up WebAuthn
  const webauthnCred = await setupWebAuthn();
  
  // Mint PKP
  const pkp = await mintPKPWithWebAuthn(webauthnCred);
  
  // Encrypt and backup
  const encrypted = await encryptKeystoreWithLit(unencryptedKeystore, pkp);
  await storeEncryptedKeystore(encrypted);
  
  // Delete unencrypted version
  await deleteUnencryptedKeystore();
  
  console.log('✅ Keystore encrypted and backed up');
}
```

**Phase 2: Session Management**
```javascript
class SecureOrbitDBSession {
  constructor() {
    this.litClient = null;
    this.decryptedKeystore = null;
    this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
    this.timeoutId = null;
  }
  
  async start(webauthnCredential) {
    // Connect to Lit
    this.litClient = new LitNodeClient({ litNetwork: 'datil' });
    await this.litClient.connect();
    
    // Authenticate and decrypt keystore
    this.decryptedKeystore = await this.decryptKeystore(webauthnCredential);
    
    // Set session timeout
    this.resetTimeout();
    
    return this.decryptedKeystore;
  }
  
  resetTimeout() {
    if (this.timeoutId) clearTimeout(this.timeoutId);
    this.timeoutId = setTimeout(() => this.end(), this.sessionTimeout);
  }
  
  async end() {
    // Clear keystore from memory
    if (this.decryptedKeystore) {
      await this.decryptedKeystore.clear();
      this.decryptedKeystore = null;
    }
    
    // Disconnect from Lit
    if (this.litClient) {
      await this.litClient.disconnect();
      this.litClient = null;
    }
    
    console.log('🔒 Session ended, keystore cleared from memory');
  }
}
```

---

## Cost Analysis

### Lit Protocol Costs

<cite index="13-21,13-22,13-23">To execute transactions with Lit, you need Capacity Credits, which allow holders to reserve a set number of requests per second over a desired period like one week.</cite>

**Datil Network (Production)**:
- **Capacity Credits**: Required for mainnet
- **Cost**: Variable based on request volume
- **Free Tier**: Available on `datil-dev` testnet

**Estimated Usage**:
- **Session start**: 1 decryption request per session
- **Typical usage**: 1-2 requests per day per user
- **Monthly**: ~30-60 requests per user

**Cost Comparison**:
| Solution | Monthly Cost/User | Security Level |
|----------|------------------|----------------|
| No encryption (current) | $0 | 🔴 Very Low |
| User password + PBKDF2 | $0 | 🟡 Medium |
| **Lit Protocol** | **$0.01-0.10** | **🟢 High** |
| HSM/Cloud KMS | $5-50 | 🟢 High |

---

## Example Implementation

### Full Integration Code

```javascript
// lit-orbitdb-integration.js
import { LitNodeClient } from '@lit-protocol/lit-node-client';
import { WebAuthnProvider } from '@lit-protocol/providers';
import { LitRelay } from '@lit-protocol/lit-auth-client';
import { createOrbitDB, KeyStore } from '@orbitdb/core';
import * as LitJsSdk from '@lit-protocol/lit-node-client';

export class LitOrbitDBIntegration {
  constructor(options = {}) {
    this.litNetwork = options.litNetwork || 'datil-dev';
    this.litClient = null;
    this.webAuthnProvider = null;
    this.pkpPublicKey = null;
    this.decryptedKeystore = null;
  }

  async initialize() {
    // Initialize Lit Node Client
    this.litClient = new LitNodeClient({
      litNetwork: this.litNetwork,
      debug: true,
    });
    await this.litClient.connect();
    console.log('✅ Connected to Lit Network');

    // Initialize WebAuthn Provider
    const relay = new LitRelay({
      relayUrl: LitRelay.getRelayUrl(this.litNetwork),
      relayApiKey: process.env.LIT_RELAY_API_KEY,
    });

    this.webAuthnProvider = new WebAuthnProvider({
      relay,
      litNodeClient: this.litClient,
    });
  }

  async setupNewUser() {
    console.log('🔑 Setting up new user with WebAuthn...');

    // 1. Register WebAuthn credential
    const webauthnOptions = await this.webAuthnProvider.register();
    console.log('✅ WebAuthn credential registered');

    // 2. Mint PKP through relay
    const txHash = await this.webAuthnProvider.verifyAndMintPKPThroughRelayer(
      webauthnOptions
    );
    const response = await this.webAuthnProvider.relay.pollRequestUntilTerminalState(
      txHash
    );

    this.pkpPublicKey = response.pkpPublicKey;
    console.log('✅ PKP minted:', this.pkpPublicKey);

    // 3. Generate OrbitDB keystore
    const keystore = await KeyStore({ path: './temp-keystore' });
    await keystore.createKey('user-identity');

    // 4. Export keystore to encrypt
    const keystoreData = await this.exportKeystore(keystore);

    // 5. Encrypt keystore with Lit
    const encrypted = await this.encryptKeystore(keystoreData);

    // 6. Store encrypted keystore metadata
    await this.storeMetadata({
      pkpPublicKey: this.pkpPublicKey,
      ...encrypted,
    });

    console.log('✅ User setup complete');
    return { pkpPublicKey: this.pkpPublicKey };
  }

  async startSession(webauthnCredential) {
    console.log('🔓 Starting session...');

    // 1. Authenticate with WebAuthn
    const authMethod = await this.webAuthnProvider.authenticate(
      webauthnCredential
    );
    console.log('✅ WebAuthn authenticated');

    // 2. Load encrypted keystore metadata
    const metadata = await this.loadMetadata();
    this.pkpPublicKey = metadata.pkpPublicKey;

    // 3. Generate session signatures
    const sessionSigs = await this.webAuthnProvider.getSessionSigs({
      authMethod,
      pkpPublicKey: this.pkpPublicKey,
      sessionSigsParams: {
        chain: 'ethereum',
        resourceAbilityRequests: [
          {
            resource: new LitPKPResource('*'),
            ability: LIT_ABILITY.AccessControlConditionDecryption,
          },
        ],
      },
    });
    console.log('✅ Session signatures generated');

    // 4. Decrypt keystore
    const decryptedData = await LitJsSdk.decryptToString(
      {
        accessControlConditions: metadata.accessControlConditions,
        chain: 'ethereum',
        ciphertext: metadata.ciphertext,
        dataToEncryptHash: metadata.dataToEncryptHash,
        sessionSigs,
      },
      this.litClient
    );
    console.log('✅ Keystore decrypted');

    // 5. Load keystore into memory
    this.decryptedKeystore = await this.importKeystore(
      JSON.parse(decryptedData)
    );

    return this.decryptedKeystore;
  }

  async createOrbitDB(ipfs, identity) {
    if (!this.decryptedKeystore) {
      throw new Error('Session not started. Call startSession() first.');
    }

    const identities = await Identities({ ipfs, keystore: this.decryptedKeystore });
    
    const orbitdb = await createOrbitDB({
      ipfs,
      identities,
      identity,
      keystore: this.decryptedKeystore,
    });

    return orbitdb;
  }

  async encryptKeystore(keystoreData) {
    const accessControlConditions = [
      {
        contractAddress: '',
        standardContractType: '',
        chain: 'ethereum',
        method: 'eth_getBalance',
        parameters: [':userAddress', 'latest'],
        returnValueTest: {
          comparator: '>=',
          value: '0',
        },
      },
    ];

    const { ciphertext, dataToEncryptHash } = await LitJsSdk.encryptString(
      {
        accessControlConditions,
        sessionSigs: {}, // Add session sigs
        chain: 'ethereum',
        dataToEncrypt: JSON.stringify(keystoreData),
      },
      this.litClient
    );

    return {
      ciphertext,
      dataToEncryptHash,
      accessControlConditions,
    };
  }

  async exportKeystore(keystore) {
    // Export keystore data for encryption
    // Implementation depends on KeyStore API
    return { /* keystore data */ };
  }

  async importKeystore(keystoreData) {
    // Import keystore from decrypted data
    // Implementation depends on KeyStore API
    return await KeyStore({ /* restore from data */ });
  }

  async storeMetadata(metadata) {
    // Store encrypted keystore metadata
    // Could use IndexedDB, IPFS, Arweave, etc.
    localStorage.setItem('lit-orbitdb-metadata', JSON.stringify(metadata));
  }

  async loadMetadata() {
    const data = localStorage.getItem('lit-orbitdb-metadata');
    return JSON.parse(data);
  }

  async endSession() {
    if (this.decryptedKeystore) {
      await this.decryptedKeystore.clear();
      this.decryptedKeystore = null;
    }

    if (this.litClient) {
      await this.litClient.disconnect();
    }

    console.log('🔒 Session ended');
  }
}

// Usage example
const litOrbitDB = new LitOrbitDBIntegration();
await litOrbitDB.initialize();

// New user
await litOrbitDB.setupNewUser();

// Returning user
const webauthnCred = await navigator.credentials.get({ /* ... */ });
const keystore = await litOrbitDB.startSession(webauthnCred);
const orbitdb = await litOrbitDB.createOrbitDB(ipfs, identity);

// Use OrbitDB normally
const db = await orbitdb.open('todos');
await db.put('todo-1', { text: 'Hello World' }); // ✅ Works!

// End session
await litOrbitDB.endSession();
```

---

## Benefits Summary

### What Lit Protocol Solves

1. **Hardware-Backed Encryption** ✅
   - WebAuthn credentials control decryption
   - Biometric authentication required

2. **Decentralized Key Management** ✅
   - No centralized server
   - Keys distributed across Lit network

3. **Good UX** ✅
   - One biometric prompt per session
   - Fast operations after decryption

4. **Cross-Device Support** ✅
   - PKP tied to WebAuthn credential
   - Can authenticate from any device with same credential

5. **Backup & Recovery** ✅
   - Encrypted keystore can be stored anywhere
   - Recoverable with WebAuthn credential

6. **No Password Required** ✅
   - Pure biometric/hardware authentication
   - Better security than password-based encryption

---

## Next Steps

1. **Prototype**: Build POC with `datil-dev` testnet (free)
2. **Test**: Validate encryption/decryption flow with WebAuthn
3. **Benchmark**: Measure session start latency
4. **Migrate**: Add migration path for existing unencrypted keystores
5. **Production**: Deploy to `datil` mainnet with Capacity Credits

---

## References

- Lit Protocol Documentation: https://developer.litprotocol.com/
- Lit + WebAuthn: https://developer.litprotocol.com/user-wallets/pkps/advanced-topics/auth-methods/web-authn
- Lit Encryption: https://developer.litprotocol.com/sdk/access-control/encryption
- OrbitDB KeyStore: `@orbitdb/core/src/key-store.js`
- Our Security Analysis: `docs/KEYSTORE-SECURITY-ARCHITECTURE.md`

---

## Conclusion

**Lit Protocol provides an ideal solution** for securing the OrbitDB keystore with WebAuthn:

- ✅ Solves the unencrypted keystore vulnerability
- ✅ Maintains good UX (one prompt per session)
- ✅ Provides decentralized key management
- ✅ Enables cross-device identity portability
- ✅ Supports backup and recovery
- ✅ Low cost (pennies per user per month)

**Recommended Action**: Implement Option 1 (Encrypt OrbitDB Keystore with Lit) as the primary security enhancement, with optional migration to Option 2 (Lit PKP as primary key) for future versions.

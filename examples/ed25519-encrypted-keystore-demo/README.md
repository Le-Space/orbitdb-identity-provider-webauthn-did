# Ed25519 Encrypted Keystore Demo

This demo showcases the **Ed25519 Keystore DID** and **WebAuthn-Encrypted Keystore** features for OrbitDB.

## Features Demonstrated

### 🆔 Ed25519 Keystore DID
- Create Ed25519 DIDs from OrbitDB keystore instead of P-256 from WebAuthn
- Unified identity: same key for DID and database operations  
- Better UCAN compatibility

### 🔐 WebAuthn-Encrypted Keystore
- Encrypt OrbitDB keystore with AES-GCM 256-bit
- Secret key protected by WebAuthn hardware (largeBlob or hmac-secret)
- One biometric prompt per session
- Protected from XSS, malicious extensions, and device theft

## Running the Demo

Install dependencies:
\`\`\`sh
npm install
\`\`\`

Start the development server:
\`\`\`sh
npm run dev
\`\`\`

Open your browser to the URL shown (typically http://localhost:5173)

## Using the Demo

1. **Create Credential**: Click to create a WebAuthn credential (biometric prompt)
2. **Choose Security Options**:
   - ☑️ Use Ed25519 DID from keystore
   - ☑️ Encrypt keystore with WebAuthn
   - Select encryption method (largeBlob or hmac-secret)
3. **Authenticate**: Click to authenticate and set up OrbitDB
4. **Add TODOs**: Your data is now secured with the selected options!

## Browser Support

- **Ed25519 DID**: All browsers with WebAuthn
- **largeBlob encryption**: Chrome 106+, Edge 106+
- **hmac-secret encryption**: Chrome, Firefox, Edge

## Sequence

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Web UI
  participant WebAuthn as WebAuthn API
  participant Auth as Authenticator
  participant LS as LocalStorage
  participant Prov as WebAuthn DID Provider
  participant KS as OrbitDB Keystore (IndexedDB)
  participant Enc as KeystoreEncryption
  participant DB as OrbitDB Database

  User->>App: Create credential
  App->>WebAuthn: navigator.credentials.create()
  WebAuthn->>Auth: Create passkey
  Auth-->>WebAuthn: Attestation
  WebAuthn-->>App: Credential (rawId, publicKey)
  App->>LS: Store credentialId

  User->>App: Authenticate / create identity
  App->>Prov: getId(useKeystoreDID=true)
  Prov->>KS: getKey() / createKey(Ed25519)
  KS-->>Prov: Ed25519 keypair
  Prov-->>App: DID from keystore public key

  opt encryptKeystore=true
    App->>Enc: generateSecretKey()
    Enc-->>App: sk
    App->>Enc: encrypt private key (AES-GCM)
    alt prf
      App->>WebAuthn: get() with PRF
      WebAuthn->>Auth: User verification
      Auth-->>WebAuthn: PRF output
      WebAuthn-->>App: PRF bytes
      App->>Enc: wrap sk with PRF
    else largeBlob
      App->>WebAuthn: get() with largeBlob write
      WebAuthn->>Auth: User verification
      Auth-->>WebAuthn: Store sk in largeBlob
      WebAuthn-->>App: largeBlob stored
    else hmac-secret
      App->>WebAuthn: get() with hmac-secret
      WebAuthn->>Auth: User verification
      Auth-->>WebAuthn: HMAC output
      WebAuthn-->>App: HMAC bytes
      App->>Enc: wrap sk with HMAC
    end
    App->>Enc: store encrypted keystore metadata
  end

  User->>App: Add TODO
  App->>DB: db.put()
  DB->>KS: sign entry with Ed25519 key
  KS-->>DB: Entry signature
```

# Example Sequences

Mermaid sequences for the JavaScript examples in `examples/`.

## `examples/ed25519-keystore-did-example.js`

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Example Script
  participant WebAuthn as WebAuthn API
  participant Auth as Authenticator
  participant Prov as WebAuthn DID Provider
  participant KS as OrbitDB Keystore (IndexedDB)
  participant DB as OrbitDB Database

  User->>App: Run example
  App->>WebAuthn: navigator.credentials.create()
  WebAuthn->>Auth: Create passkey
  Auth-->>WebAuthn: Attestation
  WebAuthn-->>App: Credential

  App->>KS: getKey() / createKey(Ed25519)
  KS-->>App: Ed25519 keypair
  App->>Prov: create identity (useKeystoreDID=true)
  Prov-->>App: DID from keystore public key

  App->>DB: db.put()
  DB->>KS: sign entry with keystore key
  KS-->>DB: Entry signature
```

## `examples/encrypted-keystore-example.js`

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Example Script
  participant WebAuthn as WebAuthn API
  participant Auth as Authenticator
  participant KS as OrbitDB Keystore (IndexedDB)
  participant Enc as KeystoreEncryption
  participant DB as OrbitDB Database

  User->>App: Run example
  App->>WebAuthn: navigator.credentials.create()
  WebAuthn->>Auth: Create passkey
  Auth-->>WebAuthn: Attestation
  WebAuthn-->>App: Credential

  App->>KS: getKey() / createKey(Ed25519)
  KS-->>App: Ed25519 keypair
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
  App->>DB: db.put()
  DB->>KS: sign entry with keystore key
  KS-->>DB: Entry signature
```

## `examples/simple-encryption-integration.js`

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Example Script
  participant WebAuthn as WebAuthn API
  participant Auth as Authenticator
  participant Enc as KeystoreEncryption
  participant KS as OrbitDB Keystore (IndexedDB)
  participant DB as OrbitDB Database
  participant SE as SimpleEncryption

  User->>App: Run example
  App->>WebAuthn: navigator.credentials.create()
  WebAuthn->>Auth: Create passkey
  Auth-->>WebAuthn: Attestation
  WebAuthn-->>App: Credential

  App->>Enc: generateSecretKey()
  Enc-->>App: sk
  App->>Enc: protect sk via PRF/largeBlob/hmac-secret
  App->>KS: createKey()
  KS-->>App: keystore keypair
  App->>Enc: encrypt keystore private key (AES-GCM)
  App->>Enc: store encrypted keystore metadata

  App->>SE: create database encryption config (sk)
  SE-->>App: encryption instance
  App->>DB: open with encryption
  App->>DB: db.put() (encrypted content)
  DB->>KS: sign entry
```

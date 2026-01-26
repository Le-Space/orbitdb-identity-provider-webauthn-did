# Example Sequences

Mermaid sequences for the JavaScript examples in `examples/`.

## `examples/ed25519-keystore-did-example.js` (tests: `tests/ed25519-keystore-did.test.js`)

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Example Script (Keystore DID)
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

  Note over App,KS: Keystore private key is stored encrypted at rest.
```

## `examples/encrypted-keystore-example.js` (tests: `tests/encrypted-keystore.test.js`)

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Example Script (Encrypted Keystore)
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

## `examples/simple-encryption-integration.js` (tests: `tests/simple-encryption-integration.test.js`)

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Example Script (Simple Encryption)
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

## `examples/webauthn-todo-demo` (tests: `tests/webauthn-focused.test.js`, `tests/webauthn-integration.test.js`, `tests/webauthn-logging-e2e.test.js`, `tests/webauthn-verification.test.js`)

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Web UI (WebAuthn DID)
  participant WebAuthn as WebAuthn API
  participant Auth as Authenticator
  participant LS as LocalStorage
  participant ID as OrbitDB Identities
  participant Prov as WebAuthn DID Provider
  participant DB as OrbitDB Database

  User->>App: Create credential
  App->>WebAuthn: navigator.credentials.create()
  WebAuthn->>Auth: Create passkey
  Auth-->>WebAuthn: Attestation
  WebAuthn-->>App: Credential (rawId, publicKey)
  App->>LS: Store credentialId

  User->>App: Authenticate / create identity
  App->>ID: createIdentity(provider)
  ID->>Prov: getId() + signIdentity()
  Prov->>WebAuthn: navigator.credentials.get()
  WebAuthn->>Auth: User verification
  Auth-->>WebAuthn: Assertion
  WebAuthn-->>Prov: Signature
  Prov-->>ID: DID (P-256) + signature
  ID-->>App: Identity

  User->>App: Add TODO
  App->>DB: db.put()
  DB->>ID: identity.sign(entry)
  ID->>Prov: signIdentity(payload)
  Prov->>WebAuthn: navigator.credentials.get()
  WebAuthn->>Auth: User verification
  Auth-->>WebAuthn: Assertion
  WebAuthn-->>Prov: Signature
  Prov-->>DB: Entry signature

  Note over App,DB: Keystore encryption/PRF are not used in this demo.
```

## `examples/ed25519-encrypted-keystore-demo` (tests: `tests/ed25519-encrypted-keystore-e2e.test.js`)

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Web UI (Encrypted Keystore)
  participant WebAuthn as WebAuthn API
  participant Auth as Authenticator
  participant KS as OrbitDB Keystore
  participant Enc as KeystoreEncryption
  participant DB as OrbitDB Database

  User->>App: Create credential
  App->>WebAuthn: navigator.credentials.create()
  WebAuthn->>Auth: Create passkey
  Auth-->>WebAuthn: Attestation
  WebAuthn-->>App: Credential (rawId, publicKey)

  User->>App: Select encryption method (PRF / largeBlob / hmac-secret)
  App->>KS: createKey(Ed25519)
  KS-->>App: Keystore keypair
  App->>Enc: generateSecretKey()
  Enc-->>App: sk
  App->>Enc: encrypt keystore private key (AES-GCM)

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

  App->>DB: db.put()
  DB->>KS: sign entry with keystore key
  KS-->>DB: Entry signature
```

## `examples/webauthn-varsig-demo` (tests: `tests/webauthn-varsig-e2e.test.js`)

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Web UI (WebAuthn Varsig)
  participant WebAuthn as WebAuthn API
  participant Auth as Authenticator
  participant LS as LocalStorage
  participant Prov as WebAuthn Varsig Provider
  participant DB as OrbitDB Database

  User->>App: Create credential
  App->>WebAuthn: navigator.credentials.create()
  WebAuthn->>Auth: Create passkey
  Auth-->>WebAuthn: Attestation
  WebAuthn-->>App: Credential (rawId, publicKey)
  App->>LS: Store credentialId

  User->>App: Authenticate / create varsig identity
  App->>Prov: createIdentity()
  Prov->>WebAuthn: navigator.credentials.get()
  WebAuthn->>Auth: User verification
  Auth-->>WebAuthn: Assertion
  WebAuthn-->>Prov: Assertion
  Prov->>Prov: build varsig envelope (encodeWebAuthnVarsigV1)
  Prov-->>App: Identity (publicKey + varsig signature)

  User->>App: Add TODO
  App->>DB: db.put()
  DB->>Prov: signIdentity(payload)
  Prov->>WebAuthn: navigator.credentials.get()
  WebAuthn->>Auth: User verification
  Auth-->>WebAuthn: Assertion
  WebAuthn-->>Prov: Assertion
  Prov->>Prov: build varsig envelope (encodeWebAuthnVarsigV1)
  Prov-->>DB: Varsig signature

  Note over App,DB: No OrbitDB keystore, no PRF/keystore encryption in this demo.
```

# WebAuthn Todo Demo

This demo uses the WebAuthn DID provider (P-256 DID) and signs each database write with a WebAuthn assertion. It does not use the OrbitDB keystore for signing unless you change the provider options.

## Running the demo

Install dependencies:
```sh
npm install
```

Start the dev server:
```sh
npm run dev
```

Open the URL shown (typically http://localhost:5173).

## Sequence

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Web UI
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

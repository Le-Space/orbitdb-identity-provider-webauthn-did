# WebAuthn Varsig Todo Demo

This demo uses WebAuthn varsig signatures to create an OrbitDB identity without a separate browser keystore. All OrbitDB entry signatures are produced directly by your passkey.

## What it demonstrates

- WebAuthn varsig identity creation (Ed25519 or P-256, depending on authenticator support)
- No additional OrbitDB keystore in the browser
- OrbitDB database operations signed with passkey-generated varsig signatures

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

## Using the demo

1. Create a WebAuthn credential (passkey prompt).
2. Authenticate to create a varsig-backed OrbitDB identity.
3. Add TODOs. Each write will trigger a passkey assertion.

## Notes

- Each database write requires a WebAuthn assertion, so expect frequent biometric prompts.
- Ed25519 support depends on your authenticator; otherwise the demo falls back to P-256.

## Sequence

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant App as Web UI
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

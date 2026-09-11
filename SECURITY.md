# Security Policy

## Supported Versions

Security fixes are provided for the current `0.5.x` release line.

| Version | Supported |
| ------- | --------- |
| 0.5.x   | Yes       |
| < 0.5   | No        |

Every release up to and including 0.5.2 is affected by
[GHSA-326j-4cc3-4rrg](https://github.com/Le-Space/orbitdb-identity-provider-webauthn-did/security/advisories/GHSA-326j-4cc3-4rrg)
(identity verification checked shapes, not signatures). Use 0.5.3 or later.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Report suspected vulnerabilities by email:

security@le-space.de

Please include as much detail as you can:

- affected package version, commit, or tag
- affected browser, runtime, or operating system
- steps to reproduce
- expected and actual behavior
- proof of concept, logs, screenshots, or traces if available
- your assessment of impact

We aim to acknowledge reports within 48 hours and coordinate fixes before
public disclosure.

## Security Model

This package provides WebAuthn-based identity providers and helper APIs for
OrbitDB. It handles sensitive identity material and should be reviewed in the
context of the application that embeds it.

There are three ways to use it, and they protect different things. The
README carries a table; the short version:

### Varsig Provider

The only option with no signing key in JavaScript: every entry is a WebAuthn
assertion in a varsig envelope, so the private key never leaves the
authenticator (or the passkey provider — synced passkeys are not
device-bound). It costs one prompt per write, and entries are bound to the
origin they were signed on.

### Default: passkey DID with a derived signing key

The DID is the passkey's own P-256 key. OrbitDB entries are signed by a
software key **derived** from the passkey's PRF output (HKDF-SHA256,
domain-separated by the DID; secp256k1, or Ed25519 with `signingKeyType`).
The passkey signs the identity document once, binding its key to the derived
key; that assertion is stored and reused.

The derived key sits in OrbitDB's keystore, **unencrypted**, in the
browser's IndexedDB. `encryptKeystore` does not apply to this path. Anyone who
can read that storage can sign as the DID until the identity is rotated.
Without PRF the keystore generates a key instead, which stays on one device.

### Keystore Provider (`useKeystoreDID` + `encryptKeystore`)

The DID is a keystore key (Ed25519 or secp256k1). With `encryptKeystore` a
sealed copy of that key is kept in localStorage, unlocked once per session by
the passkey (PRF; largeBlob or hmac-secret where supported).

Two things decide whether that means anything at rest:

- OrbitDB signs with whatever its keystore returns, and its default keystore
  writes every key to disk. Give `Identities()` the keystore from
  `createSessionKeystore()` (memory only). With any other keystore the
  unlocked key lands in IndexedDB unencrypted, and the provider warns.
- Without PRF output nothing is sealed. The provider used to fall back to
  the credential id — a value that sits in localStorage in clear — as the
  wrapping seed; since 0.5.4 it does not, and reports
  `encryptionState: { enabled: false, reason: 'prf-unavailable' }`.

During an unlocked session the private key is in page memory in every
option but varsig.

### Identity Metadata Recovery

Discoverable passkeys can identify a credential during authentication, but
WebAuthn assertions do not reliably return the public key after registration.
This package therefore needs identity metadata persistence for recovery.

The example applications use:

- WebAuthn largeBlob metadata as the preferred recovery path
- browser localStorage as a fallback when largeBlob is unavailable or empty

Applications should treat localStorage metadata as recoverability metadata, not
as a replacement for authenticator-backed key protection.

## Operational Guidance

- Serve production applications over HTTPS.
- Configure WebAuthn relying party IDs and origins deliberately.
- Prefer the varsig provider where a prompt per write is acceptable; nothing
  else keeps the signing key out of JavaScript.
- With the keystore provider, use `encryptKeystore` together with
  `createSessionKeystore()`, and check `provider.encryptionState` before
  telling users their key is encrypted.
- Verify identities and entries the way a peer would (see
  `examples/shared/lib/verification.js`); a badge that checks nothing is
  worse than none.
- Keep dependencies updated and review `npm audit --omit=dev` output before
  production deployments.
- Do not log private keys, PRF seeds, decrypted keystore archives, or raw secret
  key material.
- Review browser storage behavior for your deployment, especially if using
  localStorage fallback recovery.

## Disclosure Process

1. A vulnerability report is received privately.
2. We acknowledge the report and investigate impact.
3. We prepare and test a fix.
4. We publish a patched release.
5. We coordinate public disclosure with the reporter where appropriate.

# Security Policy

## Supported Versions

Security fixes are provided for the current `0.3.x` release line.

| Version | Supported |
| ------- | --------- |
| 0.3.x   | Yes       |
| < 0.3   | No        |

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

### Varsig Provider

The varsig provider is the preferred security model when available. Entry
signing is performed through WebAuthn assertions, so the private key remains
inside the authenticator and is not exported to application memory.

### Keystore Provider

The keystore provider can generate browser-side Ed25519 or secp256k1 keys for
OrbitDB signing. When encrypted keystore mode is enabled, key material is
encrypted at rest with AES-GCM and unlocked through WebAuthn-supported secret
recovery mechanisms such as PRF, largeBlob, or hmac-secret.

During an unlocked session, private key material may exist in browser memory.
Applications with stricter requirements should prefer the varsig provider or
keep keystore sessions short.

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
- Prefer the varsig provider for hardware-backed signing on every write.
- Enable encrypted keystore mode if using the keystore provider in production.
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

# Changes

## 0.2.2
- Ship patch-package in dependencies so postinstall works for consumers.

## 0.2.1
- Add WebAuthn varsig demo E2E coverage and test-mode stubs for CI.
- Update CI to focus on Chromium-only runs and disable failing encrypted keystore tests.
- Add @libp2p/crypto dependency and update lockfile.
- Publish varsig demo build to Storacha and link in README.

## 0.2.0
- Switch iso dependencies to the published `@le-space` fork and pin `@le-space/iso-did@2.1.2`.
- Restore unscoped `iso-web` from npm to satisfy `iso-did` runtime deps.
- Document forked iso packages used for WebAuthn varsig support.
- Clarify Varsig vs keystore-based DID paths and reference the example demos.

## 0.1.0 (preview)
- Initial preview release with WebAuthn DID and varsig provider.

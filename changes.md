# Changes

## 0.3.1

- Bump package metadata to `0.3.1` and create the clean release tag after
  the post-`0.3.0` CI fixes landed.
- Update example lockfiles so all demos install successfully with
  `pnpm install --frozen-lockfile`.
- Fix Playwright web server startup by passing Vite `preview`/`dev` arguments
  directly, avoiding CI timeouts waiting for the wrong port.
- Update GitHub Actions to current action majors:
  `actions/checkout@v7`, `pnpm/action-setup@v6`, `actions/setup-node@v6`,
  and `actions/upload-artifact@v7`.
- Verify the release commit with GitHub Actions:
  root frozen install, all three example frozen installs, all three example
  builds, WebAuthn focused tests, logging E2E, integration E2E, varsig E2E,
  encrypted-keystore tests, and Ed25519 encrypted-keystore E2E.
- Verify the package tarball with `npm pack --dry-run`; the package reports
  `@le-space/orbitdb-identity-provider-webauthn-did@0.3.1` with 27 published
  files.

## 0.3.0

- Upgrade the OrbitDB stack to `@orbitdb/core@^4.0.0`.
- Upgrade Helia to `helia@^7.0.1` and add the current Helia service packages:
  `@helia/libp2p`, `@helia/http`, and `@helia/bitswap`.
- Upgrade libp2p to `libp2p@^3.3.4` and the current scoped packages,
  including `@libp2p/gossipsub@^16.0.3`, `@libp2p/identify@^4.1.8`,
  `@libp2p/websockets@^10.1.15`, `@chainsafe/libp2p-noise@^17.0.0`,
  and `@chainsafe/libp2p-yamux@^8.0.1`.
- Confirm the gossipsub stream-registry fix from
  `libp2p/js-libp2p#3531` is included via `@libp2p/gossipsub@16.0.3`.
- Port all Svelte examples to the OrbitDB 4, Helia 7, and libp2p 3 stack:
  `webauthn-todo-demo`, `ed25519-encrypted-keystore-demo`, and
  `webauthn-varsig-demo`.
- Update example libp2p configuration for the v3 `connectionEncrypters`
  option and current `withLibp2p`, `withHTTP`, and `withBitswap` Helia setup.
- Update OrbitDB identity and keystore integration for the current OrbitDB 4
  public APIs, including keystore key generation/storage.
- Replace older dynamic codec/hash imports with static multiformats imports
  where needed.
- Remove obsolete local OrbitDB patches.
- Clean up known Vite/polyfill build warnings in the examples.
- Fix varsig verification edge cases for replicated entries, mixed
  worker/hardware verification, and Node relay default exports.

## 0.2.10

- Release metadata update after varsig verification and worker/hardware
  compatibility fixes.

## 0.2.9

- Version metadata update after discoverable passkey recovery work.

## 0.2.8

- Add discoverable passkey recovery flows.
- Add worker-backed keystore demo coverage and fix the worker keystore demo
  build.
- Export varsig verification, identity storage, and
  `wrapWithVarsigVerification`.
- Stabilize Chromium E2E/unit coverage and align Ed25519 keystore tests.
- Sync docs, format the codebase, and restrict CI Playwright runs to Chromium.

## 0.2.6

- Release metadata update for the standalone compatibility series.

## 0.2.5

- Add standalone compatibility fallback release.

## 0.2.4

- Re-enable encrypted-keystore CI and stabilize demo checks.
- Sync pnpm lockfile with package dependencies.
- Run CI on pushes to all branches.
- Merge the standalone WebAuthn toolkit feature branch.

## 0.2.3

- Add reusable standalone WebAuthn worker and varsig toolkit exports.
- Restore ucanto signer metadata and add issuance regression coverage.
- Stabilize WebAuthn unit harness and mock credentials.
- Finalize standalone toolkit integration and README updates.
- Refresh pnpm lockfile.

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

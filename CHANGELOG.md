# Changes

## Unreleased

## 0.4.2

### Fixed

- Restore debug logging in the browser. `weald`, which `@libp2p/logger` uses,
  does `import { ms as humanize } from 'ms'` — a named export that only exists
  in `ms@3`+. All three demos pinned `ms` to `2.1.3`, which is CommonJS with no
  named export, so the import resolved to `undefined` and the first debug call
  threw `TypeError: (0, import_ms2.ms) is not a function`. Enabling `DEBUG` in a
  browser therefore crashed credential creation outright. Dropping the pin lets
  `weald` resolve the version it declares.

  This is why `webauthn-logging-e2e` had been failing continuously: it is the
  only suite that sets `localStorage.debug`, so it was the only one to reach the
  broken path.

- Clear the production dependency advisories. `iso-web > iso-kv > conf > ajv`
  carried four high `fast-uri` advisories and one moderate `ajv` one; the scoped
  overrides `conf>ajv` and `ajv>fast-uri` resolve it. Scoped deliberately: a
  blanket `ajv` override also hits ESLint, which needs ajv 6 and dies on the
  removed `missingRefs` option.
  `pnpm audit --prod` now reports nothing, so the enforced CI gate moves from
  `critical` to `moderate`.
- Stop writing WebAuthn credentials to the console. `logWebAuthnResponse()` dumped
  the whole credential — `rawId`, `attestationObject`, `clientDataJSON`,
  `signature`, `getPublicKey()` and `getClientExtensionResults()` — on every
  `navigator.credentials.create()` and `.get()`, unconditionally and in
  production code paths. Two things made that more than noise: extension results
  can carry the PRF output, which is what both the keystore encryption and (since
  0.4.1) the OrbitDB signing key derive from, and `rawId` is a stable per-user,
  per-RP identifier that landed in any console capture or session replay the
  embedding app happened to run. Replaced by a single shared helper that logs
  shape only — byte lengths, presence flags and the names of the extensions that
  returned results — behind the package debug logger, so it is silent unless
  `DEBUG=orbitdb-identity-provider-webauthn-did*` is set. Closes #22.
- Keep the demos' P2P component out of the server render. Turning on `ssr`
  so prerendering emitted real content also meant `+page.svelte` was evaluated
  in Node, and it imported the libp2p stack at module scope — reaching
  `@libp2p/webrtc` and its native `node-datachannel` binding, which the demos
  do not build. The dev server returned 500 for every request. The component is
  loaded in the browser only now; the shared shell still renders server-side, so
  prerendering keeps producing a real title and description.

### Changed

- Route the remaining informational `console.log` output through the debug
  logger. A library should not print unconditionally; `console.error` and
  `console.warn` stay as they are, so genuine failures remain visible. `src/`
  went from 61 `console.*` calls to 16, none of them `console.log`.
- Deduplicate three byte-identical copies of the WebAuthn debug helper into
  `src/webauthn/debug-log.js`.

## 0.4.1

### Added

- Derive the OrbitDB signing key from the passkey PRF output instead of letting
  the keystore generate a random one. `Identities.createIdentity` takes
  `keystore.getKey(id) || keystore.createKey(id)`, and `createKey` is random, so
  the same passkey previously produced a different `publicKey` and
  `signatures.id` — and therefore a different identity document — on every
  device. Seeding the keystore during `getId()`, the last point before OrbitDB
  asks for the key, makes the whole document reproducible: one block to keep
  retrievable for a DID instead of one per device, and a device that loses its
  keystore while keeping the passkey reconstructs the same identity rather than
  minting another. Needs no change to `@orbitdb/core`.
- `createCredential()` now requests the PRF extension even when the keystore is
  not encrypted, and stores the input. Without a stored input the output would
  differ per call, so a credential registered without one can never get a
  reproducible identity. Requesting it is harmless where unsupported.

### Notes

- Falls back cleanly. No PRF support, no stored input, or a refused assertion
  leaves the keystore to generate its own key — 0.4.0 behaviour, stable per
  device but not across devices. Opt out with
  `deriveSigningKeyFromPrf: false`.
- An existing keystore key is never replaced. Swapping it under a device that
  already has history would mint a second document for the DID, which is what
  this avoids. Installs upgrading from 0.4.0 keep their key; fresh installs get
  a reproducible identity.
- Costs one extra assertion the first time an identity is created on a device.
  The key is persisted, so later loads do not repeat it.

## 0.4.0

### Breaking

- WebAuthn credentials now yield the authenticator's actual public key, so the
  derived `did:key` **changes** for anyone who registered against 0.3.x or
  earlier. Existing OrbitDB identities keyed on the old DID will not match, and
  databases gated on it become unwritable under the new DID. `extractPublicKey()`
  never took its intended path: `cbor-web` returns byte strings as views into
  the enclosing buffer, so reading `credentialIdLength` through `authData.buffer`
  without honouring `byteOffset` read bytes from inside `rpIdHash` and yielded
  43690 for every credential. The COSE slice was then empty, `cbor` threw
  `Insufficient data`, and the `catch` silently returned a synthetic key derived
  from `SHA-256(credentialId)`.

### Fixed

- Keep the identity document stable across reloads. `signIdentity()` reuses the
  proof it already produced instead of running a fresh WebAuthn assertion, which
  changed `signatures.publicKey` — and therefore the content address of the
  identity document — on every page load. Peers then dropped entries:
  `verifiedIdentitiesCache` in `@orbitdb/core` is keyed on the deterministic
  `signatures.id`, so two documents from one keystore collide on a single cache
  entry and `isEqual()` rejects whichever was not verified first. The symptom was
  a database replicating some entries and silently never receiving the rest.
- Remove the `timestamp` field from the proof envelope and the 24-hour expiry
  check that read it. Both were wrong for a value embedded in content-addressed,
  permanent history: the timestamp changed the document hash on every call, and
  the expiry would have invalidated the identity behind every entry ever signed
  under it. Compatible in both directions — proofs that still carry a timestamp
  verify fine, and 0.3.1 verifying a proof without one computes `NaN`, which
  fails its `> maxAge` test.
- Prefer `response.getPublicKey()` (WebAuthn L2) over parsing the attestation
  object, and correct the parser: honour `byteOffset`, validate the AT flag,
  bounds-check `credentialIdLength`, and decode only the first CBOR item so
  trailing extension data (the ED flag, set when PRF is requested) no longer
  throws. The synthetic fallback is now marked `synthetic: true`.
- Fix an ambiguous locator in `ed25519-keystore-did`: `getByLabel` matches
  substrings, and the demo's worker toggle is labelled
  "Use worker-backed Ed25519 keystore".

### Added

- Two-peer OrbitDB replication tests: real libp2p over loopback TCP, Helia with
  bitswap, gossipsub, two OrbitDB instances, driven by a software WebAuthn
  authenticator with a real P-256 keypair, an incrementing signature counter and
  randomised signatures. Covers identity-document stability across reloads,
  replication of entries written before and after a reload, and that two devices
  sharing a passkey keep distinct, independently valid identities.
- Attestation-parsing unit tests: credential ID lengths 16/20/32/64/128,
  trailing extension data, missing AT flag, non-P-256 COSE keys and truncated
  coordinates. 13 of the 14 fail against 0.3.1.

### Changed

- CI now runs all eleven test files. Five never ran: `webauthn-unit`,
  `webauthn-verification`, `standalone-toolkit`, `ed25519-keystore-did` and
  `simple-encryption-integration`. `webauthn-unit` imports through Vite's `/@fs`
  endpoint, which only the dev server exposes, so its step runs against `dev`
  rather than the `preview` build CI otherwise uses.
- Publishing moves into CI. A `v*` tag runs the full suite and then publishes
  via npm Trusted Publishing (OIDC), with provenance. A manual run defaults to a
  check mode that verifies tag/version agreement and packaging without
  publishing.
- `test:ci`, which `preversion` and `prepublishOnly` run, now points at the
  Node-context suites via `playwright.node.config.js` — 32 tests in about ten
  seconds. It previously ran `webauthn-verification` alone: five tests that check
  regexes against hardcoded DID literals and one fully mocked database object,
  none of which creates a credential, touches the keystore or opens an OrbitDB.
- Restore the `security-audit`, `package-validation` and `notify` jobs. The
  enforced audit gate is `--prod --audit-level=critical`; auditing the full tree
  at `moderate` reports 86 advisories from the helia and libp2p dev tree, and
  even `--prod` reports 5 through `iso-web > iso-kv > conf > ajv`, so both wider
  audits run informational until that chain is bumped.

### Also shipping in this release

Entries that had accumulated under Unreleased since 0.3.1:

- Add `SECURITY.md` with vulnerability reporting and supported-version policy.
- Rename `changes.md` to `CHANGELOG.md` and include it in the published package.
- Add public TypeScript declarations for the root, standalone, verification,
  and keystore package entrypoints.
- Add `docs/API.md` and expose `@le-space/orbitdb-identity-provider-webauthn-did/keystore`
  as a typed package subpath.
- Remove the Vite node polyfill plugin from production dependencies, update
  the varsig support stack to `iso-web@^3.1.2`, and verify
  `npm audit --omit=dev` reports zero production advisories.
- Re-enable the CI lint step and verify `pnpm run lint` passes.
- Add shared public constants and catchable error classes for WebAuthn,
  keystore, and varsig flows.
- Add root Prettier scripts, ignore rules, and a CI formatting check.
- Add `CODE_OF_CONDUCT.md` and include it in the published package.

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

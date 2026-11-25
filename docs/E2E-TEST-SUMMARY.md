# Test Summary

## Four configurations

`playwright.config.js` runs everything against a demo app. It declares a
`webServer`, so every run there — including the suites that never open a page —
installs and builds one of:

- `examples/webauthn-todo-demo`
- `examples/ed25519-encrypted-keystore-demo`
- `examples/webauthn-varsig-demo`

Which one is picked comes from the test filename and the `USE_ENCRYPTED_DEMO` /
`USE_VARSIG_DEMO` env flags. The server listens on `PLAYWRIGHT_PORT` (5173 by
default), but seven suites go to `http://localhost:5173` by its full URL
instead of `/`: `webauthn-focused`, `webauthn-integration`,
`webauthn-logging-e2e`, `encrypted-keystore`, `ed25519-encrypted-keystore-e2e`,
`ed25519-keystore-did` and `simple-encryption-integration`. With another
port they reach nothing, or a different server. With `CI` set the config
starts the demo's `preview` instead of its dev server, which serves the last
build, so build the demos first (`pnpm --dir examples -r run build`).

`playwright.node.config.js` selects only the Node-context suites. They import
the package directly and need neither a browser nor a demo server, so they run
in seconds. `test:ci` points here, and `preversion` and `prepublishOnly` run
`test:ci`. Releases no longer depend on those hooks: `.github/workflows/release.yml`
runs all of `ci.yml` as its test gate and publishes with `--ignore-scripts`,
so `prepublishOnly` does not run there.

`playwright.elements.config.js` runs `passkey-step-dialog` in Chromium. The
custom element needs a DOM but no demo: each test serves the element's source
to a blank page itself.

`playwright.fork.config.js` runs the suites in
`packages/passkey-wallet/test/fork` — Calibur checking the wallet's ERC-7739
signatures on an anvil fork of Sepolia. They need Foundry and a Sepolia RPC
URL with a provider key in `PASSKEY_WALLET_FORK_URL`;
`pnpm run test:wallet-fork` stops with a message when it is missing.

## Suites since 0.9.0

Node context (`playwright.node.config.js`):

- `prf-keys` (0.9.0) — `readPrfOutput`, `deriveSubkey`, `deriveAesKey`, vectors
  from the applications that derived their own keys before, and the provider
  taking `prfOutput` without a second touch.
- `vault` (0.9.0) — the vault record: slots, refusals, what binds each
  ciphertext.
- `passkey-wallet-session-key` (0.9.0) — `@le-space/passkey-wallet`'s sealed
  Zama session key, opening an envelope sealed by the code simple-todo's
  escrow01 runs.
- `webauthn-authenticator-type` (0.9.1) — what a registration asks for with
  each `authenticatorType`, in the request itself.
- `secret-signer` (0.10.0) — `createSecretSigner`: the same identity through
  every slot, two keys writing as one root, an identity from another secret
  refused.
- `stale-identity-cache` (0.11.0) — `createIdentities` and
  `withoutStaleIdentityCache`.
- `passkey-wallet-erc7739` (0.11.0) — the wallet's ERC-7739 hashes, recomputed
  without a chain.
- `vault-keeper` (0.12.0) — `createVaultKeeper`, including a store Belege's
  own code wrote.
- `vault-entry` (0.12.0) — the `./vault` entry imports no package.
- `ipfs-identity-storage` (0.12.1) — loading another peer's varsig identity
  from IPFS.
- `passkey-steps` (0.13.0) — the step hook before each passkey prompt.

Chromium, against the dev server (`CI` cleared, see below):

- `vault-two-authenticators` (0.9.0) — two virtual authenticators, each with
  its own PRF secret, opening one vault; unlocking is one touch.
- `webauthn-security-key` (0.9.1) — registering a roaming key on the USB
  transport, and which registrations offer it.

Chromium, `playwright.elements.config.js`:

- `passkey-step-dialog` (0.13.0) — `<passkey-step-dialog>`.

Sepolia fork, `playwright.fork.config.js`:

- `packages/passkey-wallet/test/fork/erc7739.test.js` (0.11.0) — Calibur
  v1.0.0 accepting the wallet's signatures.

## Counting the tests

Numbers written into a document go stale silently, so ask the runner:

```bash
# every suite, every browser project
pnpm exec playwright test --list

# what CI actually runs
pnpm exec playwright test --list --project=chromium

# the fast Node-context subset
pnpm exec playwright test --list --config=playwright.node.config.js
```

## CI

`.github/workflows/ci.yml` has four jobs.

`test` runs lint, the format check and the Node-context suites
(`pnpm run test:node`) before it installs any browser. Then the custom
element suite (`playwright.elements.config.js`), then the demos are built and
every other test file runs in Chromium, most as a step of their own.

A file in `tests/` runs in CI only if something selects it, so a new one needs
either an entry in `playwright.node.config.js` — if it opens no page — or a
step that names it. `scripts/check-ci-runs-every-test.mjs` runs early in the
job and fails it when neither is there; run it locally with
`node scripts/check-ci-runs-every-test.mjs`. It exists because forgetting this
happened twice: five suites had never run in CI before 0.4.0, and eight more
between July and September 2026.

CI installs with pnpm's default isolated `node_modules`, where a test can import
only packages this repository declares. With `node-linker=hoisted` in a local
pnpm config, every transitive package is importable too, so a suite can pass
locally and fail to load in CI. To reproduce CI, install with
`pnpm install --config.node-linker=isolated`.

Two details worth knowing about the Chromium steps:

- `webauthn-unit`, `vault-two-authenticators` and `webauthn-security-key` run
  with `CI` cleared. They load the package through Vite's `/@fs` endpoint
  (`tests/helpers/library-in-page.js`), which only the dev server exposes; CI
  otherwise starts `preview`, whose static build has no such route.
- The encrypted-demo suites get `USE_ENCRYPTED_DEMO: true`.

`wallet-fork` runs `pnpm run test:wallet-fork` with `PASSKEY_WALLET_FORK_URL`
from a repository secret of that name. It runs for pull requests and for
pushes to `main` only, to spare the RPC's quota. Pull requests from forks get
no secrets, so there its steps are skipped with a notice. A release gets
none either: `release.yml` passes `ci.yml` no secrets, so on a tag push the
job's condition leaves it out, and in a manual run its steps are skipped.

`security-audit` reports `pnpm audit` and enforces it at `moderate` for
production dependencies. `package-validation` packs the package, checks that
the declared entry points are in the tarball, and imports the subpath exports
from an installed copy.

## Useful commands

```bash
pnpm run lint
pnpm run test:node          # Node-context suites, no browser
pnpm run test:all           # every suite in tests/, with a demo server
pnpm exec playwright test --config=playwright.elements.config.js
PASSKEY_WALLET_FORK_URL=<sepolia rpc> pnpm run test:wallet-fork

# a single suite in Chromium
pnpm exec playwright test tests/encrypted-keystore.test.js --project=chromium --reporter=line

# force the encrypted demo
USE_ENCRYPTED_DEMO=true pnpm exec playwright test tests/ed25519-encrypted-keystore-e2e.test.js --project=chromium --reporter=line
```

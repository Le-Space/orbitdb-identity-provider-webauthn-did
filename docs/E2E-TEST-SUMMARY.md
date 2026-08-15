# Test Summary

## Two configurations

`playwright.config.js` runs everything against a demo app. It declares a
`webServer`, so every run there — including the suites that never open a page —
installs and builds one of:

- `examples/webauthn-todo-demo`
- `examples/ed25519-encrypted-keystore-demo`
- `examples/webauthn-varsig-demo`

Which one is picked comes from the test filename and the `USE_ENCRYPTED_DEMO` /
`USE_VARSIG_DEMO` env flags.

`playwright.node.config.js` selects only the Node-context suites. They import
the package directly and need neither a browser nor a demo server, so they run
in seconds. `test:ci` — what `preversion` and `prepublishOnly` invoke — points
here.

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

`.github/workflows/ci.yml` runs each test file as its own step, in Chromium.
Two details worth knowing:

- `webauthn-unit` runs with `CI` cleared. It loads the package through Vite's
  `/@fs` endpoint, which only the dev server exposes; CI otherwise starts
  `preview`, whose static build has no such route.
- The encrypted-demo suites get `USE_ENCRYPTED_DEMO: true`.

## Useful commands

```bash
pnpm run lint
pnpm run test:node          # Node-context suites, no browser
pnpm run test:all           # everything

# a single suite in Chromium
pnpm exec playwright test tests/encrypted-keystore.test.js --project=chromium --reporter=line

# force the encrypted demo
USE_ENCRYPTED_DEMO=true pnpm exec playwright test tests/ed25519-encrypted-keystore-e2e.test.js --project=chromium --reporter=line
```

# E2E Test Summary

## Scope

This repository runs Playwright tests against demo apps selected by `playwright.config.js`:

- `examples/webauthn-todo-demo`
- `examples/ed25519-encrypted-keystore-demo`
- `examples/webauthn-varsig-demo`

The selector uses test filename patterns and the env flags `USE_ENCRYPTED_DEMO` / `USE_VARSIG_DEMO`.

## Current Test Files (Chromium)

- `tests/webauthn-focused.test.js`
- `tests/webauthn-integration.test.js`
- `tests/webauthn-logging-e2e.test.js`
- `tests/webauthn-varsig-e2e.test.js`
- `tests/ed25519-encrypted-keystore-e2e.test.js` (11 tests + 1 skipped)
- `tests/ed25519-keystore-did.test.js` (7 tests)
- `tests/encrypted-keystore.test.js` (17 tests)
- `tests/simple-encryption-integration.test.js` (4 tests)

## Latest Local Verification

The latest step-by-step Chromium runs completed green for the encrypted/worker-related path:

- `tests/ed25519-encrypted-keystore-e2e.test.js`: `11 passed`, `1 skipped`
- `tests/ed25519-keystore-did.test.js`: `6 passed`
- `tests/encrypted-keystore.test.js`: `17 passed`
- `tests/simple-encryption-integration.test.js`: `4 passed`

## CI Workflow

Tests are executed from:

- `.github/workflows/ci.yml`

This workflow builds all three demo apps and runs the relevant Playwright test groups in Chromium.

## Useful Commands

```bash
# Main lint check
npm run lint

# Full Playwright suite (all configured projects)
npm test

# Chromium-only example
npx playwright test tests/encrypted-keystore.test.js --project=chromium --reporter=line

# Force encrypted demo routing
USE_ENCRYPTED_DEMO=true npx playwright test tests/ed25519-encrypted-keystore-e2e.test.js --project=chromium --reporter=line
```

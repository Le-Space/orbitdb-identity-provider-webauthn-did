/**
 * The passkey vault on its own: reading the PRF output, deriving keys from it,
 * vaults any registered authenticator opens, and a keeper for them.
 *
 * Nothing here imports OrbitDB, ucanto, libp2p or any other package: it needs
 * WebCrypto and `navigator.credentials`, and no more, so an application that
 * keeps its data elsewhere pays for nothing else
 * (`tests/vault-entry.test.js` holds it to that).
 */
export {
  readPrfOutput,
  deriveSubkey,
  deriveAesKey,
} from '../keystore/prf-keys.js';
export {
  createVault,
  openVault,
  addSlot,
  removeSlot,
  replacePayload,
  slotIdFor,
} from '../keystore/vault.js';
export {
  createVaultKeeper,
  rootPayload,
  rootOf,
} from '../keystore/vault-keeper.js';
export { PrfUnavailableError, VaultError } from '../errors.js';

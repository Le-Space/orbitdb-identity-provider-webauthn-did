/**
 * `@le-space/orbitdb-identity-provider-webauthn-did/vault`: the passkey vault
 * on its own — PRF output, keys derived from it, vaults any registered
 * authenticator opens, and a keeper for them. WebCrypto only.
 */
export {
  readPrfOutput,
  deriveSubkey,
  deriveAesKey,
  Vault,
  VaultSlotKey,
  createVault,
  openVault,
  addSlot,
  removeSlot,
  replacePayload,
  slotIdFor,
  createVaultKeeper,
  rootPayload,
  rootOf,
  VaultKeeper,
  VaultRecord,
  VaultSlotInfo,
  OpenedVault,
  VaultPasskey,
  VaultErrorCode,
  PrfUnavailableError,
  VaultError,
} from './standalone';

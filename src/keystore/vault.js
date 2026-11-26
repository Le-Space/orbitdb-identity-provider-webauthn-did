/**
 * @module Vault
 * @description
 * A secret that several authenticators can open.
 *
 * A key derived from a passkey exists only where that passkey is. That is
 * right for a signature and wrong for data that has to outlive a lost
 * security key: a second key kept in a drawer has its own PRF secret, so it
 * derives different keys and cannot open what the first one sealed. A vault
 * holds such data — a database key, database names, a peer seed — sealed under
 * a random vault key, and gives each registered authenticator a slot: the
 * vault key, sealed under a key that authenticator derives from its PRF
 * output (`deriveAesKey(prfOutput, '<app>/vault-slot/v1')`). Any slot opens
 * the vault.
 *
 * The record is plain JSON and holds nothing secret in the clear, so it can be
 * stored anywhere, replicated, and included in a public backup. Every
 * ciphertext in it is bound to the vault's id, and every slot also to the
 * authenticator it belongs to, so neither can be moved to another vault or
 * relabelled to another authenticator without failing to open.
 *
 * What a vault does not do:
 * - Removing a slot revokes nothing that was already opened. An authenticator
 *   that opened the vault has seen the vault key, and older copies of the
 *   record still carry its slot. Against a stolen key, make a new vault with a
 *   new key and move what the old one protected.
 * - It cannot tell the current record from an earlier copy of itself. Where a
 *   rollback matters, the place the record is stored has to say which is
 *   current.
 *
 * What it does do about earlier copies: a vault that replaces another — made
 * because an authenticator was lost or stolen — carries a **generation**, one
 * more than the vault it replaces, bound into every ciphertext. A slot is
 * sealed under a key only its authenticator derives, so a slot that opens at
 * generation 3 is that authenticator's word that it took part in making
 * generation 3; nobody else can raise the number for it, the removed
 * authenticator included, which knows the old vault key and nothing more.
 * Given two records its slot opens, whoever holds them can tell which is
 * later (`generationOf`). What no record can say is that a later one exists
 * somewhere it was not shown.
 *
 * Format, version 1 — a vault that replaces none, generation 0:
 *
 *     {
 *       "version": 1,
 *       "algorithm": "AES-GCM",
 *       "id": "<16 random bytes, hex>",
 *       "payload": { "iv": "<12 bytes, hex>", "ciphertext": "<hex>" },
 *       "slots": [
 *         { "kid": "<SHA-256 of the raw credential id, hex>",
 *           "iv": "<12 bytes, hex>", "ciphertext": "<48 bytes, hex>" }
 *       ]
 *     }
 *
 * Associated data, part of the format: `@le-space/vault:v1:payload:<id>` for
 * the payload, `@le-space/vault:v1:slot:<id>:<kid>` for each slot.
 *
 * Format, version 2 — a vault that replaces another: the same, with
 * `"version": 2` and `"generation": <integer, 1 or more>`, and the generation
 * at the end of the associated data: `@le-space/vault:v2:payload:<id>:<generation>`
 * and `@le-space/vault:v2:slot:<id>:<kid>:<generation>`. Code that only knows
 * version 1 refuses such a record as malformed, which is the right answer to
 * a vault it cannot place.
 */
import { ERROR_CODES, VaultError } from '../errors.js';

const VERSION = 1;
const GENERATION_VERSION = 2;
const ALGORITHM = 'AES-GCM';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const ID_BYTES = 16;
const TAG_BYTES = 16;
const encoder = new TextEncoder();

const HEX = /^(?:[0-9a-f]{2})*$/;

/** @param {Uint8Array} bytes */
const toHex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** @param {string} hex */
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return bytes;
}

/** @param {unknown} value @param {string} what @returns {Uint8Array} */
function bytesOf(value, what) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new TypeError(`${what} must be bytes`);
}

/** The end of the associated data: nothing for version 1, the generation after. */
const generationSuffix = (vault) =>
  vault.version === GENERATION_VERSION ? `:${vault.generation}` : '';

/** @param {{ version: number, id: string, generation?: number }} vault */
const payloadAad = (vault) =>
  encoder.encode(
    `@le-space/vault:v${vault.version}:payload:${vault.id}${generationSuffix(vault)}`
  );

/** @param {{ version: number, id: string, generation?: number }} vault @param {string} kid */
const slotAad = (vault, kid) =>
  encoder.encode(
    `@le-space/vault:v${vault.version}:slot:${vault.id}:${kid}${generationSuffix(vault)}`
  );

/** @param {unknown} generation */
const isGeneration = (generation) =>
  Number.isSafeInteger(generation) && /** @type {number} */ (generation) >= 0;

/**
 * An AES-GCM key from a CryptoKey or 32 raw bytes.
 * @param {CryptoKey|Uint8Array} key
 * @param {string} what
 * @returns {Promise<CryptoKey>}
 */
async function aesKey(key, what) {
  if (key instanceof Uint8Array) {
    if (key.length !== KEY_BYTES) {
      throw new TypeError(`${what} must be ${KEY_BYTES} bytes`);
    }
    return crypto.subtle.importKey('raw', key, ALGORITHM, false, [
      'encrypt',
      'decrypt',
    ]);
  }
  if (
    !key ||
    typeof key !== 'object' ||
    key.type !== 'secret' ||
    key.algorithm?.name !== ALGORITHM
  ) {
    throw new TypeError(
      `${what} must be an AES-GCM CryptoKey or ${KEY_BYTES} raw bytes`
    );
  }
  return key;
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} additionalData
 */
async function seal(key, plaintext, additionalData) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv, additionalData },
    key,
    plaintext
  );
  return { iv: toHex(iv), ciphertext: toHex(new Uint8Array(ciphertext)) };
}

/**
 * @param {CryptoKey} key
 * @param {{ iv: string, ciphertext: string }} sealed
 * @param {Uint8Array} additionalData
 * @param {string} what
 */
async function open(key, sealed, additionalData, what) {
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: ALGORITHM, iv: fromHex(sealed.iv), additionalData },
        key,
        fromHex(sealed.ciphertext)
      )
    );
  } catch (cause) {
    throw new VaultError(
      `${what} does not open with this key, or was altered`,
      {
        code: ERROR_CODES.VAULT_LOCKED,
        cause,
      }
    );
  }
}

/** @param {unknown} value @param {number} [bytes] */
const isHex = (value, bytes) =>
  typeof value === 'string' &&
  HEX.test(value) &&
  (bytes === undefined || value.length === 2 * bytes);

/**
 * Throws unless `vault` has the shape of a vault: version 1 without a
 * generation, or version 2 with one of at least 1.
 * @param {unknown} vault
 */
function assertVault(vault) {
  const versioned =
    vault &&
    typeof vault === 'object' &&
    (vault.version === VERSION
      ? vault.generation === undefined
      : vault.version === GENERATION_VERSION &&
        isGeneration(vault.generation) &&
        vault.generation >= 1);
  const ok =
    versioned &&
    vault.algorithm === ALGORITHM &&
    isHex(vault.id, ID_BYTES) &&
    vault.payload &&
    isHex(vault.payload.iv, IV_BYTES) &&
    isHex(vault.payload.ciphertext) &&
    vault.payload.ciphertext.length >= 2 * TAG_BYTES &&
    Array.isArray(vault.slots) &&
    vault.slots.every(
      (slot) =>
        slot &&
        isHex(slot.kid, 32) &&
        isHex(slot.iv, IV_BYTES) &&
        isHex(slot.ciphertext, KEY_BYTES + TAG_BYTES)
    );
  if (!ok) {
    throw new VaultError('Not a vault this version can read', {
      code: ERROR_CODES.VAULT_MALFORMED,
    });
  }
}

/** A record with the same fields, nothing shared with the original. */
const copyOf = (vault) => ({
  version: vault.version,
  algorithm: vault.algorithm,
  id: vault.id,
  ...(vault.version === GENERATION_VERSION
    ? { generation: vault.generation }
    : {}),
  payload: { iv: vault.payload.iv, ciphertext: vault.payload.ciphertext },
  slots: vault.slots.map((slot) => ({
    kid: slot.kid,
    iv: slot.iv,
    ciphertext: slot.ciphertext,
  })),
});

/**
 * The slot id an authenticator's slot is filed under: SHA-256 of its raw
 * credential id, hex. The raw id itself is never written into the record.
 *
 * @param {Uint8Array} rawCredentialId
 * @returns {Promise<string>}
 */
export async function slotIdFor(rawCredentialId) {
  const id = bytesOf(rawCredentialId, 'rawCredentialId');
  if (id.length === 0) throw new TypeError('rawCredentialId is empty');
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', id)));
}

/**
 * The vault key must open the payload before anything is sealed under it, so
 * a wrong key can never leave behind a slot or a payload nobody can open.
 *
 * @param {object} vault - A checked vault.
 * @param {Uint8Array} vaultKey
 * @returns {Promise<CryptoKey>}
 */
async function provenVaultKey(vault, vaultKey) {
  if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== KEY_BYTES) {
    throw new TypeError(
      `vaultKey must be the ${KEY_BYTES} bytes the vault gave`
    );
  }
  const key = await aesKey(vaultKey, 'vaultKey');
  await open(key, vault.payload, payloadAad(vault), 'The vault');
  return key;
}

/**
 * How many vaults this one has replaced, one after another: 0 for a vault
 * made fresh, one more for each renewal. Of two records an authenticator's
 * slot opens, the one with the higher generation is the later — see the
 * module description for why that can be believed, and what it cannot tell.
 *
 * Read from the record; only opening it shows the number is genuine.
 *
 * @param {object} vault
 * @returns {number}
 * @throws {VaultError} `VAULT_MALFORMED`
 */
export function generationOf(vault) {
  assertVault(vault);
  return vault.version === GENERATION_VERSION ? vault.generation : 0;
}

/**
 * A new vault holding `payload`, with one slot for the authenticator that
 * creates it. A vault without a slot could never be opened, so there is no way
 * to make one.
 *
 * @param {Uint8Array} payload - What the vault keeps, as bytes.
 * @param {Object} firstSlot
 * @param {CryptoKey|Uint8Array} firstSlot.slotKey - From `deriveAesKey`.
 * @param {Uint8Array} firstSlot.rawCredentialId
 * @param {Object} [options]
 * @param {number} [options.generation=0] - For a vault that replaces another:
 *   `generationOf(replaced) + 1`. Every authenticator given a slot in it
 *   vouches for that number.
 * @returns {Promise<{ vault: object, vaultKey: Uint8Array }>} The record to
 *   store, and the vault key to keep in memory while the vault is open.
 */
export async function createVault(
  payload,
  { slotKey, rawCredentialId } = {},
  { generation = 0 } = {}
) {
  if (!isGeneration(generation)) {
    throw new TypeError('generation must be a non-negative integer');
  }
  const plaintext = bytesOf(payload, 'payload');
  const slotCryptoKey = await aesKey(slotKey, 'slotKey');
  const kid = await slotIdFor(rawCredentialId);

  const vaultKey = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
  const id = toHex(crypto.getRandomValues(new Uint8Array(ID_BYTES)));
  const vaultCryptoKey = await aesKey(vaultKey, 'vaultKey');

  const header =
    generation === 0
      ? { version: VERSION, algorithm: ALGORITHM, id }
      : { version: GENERATION_VERSION, algorithm: ALGORITHM, id, generation };
  const vault = {
    ...header,
    payload: await seal(vaultCryptoKey, plaintext, payloadAad(header)),
    slots: [
      { kid, ...(await seal(slotCryptoKey, vaultKey, slotAad(header, kid))) },
    ],
  };
  return { vault, vaultKey };
}

/**
 * Open the vault with one authenticator's slot.
 *
 * @param {object} vault
 * @param {Object} slot
 * @param {CryptoKey|Uint8Array} slot.slotKey - From `deriveAesKey`.
 * @param {Uint8Array} slot.rawCredentialId
 * @returns {Promise<{ payload: Uint8Array, vaultKey: Uint8Array }>}
 * @throws {VaultError} `VAULT_NO_SLOT` when this authenticator has none,
 *   `VAULT_LOCKED` when the slot or payload does not open.
 */
export async function openVault(vault, { slotKey, rawCredentialId } = {}) {
  assertVault(vault);
  const kid = await slotIdFor(rawCredentialId);
  const slot = vault.slots.find((candidate) => candidate.kid === kid);
  if (!slot) {
    throw new VaultError('This authenticator has no slot in the vault', {
      code: ERROR_CODES.VAULT_NO_SLOT,
    });
  }
  const vaultKey = await open(
    await aesKey(slotKey, 'slotKey'),
    slot,
    slotAad(vault, kid),
    'The slot'
  );
  const payload = await open(
    await aesKey(vaultKey, 'vaultKey'),
    vault.payload,
    payloadAad(vault),
    'The vault'
  );
  return { payload, vaultKey };
}

/**
 * A slot for one more authenticator. Needs the vault open — its `vaultKey` —
 * and the new authenticator's slot key, so in practice both are at hand at
 * once: the vault is opened, then the new key is touched.
 *
 * @param {object} vault
 * @param {Uint8Array} vaultKey - From `openVault` or `createVault`.
 * @param {Object} slot
 * @param {CryptoKey|Uint8Array} slot.slotKey - The new authenticator's.
 * @param {Uint8Array} slot.rawCredentialId - The new authenticator's.
 * @returns {Promise<object>} A new record; the one passed in is unchanged.
 * @throws {VaultError} `VAULT_SLOT_EXISTS`, or `VAULT_LOCKED` when `vaultKey`
 *   does not open this vault.
 */
export async function addSlot(
  vault,
  vaultKey,
  { slotKey, rawCredentialId } = {}
) {
  assertVault(vault);
  await provenVaultKey(vault, vaultKey);
  const kid = await slotIdFor(rawCredentialId);
  if (vault.slots.some((slot) => slot.kid === kid)) {
    throw new VaultError('This authenticator already has a slot', {
      code: ERROR_CODES.VAULT_SLOT_EXISTS,
    });
  }
  const sealed = await seal(
    await aesKey(slotKey, 'slotKey'),
    bytesOf(vaultKey, 'vaultKey'),
    slotAad(vault, kid)
  );
  const next = copyOf(vault);
  next.slots.push({ kid, ...sealed });
  return next;
}

/**
 * The vault without one authenticator's slot. Needs no key: whoever may write
 * the record may shorten it, so guard the record where it is stored.
 *
 * Revokes nothing already opened — see the module description.
 *
 * @param {object} vault
 * @param {Uint8Array} rawCredentialId - The authenticator to remove.
 * @returns {Promise<object>} A new record; the one passed in is unchanged.
 * @throws {VaultError} `VAULT_NO_SLOT`, or `VAULT_LAST_SLOT` — a vault
 *   without a slot could never be opened again.
 */
export async function removeSlot(vault, rawCredentialId) {
  assertVault(vault);
  return removeSlotById(vault, await slotIdFor(rawCredentialId));
}

/**
 * `removeSlot` by the slot id itself, for an authenticator only known by the
 * id its slot is filed under — one that is not at hand. Used by the vault
 * keeper; not part of the package's entries.
 *
 * @param {object} vault
 * @param {string} kid - From `slotIdFor`.
 * @returns {object} A new record; the one passed in is unchanged.
 * @throws {VaultError} `VAULT_NO_SLOT` or `VAULT_LAST_SLOT`.
 */
export function removeSlotById(vault, kid) {
  assertVault(vault);
  if (!vault.slots.some((slot) => slot.kid === kid)) {
    throw new VaultError('This authenticator has no slot in the vault', {
      code: ERROR_CODES.VAULT_NO_SLOT,
    });
  }
  if (vault.slots.length === 1) {
    throw new VaultError(
      'The last slot cannot be removed: nothing could open the vault',
      { code: ERROR_CODES.VAULT_LAST_SLOT }
    );
  }
  const next = copyOf(vault);
  next.slots = next.slots.filter((slot) => slot.kid !== kid);
  return next;
}

/**
 * The vault with a new payload, under the same vault key and the same slots —
 * for when what it keeps changes, e.g. a pointer key for a new authenticator.
 *
 * @param {object} vault
 * @param {Uint8Array} vaultKey - From `openVault` or `createVault`.
 * @param {Uint8Array} payload
 * @returns {Promise<object>} A new record; the one passed in is unchanged.
 * @throws {VaultError} `VAULT_LOCKED` when `vaultKey` does not open this vault.
 */
export async function replacePayload(vault, vaultKey, payload) {
  assertVault(vault);
  const key = await provenVaultKey(vault, vaultKey);
  const next = copyOf(vault);
  next.payload = await seal(
    key,
    bytesOf(payload, 'payload'),
    payloadAad(vault)
  );
  return next;
}

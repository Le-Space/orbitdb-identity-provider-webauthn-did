/**
 * @module VaultKeeper
 * @description
 * Where an application keeps its vaults, and what it does with them: on every
 * unlock, find this authenticator's slot and open the vault, or make one; give
 * a second key a slot; take a key out; renew the vault key.
 *
 * Le-Space/belege and Le-Space/invoice each wrote this for themselves around
 * the same vault (`vault.js`), and the simple-todo chapters would have been
 * the third copy. The rules are the same everywhere, and each is easy to get
 * wrong once: an unreadable store is never overwritten, a removed key is
 * refused instead of being given new, empty books, and a renewal leaves no
 * key out that was meant to stay.
 *
 * The store is the application's: anything with `getItem` and `setItem`, as
 * `localStorage` has them. Under one key it holds a JSON array, one record per
 * vault:
 *
 *     {
 *       "vault": { ...a version-1 vault, see vault.js },
 *       "slots": [
 *         { "kid": "<slot id>", "label": "YubiKey 5C",
 *           "credentialId": "<base64url>", "addedAt": "<ISO 8601>" }
 *       ],
 *       "removed": ["<slot id>"]
 *     }
 *
 * `slots` says in public which authenticator each slot belongs to, so an
 * application can name them, and ask each one that stays when it renews the
 * vault. `removed` remembers the authenticators taken out here. Fields the
 * keeper does not know are kept as they are. This is the format Belege has
 * kept since its vault (Le-Space/belege#406), so its records open unchanged.
 *
 * What goes into the vault is the application's too, as bytes. The simplest
 * choice is one random root, with every key the application needs derived
 * from it — `deriveSubkey(root, '<app>/<purpose>/v1')` — so the vault never
 * has to change when the application needs one more key. `rootPayload` and
 * `rootOf` write and read such a root, in the bytes Belege writes.
 *
 * What the keeper does not do:
 * - It holds no secret. The PRF output and the vault key stay with the caller,
 *   in what `open` returns, for as long as the vault is open.
 * - It decides nothing about where a record travels. `find` is the hook for a
 *   vault kept elsewhere — in a backup, in an index.
 * - It cannot know of a renewal it is not shown. Of the records it is shown
 *   it takes the latest and never steps back (see `open`), but a device with
 *   an empty store that `find` hands only the vault from before a renewal
 *   opens that one: nothing in an old record says it was replaced. Where a
 *   removed authenticator may be in other hands, the place `find` reads has
 *   to hold the renewed record — and not be writable by whoever holds that
 *   authenticator — or the application has to check `generation` and
 *   `record.vault.id` against something it trusts.
 * - Two pages writing one store at once: the last write wins. A record is
 *   replaced whole, by its vault id.
 */
import { ERROR_CODES, VaultError } from '../errors.js';
import { deriveAesKey } from './prf-keys.js';
import {
  addSlot,
  createVault,
  generationOf,
  openVault,
  removeSlotById,
  replacePayload as replaceVaultPayload,
  slotIdFor,
} from './vault.js';

const ROOT_VERSION = 1;
const ROOT_BYTES = 32;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

/** @param {unknown} value @returns {Uint8Array} */
function bytesOf(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new TypeError('rawCredentialId must be bytes');
}

/** As WebAuthn writes a credential's id. @param {Uint8Array} bytes */
const base64url = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

/**
 * A root as vault payload: `{"version":1,"root":"<hex>"}`.
 *
 * @param {Uint8Array} root - 32 bytes, e.g. `crypto.getRandomValues`.
 * @returns {Uint8Array}
 */
export function rootPayload(root) {
  if (!(root instanceof Uint8Array) || root.length !== ROOT_BYTES) {
    throw new TypeError(`root must be ${ROOT_BYTES} bytes`);
  }
  return encoder.encode(
    JSON.stringify({ version: ROOT_VERSION, root: toHex(root) })
  );
}

/**
 * The root a payload from `rootPayload` holds.
 *
 * @param {Uint8Array} payload
 * @returns {Uint8Array} 32 bytes.
 * @throws {VaultError} `VAULT_MALFORMED` for anything else.
 */
export function rootOf(payload) {
  let parsed;
  try {
    parsed = JSON.parse(decoder.decode(payload));
  } catch (cause) {
    throw new VaultError('The vault holds no root', {
      code: ERROR_CODES.VAULT_MALFORMED,
      cause,
    });
  }
  if (
    parsed?.version !== ROOT_VERSION ||
    typeof parsed.root !== 'string' ||
    !new RegExp(`^[0-9a-f]{${2 * ROOT_BYTES}}$`).test(parsed.root)
  ) {
    throw new VaultError('The vault holds no root', {
      code: ERROR_CODES.VAULT_MALFORMED,
    });
  }
  return fromHex(parsed.root);
}

/** @param {object} record @param {string} kid */
const holds = (record, kid) =>
  record.vault.slots.some((slot) => slot?.kid === kid);

/** @param {unknown} record */
const isRecord = (record) =>
  Boolean(record) &&
  typeof record === 'object' &&
  Boolean(record.vault) &&
  typeof record.vault === 'object' &&
  Array.isArray(record.vault.slots);

/** The record with `slots` and `removed` as arrays, everything else kept. */
const normalised = (record) => ({
  ...record,
  slots: Array.isArray(record.slots) ? record.slots : [],
  removed: Array.isArray(record.removed) ? record.removed.map(String) : [],
});

/** A record's generation, or -1 for one whose vault this version cannot read. */
function generationOfRecord(record) {
  try {
    return generationOf(record.vault);
  } catch {
    return -1;
  }
}

/** @param {Uint8Array|undefined} payload */
function payloadBytes(payload, what) {
  if (!(payload instanceof Uint8Array)) {
    throw new TypeError(`${what} must be the payload as bytes`);
  }
  return payload;
}

/**
 * A keeper for the vaults kept under `key` in `storage`.
 *
 * @param {Object} options
 * @param {Pick<Storage, 'getItem' | 'setItem'>} options.storage - Where the
 *   records are kept, e.g. `localStorage`.
 * @param {string} options.key - The storage key, e.g. `myapp.vaults.v1`.
 * @param {string} options.slotInfo - The `info` every slot key is derived
 *   under, e.g. `myapp/vault-slot/v1`. Part of the data format: changed, no
 *   slot opens any more.
 * @param {() => Date} [options.now] - When a slot was added.
 */
export function createVaultKeeper({
  storage,
  key,
  slotInfo,
  now = () => new Date(),
} = {}) {
  if (
    !storage ||
    typeof storage.getItem !== 'function' ||
    typeof storage.setItem !== 'function'
  ) {
    throw new TypeError(
      'createVaultKeeper needs a storage with getItem and setItem'
    );
  }
  if (typeof key !== 'string' || key === '') {
    throw new TypeError(
      'createVaultKeeper needs the key its vaults are kept under'
    );
  }
  if (typeof slotInfo !== 'string' || slotInfo === '') {
    throw new TypeError(
      'createVaultKeeper needs the info slot keys are derived under, e.g. "myapp/vault-slot/v1"'
    );
  }

  const slotKeyOf = (prfOutput) => deriveAesKey(prfOutput, slotInfo);

  const unreadable = (cause) =>
    new VaultError(
      `The vaults kept under "${key}" cannot be read; they are left as they are`,
      { code: ERROR_CODES.VAULT_STORE_UNREADABLE, cause }
    );

  /**
   * Every record in the store, read anew. An unreadable store is an error,
   * never an empty one: it may hold the only copy of a vault.
   */
  function records() {
    const text = storage.getItem(key);
    if (text === null || text === undefined) return [];
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (cause) {
      throw unreadable(cause);
    }
    if (!Array.isArray(parsed) || !parsed.every(isRecord)) throw unreadable();
    return parsed.map(normalised);
  }

  /** Keep `record` in place of the one with vault id `replacing`, else add it. */
  function save(record, replacing = record.vault.id) {
    const all = records();
    const at = all.findIndex((r) => r.vault.id === replacing);
    if (at >= 0) all[at] = record;
    else all.push(record);
    storage.setItem(key, JSON.stringify(all));
  }

  /** What the store says in public about one authenticator's slot. */
  const slotEntry = (kid, rawCredentialId, label, addedAt) => ({
    kid,
    label: label ?? '',
    credentialId: base64url(bytesOf(rawCredentialId)),
    addedAt,
  });

  /**
   * Is there a vault here for this authenticator — without asking it?
   *
   * @param {Uint8Array} rawCredentialId
   * @returns {Promise<{ kid: string, here: boolean, removed: boolean }>}
   *   `here`: a vault kept here has its slot. `removed`: none has, and it was
   *   taken out of one.
   */
  async function status(rawCredentialId) {
    const kid = await slotIdFor(rawCredentialId);
    const all = records();
    const here = all.some((r) => holds(r, kid));
    return {
      kid,
      here,
      removed: !here && all.some((r) => r.removed.includes(kid)),
    };
  }

  /**
   * Open the vault this authenticator has a slot in, or make one.
   *
   * - A vault kept here with its slot: opened.
   * - None, and it was removed from one here: refused, `VAULT_SLOT_REMOVED` —
   *   never given a new vault, which for books made before the vault would be
   *   a stale copy that looks like the real ones.
   * - None, and `find` returns a record with its slot (from a backup, an
   *   index): opened, and kept here once it has opened, under this
   *   authenticator's `label`.
   * - None at all: a new vault holding `create()`, this authenticator's slot
   *   on it. Without `create`, refused: `VAULT_NO_SLOT`.
   *
   * Pass `find` on every unlock where the vault may be kept elsewhere, not
   * only on a restore path. A synced passkey on a new device otherwise makes
   * a vault of its own, and from then on its slot is found here and `find` is
   * never asked again (Le-Space/belege#524).
   *
   * **Renewals.** `find` is asked on every unlock, also when a vault is kept
   * here, and may return one record or several. Of everything this
   * authenticator's slot opens, the latest generation wins: a vault renewed on
   * another device replaces the one kept here as soon as `find` shows it, and
   * a record from before a renewal is never taken in place of a later one —
   * neither from `find` nor from the store. A slot only its authenticator can
   * seal vouches for the generation, so a removed authenticator cannot pass
   * an old vault off as newer. With a vault kept here, a `find` that fails
   * does not stop the unlock; the error comes back as `findError`.
   *
   * What this cannot do is on the module description: a device with nothing
   * kept that is shown only the old vault opens the old vault. An application
   * that knows better — from a pointer the owner's identity signed, say —
   * passes `minGeneration`: anything earlier is refused with
   * `VAULT_SUPERSEDED`, before it is kept here and without a new vault being
   * made in its place. `found` and `generation` are returned as well, for an
   * application that checks afterwards.
   *
   * @param {Object} unlock
   * @param {Uint8Array} unlock.prfOutput - From `readPrfOutput`.
   * @param {Uint8Array} unlock.rawCredentialId
   * @param {string} [unlock.label] - The authenticator's name, kept in public.
   * @param {() => Uint8Array | Promise<Uint8Array>} [unlock.create] - The
   *   payload of a new vault, e.g. `() => rootPayload(randomBytes)`.
   * @param {(kid: string) => Promise<object|object[]|null>} [unlock.find] -
   *   Records kept elsewhere, by slot id: one, several, or none.
   * @param {number} [unlock.minGeneration=0] - The generation the
   *   application knows the vault has reached.
   * @returns {Promise<{ record: object, payload: Uint8Array,
   *   vaultKey: Uint8Array, kid: string, created: boolean, found: boolean,
   *   generation: number, findError?: unknown }>}
   *   Keep it in memory while the vault is open; it holds the vault key.
   *   `found`: the record came from `find` on this unlock. `generation`: how
   *   many vaults this one has replaced.
   * @throws {VaultError} `VAULT_STORE_UNREADABLE`, `VAULT_SLOT_REMOVED`,
   *   `VAULT_NO_SLOT`, `VAULT_SUPERSEDED`, or `VAULT_LOCKED` when the slot
   *   does not open with this PRF output.
   */
  async function open({
    prfOutput,
    rawCredentialId,
    label,
    create,
    find,
    minGeneration = 0,
  } = {}) {
    if (!Number.isSafeInteger(minGeneration) || minGeneration < 0) {
      throw new TypeError('minGeneration must be a non-negative integer');
    }
    const superseded = (generation) =>
      new VaultError(
        generation === undefined
          ? `No vault of generation ${minGeneration} or later is at hand for this authenticator`
          : `The vault at hand is of generation ${generation}, from before a renewal: generation ${minGeneration} or later is expected`,
        { code: ERROR_CODES.VAULT_SUPERSEDED }
      );
    const kid = await slotIdFor(rawCredentialId);
    const all = records();
    // Latest first: should the store hold a vault and the one it replaced,
    // the one from before the renewal is not the one to open.
    const kept = all
      .filter((r) => holds(r, kid))
      .sort((a, b) => generationOfRecord(b) - generationOfRecord(a))[0];
    if (!kept && all.some((r) => r.removed.includes(kid))) {
      throw new VaultError(
        'This authenticator was removed from the vault kept here',
        { code: ERROR_CODES.VAULT_SLOT_REMOVED }
      );
    }
    const slotKey = await slotKeyOf(prfOutput);

    // What is kept elsewhere is asked for on every unlock, not only when
    // nothing is kept here: that is how a device learns its vault was renewed
    // on another. Only what is later than the vault kept here is of interest —
    // a copy from before a renewal must never replace the renewal.
    const keptGeneration = kept ? generationOfRecord(kept) : -1;
    let elsewhere = [];
    let findError;
    if (find) {
      try {
        const answer = await find(kid);
        const holding = (Array.isArray(answer) ? answer : [answer])
          .filter((r) => isRecord(r) && holds(r, kid))
          .map(normalised);
        // A record with this authenticator's slot that cannot be read — cut
        // short, altered, or of a version this code does not know — is not
        // "nothing found". With nothing kept here, a vault made in its place
        // would part this device from the one it belongs to, for good: the
        // real record, shown later, is no later than the new one.
        if (
          !kept &&
          holding.length > 0 &&
          holding.every((r) => generationOfRecord(r) < 0)
        ) {
          generationOf(holding[0].vault);
        }
        elsewhere = holding
          .filter((r) => generationOfRecord(r) > keptGeneration)
          .sort((a, b) => generationOfRecord(b) - generationOfRecord(a));
      } catch (error) {
        // With nothing kept here there is nothing to fall back on, and a
        // failed lookup must not end in a new, empty vault.
        if (!kept) throw error;
        findError = error;
      }
    }

    let record;
    let opened;
    let found = false;
    for (const candidate of elsewhere) {
      try {
        // The number on a record is only a claim until the slot opens: the
        // generation is part of what the slot was sealed with.
        opened = await openVault(candidate.vault, { slotKey, rawCredentialId });
        record = candidate;
        found = true;
        break;
      } catch (error) {
        // Not this authenticator's after all, or altered. With a vault kept
        // here, or another candidate, that one is passed over; with neither,
        // the caller hears why the only record it was given did not open.
        if (!kept && candidate === elsewhere[elsewhere.length - 1]) throw error;
      }
    }
    if (!record && kept) {
      record = kept;
      opened = await openVault(record.vault, { slotKey, rawCredentialId });
    }

    if (record) {
      const { payload, vaultKey } = opened;
      // Before anything is kept: a vault from before a renewal the
      // application knows of is not adopted, and not opened for use.
      if (generationOf(record.vault) < minGeneration) {
        throw superseded(generationOf(record.vault));
      }
      if (found) {
        const before = record.slots.find((slot) => slot?.kid === kid);
        record = {
          ...record,
          slots: [
            ...record.slots.filter((slot) => slot?.kid !== kid),
            slotEntry(
              kid,
              rawCredentialId,
              label ?? before?.label,
              before?.addedAt ?? now().toISOString()
            ),
          ],
          // What this device took out stays taken out across a renewal that
          // happened elsewhere.
          removed: [
            ...new Set([...record.removed, ...(kept ? kept.removed : [])]),
          ].filter((removedKid) => !holds(record, removedKid)),
        };
        // In place of the vault kept here, which it replaces.
        save(record, kept ? kept.vault.id : record.vault.id);
      }
      return {
        record,
        payload,
        vaultKey,
        kid,
        created: false,
        found,
        generation: generationOf(record.vault),
        ...(findError === undefined ? {} : { findError }),
      };
    }

    if (!create) {
      throw new VaultError(
        'No vault kept here has a slot for this authenticator',
        { code: ERROR_CODES.VAULT_NO_SLOT }
      );
    }
    // A vault made now would be of generation 0. Where a later one is known
    // to exist, making one is the wrong answer to not having found it.
    if (minGeneration > 0) throw superseded();
    const payload = payloadBytes(await create(), 'create()');
    const { vault, vaultKey } = await createVault(payload, {
      slotKey,
      rawCredentialId,
    });
    record = {
      vault,
      slots: [slotEntry(kid, rawCredentialId, label, now().toISOString())],
      removed: [],
    };
    save(record);
    return {
      record,
      payload,
      vaultKey,
      kid,
      created: true,
      found: false,
      generation: 0,
    };
  }

  /**
   * Give one more authenticator a slot, while the vault is open: the new key
   * is touched for its PRF output. A key taken out here before may come back.
   *
   * @param {object} opened - From `open`.
   * @param {Object} passkey
   * @param {Uint8Array} passkey.prfOutput - The new authenticator's.
   * @param {Uint8Array} passkey.rawCredentialId
   * @param {string} [passkey.label]
   * @returns {Promise<object>} `opened`, with the new record.
   * @throws {VaultError} `VAULT_SLOT_EXISTS` when it has a slot already, here
   *   or in another vault kept here — one key opens one vault per store.
   */
  async function addPasskey(
    opened,
    { prfOutput, rawCredentialId, label } = {}
  ) {
    const kid = await slotIdFor(rawCredentialId);
    if (
      records().some(
        (r) => r.vault.id !== opened.record.vault.id && holds(r, kid)
      )
    ) {
      throw new VaultError(
        'This authenticator already opens another vault kept here',
        { code: ERROR_CODES.VAULT_SLOT_EXISTS }
      );
    }
    const vault = await addSlot(opened.record.vault, opened.vaultKey, {
      slotKey: await slotKeyOf(prfOutput),
      rawCredentialId,
    });
    const record = {
      ...opened.record,
      vault,
      slots: [
        ...opened.record.slots.filter((slot) => slot?.kid !== kid),
        slotEntry(kid, rawCredentialId, label, now().toISOString()),
      ],
      removed: opened.record.removed.filter((k) => k !== kid),
    };
    save(record);
    return { ...opened, record };
  }

  /**
   * Take an authenticator's slot out — by its slot id, so a key that is not at
   * hand can go too. It is refused here from then on. It has seen the vault
   * key, and older copies of the record still carry its slot: for a key that
   * may be in other hands, `renew` instead.
   *
   * @param {object} opened - From `open`.
   * @param {string} kid - The slot id, as `record.slots` names it.
   * @returns {Promise<object>} `opened`, with the new record.
   * @throws {VaultError} `VAULT_SLOT_IN_USE` for the authenticator that opened
   *   the vault, `VAULT_NO_SLOT` for one without a slot.
   */
  async function removePasskey(opened, kid) {
    if (kid === opened.kid) {
      throw new VaultError(
        'The authenticator that opened the vault cannot remove itself',
        { code: ERROR_CODES.VAULT_SLOT_IN_USE }
      );
    }
    const vault = removeSlotById(opened.record.vault, kid);
    const record = {
      ...opened.record,
      vault,
      slots: opened.record.slots.filter((slot) => slot?.kid !== kid),
      removed: [...new Set([...opened.record.removed, kid])],
    };
    save(record);
    return { ...opened, record };
  }

  /**
   * Renew the vault: a new vault key and a new vault id, the same payload or
   * `payload`, and a slot for every authenticator that stays. Every one of
   * them answers — its PRF output, checked against its slot in the old vault —
   * so none is left out by mistake; the ones in `removed` are taken out and
   * refused here. The old record is replaced here; copies of it elsewhere
   * still open with the old slots.
   *
   * The new vault is one generation on from the old, and every authenticator
   * that stays vouches for that with its slot. A keeper shown both takes the
   * new one, on any device (see `open`). **Put the renewed record wherever
   * `find` reads from, straight away**: a device that has nothing kept and is
   * shown only the old record cannot know it was replaced, and would go on
   * sealing under a vault key the removed authenticator knows.
   *
   * @param {object} opened - From `open`.
   * @param {Object} change
   * @param {Array<{ prfOutput: Uint8Array, rawCredentialId: Uint8Array }>}
   *   change.answers - Every authenticator that stays, the one that opened
   *   the vault among them.
   * @param {string[]} [change.removed] - Slot ids taken out.
   * @param {Uint8Array} [change.payload] - A new payload, e.g. with keys that
   *   a removed authenticator must not know.
   * @returns {Promise<object>} `opened`, with the new record, vault key and
   *   payload.
   * @throws {VaultError} `VAULT_SLOT_IN_USE` when the authenticator that
   *   opened the vault would go; `VAULT_NO_SLOT` for a removed id without a
   *   slot; `VAULT_LOCKED` for an answer its slot does not open with.
   */
  async function renew(opened, { answers, removed = [], payload } = {}) {
    if (!Array.isArray(answers) || answers.length === 0) {
      throw new TypeError(
        'renew needs an answer from every authenticator that stays'
      );
    }
    const kids = await Promise.all(
      answers.map((answer) => slotIdFor(answer.rawCredentialId))
    );
    const out = new Set(removed);
    if (!kids.includes(opened.kid) || out.has(opened.kid)) {
      throw new VaultError(
        'The authenticator that opened the vault has to stay',
        {
          code: ERROR_CODES.VAULT_SLOT_IN_USE,
        }
      );
    }
    const current = opened.record.vault.slots.map((slot) => slot.kid);
    for (const kid of out) {
      if (!current.includes(kid)) {
        throw new VaultError(`No slot ${kid} to remove`, {
          code: ERROR_CODES.VAULT_NO_SLOT,
        });
      }
    }
    const staying = current.filter((kid) => !out.has(kid));
    if (
      new Set(kids).size !== kids.length ||
      staying.length !== kids.length ||
      !staying.every((kid) => kids.includes(kid))
    ) {
      throw new TypeError(
        'renew needs one answer from every authenticator that stays, and the others in `removed`'
      );
    }
    const slots = await Promise.all(
      answers.map(async ({ prfOutput, rawCredentialId }) => {
        const slot = { slotKey: await slotKeyOf(prfOutput), rawCredentialId };
        await openVault(opened.record.vault, slot);
        return slot;
      })
    );
    const next =
      payload === undefined
        ? opened.payload
        : payloadBytes(payload, 'renew’s payload');

    const [first, ...rest] = slots;
    let { vault, vaultKey } = await createVault(next, first, {
      generation: generationOf(opened.record.vault) + 1,
    });
    for (const slot of rest) vault = await addSlot(vault, vaultKey, slot);

    const record = {
      ...opened.record,
      vault,
      slots: opened.record.slots.filter((slot) => !out.has(slot?.kid)),
      removed: [...new Set([...opened.record.removed, ...out])],
    };
    save(record, opened.record.vault.id);
    return {
      ...opened,
      record,
      payload: next,
      vaultKey,
      generation: generationOf(vault),
    };
  }

  /**
   * A new payload under the same vault key and slots.
   *
   * @param {object} opened - From `open`.
   * @param {Uint8Array} payload
   * @returns {Promise<object>} `opened`, with the new record and payload.
   */
  async function replacePayload(opened, payload) {
    const bytes = payloadBytes(payload, 'payload');
    const vault = await replaceVaultPayload(
      opened.record.vault,
      opened.vaultKey,
      bytes
    );
    const record = { ...opened.record, vault };
    save(record);
    return { ...opened, record, payload: bytes };
  }

  return Object.freeze({
    records,
    status,
    open,
    addPasskey,
    removePasskey,
    renew,
    replacePayload,
  });
}

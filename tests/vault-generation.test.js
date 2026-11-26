/**
 * A vault that replaces another says so, and a keeper never steps back.
 *
 * `renew` is the answer to a stolen authenticator: a new vault key, a new
 * vault, no slot for the key that went. But the old record still exists
 * wherever it was copied to, still opens for the authenticators that stayed,
 * and still carries the stolen one's slot. A keeper on a device with an empty
 * store took whatever `find` gave it — the old vault as readily as the new —
 * and from then on sealed under a vault key the stolen authenticator knows.
 *
 * A renewed vault now carries a generation, sealed into every slot, so each
 * authenticator that stays vouches for it and nobody else can raise it. Shown
 * both, a keeper takes the later, moves forward when it learns of a renewal,
 * and never moves back. The last test in the keeper block states the limit:
 * shown only the old one, on a device that knows nothing, it opens the old
 * one — nothing in a record says it was replaced.
 */
import { test, expect } from '@playwright/test';
import {
  addSlot,
  createVault,
  createVaultKeeper,
  deriveAesKey,
  generationOf,
  openVault,
  removeSlot,
  replacePayload,
  rootOf,
  rootPayload,
  slotIdFor,
  VaultError,
} from '../src/index.js';

const KEY = 'test.vaults.v1';
const SLOT_INFO = 'test/vault-slot/v1';
const encode = (text) => new TextEncoder().encode(text);
const decode = (bytes) => new TextDecoder().decode(bytes);
const hex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const prf = (seed) =>
  Uint8Array.from({ length: 32 }, (_, i) => (seed * 31 + i) % 256);

const A = {
  prfOutput: prf(1),
  rawCredentialId: new Uint8Array(16).fill(0xa1),
  label: 'Key A',
};
const B = {
  prfOutput: prf(2),
  rawCredentialId: new Uint8Array(16).fill(0xb2),
  label: 'Key B, stolen',
};

const slotOf = async (passkey) => ({
  slotKey: await deriveAesKey(passkey.prfOutput, SLOT_INFO),
  rawCredentialId: passkey.rawCredentialId,
});

/** AES-GCM as the vault seals, for building what an attacker would. */
async function sealAs(keyBytes, plaintext, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, [
    'encrypt',
  ]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: encode(aad) },
      key,
      plaintext
    )
  );
  return { iv: hex(iv), ciphertext: hex(ciphertext) };
}

/**
 * What the holder of a removed authenticator can make of an old vault it
 * opened: the same vault, labelled a later generation, with a payload of its
 * choosing — it knows the vault key. The other authenticators' slots it can
 * only copy.
 */
async function relabelled(oldVault, oldVaultKey, generation, payload) {
  return {
    ...oldVault,
    version: 2,
    generation,
    payload: await sealAs(
      oldVaultKey,
      payload,
      `@le-space/vault:v2:payload:${oldVault.id}:${generation}`
    ),
  };
}

const locked = (promise) =>
  expect(promise).rejects.toMatchObject({ code: 'VAULT_LOCKED' });
const malformed = (promise) =>
  expect(promise).rejects.toMatchObject({ code: 'VAULT_MALFORMED' });

test.describe('the generation of a vault', () => {
  test('a vault made fresh is what it always was: version 1, generation 0', async () => {
    const { vault } = await createVault(encode('books'), await slotOf(A));
    expect(vault.version).toBe(1);
    expect('generation' in vault).toBe(false);
    expect(generationOf(vault)).toBe(0);
  });

  test('a vault that replaces another carries its generation through every change', async () => {
    const made = await createVault(encode('books'), await slotOf(A), {
      generation: 3,
    });
    expect(made.vault.version).toBe(2);
    expect(generationOf(made.vault)).toBe(3);

    let vault = await addSlot(made.vault, made.vaultKey, await slotOf(B));
    vault = await replacePayload(vault, made.vaultKey, encode('more books'));
    expect(generationOf(vault)).toBe(3);
    for (const passkey of [A, B]) {
      const opened = await openVault(vault, await slotOf(passkey));
      expect(decode(opened.payload)).toBe('more books');
    }
    vault = await removeSlot(vault, B.rawCredentialId);
    expect(generationOf(vault)).toBe(3);
    await openVault(vault, await slotOf(A));
  });

  test('is sealed into slot and payload: a record relabelled does not open', async () => {
    const { vault } = await createVault(encode('books'), await slotOf(A), {
      generation: 3,
    });
    await locked(openVault({ ...vault, generation: 4 }, await slotOf(A)));
    await locked(openVault({ ...vault, generation: 2 }, await slotOf(A)));

    const asVersion1 = { ...vault, version: 1 };
    delete asVersion1.generation;
    await locked(openVault(asVersion1, await slotOf(A)));

    const fresh = (await createVault(encode('books'), await slotOf(A))).vault;
    await locked(
      openVault({ ...fresh, version: 2, generation: 5 }, await slotOf(A))
    );
  });

  test('cannot be raised by a removed authenticator for one that stays', async () => {
    // B opened the vault once, so it has the vault key for good.
    const made = await createVault(encode('books'), await slotOf(A));
    const withB = await addSlot(made.vault, made.vaultKey, await slotOf(B));
    const { vaultKey } = await openVault(withB, await slotOf(B));

    const forged = await relabelled(withB, vaultKey, 9, encode('from B'));
    // The payload is B's to seal. A's slot is not: it was sealed under a key
    // only A derives, for the generation A agreed to.
    await locked(openVault(forged, await slotOf(A)));
  });

  test('a record with a generation it should not have is malformed', async () => {
    const { vault } = await createVault(encode('books'), await slotOf(A), {
      generation: 1,
    });
    const fresh = (await createVault(encode('books'), await slotOf(A))).vault;
    for (const broken of [
      { ...vault, generation: 0 },
      { ...vault, generation: -1 },
      { ...vault, generation: 1.5 },
      { ...vault, generation: '1' },
      { ...vault, generation: undefined },
      { ...fresh, generation: 1 },
      { ...fresh, version: 3 },
    ]) {
      await malformed(openVault(broken, await slotOf(A)));
      expect(() => generationOf(broken)).toThrow(VaultError);
    }
    await expect(
      createVault(encode('books'), await slotOf(A), { generation: -1 })
    ).rejects.toThrow(TypeError);
  });
});

function memoryStorage() {
  const items = new Map();
  return {
    getItem: (key) => (items.has(key) ? items.get(key) : null),
    setItem: (key, value) => items.set(key, String(value)),
  };
}
const NOW = new Date('2026-11-18T09:00:00.000Z');
const keeper = () =>
  createVaultKeeper({
    storage: memoryStorage(),
    key: KEY,
    slotInfo: SLOT_INFO,
    now: () => NOW,
  });

const OLD_ROOT = new Uint8Array(32).fill(1);
const NEW_ROOT = new Uint8Array(32).fill(2);
const rootHex = (opened) => hex(rootOf(opened.payload));

/**
 * The owner's first device: a vault for A and B, then B is stolen and the
 * vault renewed without it, around a root B must not learn.
 */
async function stolenAndRenewed() {
  const device = keeper();
  let opened = await device.open({ ...A, create: () => rootPayload(OLD_ROOT) });
  opened = await device.addPasskey(opened, B);
  const before = structuredClone(opened.record);
  const kidB = await slotIdFor(B.rawCredentialId);

  opened = await device.renew(opened, {
    answers: [A],
    removed: [kidB],
    payload: rootPayload(NEW_ROOT),
  });
  return { device, before, after: structuredClone(opened.record), kidB };
}

test.describe('the keeper, after a renewal', () => {
  test('a renewal is one generation on, and says so', async () => {
    const { before, after } = await stolenAndRenewed();
    expect(generationOf(before.vault)).toBe(0);
    expect(generationOf(after.vault)).toBe(1);
    expect(after.vault.id).not.toBe(before.vault.id);

    // And again: each renewal counts.
    const device = keeper();
    let opened = await device.open({ ...A, find: async () => after });
    opened = await device.renew(opened, { answers: [A] });
    expect(opened.generation).toBe(2);
  });

  for (const order of ['old first', 'new first']) {
    test(`a device with nothing kept, shown both records (${order}), opens the renewed one`, async () => {
      const { before, after, kidB } = await stolenAndRenewed();
      const shown = order === 'old first' ? [before, after] : [after, before];

      const fresh = keeper();
      const opened = await fresh.open({ ...A, find: async () => shown });

      expect(opened.found).toBe(true);
      expect(opened.generation).toBe(1);
      expect(opened.record.vault.id).toBe(after.vault.id);
      expect(rootHex(opened)).toBe(hex(NEW_ROOT));
      // What is sealed from here on, B cannot read: it has no slot.
      const next = await fresh.replacePayload(
        opened,
        encode('after the theft')
      );
      await expect(
        openVault(next.record.vault, await slotOf(B))
      ).rejects.toMatchObject({ code: 'VAULT_NO_SLOT' });
      // And B is refused here like on the device that removed it.
      expect((await fresh.status(B.rawCredentialId)).removed).toBe(true);
      expect(next.record.removed).toContain(kidB);
    });
  }

  test('a device still on the old vault moves to the renewed one when it is shown it', async () => {
    const { before, after } = await stolenAndRenewed();
    const second = keeper();
    // Set up before the theft, from a copy of the vault as it was.
    await second.open({ ...A, find: async () => before });
    expect(second.records()).toHaveLength(1);

    const opened = await second.open({ ...A, find: async () => after });
    expect(opened.found).toBe(true);
    expect(opened.generation).toBe(1);
    expect(rootHex(opened)).toBe(hex(NEW_ROOT));
    // In place of the old record, not beside it.
    expect(second.records().map((r) => r.vault.id)).toEqual([after.vault.id]);
  });

  test('a device on the renewed vault is not moved back by an old copy', async () => {
    const { device, before, after } = await stolenAndRenewed();
    for (const shown of [before, [before], [before, after]]) {
      const opened = await device.open({ ...A, find: async () => shown });
      expect(opened.found).toBe(false);
      expect(opened.generation).toBe(1);
      expect(opened.record.vault.id).toBe(after.vault.id);
      expect(rootHex(opened)).toBe(hex(NEW_ROOT));
    }
    expect(device.records().map((r) => r.vault.id)).toEqual([after.vault.id]);
  });

  test('an old vault relabelled as newer is passed over', async () => {
    const { device, before, after } = await stolenAndRenewed();
    const { vaultKey } = await openVault(before.vault, await slotOf(B));
    const forged = {
      ...before,
      vault: await relabelled(before.vault, vaultKey, 7, rootPayload(OLD_ROOT)),
    };

    // On the device that renewed: stays where it is.
    const kept = await device.open({ ...A, find: async () => forged });
    expect(kept.found).toBe(false);
    expect(kept.record.vault.id).toBe(after.vault.id);

    // On a device with nothing kept: beside the real renewal it loses …
    const fresh = keeper();
    const opened = await fresh.open({
      ...A,
      find: async () => [forged, after],
    });
    expect(opened.record.vault.id).toBe(after.vault.id);

    // … and alone it does not open — nor is a new, empty vault made instead.
    const alone = keeper();
    await locked(
      alone.open({
        ...A,
        find: async () => forged,
        create: () => rootPayload(NEW_ROOT),
      })
    );
    expect(alone.records()).toEqual([]);
  });

  test('a find that fails does not stop a device that has its vault, and does stop one that has not', async () => {
    const { device, after } = await stolenAndRenewed();
    const offline = async () => {
      throw new Error('offline');
    };

    const opened = await device.open({ ...A, find: offline });
    expect(opened.record.vault.id).toBe(after.vault.id);
    expect(opened.findError).toBeInstanceOf(Error);
    expect((await device.open({ ...A })).findError).toBeUndefined();

    // Nothing kept: no vault is made on the strength of a lookup that failed.
    const fresh = keeper();
    await expect(
      fresh.open({ ...A, find: offline, create: () => rootPayload(NEW_ROOT) })
    ).rejects.toThrow('offline');
    expect(fresh.records()).toEqual([]);
  });

  test('a device with nothing kept, shown only a record it cannot read, makes no vault of its own', async () => {
    const { after } = await stolenAndRenewed();
    const unreadable = { ...after, vault: { ...after.vault, version: 3 } };
    let created = false;
    const create = () => {
      created = true;
      return rootPayload(OLD_ROOT);
    };

    const fresh = keeper();
    await malformed(fresh.open({ ...A, find: async () => unreadable, create }));
    expect(created).toBe(false);
    expect(fresh.records()).toEqual([]);

    // Once the readable record is shown, the device joins the real vault.
    const opened = await fresh.open({ ...A, find: async () => after, create });
    expect(opened.found).toBe(true);
    expect(opened.record.vault.id).toBe(after.vault.id);
    expect(rootHex(opened)).toBe(hex(NEW_ROOT));
    expect(created).toBe(false);

    // A readable record beside the unreadable one is taken.
    const other = keeper();
    const both = await other.open({
      ...A,
      find: async () => [unreadable, after],
      create,
    });
    expect(both.record.vault.id).toBe(after.vault.id);
  });

  test('an application that knows the generation refuses the old vault before it is kept', async () => {
    const { before, after } = await stolenAndRenewed();
    const superseded = (promise) =>
      expect(promise).rejects.toMatchObject({ code: 'VAULT_SUPERSEDED' });

    // Shown only the old record, on a device with nothing kept.
    const fresh = keeper();
    await superseded(
      fresh.open({ ...A, find: async () => before, minGeneration: 1 })
    );
    // Not adopted — and no new vault in its place, either.
    await superseded(
      fresh.open({
        ...A,
        minGeneration: 1,
        create: () => rootPayload(NEW_ROOT),
      })
    );
    expect(fresh.records()).toEqual([]);

    // A device that still keeps the old vault is not left sealing under it.
    const second = keeper();
    await second.open({ ...A, find: async () => before });
    await superseded(second.open({ ...A, minGeneration: 1 }));

    // With the renewed record at hand, the same call opens it.
    const opened = await second.open({
      ...A,
      find: async () => after,
      minGeneration: 1,
    });
    expect(opened.generation).toBe(1);
    await expect(second.open({ ...A, minGeneration: -1 })).rejects.toThrow(
      TypeError
    );
  });

  test('the limit: with nothing kept and only the old record shown, the old vault opens', async () => {
    // No record says it was replaced. This is what the place `find` reads
    // from has to prevent, and why `generation` and the vault id come back.
    const { before } = await stolenAndRenewed();
    const fresh = keeper();
    const opened = await fresh.open({ ...A, find: async () => before });

    expect(opened.found).toBe(true);
    expect(opened.generation).toBe(0);
    expect(opened.record.vault.id).toBe(before.vault.id);
    expect(rootHex(opened)).toBe(hex(OLD_ROOT));
  });
});

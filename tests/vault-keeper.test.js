/**
 * The vault keeper: where an application keeps its vaults, and what every
 * unlock does with them.
 *
 * Fixed PRF outputs stand for the authenticators here — the keeper never asks
 * one; it gets the answer. `vault-two-authenticators.test.js` runs the same
 * flow in Chromium, with two virtual authenticators answering.
 *
 * The Belege record below was written by Le-Space/belege's own
 * `app/src/lib/books-vault.js` (two keys, the PRF outputs printed here, so
 * nothing in it is secret). The keeper keeps the format Belege has stored
 * since #406 there; this record has to keep opening.
 */
import { test, expect } from '@playwright/test';
import {
  createVaultKeeper,
  rootPayload,
  rootOf,
  openVault,
  addSlot,
  deriveAesKey,
  slotIdFor,
  VaultError,
} from '../src/index.js';

const KEY = 'test.vaults.v1';
const SLOT_INFO = 'test/vault-slot/v1';
const encode = (text) => new TextEncoder().encode(text);
const decode = (bytes) => new TextDecoder().decode(bytes);

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
  label: 'Key B',
};
const C = {
  prfOutput: prf(3),
  rawCredentialId: new Uint8Array(16).fill(0xc3),
  label: 'Key C',
};

/** A store like localStorage, in memory. */
function memoryStorage(initial = {}) {
  const items = new Map(Object.entries(initial));
  return {
    getItem: (key) => (items.has(key) ? items.get(key) : null),
    setItem: (key, value) => items.set(key, String(value)),
    removeItem: (key) => items.delete(key),
  };
}

const NOW = new Date('2026-10-31T09:00:00.000Z');
const keeperOn = (storage, options = {}) =>
  createVaultKeeper({
    storage,
    key: KEY,
    slotInfo: SLOT_INFO,
    now: () => NOW,
    ...options,
  });

/** A keeper whose store holds one vault, opened by A, with B's slot on it. */
async function booksOfAAndB() {
  const storage = memoryStorage();
  const keeper = keeperOn(storage);
  let opened = await keeper.open({ ...A, create: () => encode('{"books":1}') });
  opened = await keeper.addPasskey(opened, B);
  return { storage, keeper, opened };
}

const code = (promise) =>
  promise.then(
    () => 'opened',
    (error) => (error instanceof VaultError ? error.code : error.name)
  );

// Written by Belege's books-vault.js: openBooksVault with key A (PRF output
// 0…31, credential id 16 × 0xaa), then addPasskey with key B (PRF output
// 255…224, credential id 16 × 0xbb), under 'belege/vault-slot/v1'.
const BELEGE = Object.freeze({
  key: 'belege.vaults.v1',
  slotInfo: 'belege/vault-slot/v1',
  prfA: Uint8Array.from({ length: 32 }, (_, i) => i),
  prfB: Uint8Array.from({ length: 32 }, (_, i) => 255 - i),
  idA: new Uint8Array(16).fill(0xaa),
  idB: new Uint8Array(16).fill(0xbb),
  stored: JSON.stringify([
    {
      vault: {
        version: 1,
        algorithm: 'AES-GCM',
        id: '82868fe23424a2fe7ecd914017227bc2',
        payload: {
          iv: '61dd7180baabfb66d24c53b4',
          ciphertext:
            '27792261d391bec63f30701ca59ca2d63b34bd496bb9bf110717c36a6f08efdd8a8baacf996c931bb9100841fb3e6187df4e5e75a4de11d2ffd0fd49e97d3fe743ca2819ac8073427707c0fa0b5f79fe5bb1fe639b737dce683dfe4017aef57ebbf9433417ca73',
        },
        slots: [
          {
            kid: 'bc1443a0d17aab2db1ea0302ef280717ac9a2f23355c5b649ea87d605430458d',
            iv: '8471f554f9142799ee82f830',
            ciphertext:
              '7b21d27401c57f29060a84dd53bf3c969597e9d1b7ec5c1634b1e1ac62ce6811073a756cba03f759d49c9f6b8271c862',
          },
          {
            kid: '5096f043e0a447557cd2ca843d65911aa67dfdd6883ab03bdb666c44a2753365',
            iv: '133cd9cdecf493e48e7a08ed',
            ciphertext:
              'd3a5d825319323452449d8392535f431eb7353dda8888657d4382c0b83db793bd3d16f3e268167947d97fe25861d5573',
          },
        ],
      },
      slots: [
        {
          kid: 'bc1443a0d17aab2db1ea0302ef280717ac9a2f23355c5b649ea87d605430458d',
          label: 'Key A',
          credentialId: 'qqqqqqqqqqqqqqqqqqqqqg',
          addedAt: '2026-10-25T10:00:00.000Z',
        },
        {
          kid: '5096f043e0a447557cd2ca843d65911aa67dfdd6883ab03bdb666c44a2753365',
          label: 'Key B',
          credentialId: 'u7u7u7u7u7u7u7u7u7u7uw',
          addedAt: '2026-10-25T10:00:00.000Z',
        },
      ],
      removed: [],
    },
  ]),
});

test.describe('unlocking', () => {
  test('the first unlock makes a vault with this key’s slot; later ones open it', async () => {
    const storage = memoryStorage();
    const keeper = keeperOn(storage);

    const first = await keeper.open({
      ...A,
      create: () => encode('{"books":1}'),
    });
    expect(first.created).toBe(true);
    expect(first.found).toBe(false);
    expect(first.kid).toBe(await slotIdFor(A.rawCredentialId));
    expect(decode(first.payload)).toBe('{"books":1}');
    expect(first.record.slots).toEqual([
      {
        kid: first.kid,
        label: 'Key A',
        credentialId: Buffer.from(A.rawCredentialId).toString('base64url'),
        addedAt: NOW.toISOString(),
      },
    ]);
    expect(first.record.removed).toEqual([]);

    // Nothing secret is kept: neither the PRF output nor the vault key.
    const stored = storage.getItem(KEY);
    expect(stored).not.toContain(Buffer.from(A.prfOutput).toString('hex'));
    expect(stored).not.toContain(Buffer.from(first.vaultKey).toString('hex'));
    expect(stored).not.toContain('books');

    const create = () => {
      throw new Error('a second vault for the same key');
    };
    const again = await keeper.open({ ...A, create });
    expect(again.created).toBe(false);
    expect(decode(again.payload)).toBe('{"books":1}');
    expect(again.record.vault.id).toBe(first.record.vault.id);
    expect(keeper.records()).toHaveLength(1);
  });

  test('without `create`, no vault is made', async () => {
    const storage = memoryStorage();
    const keeper = keeperOn(storage);
    expect(await code(keeper.open(A))).toBe('VAULT_NO_SLOT');
    expect(storage.getItem(KEY)).toBeNull();
  });

  test('a slot that does not open with this PRF output is refused, and nothing is made', async () => {
    const { storage, keeper } = await booksOfAAndB();
    const before = storage.getItem(KEY);
    const create = () => encode('{"books":2}');
    expect(await code(keeper.open({ ...A, prfOutput: prf(9), create }))).toBe(
      'VAULT_LOCKED'
    );
    expect(storage.getItem(KEY)).toBe(before);
  });

  test('another application’s slot info does not open the slot', async () => {
    const { storage } = await booksOfAAndB();
    const other = createVaultKeeper({
      storage,
      key: KEY,
      slotInfo: 'other/vault-slot/v1',
    });
    expect(await code(other.open(A))).toBe('VAULT_LOCKED');
  });

  test('status tells, without asking the key, whether a vault here has its slot', async () => {
    const { keeper, opened } = await booksOfAAndB();
    expect(await keeper.status(A.rawCredentialId)).toEqual({
      kid: opened.kid,
      here: true,
      removed: false,
    });
    expect((await keeper.status(C.rawCredentialId)).here).toBe(false);
    const kidB = await slotIdFor(B.rawCredentialId);
    await keeper.removePasskey(opened, kidB);
    expect(await keeper.status(B.rawCredentialId)).toEqual({
      kid: kidB,
      here: false,
      removed: true,
    });
  });
});

test.describe('a second key', () => {
  test('gets its own slot and opens the same payload; the store names both', async () => {
    const { storage, opened } = await booksOfAAndB();
    expect(opened.record.vault.slots).toHaveLength(2);
    expect(opened.record.slots.map((slot) => slot.label)).toEqual([
      'Key A',
      'Key B',
    ]);

    // Another page, the same store: B alone opens it.
    const byB = await keeperOn(storage).open(B);
    expect(decode(byB.payload)).toBe('{"books":1}');
    expect(byB.kid).toBe(await slotIdFor(B.rawCredentialId));
  });

  test('one key opens one vault per store', async () => {
    const storage = memoryStorage();
    const keeper = keeperOn(storage);
    const booksOfA = await keeper.open({ ...A, create: () => encode('a') });
    await keeper.open({ ...C, create: () => encode('c') });
    expect(await code(keeper.addPasskey(booksOfA, C))).toBe(
      'VAULT_SLOT_EXISTS'
    );
    expect(await code(keeper.addPasskey(booksOfA, A))).toBe(
      'VAULT_SLOT_EXISTS'
    );
  });
});

test.describe('removing a key', () => {
  test('it is refused here from then on, and given no new vault either', async () => {
    const { storage, keeper, opened } = await booksOfAAndB();
    const kidB = await slotIdFor(B.rawCredentialId);
    const after = await keeper.removePasskey(opened, kidB);
    expect(after.record.vault.slots.map((slot) => slot.kid)).toEqual([
      opened.kid,
    ]);
    expect(after.record.slots.map((slot) => slot.label)).toEqual(['Key A']);
    expect(after.record.removed).toEqual([kidB]);

    const create = () => encode('{"books":"stale copy"}');
    expect(await code(keeperOn(storage).open({ ...B, create }))).toBe(
      'VAULT_SLOT_REMOVED'
    );
    expect(keeper.records()).toHaveLength(1);
    expect(decode((await keeper.open(A)).payload)).toBe('{"books":1}');
  });

  test('it may come back: added again, it is no longer refused', async () => {
    const { storage, keeper, opened } = await booksOfAAndB();
    const kidB = await slotIdFor(B.rawCredentialId);
    const removed = await keeper.removePasskey(opened, kidB);
    const back = await keeper.addPasskey(removed, B);
    expect(back.record.removed).toEqual([]);
    expect(decode((await keeperOn(storage).open(B)).payload)).toBe(
      '{"books":1}'
    );
  });

  test('the key that opened the vault cannot remove itself', async () => {
    const { keeper, opened } = await booksOfAAndB();
    expect(await code(keeper.removePasskey(opened, opened.kid))).toBe(
      'VAULT_SLOT_IN_USE'
    );
    expect(await code(keeper.removePasskey(opened, 'ab'.repeat(32)))).toBe(
      'VAULT_NO_SLOT'
    );
  });
});

test.describe('renewing the vault', () => {
  test('a new vault key and id, every key that stays answers, the removed one is refused', async () => {
    const { storage, keeper, opened } = await booksOfAAndB();
    const withC = await keeper.addPasskey(opened, C);
    const kidC = await slotIdFor(C.rawCredentialId);

    const renewed = await keeper.renew(withC, {
      answers: [A, B],
      removed: [kidC],
    });
    expect(renewed.record.vault.id).not.toBe(opened.record.vault.id);
    expect(
      Buffer.from(renewed.vaultKey).equals(Buffer.from(opened.vaultKey))
    ).toBe(false);
    expect(decode(renewed.payload)).toBe('{"books":1}');
    expect(renewed.record.vault.slots).toHaveLength(2);
    expect(renewed.record.removed).toEqual([kidC]);
    expect(keeper.records()).toHaveLength(1);

    // The old vault key opens nothing in the new record.
    const slot = {
      slotKey: await deriveAesKey(C.prfOutput, SLOT_INFO),
      rawCredentialId: C.rawCredentialId,
    };
    expect(
      await code(addSlot(renewed.record.vault, opened.vaultKey, slot))
    ).toBe('VAULT_LOCKED');

    expect(decode((await keeperOn(storage).open(B)).payload)).toBe(
      '{"books":1}'
    );
    expect(await code(keeperOn(storage).open(C))).toBe('VAULT_SLOT_REMOVED');
  });

  test('with a new payload, for keys a removed key must not know', async () => {
    const { storage, keeper, opened } = await booksOfAAndB();
    const kidB = await slotIdFor(B.rawCredentialId);
    const renewed = await keeper.renew(opened, {
      answers: [A],
      removed: [kidB],
      payload: encode('{"books":1,"backupKey":"new"}'),
    });
    expect(decode(renewed.payload)).toBe('{"books":1,"backupKey":"new"}');
    expect(decode((await keeperOn(storage).open(A)).payload)).toBe(
      '{"books":1,"backupKey":"new"}'
    );
  });

  test('leaves no key out by mistake', async () => {
    const { keeper, opened } = await booksOfAAndB();
    const kidB = await slotIdFor(B.rawCredentialId);
    // B stays, but did not answer.
    await expect(keeper.renew(opened, { answers: [A] })).rejects.toThrow(
      TypeError
    );
    // An answer its slot does not open with.
    expect(
      await code(
        keeper.renew(opened, { answers: [A, { ...B, prfOutput: prf(9) }] })
      )
    ).toBe('VAULT_LOCKED');
    // The key that opened the vault, removed.
    expect(
      await code(keeper.renew(opened, { answers: [B], removed: [opened.kid] }))
    ).toBe('VAULT_SLOT_IN_USE');
    // A key without a slot, removed.
    expect(
      await code(
        keeper.renew(opened, { answers: [A, B], removed: ['ab'.repeat(32)] })
      )
    ).toBe('VAULT_NO_SLOT');
    // Nothing changed.
    expect(keeper.records()[0].vault.id).toBe(opened.record.vault.id);
    expect(keeper.records()[0].vault.slots.map((slot) => slot.kid)).toContain(
      kidB
    );
  });
});

test.describe('the store', () => {
  test('an unreadable store is refused and left exactly as it is', async () => {
    for (const text of [
      'not json',
      '{"vault":{}}',
      '[{"vault":{"slots":"no"}}]',
    ]) {
      const storage = memoryStorage({ [KEY]: text });
      const keeper = keeperOn(storage);
      expect(await code(keeper.open({ ...A, create: () => encode('x') }))).toBe(
        'VAULT_STORE_UNREADABLE'
      );
      expect(() => keeper.records()).toThrow(VaultError);
      expect(storage.getItem(KEY)).toBe(text);
    }
  });

  test('fields the keeper does not know are kept', async () => {
    const { storage, opened } = await booksOfAAndB();
    const [record] = JSON.parse(storage.getItem(KEY));
    record.index = { published: '2026-10-30' };
    record.slots.push({
      kid: 'words',
      label: '',
      credentialId: '',
      addedAt: '',
      kind: 'words',
    });
    storage.setItem(KEY, JSON.stringify([record]));

    const keeper = keeperOn(storage);
    const reopened = await keeper.open(A);
    const withC = await keeper.addPasskey(reopened, C);
    expect(withC.record.index).toEqual({ published: '2026-10-30' });
    expect(withC.record.slots.find((slot) => slot.kid === 'words')?.kind).toBe(
      'words'
    );
    expect(JSON.parse(storage.getItem(KEY))[0].index).toEqual({
      published: '2026-10-30',
    });
    expect(opened.record.index).toBeUndefined();
  });

  test('a vault found elsewhere is opened, and kept here under this key’s name', async () => {
    const { storage: there } = await booksOfAAndB();
    const [record] = JSON.parse(there.getItem(KEY));
    record.slots = record.slots.map((slot) => ({
      ...slot,
      label: 'named elsewhere',
    }));

    const here = memoryStorage();
    const keeper = keeperOn(here);
    const asked = [];
    const find = async (kid) => {
      asked.push(kid);
      return record;
    };
    const opened = await keeper.open({
      ...B,
      label: 'My key B',
      find,
      create: () => encode('new'),
    });
    expect(opened.found).toBe(true);
    expect(opened.created).toBe(false);
    expect(asked).toEqual([await slotIdFor(B.rawCredentialId)]);
    expect(decode(opened.payload)).toBe('{"books":1}');
    const kept = keeper.records();
    expect(kept).toHaveLength(1);
    expect(kept[0].slots.find((slot) => slot.kid === opened.kid)?.label).toBe(
      'My key B'
    );

    // Found, but without this key's slot: not taken, so a new vault is made.
    const elsewhere = memoryStorage();
    const fresh = await keeperOn(elsewhere).open({
      ...C,
      find: async () => record,
      create: () => encode('new'),
    });
    expect(fresh.found).toBe(false);
    expect(fresh.created).toBe(true);
  });

  test('a vault from elsewhere that does not open is not kept', async () => {
    const { storage: there } = await booksOfAAndB();
    const [record] = JSON.parse(there.getItem(KEY));
    const here = memoryStorage();
    const find = async () => record;
    expect(
      await code(keeperOn(here).open({ ...B, prfOutput: prf(9), find }))
    ).toBe('VAULT_LOCKED');
    expect(here.getItem(KEY)).toBeNull();
  });

  test('replacePayload keeps the vault key and every slot', async () => {
    const { storage, keeper, opened } = await booksOfAAndB();
    const next = await keeper.replacePayload(opened, encode('{"books":2}'));
    expect(next.record.vault.id).toBe(opened.record.vault.id);
    expect(next.vaultKey).toBe(opened.vaultKey);
    expect(decode((await keeperOn(storage).open(B)).payload)).toBe(
      '{"books":2}'
    );
  });

  test('a keeper needs a store, a key and the slot info', () => {
    const storage = memoryStorage();
    expect(() => createVaultKeeper({ key: KEY, slotInfo: SLOT_INFO })).toThrow(
      TypeError
    );
    expect(() => createVaultKeeper({ storage, slotInfo: SLOT_INFO })).toThrow(
      TypeError
    );
    expect(() => createVaultKeeper({ storage, key: KEY })).toThrow(TypeError);
  });
});

test.describe('a root as payload', () => {
  test('is written as {"version":1,"root":"<hex>"} and read back', () => {
    const root = Uint8Array.from({ length: 32 }, (_, i) => i);
    const payload = rootPayload(root);
    expect(decode(payload)).toBe(
      '{"version":1,"root":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}'
    );
    expect(Array.from(rootOf(payload))).toEqual(Array.from(root));
  });

  test('anything else is refused', () => {
    for (const text of [
      'not json',
      '{"version":2,"root":"00"}',
      '{"version":1,"root":"00"}',
      '{"version":1}',
      '{"books":1}',
    ]) {
      let refused;
      try {
        rootOf(encode(text));
      } catch (error) {
        refused = error.code;
      }
      expect(refused).toBe('VAULT_MALFORMED');
    }
    expect(() => rootPayload(new Uint8Array(16))).toThrow(TypeError);
  });
});

test.describe('Belege’s vaults', () => {
  const belegeKeeper = (storage) =>
    createVaultKeeper({
      storage,
      key: BELEGE.key,
      slotInfo: BELEGE.slotInfo,
      now: () => NOW,
    });
  const keyA = () => ({ prfOutput: BELEGE.prfA, rawCredentialId: BELEGE.idA });
  const keyB = () => ({ prfOutput: BELEGE.prfB, rawCredentialId: BELEGE.idB });

  test('open unchanged with both keys, to the root Belege put in', async () => {
    const storage = memoryStorage({ [BELEGE.key]: BELEGE.stored });
    for (const key of [keyA(), keyB()]) {
      const opened = await belegeKeeper(storage).open(key);
      expect(opened.created).toBe(false);
      // Belege's first passkey's PRF output is the root, in the bytes rootPayload writes.
      expect(Array.from(rootOf(opened.payload))).toEqual(
        Array.from(BELEGE.prfA)
      );
      expect(decode(opened.payload)).toBe(decode(rootPayload(BELEGE.prfA)));
    }
    expect(storage.getItem(BELEGE.key)).toBe(BELEGE.stored);
  });

  test('a key added by the keeper is written as Belege writes one', async () => {
    const storage = memoryStorage({ [BELEGE.key]: BELEGE.stored });
    const keeper = belegeKeeper(storage);
    const withC = await keeper.addPasskey(await keeper.open(keyA()), {
      prfOutput: C.prfOutput,
      rawCredentialId: C.rawCredentialId,
      label: 'Key C',
    });
    const [before] = JSON.parse(BELEGE.stored);
    const [after] = JSON.parse(storage.getItem(BELEGE.key));
    expect(Object.keys(after)).toEqual(Object.keys(before));
    expect(after.slots.slice(0, 2)).toEqual(before.slots);
    expect(Object.keys(after.slots[2])).toEqual(Object.keys(before.slots[0]));
    expect(after.slots[2].credentialId).toBe(
      Buffer.from(C.rawCredentialId).toString('base64url')
    );
    // Belege's own encoding of a credential id, for its keys: the same.
    expect(before.slots[0].credentialId).toBe(
      Buffer.from(BELEGE.idA).toString('base64url')
    );

    const slotKey = await deriveAesKey(C.prfOutput, BELEGE.slotInfo);
    const { payload } = await openVault(withC.record.vault, {
      slotKey,
      rawCredentialId: C.rawCredentialId,
    });
    expect(Array.from(rootOf(payload))).toEqual(Array.from(BELEGE.prfA));
  });
});

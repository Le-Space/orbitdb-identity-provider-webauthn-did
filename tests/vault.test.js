/**
 * A vault that several authenticators can open.
 *
 * The case it exists for: a second security key in a drawer has its own PRF
 * secret, so it can never derive the keys the first one derives. Here two mock
 * authenticators with different PRF secrets stand for two YubiKeys — the
 * mock's `prfSecret` models exactly that — and each opens the same vault
 * through its own slot. A third has no slot and is refused.
 *
 * The golden vault below was made by this module when it was written; it has
 * to keep opening for as long as version 1 exists, because vaults like it will
 * be stored for years.
 */
import { test, expect } from '@playwright/test';
import {
  readPrfOutput,
  deriveAesKey,
  createVault,
  openVault,
  addSlot,
  removeSlot,
  replacePayload,
  slotIdFor,
  VaultError,
} from '../src/index.js';
import { ensureDerivedSigningKey } from '../src/keystore/derived-signing-key.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';

const SLOT_INFO = 'test/vault-slot/v1';
const encode = (text) => new TextEncoder().encode(text);
const decode = (bytes) => new TextDecoder().decode(bytes);
const hex = (bytes) => Buffer.from(bytes).toString('hex');

// Made with createVault and addSlot; the slot keys come from the PRF outputs
// printed here, so nothing in it is secret.
const GOLDEN = Object.freeze({
  prfA: Uint8Array.from({ length: 32 }, (_, i) => i),
  prfB: Uint8Array.from({ length: 32 }, (_, i) => 255 - i),
  idA: new Uint8Array(16).fill(0xaa),
  idB: new Uint8Array(16).fill(0xbb),
  payload: '{"books":"golden"}',
  vaultKey: '990d02fb8ce3ea12af42176dcfe44344bc5b5688b9dbbc0929afb29911e6c916',
  vault: {
    version: 1,
    algorithm: 'AES-GCM',
    id: '9ae2f688f91ec8e3c2f67297ca8247f6',
    payload: {
      iv: '1efd13e0d932e51eaad92435',
      ciphertext:
        '7496b10772d2ecbbb880d598feed7e49c1041ca4251c1f9e616c2af9154524de4009',
    },
    slots: [
      {
        kid: 'bc1443a0d17aab2db1ea0302ef280717ac9a2f23355c5b649ea87d605430458d',
        iv: '6d4c3cd6cd6e5fa8928a5705',
        ciphertext:
          '9b238b0d10ee44596398d2241a10d343dd2d378ea9f891f22d78388a65b70769e825f1534be9885e57ad78f29178fbd1',
      },
      {
        kid: '5096f043e0a447557cd2ca843d65911aa67dfdd6883ab03bdb666c44a2753365',
        iv: '6fa7ee1b7771851d4956680e',
        ciphertext:
          '1a81cbe624e4d553ecbc8ad072d90ba0f2e4923d283b1812a955432af3e5d4f90496089615e178b9b5f11935ecc0e5d0',
      },
    ],
  },
});

/**
 * One touch of a mock authenticator: install it, read its PRF output once,
 * derive the slot key from that answer.
 */
async function touch(authenticator) {
  const restore = installMockAuthenticator(authenticator);
  try {
    const rawCredentialId = authenticator.credentialId;
    const prf = await readPrfOutput({ rawCredentialId }, { rpId: 'localhost' });
    return {
      prf,
      rawCredentialId,
      slotKey: await deriveAesKey(prf, SLOT_INFO),
    };
  } finally {
    restore();
  }
}

/** Two YubiKeys, one vault with a slot for each. */
async function twoKeyVault(payload = 'the books') {
  const yubikeyA = await createMockAuthenticator();
  const yubikeyB = await createMockAuthenticator();
  const a = await touch(yubikeyA);
  const b = await touch(yubikeyB);
  const { vault, vaultKey } = await createVault(encode(payload), a);
  const withB = await addSlot(vault, vaultKey, b);
  return { vault: withB, vaultKey, a, b, yubikeyA, yubikeyB };
}

const flipLastByte = (text) =>
  text.slice(0, -2) +
  (parseInt(text.slice(-2), 16) ^ 0xff).toString(16).padStart(2, '0');

const expectVaultError = async (promise, code) => {
  const error = await promise.then(
    () => null,
    (e) => e
  );
  expect(error).toBeInstanceOf(VaultError);
  expect(error.code).toBe(code);
};

test.describe('a vault two security keys can open', () => {
  test('each key opens it through its own slot, to the same contents', async () => {
    const { vault, vaultKey, a, b } = await twoKeyVault();
    const byA = await openVault(vault, a);
    const byB = await openVault(vault, b);
    expect(decode(byA.payload)).toBe('the books');
    expect(decode(byB.payload)).toBe('the books');
    expect(hex(byA.vaultKey)).toBe(hex(vaultKey));
    expect(hex(byB.vaultKey)).toBe(hex(vaultKey));
    expect(vault.slots).toHaveLength(2);
  });

  test('a third key has no slot and is refused', async () => {
    const { vault } = await twoKeyVault();
    const stranger = await touch(await createMockAuthenticator());
    await expectVaultError(openVault(vault, stranger), 'VAULT_NO_SLOT');
  });

  test('unlocking costs one touch, signing key included', async () => {
    const { vault, yubikeyB } = await twoKeyVault();
    const before = {
      prfEvals: yubikeyB.state.prfEvals,
      assertions: yubikeyB.state.assertions,
    };

    // What an application does on unlock: read the PRF once, open the vault,
    // and hand the same answer to the identity provider.
    const restore = installMockAuthenticator(yubikeyB);
    try {
      const credential = { rawCredentialId: yubikeyB.credentialId };
      const seed = await readPrfOutput(credential, { rpId: 'localhost' });
      const { payload } = await openVault(vault, {
        slotKey: await deriveAesKey(seed, SLOT_INFO),
        rawCredentialId: credential.rawCredentialId,
      });
      const keys = new Map();
      const outcome = await ensureDerivedSigningKey({
        keystore: {
          getKey: async (id) => keys.get(id),
          addKey: async (id, value) => keys.set(id, value),
        },
        did: 'did:key:zTestOnly',
        credential,
        rpId: 'localhost',
        seed,
      });
      expect(decode(payload)).toBe('the books');
      expect(outcome).toBe('derived');
    } finally {
      restore();
    }
    expect(yubikeyB.state.prfEvals - before.prfEvals).toBe(1);
    expect(yubikeyB.state.assertions - before.assertions).toBe(1);
  });

  test('a slot key derived under another info does not open the slot', async () => {
    const { vault, b } = await twoKeyVault();
    await expectVaultError(
      openVault(vault, {
        slotKey: await deriveAesKey(b.prf, 'test/another-purpose/v1'),
        rawCredentialId: b.rawCredentialId,
      }),
      'VAULT_LOCKED'
    );
  });

  test('survives being stored as JSON', async () => {
    const { vault, a } = await twoKeyVault();
    const stored = JSON.parse(JSON.stringify(vault));
    expect(decode((await openVault(stored, a)).payload)).toBe('the books');
  });
});

test.describe('the golden vault', () => {
  test('opens with both of its keys, as made', async () => {
    for (const [prf, rawCredentialId] of [
      [GOLDEN.prfA, GOLDEN.idA],
      [GOLDEN.prfB, GOLDEN.idB],
    ]) {
      const { payload, vaultKey } = await openVault(GOLDEN.vault, {
        slotKey: await deriveAesKey(prf, SLOT_INFO),
        rawCredentialId,
      });
      expect(decode(payload)).toBe(GOLDEN.payload);
      expect(hex(vaultKey)).toBe(GOLDEN.vaultKey);
    }
  });

  test('files slots under the SHA-256 of the credential id', async () => {
    expect(await slotIdFor(GOLDEN.idA)).toBe(GOLDEN.vault.slots[0].kid);
    expect(await slotIdFor(GOLDEN.idB)).toBe(GOLDEN.vault.slots[1].kid);
  });
});

test.describe('what a vault refuses', () => {
  const keyA = async () => ({
    slotKey: await deriveAesKey(GOLDEN.prfA, SLOT_INFO),
    rawCredentialId: GOLDEN.idA,
  });

  test('an altered payload', async () => {
    const altered = structuredClone(GOLDEN.vault);
    altered.payload.ciphertext = flipLastByte(altered.payload.ciphertext);
    await expectVaultError(openVault(altered, await keyA()), 'VAULT_LOCKED');
  });

  test('an altered slot', async () => {
    const altered = structuredClone(GOLDEN.vault);
    altered.slots[0].ciphertext = flipLastByte(altered.slots[0].ciphertext);
    await expectVaultError(openVault(altered, await keyA()), 'VAULT_LOCKED');
  });

  test('a slot moved into another vault', async () => {
    // Same slots, another id: every ciphertext is bound to the id.
    const moved = structuredClone(GOLDEN.vault);
    moved.id = '00'.repeat(16);
    await expectVaultError(openVault(moved, await keyA()), 'VAULT_LOCKED');
  });

  test('a slot relabelled to another key', async () => {
    // B's sealed vault key filed under A's id: bound to B's id, it fails.
    const relabelled = structuredClone(GOLDEN.vault);
    relabelled.slots[0] = {
      ...GOLDEN.vault.slots[1],
      kid: GOLDEN.vault.slots[0].kid,
    };
    relabelled.slots.pop();
    await expectVaultError(
      openVault(relabelled, {
        slotKey: await deriveAesKey(GOLDEN.prfB, SLOT_INFO),
        rawCredentialId: GOLDEN.idA,
      }),
      'VAULT_LOCKED'
    );
  });

  test('anything that is not a version-1 vault', async () => {
    const key = await keyA();
    for (const notAVault of [
      null,
      'vault',
      { ...GOLDEN.vault, version: 2 },
      { ...GOLDEN.vault, algorithm: 'AES-CBC' },
      { ...GOLDEN.vault, id: 'not hex' },
      { ...GOLDEN.vault, slots: 'none' },
      { ...GOLDEN.vault, slots: [{ kid: 'short', iv: '', ciphertext: '' }] },
      { ...GOLDEN.vault, payload: { iv: '00', ciphertext: '' } },
    ]) {
      await expectVaultError(openVault(notAVault, key), 'VAULT_MALFORMED');
    }
  });
});

test.describe('changing a vault', () => {
  test('a removed key no longer opens it; the others still do', async () => {
    const { vault, a, b } = await twoKeyVault();
    const withoutA = await removeSlot(vault, a.rawCredentialId);
    await expectVaultError(openVault(withoutA, a), 'VAULT_NO_SLOT');
    expect(decode((await openVault(withoutA, b)).payload)).toBe('the books');
    // The record passed in is left as it was.
    expect(vault.slots).toHaveLength(2);
  });

  test('the last slot cannot be removed', async () => {
    const { vault, a, b } = await twoKeyVault();
    const onlyB = await removeSlot(vault, a.rawCredentialId);
    await expectVaultError(
      removeSlot(onlyB, b.rawCredentialId),
      'VAULT_LAST_SLOT'
    );
  });

  test('removing a key that has no slot is refused', async () => {
    const { vault } = await twoKeyVault();
    await expectVaultError(
      removeSlot(vault, new Uint8Array(16).fill(1)),
      'VAULT_NO_SLOT'
    );
  });

  test('a key that already has a slot cannot get a second', async () => {
    const { vault, vaultKey, a } = await twoKeyVault();
    await expectVaultError(addSlot(vault, vaultKey, a), 'VAULT_SLOT_EXISTS');
  });

  test('a slot is only added with the vault’s own key', async () => {
    const { vault } = await twoKeyVault();
    const newcomer = await touch(await createMockAuthenticator());
    await expectVaultError(
      addSlot(vault, crypto.getRandomValues(new Uint8Array(32)), newcomer),
      'VAULT_LOCKED'
    );
  });

  test('a new payload opens with every slot, under the same vault key', async () => {
    const { vault, vaultKey, a, b } = await twoKeyVault();
    const updated = await replacePayload(vault, vaultKey, encode('new books'));
    expect(decode((await openVault(updated, a)).payload)).toBe('new books');
    expect(decode((await openVault(updated, b)).payload)).toBe('new books');
    expect(hex((await openVault(updated, b)).vaultKey)).toBe(hex(vaultKey));
    expect(decode((await openVault(vault, a)).payload)).toBe('the books');
  });

  test('a payload is only replaced with the vault’s own key', async () => {
    const { vault } = await twoKeyVault();
    await expectVaultError(
      replacePayload(
        vault,
        crypto.getRandomValues(new Uint8Array(32)),
        encode('x')
      ),
      'VAULT_LOCKED'
    );
  });
});

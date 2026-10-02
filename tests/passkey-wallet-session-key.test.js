/**
 * @le-space/passkey-wallet: the sealed Zama session key.
 *
 * simple-todo's escrow01 has stored its read key in this format since
 * Le-Space/simple-todo#56, so the format is data people already hold, not an
 * implementation detail. The first test is the yardstick: it opens an envelope
 * sealed by the code escrow01 runs today. That envelope was made with
 * packages/passkey-wallet/src at a650e64, which is the vendored tarball
 * `le-space-passkey-wallet-0.0.0-cde6878.tgz` byte for byte. Whatever this
 * package becomes, that envelope has to keep opening.
 *
 * The rest pin down what the format refuses: another sealing key, an altered
 * ciphertext, an envelope naming another address, anything that is not an
 * envelope at all.
 */
import { test, expect } from '@playwright/test';
import {
  createZamaSessionKey,
  openZamaSessionKey,
} from '../packages/passkey-wallet/src/zama.js';

// The sealing key is printed here, so the private key inside GOLDEN is public
// by construction. It was made for this test and holds nothing.
const SEALING_KEY = Uint8Array.from({ length: 32 }, (_, i) => i);

const GOLDEN = Object.freeze({
  version: 1,
  algorithm: 'AES-GCM',
  address: '0x569C62952f1De0e1AD868a93285CF7a96117D814',
  iv: '0xbd1d010c44aade11e6730c07',
  ciphertext:
    '0x5b0a31e162a67124954b6568e06f70d1080914abb91bf4422a051a6d6223206edb7f4f84f0a200d9a6206b886057f765',
});

const OTHER_ADDRESS = '0x000000000000000000000000000000000000dEaD';

const asCryptoKey = (bytes) =>
  crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);

/** Flip the last byte of a 0x-hex string. */
const alterLastByte = (hex) => {
  const last = parseInt(hex.slice(-2), 16) ^ 0xff;
  return `${hex.slice(0, -2)}${last.toString(16).padStart(2, '0')}`;
};

test.describe('passkey-wallet: sealed Zama session key', () => {
  test('opens an envelope sealed by the vendored cde6878 build', async () => {
    const key = await openZamaSessionKey(GOLDEN, SEALING_KEY);
    expect(key.address).toBe(GOLDEN.address);
    expect(key.account.address).toBe(GOLDEN.address);
  });

  test('opens it under the same key given as a CryptoKey', async () => {
    const key = await openZamaSessionKey(
      GOLDEN,
      await asCryptoKey(SEALING_KEY)
    );
    expect(key.address).toBe(GOLDEN.address);
  });

  test('keeps the shape escrow01 stores', async () => {
    const sealed = await createZamaSessionKey().seal(SEALING_KEY);
    expect(Object.keys(sealed).sort()).toEqual([
      'address',
      'algorithm',
      'ciphertext',
      'iv',
      'version',
    ]);
    expect(sealed.version).toBe(1);
    expect(sealed.algorithm).toBe('AES-GCM');
    // A 12-byte IV, and 32 bytes of key plus a 16-byte tag.
    expect(sealed.iv).toMatch(/^0x[0-9a-f]{24}$/);
    expect(sealed.ciphertext).toMatch(/^0x[0-9a-f]{96}$/);
  });

  test('seals and opens again, to the same key', async () => {
    const original = createZamaSessionKey();
    const sealed = await original.seal(SEALING_KEY);
    const opened = await openZamaSessionKey(sealed, SEALING_KEY);
    expect(opened.address).toBe(original.address);
    expect(sealed.address).toBe(original.address);
  });

  test('draws a fresh IV for every seal', async () => {
    const key = createZamaSessionKey();
    const [a, b] = await Promise.all([
      key.seal(SEALING_KEY),
      key.seal(SEALING_KEY),
    ]);
    expect(a.iv).not.toBe(b.iv);
  });

  test('refuses another sealing key', async () => {
    const other = SEALING_KEY.map((byte) => byte ^ 0x01);
    await expect(openZamaSessionKey(GOLDEN, other)).rejects.toThrow(
      /does not open with this sealing key/
    );
  });

  test('refuses an altered ciphertext', async () => {
    const altered = { ...GOLDEN, ciphertext: alterLastByte(GOLDEN.ciphertext) };
    await expect(openZamaSessionKey(altered, SEALING_KEY)).rejects.toThrow(
      /does not open with this sealing key, or was altered/
    );
  });

  test('refuses an envelope that names another address', async () => {
    // The address is bound into the ciphertext as associated data, so moving
    // the key under another name breaks the seal rather than the name check.
    const renamed = { ...GOLDEN, address: OTHER_ADDRESS };
    await expect(openZamaSessionKey(renamed, SEALING_KEY)).rejects.toThrow(
      /does not open with this sealing key, or was altered/
    );
  });

  test('refuses what is not an envelope', async () => {
    for (const notSealed of [
      null,
      'sealed',
      { ...GOLDEN, version: 2 },
      { ...GOLDEN, algorithm: 'AES-CBC' },
      { ...GOLDEN, address: 'not an address' },
      { ...GOLDEN, iv: undefined },
    ]) {
      await expect(openZamaSessionKey(notSealed, SEALING_KEY)).rejects.toThrow(
        TypeError
      );
    }
  });

  test('refuses a raw sealing key that is not 32 bytes', async () => {
    await expect(
      openZamaSessionKey(GOLDEN, new Uint8Array(16))
    ).rejects.toThrow(/must be 32 bytes/);
  });
});

/**
 * One read of the PRF output, and the keys derived from it.
 *
 * The yardstick for `deriveSubkey` and `deriveAesKey` is the code that already
 * holds data: before these functions existed, four places wrote their own
 * HKDF over the PRF output. Each vector below was produced by that place's own
 * code, not by a copy of it:
 *
 * - Le-Space/belege `app/src/lib/database-keys.js` at 7165bd5
 * - Le-Space/invoice `app/src/lib/database-keys.js` at 2917386
 * - this repository's `deriveSigningKeyBytes` at a83eb40, before it was moved
 *   onto the shared HKDF
 * - Le-Space/simple-todo `apps/escrow01/src/lib/chain/read-key-seal.js` at
 *   b5af708, whose sealing key is not extractable — so the vector is a
 *   ciphertext it made, and the test is that `deriveAesKey` opens it. That
 *   one uses a salt of 32 zero bytes where the others use none; HKDF-SHA-256
 *   gives the same key for both.
 *
 * If one of these changes, data somebody holds stops opening.
 */
import { test, expect } from '@playwright/test';
import {
  readPrfOutput,
  deriveSubkey,
  deriveAesKey,
  deriveSigningKeyBytes,
  prfInputForRelyingParty,
  PrfUnavailableError,
  OrbitDBWebAuthnIdentityProvider,
} from '../src/index.js';
import { ensureDerivedSigningKey } from '../src/keystore/derived-signing-key.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i);
const DID = 'did:key:zTestVectorsOnlyNotARealKey';
const hex = (bytes) => Buffer.from(bytes).toString('hex');

const VECTORS = [
  [
    'belege/db-key/v1',
    32,
    'bf068d09d75138f38ed42f6b27e54ac67c1214eb12691a5f4b0670a4b0e0895c',
  ],
  ['belege/db-name/v1:receipts', 16, 'c80acf93820d1ce9fe32701b5367b168'],
  [
    'invoice/db-key/v1',
    32,
    '8861e5c3138d25622f04634cf39053b47d5a34f8f5fdb3a3c5201b0a0894ad21',
  ],
  ['invoice/db-name/v1:invoices', 16, '690ba898c146f1a5ea9519b1dd1431af'],
  [
    'invoice/peer-key/v1',
    32,
    '2b41411ad7a35b13bfe9f791db6811b9bd5cda61443c6f19b06e0c9c6cea4d8f',
  ],
];

const ESCROW01 = {
  info: 'simple-todo:escrow01:read-key-seal:v1',
  iv: '090909090909090909090909',
  ciphertext:
    '525e3c55fd6d882d18ba023c085e741f135fdde4ac806ef5cba1447ba4cabb4bc4f4',
  plaintext: 'sealed by escrow01',
};

/** A credential as the provider stores it, for the mock's active one. */
const credentialOf = (authenticator, extra = {}) => ({
  rawCredentialId: authenticator.credentialId,
  ...extra,
});

/** Run `fn` with `authenticator` installed as the page's navigator. */
async function withAuthenticator(authenticator, fn) {
  const restore = installMockAuthenticator(authenticator);
  try {
    return await fn();
  } finally {
    restore();
  }
}

test.describe('deriveSubkey reproduces what applications derived themselves', () => {
  for (const [info, length, expected] of VECTORS) {
    test(`${info} (${length} bytes)`, async () => {
      expect(hex(await deriveSubkey(SEED, info, { length }))).toBe(expected);
    });
  }

  test('the provider’s signing key is unchanged by moving onto it', async () => {
    expect(hex(await deriveSigningKeyBytes(SEED, DID))).toBe(
      'b2648f2322b357334d84ba88cc0f822652a79867bbb76180b701f410e10f424d'
    );
    expect(hex(await deriveSigningKeyBytes(SEED, DID, 'Ed25519'))).toBe(
      '1ff2fd49218847fd159dc6664449d02488d497d61c5420fa23d7ab22374d487e' +
        '148871d078645360727f292392fdac8fdc3572143789a0b8b7826f8d6f54337b'
    );
  });

  test('deriveAesKey opens what escrow01 sealed', async () => {
    const key = await deriveAesKey(SEED, ESCROW01.info);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Buffer.from(ESCROW01.iv, 'hex') },
      key,
      Buffer.from(ESCROW01.ciphertext, 'hex')
    );
    expect(new TextDecoder().decode(plaintext)).toBe(ESCROW01.plaintext);
  });
});

test.describe('deriveSubkey and deriveAesKey', () => {
  test('give unrelated bytes for different info, the same for the same', async () => {
    const a = await deriveSubkey(SEED, 'app/a/v1');
    expect(hex(await deriveSubkey(SEED, 'app/a/v1'))).toBe(hex(a));
    expect(hex(await deriveSubkey(SEED, 'app/b/v1'))).not.toBe(hex(a));
  });

  test('the AES key is not extractable, and its material is deriveSubkey', async () => {
    const key = await deriveAesKey(SEED, 'app/seal/v1');
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });

    const twin = await crypto.subtle.importKey(
      'raw',
      await deriveSubkey(SEED, 'app/seal/v1'),
      'AES-GCM',
      false,
      ['decrypt']
    );
    const iv = new Uint8Array(12);
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode('same key')
    );
    const opened = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      twin,
      sealed
    );
    expect(new TextDecoder().decode(opened)).toBe('same key');
  });

  test('refuse what is not a PRF output, an empty info, an impossible length', async () => {
    await expect(deriveSubkey(new Uint8Array(16), 'x')).rejects.toThrow(
      TypeError
    );
    await expect(deriveSubkey('seed', 'x')).rejects.toThrow(TypeError);
    await expect(deriveSubkey(SEED, '')).rejects.toThrow(TypeError);
    await expect(deriveSubkey(SEED, 'x', { length: 0 })).rejects.toThrow(
      RangeError
    );
    await expect(deriveSubkey(SEED, 'x', { length: 8161 })).rejects.toThrow(
      RangeError
    );
    await expect(deriveAesKey(new Uint8Array(31), 'x')).rejects.toThrow(
      TypeError
    );
  });
});

test.describe('readPrfOutput', () => {
  test('reads 32 bytes, and the same bytes every time', async () => {
    const authenticator = await createMockAuthenticator();
    const [first, second] = await withAuthenticator(authenticator, () =>
      Promise.all([
        readPrfOutput(credentialOf(authenticator), { rpId: 'localhost' }),
        readPrfOutput(credentialOf(authenticator), { rpId: 'localhost' }),
      ])
    );
    expect(first).toHaveLength(32);
    expect(hex(second)).toBe(hex(first));
    expect(authenticator.state.prfEvals).toBe(2);
  });

  test('asks with the fixed input for the relying party when the credential has none', async () => {
    const authenticator = await createMockAuthenticator({
      prfSecret: new Uint8Array(32).fill(1),
    });
    const fixed = await prfInputForRelyingParty('localhost');
    const [implicit, explicit] = await withAuthenticator(
      authenticator,
      async () => [
        await readPrfOutput(credentialOf(authenticator), { rpId: 'localhost' }),
        await readPrfOutput(credentialOf(authenticator), {
          rpId: 'localhost',
          prfInput: fixed,
        }),
      ]
    );
    expect(hex(implicit)).toBe(hex(explicit));
  });

  test('uses the input the credential was registered with', async () => {
    const authenticator = await createMockAuthenticator({
      prfSecret: new Uint8Array(32).fill(2),
    });
    const own = new Uint8Array(32).fill(7);
    const [registered, explicit, fixed] = await withAuthenticator(
      authenticator,
      async () => [
        await readPrfOutput(credentialOf(authenticator, { prfInput: own }), {
          rpId: 'localhost',
        }),
        await readPrfOutput(credentialOf(authenticator), {
          rpId: 'localhost',
          prfInput: own,
        }),
        await readPrfOutput(credentialOf(authenticator), { rpId: 'localhost' }),
      ]
    );
    expect(hex(registered)).toBe(hex(explicit));
    expect(hex(registered)).not.toBe(hex(fixed));
  });

  test('two security keys answer differently; one synced passkey answers the same', async () => {
    const secret = new Uint8Array(32).fill(3);
    const read = async (authenticator) =>
      hex(
        await withAuthenticator(authenticator, () =>
          readPrfOutput(credentialOf(authenticator), { rpId: 'localhost' })
        )
      );
    const yubikeyA = await read(await createMockAuthenticator());
    const yubikeyB = await read(await createMockAuthenticator());
    const syncedHere = await read(
      await createMockAuthenticator({ prfSecret: secret })
    );
    const syncedThere = await read(
      await createMockAuthenticator({ prfSecret: secret })
    );
    expect(yubikeyA).not.toBe(yubikeyB);
    expect(syncedHere).toBe(syncedThere);
  });

  test('an authenticator without PRF is PrfUnavailableError', async () => {
    const authenticator = await createMockAuthenticator({ supportsPrf: false });
    await withAuthenticator(authenticator, async () => {
      await expect(
        readPrfOutput(credentialOf(authenticator), { rpId: 'localhost' })
      ).rejects.toBeInstanceOf(PrfUnavailableError);
    });
  });

  test('a refused prompt stays the browser’s refusal', async () => {
    const authenticator = await createMockAuthenticator();
    const refusal = new DOMException('The user said no', 'NotAllowedError');
    authenticator.navigator.credentials.get = async () => {
      throw refusal;
    };
    await withAuthenticator(authenticator, async () => {
      await expect(
        readPrfOutput(credentialOf(authenticator), { rpId: 'localhost' })
      ).rejects.toBe(refusal);
    });
  });

  test('needs the credential’s raw id', async () => {
    await expect(readPrfOutput({}, { rpId: 'localhost' })).rejects.toThrow(
      /rawCredentialId/
    );
    await expect(readPrfOutput(null)).rejects.toThrow(TypeError);
  });
});

test.describe('ensureDerivedSigningKey with a seed already read', () => {
  test('derives the signing key without asking the passkey again', async () => {
    const authenticator = await createMockAuthenticator();
    const keys = new Map();
    const keystore = {
      getKey: async (id) => keys.get(id),
      addKey: async (id, { privateKey }) => keys.set(id, { privateKey }),
    };

    await withAuthenticator(authenticator, async () => {
      const credential = credentialOf(authenticator);
      const seed = await readPrfOutput(credential, { rpId: 'localhost' });
      const outcome = await ensureDerivedSigningKey({
        keystore,
        did: DID,
        credential,
        rpId: 'localhost',
        seed,
      });
      expect(outcome).toBe('derived');
      expect(hex(keys.get(DID).privateKey)).toBe(
        hex(await deriveSigningKeyBytes(seed, DID))
      );
    });
    expect(authenticator.state.prfEvals).toBe(1);
    expect(authenticator.state.assertions).toBe(1);
  });
});

test.describe('the identity provider with a PRF output already read', () => {
  /** A keystore that holds what it is given, as OrbitDB's does. */
  const memoryKeystore = () => {
    const keys = new Map();
    return {
      keys,
      getKey: async (id) => keys.get(id),
      addKey: async (id, { privateKey }) => keys.set(id, { privateKey }),
    };
  };

  /** A page: the provider and readPrfOutput both default to its hostname. */
  async function inPage(authenticator, fn) {
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'location');
    globalThis.location = { hostname: 'localhost' };
    try {
      return await withAuthenticator(authenticator, fn);
    } finally {
      if (previous) Object.defineProperty(globalThis, 'location', previous);
      else delete globalThis.location;
    }
  }

  const credentialFor = (authenticator) => ({
    rawCredentialId: authenticator.credentialId,
    publicKey: authenticator.publicKey,
  });

  test('derives the signing key from it — one touch — and it is the key the provider would have read itself', async () => {
    const authenticator = await createMockAuthenticator();
    await inPage(authenticator, async () => {
      const credential = credentialFor(authenticator);

      // The application reads once, to unlock something of its own …
      const prfOutput = await readPrfOutput(credential);
      const handedOver = memoryKeystore();
      const provider = new OrbitDBWebAuthnIdentityProvider({
        webauthnCredential: credential,
        keystore: handedOver,
        prfOutput,
      });
      const did = await provider.getId();

      // … and the identity costs no second touch.
      expect(authenticator.state.prfEvals).toBe(1);
      expect(authenticator.state.assertions).toBe(1);
      expect(hex(handedOver.keys.get(did).privateKey)).toBe(
        hex(await deriveSigningKeyBytes(prfOutput, did))
      );

      // The provider let go of the secret; the caller's bytes are intact.
      expect(provider.prfOutput).toBeNull();
      expect(hex(prfOutput)).toBe(hex(await readPrfOutput(credential)));

      // On a device where nobody hands it over, the provider asks the passkey
      // itself — and must arrive at the same key, or that device would mint a
      // second identity document for the same DID.
      const ownRead = memoryKeystore();
      await new OrbitDBWebAuthnIdentityProvider({
        webauthnCredential: credential,
        keystore: ownRead,
      }).getId();
      expect(authenticator.state.prfEvals).toBe(3);
      expect(hex(ownRead.keys.get(did).privateKey)).toBe(
        hex(handedOver.keys.get(did).privateKey)
      );
    });
  });

  test('refuses what is not a PRF output', () => {
    const webauthnCredential = { rawCredentialId: new Uint8Array(16) };
    for (const prfOutput of [new Uint8Array(16), 'secret', [1, 2, 3]]) {
      expect(
        () =>
          new OrbitDBWebAuthnIdentityProvider({ webauthnCredential, prfOutput })
      ).toThrow(TypeError);
    }
    expect(
      () =>
        new OrbitDBWebAuthnIdentityProvider({
          webauthnCredential,
          prfOutput: null,
        })
    ).not.toThrow();
  });
});

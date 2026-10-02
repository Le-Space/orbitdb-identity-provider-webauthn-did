/**
 * Two security keys, one vault — in Chromium, with the authenticator's real
 * PRF answering.
 *
 * Each key is its own virtual authenticator with its own PRF secret, as two
 * YubiKeys are. A credential copied from one virtual authenticator into
 * another would not do: it keeps its id but loses that secret, so it stands
 * for neither one key nor two.
 *
 * One page per key. Chromium's virtual authenticators belong to a page, and on
 * one page every registration would race all of them. The vault record is
 * plain JSON and travels between the pages as it would through a database.
 * The vault key crosses once, from A to B, standing for the moment both keys
 * are at one computer: the vault opened with A, then B touched.
 *
 * Twice: with passkeys of the device itself, and with roaming keys on the USB
 * transport registered as `authenticatorType: 'cross-platform'` — two YubiKeys
 * as near as a virtual authenticator comes.
 */
import { test, expect } from '@playwright/test';
import {
  addVirtualAuthenticator,
  requireChromium,
} from './helpers/virtual-authenticator.js';
import { loadLibrary } from './helpers/library-in-page.js';

const SLOT_INFO = 'vault-test/vault-slot/v1';

const KINDS = [
  { name: 'two passkeys of the device', transport: 'internal' },
  {
    name: 'two security keys',
    transport: 'usb',
    authenticatorType: 'cross-platform',
  },
];

/** A page holding one key of this kind, with the library loaded. */
async function securityKey(context, kind) {
  const page = await context.newPage();
  await addVirtualAuthenticator(page, { transport: kind.transport });
  await loadLibrary(page);
  return page;
}

/**
 * Register the key's credential and keep it on the page, as an application
 * keeps it in storage. Returns the credential's DID.
 */
function register(page, displayName, kind) {
  return page.evaluate(
    async ({ displayName, authenticatorType }) => {
      const { WebAuthnDIDProvider } = window.WebAuthnModule;
      window.credential = await WebAuthnDIDProvider.createCredential({
        userId: 'owner',
        displayName,
        authenticatorType,
      });
      return WebAuthnDIDProvider.createDID(window.credential);
    },
    { displayName, authenticatorType: kind.authenticatorType }
  );
}

/**
 * Unlock: touch the key once, open the vault through its slot, and create the
 * OrbitDB identity from the same answer. Counts the touches.
 */
function unlock(page, vault, slotInfo) {
  return page.evaluate(
    async ({ vault, slotInfo }) => {
      const M = window.WebAuthnModule;
      const credentials = navigator.credentials;
      const get = credentials.get.bind(credentials);
      let touches = 0;
      credentials.get = (...args) => {
        touches += 1;
        return get(...args);
      };
      try {
        const prfOutput = await M.readPrfOutput(window.credential);
        let payload;
        try {
          ({ payload } = await M.openVault(vault, {
            slotKey: await M.deriveAesKey(prfOutput, slotInfo),
            rawCredentialId: window.credential.rawCredentialId,
          }));
        } catch (error) {
          return { refused: error.code ?? error.name, touches };
        }

        const keys = new Map();
        const provider = new M.OrbitDBWebAuthnIdentityProvider({
          webauthnCredential: window.credential,
          keystore: {
            getKey: async (id) => keys.get(id),
            addKey: async (id, { privateKey }) => keys.set(id, { privateKey }),
          },
          prfOutput,
        });
        const did = await provider.getId();
        return {
          payload: new TextDecoder().decode(payload),
          did,
          signingKey: keys.has(did),
          touches,
        };
      } finally {
        delete credentials.get;
      }
    },
    { vault, slotInfo }
  );
}

test.describe('a vault two keys open', () => {
  test.beforeEach(({ browserName }) => {
    requireChromium(test, browserName);
  });

  for (const kind of KINDS) {
    test(`${kind.name}: A creates it, B is added, a stranger is refused, and unlocking is one touch`, async ({
      context,
    }) => {
      test.setTimeout(120000);
      const keyA = await securityKey(context, kind);
      const keyB = await securityKey(context, kind);
      const stranger = await securityKey(context, kind);

      const didA = await register(keyA, 'Key A', kind);
      const didB = await register(keyB, 'Key B', kind);
      await register(stranger, 'Not ours', kind);
      // Two keys, two passkeys, two DIDs: what they share is the vault.
      expect(didB).not.toBe(didA);

      // Key A makes the vault: a random database key in it, A's slot on it.
      const made = await keyA.evaluate(async (slotInfo) => {
        const M = window.WebAuthnModule;
        const prfOutput = await M.readPrfOutput(window.credential);
        const secret = Array.from(crypto.getRandomValues(new Uint8Array(32)))
          .map((byte) => byte.toString(16).padStart(2, '0'))
          .join('');
        const { vault, vaultKey } = await M.createVault(
          new TextEncoder().encode(JSON.stringify({ dbKey: secret })),
          {
            slotKey: await M.deriveAesKey(prfOutput, slotInfo),
            rawCredentialId: window.credential.rawCredentialId,
          }
        );
        return { vault, vaultKey: Array.from(vaultKey), secret };
      }, SLOT_INFO);
      expect(made.vault.slots).toHaveLength(1);

      // With the vault open from A, key B is touched and gets its own slot.
      const withB = await keyB.evaluate(
        async ({ vault, vaultKey, slotInfo }) => {
          const M = window.WebAuthnModule;
          const prfOutput = await M.readPrfOutput(window.credential);
          return M.addSlot(vault, Uint8Array.from(vaultKey), {
            slotKey: await M.deriveAesKey(prfOutput, slotInfo),
            rawCredentialId: window.credential.rawCredentialId,
          });
        },
        { ...made, slotInfo: SLOT_INFO }
      );
      expect(withB.slots).toHaveLength(2);
      expect(JSON.stringify(withB)).not.toContain(made.secret);

      // Later, anywhere: each key opens it alone, with one touch, and gets its
      // own signing identity from that same touch.
      const expected = JSON.stringify({ dbKey: made.secret });
      const openedByB = await unlock(keyB, withB, SLOT_INFO);
      expect(openedByB).toEqual({
        payload: expected,
        did: didB,
        signingKey: true,
        touches: 1,
      });
      const openedByA = await unlock(keyA, withB, SLOT_INFO);
      expect(openedByA).toEqual({
        payload: expected,
        did: didA,
        signingKey: true,
        touches: 1,
      });

      // A key that was never added has no slot.
      expect(await unlock(stranger, withB, SLOT_INFO)).toEqual({
        refused: 'VAULT_NO_SLOT',
        touches: 1,
      });
      // Nor does a registered key under another application's slot info.
      expect(await unlock(keyB, withB, 'other-app/vault-slot/v1')).toEqual({
        refused: 'VAULT_LOCKED',
        touches: 1,
      });

      // A is lost: its slot goes, and B still opens what A made.
      const withoutA = await keyB.evaluate(
        async ({ vault, rawCredentialId }) =>
          window.WebAuthnModule.removeSlot(
            vault,
            Uint8Array.from(rawCredentialId)
          ),
        {
          vault: withB,
          rawCredentialId: await keyA.evaluate(() =>
            Array.from(window.credential.rawCredentialId)
          ),
        }
      );
      expect(await unlock(keyA, withoutA, SLOT_INFO)).toEqual({
        refused: 'VAULT_NO_SLOT',
        touches: 1,
      });
      expect((await unlock(keyB, withoutA, SLOT_INFO)).payload).toBe(expected);
    });
  }
});

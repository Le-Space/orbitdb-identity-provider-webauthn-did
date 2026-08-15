/**
 * Guards WebAuthn extension detection.
 *
 * The check this replaced asked `'largeBlob' in PublicKeyCredential.prototype`.
 * Extensions are never properties of that interface — they arrive through
 * getClientExtensionResults() — so it answered `false` in every browser ever
 * shipped, including those with complete support, and permanently disabled
 * keystore encryption in the demo. Measured on Chrome 148: the prototype probe
 * said false for largeBlob, prf and hmacCreateSecret while
 * getClientCapabilities() reported all three true. See issue #9.
 */
import { test, expect } from '@playwright/test';

import {
  checkExtensionSupport,
  extensionSupportFromCredential,
  writeSKToLargeBlob,
} from '../src/keystore/encryption.js';

const CREDENTIAL_ID = new Uint8Array(32).fill(0x11);
const SECRET_KEY = new Uint8Array(32).fill(0x22);

// Node defines globalThis.navigator as a getter-only accessor, so a plain
// assignment throws. Swap the property descriptor and put the original back.
const ORIGINAL_NAVIGATOR = Object.getOwnPropertyDescriptor(
  globalThis,
  'navigator'
);

/**
 * Stand in for navigator.credentials.get, answering with whatever the
 * authenticator is meant to have reported back.
 */
function installCredentialsGet(extensionResults, { rejectWith } = {}) {
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    writable: true,
    value: {
      credentials: {
        get: async () => {
          if (rejectWith) throw rejectWith;
          return { getClientExtensionResults: () => extensionResults };
        },
      },
    },
  });
}

function restoreNavigator() {
  if (ORIGINAL_NAVIGATOR) {
    Object.defineProperty(globalThis, 'navigator', ORIGINAL_NAVIGATOR);
  } else {
    delete globalThis.navigator;
  }
}

/**
 * The real interface: extensions do not appear here, only these six members.
 */
const REAL_PROTOTYPE_MEMBERS = [
  'rawId',
  'response',
  'authenticatorAttachment',
  'getClientExtensionResults',
  'toJSON',
  'constructor',
];

function installPublicKeyCredential({ capabilities, throws } = {}) {
  function PublicKeyCredential() {}

  for (const name of REAL_PROTOTYPE_MEMBERS) {
    if (name === 'constructor') continue;
    Object.defineProperty(PublicKeyCredential.prototype, name, {
      value: undefined,
      configurable: true,
    });
  }

  if (capabilities !== undefined) {
    PublicKeyCredential.getClientCapabilities = async () => {
      if (throws) throw new Error('capability query refused');
      return capabilities;
    };
  }

  globalThis.PublicKeyCredential = PublicKeyCredential;
  return PublicKeyCredential;
}

function clearPublicKeyCredential() {
  delete globalThis.PublicKeyCredential;
}

test.afterEach(() => clearPublicKeyCredential());

test.describe('client extension support', () => {
  test('reads capabilities instead of probing the prototype', async () => {
    const PKC = installPublicKeyCredential({
      capabilities: {
        'extension:largeBlob': true,
        'extension:prf': true,
        'extension:hmacCreateSecret': true,
      },
    });

    // The old check, kept here so the regression cannot come back unnoticed.
    expect('largeBlob' in PKC.prototype).toBe(false);
    expect('prf' in PKC.prototype).toBe(false);

    expect(await checkExtensionSupport()).toEqual({
      largeBlob: true,
      prf: true,
      hmacSecret: true,
      known: true,
    });
  });

  test('a client that answers "none of them" is still a known answer', async () => {
    installPublicKeyCredential({
      capabilities: { 'extension:credProps': true },
    });

    expect(await checkExtensionSupport()).toEqual({
      largeBlob: false,
      prf: false,
      hmacSecret: false,
      known: true,
    });
  });

  test('distinguishes "cannot say" from "unsupported"', async () => {
    // No getClientCapabilities at all — an older or minimal browser.
    installPublicKeyCredential();

    const support = await checkExtensionSupport();
    expect(support.known).toBe(false);
    expect(support.largeBlob).toBe(false);

    // The distinction is the whole point: callers must not read known:false as
    // a refusal, or they disable a feature that may well work.
    expect(support).toEqual({
      largeBlob: false,
      prf: false,
      hmacSecret: false,
      known: false,
    });
  });

  test('treats a throwing capability query as unknown, not unsupported', async () => {
    installPublicKeyCredential({ capabilities: {}, throws: true });

    const support = await checkExtensionSupport();
    expect(support.known).toBe(false);
  });

  test('survives a browser with no WebAuthn at all', async () => {
    clearPublicKeyCredential();

    expect(await checkExtensionSupport()).toEqual({
      largeBlob: false,
      prf: false,
      hmacSecret: false,
      known: false,
    });
  });

  test('does not treat a missing capability key as supported', async () => {
    installPublicKeyCredential({
      capabilities: { 'extension:largeBlob': true },
    });

    const support = await checkExtensionSupport();
    expect(support.largeBlob).toBe(true);
    expect(support.prf).toBe(false);
    expect(support.hmacSecret).toBe(false);
  });
});

test.describe('per-credential extension support', () => {
  test('reads what the authenticator actually agreed to', () => {
    const credential = {
      getClientExtensionResults: () => ({
        largeBlob: { supported: true },
        prf: { enabled: true },
        hmacCreateSecret: true,
      }),
    };

    expect(extensionSupportFromCredential(credential)).toEqual({
      largeBlob: true,
      prf: true,
      hmacSecret: true,
    });
  });

  test('a client that supports largeBlob does not mean the authenticator does', () => {
    // The reason this function exists: the browser said yes, the key said no.
    const credential = {
      getClientExtensionResults: () => ({ largeBlob: { supported: false } }),
    };

    expect(extensionSupportFromCredential(credential).largeBlob).toBe(false);
  });

  test('counts PRF as available when the ceremony returned results', () => {
    const credential = {
      getClientExtensionResults: () => ({
        prf: { results: { first: new Uint8Array(32) } },
      }),
    };

    expect(extensionSupportFromCredential(credential).prf).toBe(true);
  });

  test('an absent largeBlob result is not support', () => {
    const credential = { getClientExtensionResults: () => ({}) };

    expect(extensionSupportFromCredential(credential)).toEqual({
      largeBlob: false,
      prf: false,
      hmacSecret: false,
    });
  });

  test('handles a credential that cannot report extensions', () => {
    expect(extensionSupportFromCredential(null)).toEqual({
      largeBlob: false,
      prf: false,
      hmacSecret: false,
    });
    expect(extensionSupportFromCredential({})).toEqual({
      largeBlob: false,
      prf: false,
      hmacSecret: false,
    });
  });

  test('the two questions can disagree, which is the point', () => {
    // Measured on a real macOS platform authenticator in Brave: the client
    // advertises hmacCreateSecret, the authenticator refuses it, and PRF works.
    // Reading only the client is what left the demo offering hmac-secret and
    // failing at the ceremony.
    const clientSaysYesToEverything = {
      largeBlob: true,
      prf: true,
      hmacSecret: true,
    };
    const credential = {
      getClientExtensionResults: () => ({
        largeBlob: { supported: true },
        prf: { enabled: true },
        // no hmacCreateSecret at all
      }),
    };

    const authenticator = extensionSupportFromCredential(credential);

    expect(clientSaysYesToEverything.hmacSecret).toBe(true);
    expect(authenticator.hmacSecret).toBe(false);
    expect(authenticator.prf).toBe(true);
  });

  test('survives getClientExtensionResults throwing', () => {
    const credential = {
      getClientExtensionResults: () => {
        throw new Error('no extension results available');
      },
    };

    expect(extensionSupportFromCredential(credential)).toEqual({
      largeBlob: false,
      prf: false,
      hmacSecret: false,
    });
  });
});

test.describe('writing the secret key to largeBlob', () => {
  test.afterEach(() => {
    restoreNavigator();
  });

  test('resolves when the authenticator confirms the write', async () => {
    installCredentialsGet({ largeBlob: { written: true } });

    await expect(
      writeSKToLargeBlob(CREDENTIAL_ID, SECRET_KEY, 'example.com')
    ).resolves.toBeUndefined();
  });

  test('throws when the authenticator declines the write', async () => {
    // The regression this exists for. Ignoring `written` leaves a keystore
    // whose key lives only in memory: usable this session, unopenable after.
    installCredentialsGet({ largeBlob: { written: false } });

    await expect(
      writeSKToLargeBlob(CREDENTIAL_ID, SECRET_KEY, 'example.com')
    ).rejects.toThrow(/did not store the secret key/i);
  });

  test('throws when there is no largeBlob result at all', async () => {
    installCredentialsGet({});

    await expect(
      writeSKToLargeBlob(CREDENTIAL_ID, SECRET_KEY, 'example.com')
    ).rejects.toThrow(/did not store the secret key/i);
  });

  test('does not accept a truthy non-true value as a write', async () => {
    installCredentialsGet({ largeBlob: { written: 'yes' } });

    await expect(
      writeSKToLargeBlob(CREDENTIAL_ID, SECRET_KEY, 'example.com')
    ).rejects.toThrow(/did not store the secret key/i);
  });

  test('surfaces a refused or failed assertion', async () => {
    installCredentialsGet(null, { rejectWith: new Error('user cancelled') });

    await expect(
      writeSKToLargeBlob(CREDENTIAL_ID, SECRET_KEY, 'example.com')
    ).rejects.toThrow(/Failed to write secret key to largeBlob/i);
  });
});

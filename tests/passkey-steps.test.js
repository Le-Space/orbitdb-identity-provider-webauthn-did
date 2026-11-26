/**
 * Before each passkey prompt, a word on what it is for — announced by the
 * package, answered by the application's handler.
 *
 * Driven through the real entry points an application uses (createCredential,
 * the signing key's PRF read, the identity signature, the restore), against
 * the mock authenticator, so what is asserted is the order and purpose of the
 * prompts the package actually makes, not a list kept beside it.
 */
import { test, expect } from '@playwright/test';
import {
  WebAuthnDIDProvider,
  setPasskeyStepHandler,
  withPasskeySteps,
  beforePasskeyCeremony,
  PasskeyStepCancelled,
  PASSKEY_PURPOSES,
  restoreIdentityFromAuthenticator,
  OrbitDBWebAuthnIdentityProvider,
  createSessionKeystore,
} from '../src/index.js';
import * as standalone from '../src/standalone/index.js';
import { getPrfOutput } from '../src/keystore/derived-signing-key.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';

let authenticator;
let restore;
/** @type {Array<{ purpose: string, n: number, of: number | null, kind: string }>} */
let asked;
let unregister;

test.beforeEach(async () => {
  authenticator = await createMockAuthenticator({ rpId: 'localhost' });
  restore = installMockAuthenticator(authenticator);
  asked = [];
  unregister = setPasskeyStepHandler((step) => {
    asked.push(step);
  });
});

test.afterEach(() => {
  unregister?.();
  restore?.();
});

/** What creating a passkey-backed identity asks, in the order it asks it. */
async function createIdentity() {
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'alice',
    displayName: 'Alice',
  });
  await getPrfOutput(credential, { rpId: 'localhost' });
  await new WebAuthnDIDProvider(credential).sign('identity');
  return credential;
}

test.describe('passkey steps', () => {
  test('outside a plan nothing is announced, and every prompt still happens', async () => {
    const before = authenticator.state.assertions;
    await createIdentity();
    expect(asked).toEqual([]);
    expect(authenticator.state.assertions - before).toBe(2);
  });

  test('inside a plan, every prompt after the first is announced, numbered and named', async () => {
    await withPasskeySteps(3, createIdentity);
    // The first — the passkey itself — comes from the click that started it.
    expect(asked).toEqual([
      { purpose: 'signing-key', n: 2, of: 3, kind: 'get' },
      { purpose: 'identity', n: 3, of: 3, kind: 'get' },
    ]);
  });

  test('askFirst announces the first prompt too', async () => {
    await withPasskeySteps({ of: 3, askFirst: true }, createIdentity);
    expect(asked.map((step) => [step.purpose, step.n, step.kind])).toEqual([
      ['create', 1, 'create'],
      ['signing-key', 2, 'get'],
      ['identity', 3, 'get'],
    ]);
  });

  test('a plan without a count numbers its prompts and says of: null', async () => {
    await withPasskeySteps(null, createIdentity);
    expect(asked.map((step) => [step.n, step.of])).toEqual([
      [2, null],
      [3, null],
    ]);
  });

  test('a cancel stops before the authenticator is asked, and reaches the caller as it is', async () => {
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'alice',
      displayName: 'Alice',
    });
    setPasskeyStepHandler(() => {
      throw new PasskeyStepCancelled();
    });
    const before = authenticator.state.assertions;

    // The signing key's read sits in a try that turns a failed ceremony into
    // a fallback; a cancel must not be read as "this authenticator cannot".
    const reading = withPasskeySteps({ of: 3, askFirst: true }, () =>
      getPrfOutput(credential, { rpId: 'localhost' })
    );
    await expect(reading).rejects.toBeInstanceOf(PasskeyStepCancelled);

    // The identity signature wraps WebAuthn errors in its own; a cancel is
    // not one of them.
    const signing = withPasskeySteps({ of: 1, askFirst: true }, () =>
      new WebAuthnDIDProvider(credential).sign('identity')
    );
    await expect(signing).rejects.toBeInstanceOf(PasskeyStepCancelled);

    expect(authenticator.state.assertions - before).toBe(0);
  });

  for (const useKeystoreDID of [false, true]) {
    test(`a cancel at the keystore step stops createIdentity (useKeystoreDID: ${useKeystoreDID})`, async () => {
      const credential = await WebAuthnDIDProvider.createCredential({
        userId: 'alice',
        displayName: 'Alice',
      });
      setPasskeyStepHandler((step) => {
        asked.push(step);
        if (step.purpose === 'keystore') throw new PasskeyStepCancelled();
      });
      const keystore = await createSessionKeystore();

      // createIdentity used to log the failure and carry on, so the identity
      // came out without the encrypted keystore the person had declined.
      const creating = withPasskeySteps({ of: 3, askFirst: true }, () =>
        OrbitDBWebAuthnIdentityProvider.createIdentity({
          webauthnCredential: credential,
          encryptKeystore: true,
          keystore,
          useKeystoreDID,
          ...(useKeystoreDID ? { keystoreKeyType: 'Ed25519' } : {}),
        })
      );
      await expect(creating).rejects.toBeInstanceOf(PasskeyStepCancelled);
      expect(asked.map((step) => step.purpose)).toEqual(['keystore']);
    });
  }

  test('the handler is awaited: the prompt starts only once it resolves', async () => {
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'alice',
      displayName: 'Alice',
    });
    let release;
    setPasskeyStepHandler(
      () =>
        new Promise((resolve) => {
          release = resolve;
        })
    );
    const before = authenticator.state.assertions;
    const reading = withPasskeySteps({ of: 1, askFirst: true }, () =>
      getPrfOutput(credential, { rpId: 'localhost' })
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(authenticator.state.assertions - before).toBe(0);
    release();
    await reading;
    expect(authenticator.state.assertions - before).toBe(1);
  });

  test('a restore announces its second touch, and the identity signature after it', async () => {
    await WebAuthnDIDProvider.createCredential({
      userId: 'alice',
      displayName: 'Alice',
    });
    asked = [];
    await withPasskeySteps(3, async () => {
      const restored = await restoreIdentityFromAuthenticator({
        rpId: 'localhost',
      });
      await new WebAuthnDIDProvider(restored.credential).sign('identity');
    });
    expect(asked.map((step) => [step.purpose, step.n, step.of])).toEqual([
      ['restore-confirm', 2, 3],
      ['identity', 3, 3],
    ]);
  });

  test('plans do not nest: the inner one counts its own, the outer one resumes', async () => {
    await withPasskeySteps({ of: 4, askFirst: true }, async () => {
      await beforePasskeyCeremony('prf');
      await withPasskeySteps({ of: 1, askFirst: true }, () =>
        beforePasskeyCeremony('wallet')
      );
      await beforePasskeyCeremony('keystore');
    });
    expect(asked.map((step) => [step.purpose, step.n, step.of])).toEqual([
      ['prf', 1, 4],
      ['wallet', 1, 1],
      ['keystore', 2, 4],
    ]);
  });

  test('overlapping actions each leave their own plan, whichever ends first', async () => {
    // Two actions both waiting on something other than WebAuthn: A ends
    // first. Its plan used to be restored by the later one, and stayed.
    let finishA;
    let finishB;
    const a = withPasskeySteps(
      { of: 3 },
      () => new Promise((r) => (finishA = r))
    );
    const b = withPasskeySteps(
      { of: 2 },
      () => new Promise((r) => (finishB = r))
    );
    finishA();
    await a;
    // B is still running: its prompts are counted against its plan.
    await beforePasskeyCeremony('prf');
    await beforePasskeyCeremony('wallet');
    finishB();
    await b;
    expect(asked.map((step) => [step.purpose, step.n, step.of])).toEqual([
      ['wallet', 2, 2],
    ]);

    // Outside any plan again: nothing is announced.
    asked = [];
    await beforePasskeyCeremony('prf');
    await beforePasskeyCeremony('wallet');
    expect(asked).toEqual([]);
  });

  test('importing ./elements works without a DOM', async () => {
    // A server-side render imports it too; the element is defined only where
    // there is a customElements registry.
    const elements = await import('../src/elements/index.js');
    expect(typeof elements.connectPasskeyStepDialog).toBe('function');
    expect(typeof elements.PasskeyStepDialogElement).toBe('function');
  });

  test('a handler that was replaced does not unregister its successor', async () => {
    const first = setPasskeyStepHandler(() => {});
    const later = [];
    setPasskeyStepHandler((step) => later.push(step.purpose));
    first();
    await withPasskeySteps({ of: 1, askFirst: true }, () =>
      beforePasskeyCeremony('metadata')
    );
    expect(later).toEqual(['metadata']);
  });

  test('the standalone entry shares the handler and the plan', async () => {
    expect(standalone.setPasskeyStepHandler).toBe(setPasskeyStepHandler);
    expect(standalone.withPasskeySteps).toBe(withPasskeySteps);
    expect(PASSKEY_PURPOSES).toContain('wallet');
  });
});

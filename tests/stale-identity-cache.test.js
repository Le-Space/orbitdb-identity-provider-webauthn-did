/**
 * OrbitDB's verified-identity cache refuses another session of the same
 * passkey (orbitdb/orbitdb#1258), and the provider's wrapper lets it through
 * — without letting through anything OrbitDB was right to refuse.
 *
 * Two sessions of one passkey: two `Identities` instances, two keystores,
 * the same mock credential. The PRF-derived signing key is the same in both,
 * so `publicKey` and `signatures.id` agree; the WebAuthn proof in
 * `signatures.publicKey` is a fresh assertion each time. A third instance
 * plays the peer that verifies them: the first session goes into its cache,
 * and the second — same DID, valid proof — comes back `false` from OrbitDB.
 */
import { test, expect } from '@playwright/test';
import {
  Identities,
  KeyStore,
  MemoryStorage,
  useIdentityProvider,
} from '@orbitdb/core';

import { OrbitDBWebAuthnIdentityProviderFunction } from '../src/keystore/provider.js';
import {
  withoutStaleIdentityCache,
  createIdentities,
} from '../src/keystore/stale-identity-cache.js';
import { WebAuthnDIDProvider } from '../src/webauthn/provider.js';
import { clearIdentityProofs } from '../src/webauthn/identity-proof-store.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { silenceWebAuthnDebugLogging } from './helpers/two-peer.js';

let restoreAuthenticator;
let restoreLogging;
test.beforeEach(async () => {
  restoreLogging = silenceWebAuthnDebugLogging();
  restoreAuthenticator = installMockAuthenticator(
    await createMockAuthenticator()
  );
  try {
    useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
  } catch {
    // registered by an earlier test
  }
});
test.afterEach(() => {
  restoreAuthenticator?.();
  restoreLogging?.();
});

async function orbitIdentities() {
  const keystore = await KeyStore({ storage: await MemoryStorage() });
  return Identities({ keystore, storage: await MemoryStorage() });
}

/**
 * One session of the passkey: its own keystore, the same credential, and no
 * proof remembered from before — the provider keeps the last proof in storage
 * so a browser does not ask the passkey twice, which is exactly what another
 * device does not have.
 */
async function session(credential) {
  clearIdentityProofs();
  const identities = await orbitIdentities();
  return identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: credential,
    }),
  });
}

test.describe('two sessions of one passkey', () => {
  test('OrbitDB alone refuses the second; the wrapper verifies it', async () => {
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'alice',
      displayName: 'Alice',
    });
    const first = await session(credential);
    const second = await session(credential);

    // The shape of the problem: same DID, same signing key, same id
    // signature — a different proof.
    expect(second.id).toBe(first.id);
    expect(second.publicKey).toBe(first.publicKey);
    expect(second.signatures.id).toBe(first.signatures.id);
    expect(second.signatures.publicKey).not.toBe(first.signatures.publicKey);

    // A peer that met the first session first.
    const peer = await orbitIdentities();
    expect(await peer.verifyIdentity(first)).toBe(true);
    // OrbitDB 4 as shipped: cache hit on signatures.id, isEqual fails.
    expect(await peer.verifyIdentity(second)).toBe(false);

    // The same peer, wrapped: the second session is checked on its own merits.
    withoutStaleIdentityCache(peer);
    expect(await peer.verifyIdentity(second)).toBe(true);
    expect(await peer.verifyIdentity(first)).toBe(true);

    // And a peer built with `createIdentities` never had the problem.
    const wrapped = await createIdentities({
      keystore: await KeyStore({ storage: await MemoryStorage() }),
      storage: await MemoryStorage(),
    });
    expect(await wrapped.verifyIdentity(first)).toBe(true);
    expect(await wrapped.verifyIdentity(second)).toBe(true);
  });

  test('a forged second session is still refused', async () => {
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'alice',
      displayName: 'Alice',
    });
    const first = await session(credential);
    const peer = withoutStaleIdentityCache(await orbitIdentities());
    expect(await peer.verifyIdentity(first)).toBe(true);

    // Same id signature, but a proof that proves nothing: the provider says no.
    const forgedProof = {
      ...first,
      signatures: { ...first.signatures, publicKey: 'not-a-proof' },
    };
    expect(await peer.verifyIdentity(forgedProof)).toBe(false);
    // Another provider's identity with this shape: OrbitDB's no stands.
    expect(await peer.verifyIdentity({ ...first, type: 'publickey' })).toBe(
      false
    );
    // Not an identity at all.
    expect(await peer.verifyIdentity({ type: 'webauthn' })).toBe(false);
  });
});

test.describe('withoutStaleIdentityCache on a fake', () => {
  /** An identity's shape, made up; its proof proves nothing. */
  const identity = (over = {}) => ({
    id: 'did:key:zDnaeExampleOnlyNotARealKeyAAAAAAAAAAAAAAAAAAAAAAAA',
    hash: 'zdpuExampleIdentityHash',
    bytes: new Uint8Array([1]),
    publicKey: '02' + 'ab'.repeat(32),
    signatures: { id: 'aa'.repeat(70), publicKey: 'not-a-webauthn-proof' },
    type: 'webauthn',
    ...over,
  });
  const fake = ({ cached, idSignature }) => {
    const calls = { verify: 0 };
    const identities = {
      verifyIdentity: async () => cached,
      verify: async () => {
        calls.verify++;
        return idSignature;
      },
    };
    return { identities: withoutStaleIdentityCache(identities), calls };
  };

  test('keeps what OrbitDB accepts, without asking again', async () => {
    const { identities, calls } = fake({ cached: true, idSignature: false });
    expect(await identities.verifyIdentity(identity())).toBe(true);
    expect(calls.verify).toBe(0);
  });

  test('asks again only for a webauthn identity, and never takes one OrbitDB would refuse', async () => {
    expect(
      await fake({
        cached: false,
        idSignature: true,
      }).identities.verifyIdentity(identity({ type: 'publickey' }))
    ).toBe(false);
    expect(
      await fake({
        cached: false,
        idSignature: false,
      }).identities.verifyIdentity(identity())
    ).toBe(false);
    // Signed, but the key not bound to the DID by a passkey proof.
    expect(
      await fake({
        cached: false,
        idSignature: true,
      }).identities.verifyIdentity(identity())
    ).toBe(false);
  });

  test('refuses to wrap something that is not an Identities instance', () => {
    expect(() => withoutStaleIdentityCache({})).toThrow(/Identities/);
  });
});

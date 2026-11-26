/**
 * An identity proof is a proof and nothing else.
 *
 * The same passkey may sign for other protocols — it is meant to be a wallet
 * key too, and `signP256Challenge` signs any 32 bytes it is given. The first
 * proof format made its challenge SHA-256(credentialId ‖ data): 32 bytes, a
 * bare hash. So one wallet signature over a value somebody chose was an
 * identity proof for whatever that value hashed — a permanent binding of the
 * attacker's key to the victim's DID.
 *
 * The current format's challenge is labelled and longer than any hash, which
 * a 32-byte signer cannot produce. These tests show the attack against the
 * first format, that it is over once that format is refused, and that the
 * current one cannot be reached through the wallet or through a proof made
 * for an application.
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
  getP256CredentialDescriptor,
  signP256Challenge,
} from '../src/standalone/webauthn/p256-wallet.js';
import {
  configureWebAuthn,
  resetWebAuthnConfig,
} from '../src/webauthn/config.js';
import {
  clearIdentityProofs,
  identityProofKey,
  storeIdentityProof,
} from '../src/webauthn/identity-proof-store.js';
import {
  PROOF_CONTEXTS,
  proofChallenge,
  proofFormat,
  verifyWebAuthnIdentityBinding,
  verifyWebAuthnProof,
} from '../src/webauthn/proof-verification.js';
import { WebAuthnDIDProvider } from '../src/webauthn/provider.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { silenceWebAuthnDebugLogging } from './helpers/two-peer.js';

const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const utf8 = (text) => new TextEncoder().encode(text);
const sha256 = async (bytes) =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const concat = (...parts) => Uint8Array.from(parts.flatMap((p) => [...p]));

/** The proof envelope `sign()` returns, from the parts of an assertion. */
const envelope = ({
  credentialId,
  authenticatorData,
  clientDataJSON,
  signature,
}) =>
  b64url(
    utf8(
      JSON.stringify({
        credentialId: b64url(credentialId),
        authenticatorData: b64url(authenticatorData),
        clientDataJSON,
        signature: b64url(signature),
      })
    )
  );

/** The first format's challenge: a bare hash, 32 bytes. */
const legacyChallenge = (credentialId, data) =>
  sha256(concat(credentialId, utf8(data)));

let restoreAuthenticator;
let restoreLogging;
let credential;
let warnings;
let originalWarn;

test.beforeEach(async () => {
  restoreLogging = silenceWebAuthnDebugLogging();
  restoreAuthenticator = installMockAuthenticator(
    await createMockAuthenticator()
  );
  try {
    useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
  } catch {
    // registered by an earlier test file in this worker
  }
  resetWebAuthnConfig();
  clearIdentityProofs();
  credential = await WebAuthnDIDProvider.createCredential({
    userId: 'alice',
    displayName: 'Alice',
  });
  warnings = [];
  originalWarn = console.warn;
  console.warn = (...args) => warnings.push(args.join(' '));
});

test.afterEach(() => {
  console.warn = originalWarn;
  resetWebAuthnConfig();
  restoreAuthenticator?.();
  restoreLogging?.();
});

/** One session of the passkey: OrbitDB builds the identity, proof and all. */
async function identityOf(webauthnCredential) {
  const identities = await Identities({
    keystore: await KeyStore({ storage: await MemoryStorage() }),
    storage: await MemoryStorage(),
  });
  return identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ webauthnCredential }),
  });
}

/** A proof in the first format over `data`, as versions before 0.13.0 made it. */
async function legacyProof(data) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: await legacyChallenge(credential.rawCredentialId, data),
    },
  });
  return envelope({
    credentialId: credential.rawCredentialId,
    authenticatorData: new Uint8Array(assertion.response.authenticatorData),
    clientDataJSON: new TextDecoder().decode(assertion.response.clientDataJSON),
    signature: new Uint8Array(assertion.response.signature),
  });
}

/**
 * What an attacker brings: a key of their own (as OrbitDB stores a public
 * key, hex) and that key's signature over the victim's id. Any key signs an
 * id for itself; the proof is the only thing tying it to the DID.
 */
const ATTACKER = {
  publicKey: `02${'ab'.repeat(32)}`,
  idSignature: 'deadbeef'.repeat(16),
};
const attackerData = ATTACKER.publicKey + ATTACKER.idSignature;
const identityClaiming = (did, proof) => ({
  id: did,
  type: 'webauthn',
  publicKey: ATTACKER.publicKey,
  signatures: { id: ATTACKER.idSignature, publicKey: proof },
});

test.describe('the current format', () => {
  test('a new identity proves itself with a labelled challenge, not a hash', async () => {
    const identity = await identityOf(credential);
    const proof = JSON.parse(
      Buffer.from(identity.signatures.publicKey, 'base64url').toString()
    );
    const challenge = Buffer.from(
      JSON.parse(proof.clientDataJSON).challenge,
      'base64url'
    );

    expect(proofFormat(identity.signatures.publicKey)).toBe(2);
    expect(challenge.subarray(0, 33).toString()).toBe(
      'orbitdb-webauthn-did:v2:identity:'
    );
    expect(challenge.length).toBe(33 + 32);

    // It needs no legacy allowance to verify.
    configureWebAuthn({ acceptLegacyProofs: false });
    expect(await verifyWebAuthnIdentityBinding(identity)).toBe(true);
    expect(warnings).toEqual([]);
  });

  test('a proof made for an application is not an identity', async () => {
    // An application has the passkey sign some text it was handed — which
    // happens to be an attacker's key and id signature.
    const provider = new WebAuthnDIDProvider(credential);
    const forApplication = await provider.sign(attackerData);

    expect(
      await provider.verify(forApplication, attackerData, credential.publicKey)
    ).toBe(true);
    expect(
      await provider.verify(
        forApplication,
        attackerData,
        credential.publicKey,
        {
          context: PROOF_CONTEXTS.IDENTITY,
        }
      )
    ).toBe(false);
    expect(
      await verifyWebAuthnIdentityBinding(
        identityClaiming((await identityOf(credential)).id, forApplication)
      )
    ).toBe(false);
  });

  test('the wallet signer cannot be asked for one', async () => {
    const challenge = await proofChallenge({
      credentialId: credential.rawCredentialId,
      data: attackerData,
      context: PROOF_CONTEXTS.IDENTITY,
    });
    expect(challenge.length).not.toBe(32);
    await expect(
      signP256Challenge(getP256CredentialDescriptor(credential), challenge)
    ).rejects.toThrow(/exactly 32 bytes/);
  });

  test('wants the user verified, not merely present', async () => {
    // An assertion over the right challenge by the right key, but from an
    // authenticator that only saw a touch.
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const keyBytes = new Uint8Array(
      await crypto.subtle.exportKey('raw', publicKey)
    );
    const credentialId = Uint8Array.from({ length: 16 }, (_, i) => i);
    const proofWithFlags = async (flags) => {
      const challenge = await proofChallenge({ credentialId, data: 'hello' });
      const clientDataJSON = JSON.stringify({
        type: 'webauthn.get',
        challenge: b64url(challenge),
        origin: 'https://localhost',
      });
      const authenticatorData = concat(
        await sha256(utf8('localhost')),
        [flags],
        [0, 0, 0, 1]
      );
      const signature = new Uint8Array(
        await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          privateKey,
          concat(authenticatorData, await sha256(utf8(clientDataJSON)))
        )
      );
      return envelope({
        credentialId,
        authenticatorData,
        clientDataJSON,
        signature,
      });
    };

    expect(
      await verifyWebAuthnProof(
        await proofWithFlags(0x01 | 0x04),
        'hello',
        keyBytes
      )
    ).toBe(true);
    expect(
      await verifyWebAuthnProof(await proofWithFlags(0x01), 'hello', keyBytes)
    ).toBe(false);
  });
});

test.describe('the first format', () => {
  test('one wallet signature over a chosen value is an identity for the victim’s DID — until it is refused', async () => {
    const victim = await identityOf(credential);

    // All the attacker needs from the victim: the wallet signing 32 bytes.
    const signed = await signP256Challenge(
      getP256CredentialDescriptor(credential),
      await legacyChallenge(credential.rawCredentialId, attackerData)
    );
    const forged = identityClaiming(
      victim.id,
      envelope({
        credentialId: credential.rawCredentialId,
        authenticatorData: signed.authenticatorData,
        clientDataJSON: signed.clientDataJSON,
        signature: concat(signed.r, signed.s),
      })
    );

    // While the first format is accepted, this is the hole.
    expect(await verifyWebAuthnIdentityBinding(forged)).toBe(true);

    configureWebAuthn({ acceptLegacyProofs: false });
    expect(await verifyWebAuthnIdentityBinding(forged)).toBe(false);
    // The victim, on the current format, is untouched by the refusal.
    expect(await verifyWebAuthnIdentityBinding(victim)).toBe(true);
  });

  test('is accepted with one notice until somebody decides', async () => {
    const proof = await legacyProof('some data');
    const key = credential.publicKey;
    const provider = new WebAuthnDIDProvider(credential);
    expect(proofFormat(proof)).toBe(1);

    // Undecided: accepted, and said once.
    expect(await provider.verify(proof, 'some data', key)).toBe(true);
    expect(await provider.verify(proof, 'some data', key)).toBe(true);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/acceptLegacyProofs/);

    // Accepted knowingly: no notice.
    resetWebAuthnConfig();
    warnings.length = 0;
    configureWebAuthn({ acceptLegacyProofs: true });
    expect(await provider.verify(proof, 'some data', key)).toBe(true);
    expect(warnings).toEqual([]);

    // Refused — for the application as a whole, or for one call.
    configureWebAuthn({ acceptLegacyProofs: false });
    expect(await provider.verify(proof, 'some data', key)).toBe(false);
    resetWebAuthnConfig();
    expect(
      await provider.verify(proof, 'some data', key, {
        acceptLegacyProofs: false,
      })
    ).toBe(false);
  });

  test('a device keeps the proof it has while it is accepted, and makes a new one once it is refused', async () => {
    // The PRF-derived signing key makes the signed data the same in every
    // session, so the stored proof is found again.
    const first = await identityOf(credential);
    const stored = await legacyProof(first.publicKey + first.signatures.id);
    storeIdentityProof(
      await identityProofKey(
        credential.credentialId,
        first.publicKey + first.signatures.id
      ),
      stored
    );

    // As a device that set up before 0.13.0: same document as before, no prompt.
    const kept = await identityOf(credential);
    expect(kept.signatures.publicKey).toBe(stored);

    // Refused: nobody would take that proof, so a new one is made and kept.
    configureWebAuthn({ acceptLegacyProofs: false });
    const renewed = await identityOf(credential);
    expect(proofFormat(renewed.signatures.publicKey)).toBe(2);
    expect(await verifyWebAuthnIdentityBinding(renewed)).toBe(true);
    expect((await identityOf(credential)).signatures.publicKey).toBe(
      renewed.signatures.publicKey
    );
    // Same passkey, same DID.
    expect(renewed.id).toBe(first.id);
  });
});

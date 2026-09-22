/**
 * Passkey primitives for wallets (#60): a P-256 credential descriptor, and a
 * raw 32-byte challenge signed into the parts a smart account verifies.
 *
 * `verifyAsCalibur` is the yardstick. Uniswap's Calibur checks a WebAuthn P-256
 * key with Base's webauthn-sol (KeyLib.verify → WebAuthn.verify, webauthn-sol
 * at 619f20a, the commit Calibur pins), passing its 32-byte hash as the
 * challenge and requireUV false. The helper repeats that verifier step by
 * step, so "verifies" here means what it means on-chain.
 */
import { test, expect } from '@playwright/test';
import cborModule from 'cbor-web';
import { DIDKey } from 'iso-did';
import { derToRawSignature } from 'iso-webauthn-varsig';

import {
  WebAuthnHardwareSignerService,
  getP256CredentialDescriptor,
  loadWebAuthnCredentialSafe,
  signP256Challenge,
  storeWebAuthnCredentialSafe,
} from '../src/standalone/index.js';
import {
  WebAuthnAuthenticationError,
  WebAuthnIdentityError,
  WebAuthnVerificationError,
} from '../src/errors.js';
import { getWebAuthnConfig } from '../src/webauthn/config.js';
import {
  createDidLargeBlobPayload,
  createVarsigLargeBlobPayload,
  parseDidLargeBlobPayload,
} from '../src/webauthn/large-blob-metadata.js';
import { decodeDidKey } from '../src/webauthn/proof-verification.js';
import { WebAuthnDIDProvider } from '../src/webauthn/provider.js';
import { WebAuthnVarsigProvider } from '../src/varsig/provider.js';
import {
  createMockAuthenticator,
  installMockAuthenticator,
} from './helpers/mock-authenticator.js';
import { silenceWebAuthnDebugLogging } from './helpers/two-peer.js';

const cbor = cborModule.default ?? cborModule;

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N / 2n;

const toBigInt = (bytes) => BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
const toBytes32 = (value) =>
  Uint8Array.from(Buffer.from(value.toString(16).padStart(64, '0'), 'hex'));
const sOf = (raw) => raw.slice(32);
const challenge32 = () => crypto.getRandomValues(new Uint8Array(32));
const toArrayBuffer = (bytes) =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);

/**
 * webauthn-sol's WebAuthn.verify, step for step, as Calibur calls it.
 * @returns {Promise<boolean>}
 */
async function verifyAsCalibur(parts, challenge, { x, y }) {
  const { authenticatorData, clientDataJSON, challengeIndex, typeIndex } =
    parts;
  // Malleability guard: any s above n / 2 is refused.
  if (toBigInt(parts.s) > HALF_N) return false;

  // clientDataJSON.slice(typeIndex, typeIndex + 21) == '"type":"webauthn.get"'
  const json = Buffer.from(clientDataJSON, 'utf8');
  const type = json.subarray(typeIndex, typeIndex + 21).toString('utf8');
  if (type !== '"type":"webauthn.get"') return false;

  // '"challenge":"' ‖ Base64.encodeURL(challenge) ‖ '"' at challengeIndex;
  // OpenZeppelin's encodeURL does not pad.
  const expected = Buffer.from(
    `"challenge":"${Buffer.from(challenge).toString('base64url')}"`
  );
  const actual = json.subarray(
    challengeIndex,
    challengeIndex + expected.length
  );
  if (!actual.equals(expected)) return false;

  // User present. Calibur does not require user verification.
  if ((authenticatorData[32] & 0x01) !== 0x01) return false;

  // P-256 over sha256(authenticatorData ‖ sha256(clientDataJSON)).
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', json)
  );
  const key = await crypto.subtle.importKey(
    'raw',
    Buffer.concat([Buffer.from([0x04]), x, y]),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    Buffer.concat([parts.r, parts.s]),
    Buffer.concat([authenticatorData, clientDataHash])
  );
}

/** Route the authenticator's assertions through `intercept(options, get)`. */
function interceptAssertions(authenticator, intercept) {
  const get = authenticator.navigator.credentials.get;
  authenticator.navigator.credentials.get = (options) =>
    intercept(options, get);
}

/** Record what each assertion was asked for, and the DER it returned. */
function recordAssertions(authenticator) {
  const seen = [];
  interceptAssertions(authenticator, async (options, get) => {
    const assertion = await get(options);
    seen.push({ options, der: new Uint8Array(assertion.response.signature) });
    return assertion;
  });
  return seen;
}

function withResponse(assertion, changes) {
  return { ...assertion, response: { ...assertion.response, ...changes } };
}

/**
 * Answer registration with an RS256 key — the fallback the default path
 * offers (alg -257): an RSA SPKI from getPublicKey() and a COSE RSA key in
 * the attestation, neither of which reads as P-256.
 */
async function answerRegistrationWithRs256(authenticator) {
  const rsa = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );
  const spki = await crypto.subtle.exportKey('spki', rsa.publicKey);
  const jwk = await crypto.subtle.exportKey('jwk', rsa.publicKey);
  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  const rpIdHash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode('localhost')
  );
  const coseKey = cbor.encode(
    new Map([
      [1, 3], // kty: RSA
      [3, -257], // alg: RS256
      [-1, Buffer.from(jwk.n, 'base64url')],
      [-2, Buffer.from(jwk.e, 'base64url')],
    ])
  );
  const authData = Buffer.concat([
    Buffer.from(rpIdHash),
    Buffer.from([0x45]), // UP | UV | AT
    Buffer.alloc(4), // signCount
    Buffer.alloc(16), // aaguid
    Buffer.from([0, credentialId.length]),
    credentialId,
    coseKey,
  ]);
  const attestationObject = cbor.encode(
    new Map([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authData],
    ])
  );

  authenticator.navigator.credentials.create = async () => ({
    id: Buffer.from(credentialId).toString('base64url'),
    rawId: toArrayBuffer(credentialId),
    type: 'public-key',
    response: {
      attestationObject: toArrayBuffer(attestationObject),
      clientDataJSON: toArrayBuffer(new TextEncoder().encode('{}')),
      getPublicKey: () => spki,
      getPublicKeyAlgorithm: () => -257,
    },
    getClientExtensionResults: () => ({}),
  });
}

/** createCredential warns when it falls back to its placeholder key. */
async function withoutWarnings(run) {
  const warn = console.warn;
  console.warn = () => {};
  try {
    return await run();
  } finally {
    console.warn = warn;
  }
}

function useMockAuthenticator(options) {
  const context = { authenticator: null };
  let restore = [];
  test.beforeEach(async () => {
    context.authenticator = await createMockAuthenticator(options);
    restore = [
      silenceWebAuthnDebugLogging(),
      installMockAuthenticator(context.authenticator),
    ];
  });
  test.afterEach(() => restore.forEach((undo) => undo?.()));
  return context;
}

const createDefaultCredential = (options = {}) =>
  WebAuthnDIDProvider.createCredential({
    userId: 'alice',
    displayName: 'Alice',
    ...options,
  });

const createHardwareCredential = (options = {}) =>
  WebAuthnVarsigProvider.createCredential({
    userId: 'carol',
    displayName: 'Carol',
    ...options,
  });

async function otherP256Key() {
  const { publicKey } = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  return { raw, x: raw.slice(1, 33), y: raw.slice(33) };
}

test.describe('getP256CredentialDescriptor', () => {
  const context = useMockAuthenticator();

  test('describes an ES256 passkey from the default path', async () => {
    const { authenticator } = context;
    const credential = await createDefaultCredential();
    expect(credential.rpId).toBe('localhost');

    const descriptor = getP256CredentialDescriptor(credential);

    expect(descriptor).toEqual({
      credentialId: credential.credentialId,
      rawCredentialId: authenticator.credentialId,
      x: authenticator.publicKey.x,
      y: authenticator.publicKey.y,
      rpId: 'localhost',
      userVerification: 'required',
    });
    expect(descriptor.rawCredentialId).toBeInstanceOf(Uint8Array);
    expect(descriptor.x).toBeInstanceOf(Uint8Array);
    expect(descriptor.x).toHaveLength(32);
    expect(descriptor.y).toHaveLength(32);
    // Copies: changing the descriptor leaves the credential alone.
    descriptor.x[0] ^= 0xff;
    expect(credential.publicKey.x[0]).toBe(authenticator.publicKey.x[0]);
  });

  test('describes an ES256 hardware passkey, also by its did:key alone', async () => {
    const { authenticator } = context;
    const credential = await createHardwareCredential({
      domain: 'example.test',
    });
    expect(credential.algorithm).toBe('P-256');
    expect(credential.rpId).toBe('example.test');

    const expected = {
      credentialId: Buffer.from(authenticator.credentialId).toString(
        'base64url'
      ),
      rawCredentialId: authenticator.credentialId,
      x: authenticator.publicKey.x,
      y: authenticator.publicKey.y,
      rpId: 'example.test',
      userVerification: 'required',
    };
    expect(getP256CredentialDescriptor(credential)).toEqual(expected);

    // A varsig did:key holds the key compressed, so y is recovered from x.
    expect(
      getP256CredentialDescriptor({
        credentialId: credential.credentialId,
        did: credential.did,
        rpId: credential.rpId,
      })
    ).toEqual(expected);

    // The default path's did:key holds it uncompressed.
    const defaultCredential = await createDefaultCredential();
    expect(
      getP256CredentialDescriptor({
        rawCredentialId: defaultCredential.rawCredentialId,
        did: await WebAuthnDIDProvider.createDID(defaultCredential),
      })
    ).toEqual(getP256CredentialDescriptor(defaultCredential));
  });

  test('recovers y from a compressed did:key, whichever its parity', async () => {
    // A random key's y is odd or even by chance; take one of each, so a
    // decompression that picks the wrong root cannot pass by luck.
    const byParity = new Map();
    while (byParity.size < 2) {
      const key = await otherP256Key();
      byParity.set(key.y[31] & 1, key);
    }

    for (const [parity, key] of byParity) {
      const did = DIDKey.fromPublicKey('P-256', key.raw).did;
      const { keyBytes } = decodeDidKey(did);
      expect(keyBytes).toHaveLength(33);
      expect(keyBytes[0]).toBe(0x02 + parity);

      const descriptor = getP256CredentialDescriptor({
        credentialId: new Uint8Array([7, 7, 7]),
        did,
        rpId: 'example.test',
      });
      expect(descriptor?.x, `parity ${parity}`).toEqual(key.x);
      expect(descriptor?.y, `parity ${parity}`).toEqual(key.y);
    }
  });

  test('describes the same passkey after storage, JSON and largeBlob', async () => {
    const credential = await createDefaultCredential();
    const descriptor = getP256CredentialDescriptor(credential);

    storeWebAuthnCredentialSafe(credential, 'p256-descriptor-test');
    expect(
      getP256CredentialDescriptor(
        loadWebAuthnCredentialSafe('p256-descriptor-test')
      )
    ).toEqual(descriptor);

    // JSON turns each Uint8Array into { "0": …, "1": … }.
    expect(
      getP256CredentialDescriptor(JSON.parse(JSON.stringify(credential)))
    ).toEqual(descriptor);

    // largeBlob metadata has no rpId; the page's hostname stands in. It reads
    // the same parsed, and as the raw JSON with base64url fields.
    const didBlob = createDidLargeBlobPayload(credential);
    expect(
      getP256CredentialDescriptor(parseDidLargeBlobPayload(didBlob))
    ).toEqual(descriptor);
    expect(
      getP256CredentialDescriptor(JSON.parse(new TextDecoder().decode(didBlob)))
    ).toEqual(descriptor);

    // A stored hardware signer keeps an rpId other than the hostname.
    const hardware = await createHardwareCredential({ domain: 'example.test' });
    const service = new WebAuthnHardwareSignerService({
      storageKey: 'p256-hardware-test',
    });
    service.store({ credential: hardware });
    const restored = getP256CredentialDescriptor(service.load().credential);
    expect(restored).toEqual(getP256CredentialDescriptor(hardware));
    expect(restored.rpId).toBe('example.test');

    const varsigBlob = createVarsigLargeBlobPayload(hardware);
    expect(
      getP256CredentialDescriptor(
        JSON.parse(new TextDecoder().decode(varsigBlob))
      )
    ).toEqual({ ...restored, rpId: 'localhost' });
  });

  test('returns null for an RS256 passkey', async () => {
    const { authenticator } = context;
    const p256 = await createDefaultCredential();
    const hardware = await createHardwareCredential();

    await answerRegistrationWithRs256(authenticator);
    const rs256 = await withoutWarnings(() => createDefaultCredential());

    // createCredential cannot read an RSA key and writes its placeholder.
    expect(rs256.publicKey.synthetic).toBe(true);
    expect(getP256CredentialDescriptor(rs256)).toBeNull();

    // An RS256 key described as such, in either credential shape.
    for (const change of [{ algorithm: -257 }, { keyType: 3 }]) {
      expect(
        getP256CredentialDescriptor({
          ...p256,
          publicKey: { ...p256.publicKey, ...change },
        })
      ).toBeNull();
    }
    expect(
      getP256CredentialDescriptor({ ...hardware, cose: { kty: 3, alg: -257 } })
    ).toBeNull();
    expect(
      getP256CredentialDescriptor({ ...hardware, algorithm: 'RS256' })
    ).toBeNull();
  });

  test('returns null for the placeholder key, flagged or not', async () => {
    const { authenticator } = context;
    const real = await createDefaultCredential();
    await answerRegistrationWithRs256(authenticator);
    const placeholder = await withoutWarnings(() => createDefaultCredential());
    expect(getP256CredentialDescriptor(placeholder)).toBeNull();

    // largeBlob metadata drops the flag, so a recovered placeholder looks
    // like any other key. Its point is not on the curve.
    const recovered = parseDidLargeBlobPayload(
      createDidLargeBlobPayload(placeholder)
    );
    expect(recovered.publicKey.synthetic).toBeUndefined();
    expect(getP256CredentialDescriptor(recovered)).toBeNull();

    // The flag alone refuses, even on a real point.
    expect(
      getP256CredentialDescriptor({
        ...real,
        publicKey: { ...real.publicKey, synthetic: true },
      })
    ).toBeNull();
  });

  test('returns null for Ed25519 and for anything unreadable', async () => {
    const credential = await createDefaultCredential();
    const hardware = await createHardwareCredential();
    const other = await otherP256Key();
    const { publicKey } = credential;

    const unusable = {
      'a hardware Ed25519 passkey': {
        credentialId: new Uint8Array([1, 2, 3]),
        publicKey: new Uint8Array(32).fill(8),
        algorithm: 'Ed25519',
        did: 'did:key:z6MkrmFAKE123',
        cose: { kty: 1, alg: -8, crv: 6 },
      },
      'no credential id': {
        ...credential,
        credentialId: undefined,
        rawCredentialId: undefined,
      },
      'an empty credential id': {
        ...credential,
        credentialId: '',
        rawCredentialId: undefined,
      },
      'ids that disagree': {
        ...credential,
        rawCredentialId: new Uint8Array([9, 9, 9]),
      },
      'a credential id that is not base64url': {
        ...hardware,
        credentialId: 'not base64url!',
      },
      'a short coordinate': {
        ...credential,
        publicKey: { ...publicKey, x: publicKey.x.slice(1) },
      },
      'a point off the curve': {
        ...credential,
        publicKey: { ...publicKey, y: other.y },
      },
      'SEC1 bytes that are no point': {
        ...hardware,
        publicKey: new Uint8Array(33).fill(7),
      },
      'a P-256 did:key naming another key': {
        ...hardware,
        did: await WebAuthnDIDProvider.createDID({ publicKey: other }),
      },
      'no key at all': { rawCredentialId: credential.rawCredentialId },
    };

    for (const [label, candidate] of Object.entries(unusable)) {
      expect(getP256CredentialDescriptor(candidate), label).toBeNull();
    }
    for (const value of [null, undefined, 'credential', 42]) {
      expect(getP256CredentialDescriptor(value)).toBeNull();
    }

    // No recorded rpId, and no page to take the hostname from.
    const { rpId, ...withoutRpId } = credential;
    expect(rpId).toBe('localhost');
    const savedWindow = globalThis.window;
    globalThis.window = undefined;
    try {
      expect(getP256CredentialDescriptor(withoutRpId)).toBeNull();
    } finally {
      globalThis.window = savedWindow;
    }
    expect(getP256CredentialDescriptor(withoutRpId).rpId).toBe('localhost');
  });
});

test.describe('signP256Challenge', () => {
  const context = useMockAuthenticator();

  test('pins the request to the descriptor’s credential, rpId and user verification', async () => {
    const { authenticator } = context;
    const credential = await createDefaultCredential({
      domain: 'example.test',
    });
    const descriptor = getP256CredentialDescriptor(credential);
    const seen = recordAssertions(authenticator);
    const challenge = challenge32();

    // Discoverable credentials are on, so other requests leave the choice of
    // passkey to the browser. This one must not.
    expect(getWebAuthnConfig().discoverableCredentials).toBe(true);

    await signP256Challenge(descriptor, challenge);

    expect(seen).toHaveLength(1);
    const { publicKey } = seen[0].options;
    expect(publicKey.allowCredentials).toHaveLength(1);
    expect(publicKey.allowCredentials[0].type).toBe('public-key');
    expect(new Uint8Array(publicKey.allowCredentials[0].id)).toEqual(
      credential.rawCredentialId
    );
    expect(publicKey.rpId).toBe('example.test');
    expect(publicKey.userVerification).toBe('required');
    expect(new Uint8Array(publicKey.challenge)).toEqual(challenge);
  });

  test('returns parts that verify the way Calibur verifies them', async () => {
    const descriptor = getP256CredentialDescriptor(
      await createDefaultCredential()
    );
    const challenge = challenge32();

    const parts = await signP256Challenge(descriptor, challenge);

    expect(Object.keys(parts).sort()).toEqual([
      'authenticatorData',
      'challengeIndex',
      'clientDataJSON',
      'r',
      's',
      'typeIndex',
    ]);
    expect(parts.authenticatorData).toBeInstanceOf(Uint8Array);
    expect(typeof parts.clientDataJSON).toBe('string');
    expect(parts.r).toHaveLength(32);
    expect(parts.s).toHaveLength(32);
    // Browsers serialise type first and challenge second, which is why
    // webauthn-sol's own test vectors use exactly these offsets.
    expect(parts.typeIndex).toBe(1);
    expect(parts.challengeIndex).toBe(23);

    expect(await verifyAsCalibur(parts, challenge, descriptor)).toBe(true);

    // The yardstick is not vacuous: it refuses what the contract refuses.
    const refused = [
      [{ ...parts, s: toBytes32(N - toBigInt(parts.s)) }, challenge],
      [parts, challenge32()],
      [{ ...parts, typeIndex: parts.typeIndex + 1 }, challenge],
      [{ ...parts, challengeIndex: parts.challengeIndex - 1 }, challenge],
    ];
    for (const [candidate, againstChallenge] of refused) {
      expect(
        await verifyAsCalibur(candidate, againstChallenge, descriptor)
      ).toBe(false);
    }
    expect(await verifyAsCalibur(parts, challenge, await otherP256Key())).toBe(
      false
    );
  });
});

// ECDSA is randomised, so the shapes DER handling gets wrong turn up only now
// and then; the mock re-signs until its raw r‖s has the shape asked for.
const SHAPES = {
  'a short r': (raw) => raw[0] === 0x00,
  'a short s': (raw) => raw[32] === 0x00,
  'an r with its top bit set (a 33-byte DER integer)': (raw) =>
    (raw[0] & 0x80) !== 0,
  'a high s': (raw) => toBigInt(sOf(raw)) > HALF_N,
  'a low s': (raw) => toBigInt(sOf(raw)) <= HALF_N,
};

for (const [shape, signatureShape] of Object.entries(SHAPES)) {
  test.describe(`signP256Challenge, signature with ${shape}`, () => {
    const context = useMockAuthenticator({ signatureShape });

    test('pads r and s to 32 bytes, keeps s low, and verifies', async () => {
      const { authenticator } = context;
      const descriptor = getP256CredentialDescriptor(
        await createDefaultCredential()
      );
      const seen = recordAssertions(authenticator);
      const challenge = challenge32();

      const parts = await signP256Challenge(descriptor, challenge);

      const raw = derToRawSignature(seen[0].der);
      expect(signatureShape(raw)).toBe(true);
      const rawS = toBigInt(sOf(raw));

      expect(parts.r).toHaveLength(32);
      expect(parts.s).toHaveLength(32);
      expect(parts.r).toEqual(raw.slice(0, 32));
      expect(toBigInt(parts.s)).toBe(rawS > HALF_N ? N - rawS : rawS);
      expect(await verifyAsCalibur(parts, challenge, descriptor)).toBe(true);

      if (rawS > HALF_N) {
        // The s the authenticator returned would have been refused on-chain.
        expect(
          await verifyAsCalibur(
            { ...parts, s: sOf(raw) },
            challenge,
            descriptor
          )
        ).toBe(false);
      }
    });
  });
}

test.describe('signP256Challenge refuses', () => {
  const context = useMockAuthenticator();

  test('an assertion from a different credential', async () => {
    const { authenticator } = context;
    const descriptor = getP256CredentialDescriptor(
      await createDefaultCredential()
    );
    // A second passkey, which the authenticator now answers with — as a
    // browser offering another passkey would. The mock signs every
    // credential with one key, so only the rawId check can catch this.
    await createDefaultCredential();

    const error = await signP256Challenge(descriptor, challenge32()).catch(
      (caught) => caught
    );

    expect(error).toBeInstanceOf(WebAuthnAuthenticationError);
    expect(error.message).toMatch(/different credential/);
    expect(authenticator.state.assertions).toBe(1);
  });

  test('a challenge that is not exactly 32 bytes, before any prompt', async () => {
    const { authenticator } = context;
    const descriptor = getP256CredentialDescriptor(
      await createDefaultCredential()
    );

    for (const challenge of [
      new Uint8Array(31),
      new Uint8Array(33),
      new Uint8Array(0),
      `0x${'ab'.repeat(32)}`,
      Array.from({ length: 32 }, () => 1),
      undefined,
    ]) {
      await expect(signP256Challenge(descriptor, challenge)).rejects.toThrow(
        WebAuthnIdentityError
      );
    }
    // Nor a descriptor that names no usable key.
    await expect(
      signP256Challenge({ ...descriptor, x: descriptor.y }, challenge32())
    ).rejects.toThrow(WebAuthnIdentityError);
    expect(authenticator.state.assertions).toBe(0);

    // 32 bytes as an ArrayBuffer are fine.
    const parts = await signP256Challenge(descriptor, challenge32().buffer);
    expect(parts.r).toHaveLength(32);
  });

  test('an assertion over a different challenge', async () => {
    const { authenticator } = context;
    const descriptor = getP256CredentialDescriptor(
      await createDefaultCredential()
    );
    interceptAssertions(authenticator, (options, get) =>
      get({
        ...options,
        publicKey: { ...options.publicKey, challenge: challenge32() },
      })
    );

    const error = await signP256Challenge(descriptor, challenge32()).catch(
      (caught) => caught
    );

    expect(error).toBeInstanceOf(WebAuthnVerificationError);
    expect(error.message).toMatch(/this challenge/);
  });

  test('an assertion without user verification', async () => {
    const { authenticator } = context;
    const descriptor = getP256CredentialDescriptor(
      await createDefaultCredential()
    );
    interceptAssertions(authenticator, async (options, get) => {
      const assertion = await get(options);
      const authData = new Uint8Array(assertion.response.authenticatorData);
      authData[32] &= ~0x04;
      return withResponse(assertion, {
        authenticatorData: toArrayBuffer(authData),
      });
    });

    await expect(signP256Challenge(descriptor, challenge32())).rejects.toThrow(
      /user presence and verification/
    );
  });

  test('a signature that is not well-formed DER', async () => {
    const { authenticator } = context;
    const descriptor = getP256CredentialDescriptor(
      await createDefaultCredential()
    );
    let reshape;
    interceptAssertions(authenticator, async (options, get) => {
      const assertion = await get(options);
      const der = new Uint8Array(assertion.response.signature);
      return withResponse(assertion, {
        signature: toArrayBuffer(Uint8Array.from(reshape(der))),
      });
    });

    // Refused for its form, not merely because it then fails to verify.
    const malformed = [
      ['raw r‖s', (der) => derToRawSignature(der), /DER/],
      ['DER with a trailing byte', (der) => [...der, 0x00], /Malformed DER/],
      [
        'DER with r = 0',
        () => [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
        /out of range/,
      ],
    ];
    for (const [label, makeSignature, reason] of malformed) {
      reshape = makeSignature;
      const error = await signP256Challenge(descriptor, challenge32()).catch(
        (caught) => caught
      );
      expect(error, label).toBeInstanceOf(WebAuthnVerificationError);
      expect(error.message, label).toMatch(reason);
    }
  });

  test('a descriptor whose key is not the passkey’s', async () => {
    const credential = await createDefaultCredential();
    const descriptor = getP256CredentialDescriptor({
      ...credential,
      publicKey: { ...credential.publicKey, ...(await otherP256Key()) },
    });
    expect(descriptor).not.toBeNull();

    const error = await signP256Challenge(descriptor, challenge32()).catch(
      (caught) => caught
    );

    expect(error).toBeInstanceOf(WebAuthnVerificationError);
    expect(error.message).toMatch(/does not verify/);
  });
});

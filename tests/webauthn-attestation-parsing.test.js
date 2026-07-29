import { test, expect } from '@playwright/test';
import cborModule from 'cbor-web';
import { WebAuthnDIDProvider } from '../src/webauthn/provider.js';

const cbor = cborModule.default ?? cborModule;
const { encode } = cbor;

const X_FILL = 0x11;
const Y_FILL = 0x22;

/**
 * Build authenticatorData exactly as an authenticator would (WebAuthn L2 §6.1):
 * rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) |
 * credentialIdLength(2) | credentialId(L) | credentialPublicKey(COSE) | extensions?
 */
function buildAuthData({
  credIdLen = 32,
  withExtensions = false,
  kty = 2,
  alg = -7,
  crv = 1,
  xLen = 32,
  yLen = 32,
  setAtFlag = true,
} = {}) {
  const rpIdHash = new Uint8Array(32).fill(0xaa);
  // UP(0x01) | UV(0x04) | AT(0x40) | ED(0x80)
  let flagByte = 0x01 | 0x04;
  if (setAtFlag) flagByte |= 0x40;
  if (withExtensions) flagByte |= 0x80;

  const flags = new Uint8Array([flagByte]);
  const signCount = new Uint8Array([0, 0, 0, 1]);
  const aaguid = new Uint8Array(16).fill(0xbb);
  const credIdLenBytes = new Uint8Array(2);
  new DataView(credIdLenBytes.buffer).setUint16(0, credIdLen);
  const credId = new Uint8Array(credIdLen).fill(0xcc);

  const coseKey = encode(
    new Map([
      [1, kty],
      [3, alg],
      [-1, crv],
      [-2, Buffer.alloc(xLen, X_FILL)],
      [-3, Buffer.alloc(yLen, Y_FILL)],
    ])
  );

  const extensions = withExtensions
    ? encode(new Map([['prf', new Map([['enabled', true]])]]))
    : new Uint8Array(0);

  const parts = [
    rpIdHash,
    flags,
    signCount,
    aaguid,
    credIdLenBytes,
    credId,
    coseKey,
    extensions,
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function buildAttestationObject(authData) {
  return new Uint8Array(
    encode(
      new Map([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', Buffer.from(authData)],
      ])
    )
  );
}

/** A credential shaped like the browser's, minus getPublicKey(). */
function makeCredential(attestationObject, credIdLen = 32) {
  return {
    rawId: new Uint8Array(credIdLen).fill(0xcc).buffer,
    response: { attestationObject },
  };
}

test.describe('WebAuthn attestation object parsing', () => {
  test('extracts the real COSE public key from an attestation object', async () => {
    const attestationObject = buildAttestationObject(buildAuthData());

    const key =
      await WebAuthnDIDProvider.parseAttestedCredentialPublicKey(
        attestationObject
      );

    expect(key.keyType).toBe(2);
    expect(key.algorithm).toBe(-7);
    expect(key.curve).toBe(1);
    expect(key.x).toHaveLength(32);
    expect(key.y).toHaveLength(32);
    // The coordinates must be the authenticator's, not a hash of anything else.
    expect([...key.x].every((b) => b === X_FILL)).toBe(true);
    expect([...key.y].every((b) => b === Y_FILL)).toBe(true);
  });

  // Regression: authData is a view into the enclosing CBOR buffer with a
  // non-zero byteOffset. Reading credentialIdLength via authData.buffer without
  // honouring that offset yielded 0xaaaa (rpIdHash filler) for every credential
  // length, so the COSE slice was always empty and cbor threw "Insufficient
  // data" — silently degrading every credential to the synthetic fallback.
  for (const credIdLen of [16, 20, 32, 64, 128]) {
    test(`survives the authData byteOffset with credentialId length ${credIdLen}`, async () => {
      const attestationObject = buildAttestationObject(
        buildAuthData({ credIdLen })
      );

      const key =
        await WebAuthnDIDProvider.parseAttestedCredentialPublicKey(
          attestationObject
        );

      expect([...key.x].every((b) => b === X_FILL)).toBe(true);
      expect([...key.y].every((b) => b === Y_FILL)).toBe(true);
    });
  }

  test('tolerates trailing CBOR extension data when the ED flag is set', async () => {
    const attestationObject = buildAttestationObject(
      buildAuthData({ withExtensions: true })
    );

    const key =
      await WebAuthnDIDProvider.parseAttestedCredentialPublicKey(
        attestationObject
      );

    expect([...key.x].every((b) => b === X_FILL)).toBe(true);
    expect([...key.y].every((b) => b === Y_FILL)).toBe(true);
  });

  test('throws instead of guessing when attested credential data is absent', async () => {
    const attestationObject = buildAttestationObject(
      buildAuthData({ setAtFlag: false })
    );

    await expect(
      WebAuthnDIDProvider.parseAttestedCredentialPublicKey(attestationObject)
    ).rejects.toThrow(/AT flag unset/);
  });

  test('throws on a non-P-256 COSE key rather than returning garbage', async () => {
    const attestationObject = buildAttestationObject(
      buildAuthData({ kty: 1, alg: -8, crv: 6 })
    );

    await expect(
      WebAuthnDIDProvider.parseAttestedCredentialPublicKey(attestationObject)
    ).rejects.toThrow(/Unsupported COSE key/);
  });

  test('throws on truncated coordinates', async () => {
    const attestationObject = buildAttestationObject(
      buildAuthData({ xLen: 31 })
    );

    await expect(
      WebAuthnDIDProvider.parseAttestedCredentialPublicKey(attestationObject)
    ).rejects.toThrow(/Invalid P-256 coordinate length/);
  });
});

test.describe('extractPublicKey end to end', () => {
  test('returns the authenticator key, not the synthetic fallback', async () => {
    const attestationObject = buildAttestationObject(buildAuthData());
    const credential = makeCredential(attestationObject);

    const key = await WebAuthnDIDProvider.extractPublicKey(credential);

    expect(key.synthetic).toBeUndefined();
    expect([...key.x].every((b) => b === X_FILL)).toBe(true);
    expect([...key.y].every((b) => b === Y_FILL)).toBe(true);
  });

  test('marks the synthetic fallback so it cannot pass as a real key', async () => {
    const credential = makeCredential(new Uint8Array([0x00, 0x01, 0x02]));

    const key = await WebAuthnDIDProvider.extractPublicKey(credential);

    expect(key.synthetic).toBe(true);
    expect(key.x).toHaveLength(32);
  });

  test('derives a DID from the authenticator key that differs from the fallback DID', async () => {
    const attestationObject = buildAttestationObject(buildAuthData());

    const realKey = await WebAuthnDIDProvider.extractPublicKey(
      makeCredential(attestationObject)
    );
    const fallbackKey = await WebAuthnDIDProvider.extractPublicKey(
      makeCredential(new Uint8Array([0x00]))
    );

    const realDid = await WebAuthnDIDProvider.createDID({
      publicKey: realKey,
    });
    const fallbackDid = await WebAuthnDIDProvider.createDID({
      publicKey: fallbackKey,
    });

    expect(realDid).toMatch(/^did:key:z/);
    expect(realDid).not.toBe(fallbackDid);
  });

  test('is deterministic across repeated extractions', async () => {
    const attestationObject = buildAttestationObject(buildAuthData());

    const first = await WebAuthnDIDProvider.extractPublicKey(
      makeCredential(attestationObject)
    );
    const second = await WebAuthnDIDProvider.extractPublicKey(
      makeCredential(attestationObject)
    );

    expect([...first.x]).toEqual([...second.x]);
    expect([...first.y]).toEqual([...second.y]);
  });
});

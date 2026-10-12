/**
 * A P-256 key in memory that answers like a passkey: for a challenge it
 * returns the parts of a WebAuthn assertion — authenticatorData,
 * clientDataJSON with the challenge in base64url, the offsets of its "type"
 * and "challenge", and a low-s ECDSA signature over authenticatorData ‖
 * sha256(clientDataJSON) — in the shape `signP256Challenge` returns. For
 * tests that cannot reach an authenticator. The key is random per call and
 * holds nothing.
 *
 * WebCrypto only: the repository declares no curve library, and a test that
 * finds one only because a local install hoisted it fails in CI.
 */
const { subtle } = globalThis.crypto;
const encoder = new TextEncoder();
const ECDSA = { name: 'ECDSA', hash: 'SHA-256' };
/** The order of P-256; webauthn-sol accepts only s <= N / 2. */
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** @param {Uint8Array} bytes */
const toBigInt = (bytes) => BigInt(`0x${Buffer.from(bytes).toString('hex')}`);

/** @param {...Uint8Array} parts */
function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export async function createSoftwarePasskey({ rpId = 'wallet.test' } = {}) {
  const { privateKey, publicKey } = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify']
  );
  const point = new Uint8Array(await subtle.exportKey('raw', publicKey));
  const rpIdHash = new Uint8Array(
    await subtle.digest('SHA-256', encoder.encode(rpId))
  );
  let signCount = 0;

  /** @param {Uint8Array} challenge */
  async function sign(challenge) {
    signCount += 1;
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(rpIdHash, 0);
    authenticatorData[32] = 0x05; // user present, user verified
    new DataView(authenticatorData.buffer).setUint32(33, signCount);
    const clientDataJSON = JSON.stringify({
      type: 'webauthn.get',
      challenge: Buffer.from(challenge).toString('base64url'),
      origin: `https://${rpId}`,
      crossOrigin: false,
    });
    const clientDataHash = new Uint8Array(
      await subtle.digest('SHA-256', encoder.encode(clientDataJSON))
    );
    // ECDSA with SHA-256 over authenticatorData ‖ clientDataHash, as an
    // authenticator signs; WebCrypto returns r ‖ s.
    const signature = new Uint8Array(
      await subtle.sign(
        ECDSA,
        privateKey,
        concatBytes(authenticatorData, clientDataHash)
      )
    );
    const r = toBigInt(signature.slice(0, 32));
    let s = toBigInt(signature.slice(32, 64));
    if (s > N / 2n) s = N - s;
    return {
      authenticatorData,
      clientDataJSON,
      challengeIndex: clientDataJSON.indexOf('"challenge":"'),
      typeIndex: clientDataJSON.indexOf('"type":"'),
      r,
      s,
    };
  }

  return {
    sign,
    publicKey,
    descriptor: {
      credentialId: 'AQ',
      rawCredentialId: new Uint8Array([1]),
      rpId,
      x: point.slice(1, 33),
      y: point.slice(33, 65),
      userVerification: 'required',
    },
  };
}

/**
 * Whether a WebAuthn assertion's signature verifies with the passkey's public
 * key, by WebCrypto.
 * @param {CryptoKey} publicKey
 * @param {{ authenticatorData: Uint8Array, clientDataJSON: string, r: bigint, s: bigint }} auth
 */
export async function verifiesWithPasskey(publicKey, auth) {
  const word = (/** @type {bigint} */ n) =>
    Uint8Array.from(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'));
  const clientDataHash = new Uint8Array(
    await subtle.digest('SHA-256', encoder.encode(auth.clientDataJSON))
  );
  return subtle.verify(
    ECDSA,
    publicKey,
    concatBytes(word(auth.r), word(auth.s)),
    concatBytes(auth.authenticatorData, clientDataHash)
  );
}

/**
 * The 160-byte input of the P-256 precompile (EIP-7951 / RIP-7212, 0x100) for
 * a valid signature by a fresh key: sha256(data) ‖ r ‖ s ‖ x ‖ y.
 */
export async function p256PrecompileInput() {
  const { privateKey, publicKey } = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const point = new Uint8Array(await subtle.exportKey('raw', publicKey));
  const data = encoder.encode('a message for the precompile');
  const hash = new Uint8Array(await subtle.digest('SHA-256', data));
  const signature = new Uint8Array(await subtle.sign(ECDSA, privateKey, data));
  return `0x${Buffer.from(concatBytes(hash, signature, point.slice(1, 65))).toString('hex')}`;
}

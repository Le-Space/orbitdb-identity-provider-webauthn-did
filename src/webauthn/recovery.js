/**
 * @module Recovery
 * @description
 * Get the credential's public key back from assertions, so a device that has
 * stored nothing can still know which identity it holds.
 *
 * A WebAuthn assertion does not carry the public key; only registration does.
 * That is why the identity metadata has had to be kept somewhere — largeBlob,
 * localStorage, a proof store — and why a fresh device with the same
 * authenticator could not name the identity it was holding.
 *
 * It does not have to be kept. An ECDSA signature admits exactly two public
 * keys, and both are computable from the signature itself; a second signature
 * over a different challenge admits two more, and only the signer's key is in
 * both sets. So two touches of the same passkey are enough to recover the key,
 * and from it the DID. See issue #61.
 *
 * Every candidate this module returns has been checked against the signature
 * it came from with `crypto.subtle.verify`. A mistake in the arithmetic below
 * can therefore cost a candidate, never invent one: what comes out has
 * verified, or it does not come out.
 */
import { derToRawSignature } from 'iso-webauthn-varsig';

import { ERROR_CODES, WebAuthnIdentityError } from '../errors.js';
import { CRYPTO_ALGORITHMS } from '../constants.js';

// NIST P-256 (secp256r1). a = p - 3.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const G = {
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};
const P1363_SIGNATURE_LENGTH = 64;
const COORDINATE_BYTES = 32;

const mod = (value, modulus = P) => ((value % modulus) + modulus) % modulus;

/** Extended Euclid; `value` must not be a multiple of `modulus`. */
function inverse(value, modulus) {
  let [old, current] = [mod(value, modulus), modulus];
  let [oldCoefficient, coefficient] = [1n, 0n];
  while (current !== 0n) {
    const quotient = old / current;
    [old, current] = [current, old - quotient * current];
    [oldCoefficient, coefficient] = [
      coefficient,
      oldCoefficient - quotient * coefficient,
    ];
  }
  if (old !== 1n) throw new Error('not invertible');
  return mod(oldCoefficient, modulus);
}

function power(base, exponent, modulus) {
  let result = 1n;
  let factor = mod(base, modulus);
  let left = exponent;
  while (left > 0n) {
    if (left & 1n) result = mod(result * factor, modulus);
    factor = mod(factor * factor, modulus);
    left >>= 1n;
  }
  return result;
}

/** P ≡ 3 (mod 4), so a square root is one exponentiation. Null when there is none. */
function squareRoot(value) {
  const root = power(value, (P + 1n) / 4n, P);
  return mod(root * root, P) === mod(value, P) ? root : null;
}

// Points are `{ x, y }`, or null for the point at infinity.
function add(left, right) {
  if (left === null) return right;
  if (right === null) return left;
  if (left.x === right.x && mod(left.y + right.y) === 0n) return null;
  const slope =
    left.x === right.x && left.y === right.y
      ? mod((3n * left.x * left.x - 3n) * inverse(2n * left.y, P))
      : mod((right.y - left.y) * inverse(right.x - left.x, P));
  const x = mod(slope * slope - left.x - right.x);
  return { x, y: mod(slope * (left.x - x) - left.y) };
}

function multiply(point, scalar) {
  let result = null;
  let addend = point;
  let left = mod(scalar, N);
  while (left > 0n) {
    if (left & 1n) result = add(result, addend);
    addend = add(addend, addend);
    left >>= 1n;
  }
  return result;
}

const toBigInt = (bytes) =>
  bytes.reduce((value, byte) => (value << 8n) + BigInt(byte), 0n);

function toBytes(value, length = COORDINATE_BYTES) {
  const out = new Uint8Array(length);
  let left = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    out[index] = Number(left & 0xffn);
    left >>= 8n;
  }
  return out;
}

const asBytes = (value) =>
  value instanceof Uint8Array ? value : new Uint8Array(value);

/** The bytes WebAuthn signs: authenticatorData ‖ SHA-256(clientDataJSON). */
async function signedBytesOf(authenticatorData, clientDataJSON) {
  const hash = new Uint8Array(
    await crypto.subtle.digest(CRYPTO_ALGORITHMS.SHA_256, clientDataJSON)
  );
  const out = new Uint8Array(authenticatorData.length + hash.length);
  out.set(authenticatorData, 0);
  out.set(hash, authenticatorData.length);
  return out;
}

async function verifies(point, signedBytes, rawSignature) {
  const uncompressed = new Uint8Array(1 + COORDINATE_BYTES * 2);
  uncompressed[0] = 0x04;
  uncompressed.set(toBytes(point.x), 1);
  uncompressed.set(toBytes(point.y), 1 + COORDINATE_BYTES);
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      uncompressed,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: CRYPTO_ALGORITHMS.SHA_256 },
      key,
      rawSignature,
      signedBytes
    );
  } catch {
    return false; // not a point on the curve, or not a key at all
  }
}

/** An assertion, however the caller happens to hold it. */
function responseOf(assertion) {
  const response = assertion?.response ?? assertion;
  const { authenticatorData, clientDataJSON, signature } = response ?? {};
  if (!authenticatorData || !clientDataJSON || !signature) {
    throw new WebAuthnIdentityError(
      'an assertion with authenticatorData, clientDataJSON and signature is required',
      { code: ERROR_CODES.INVALID_INPUT }
    );
  }
  return {
    authenticatorData: asBytes(authenticatorData),
    clientDataJSON: asBytes(clientDataJSON),
    signature: asBytes(signature),
  };
}

/**
 * The public keys that could have produced this assertion — at most two, each
 * checked against the signature.
 *
 * @param {PublicKeyCredential|{authenticatorData: BufferSource, clientDataJSON: BufferSource, signature: BufferSource}} assertion
 * @returns {Promise<Array<{x: bigint, y: bigint}>>}
 */
export async function recoverPublicKeyCandidates(assertion) {
  const { authenticatorData, clientDataJSON, signature } =
    responseOf(assertion);
  const raw =
    signature.length === P1363_SIGNATURE_LENGTH
      ? signature
      : derToRawSignature(signature);
  const r = toBigInt(raw.slice(0, COORDINATE_BYTES));
  const s = toBigInt(raw.slice(COORDINATE_BYTES));
  if (r <= 0n || r >= N || s <= 0n || s >= N) {
    throw new WebAuthnIdentityError(
      'the signature is not an ES256 signature, so no key can be recovered from it',
      { code: ERROR_CODES.INVALID_INPUT }
    );
  }

  const signedBytes = await signedBytesOf(authenticatorData, clientDataJSON);
  const digest = new Uint8Array(
    await crypto.subtle.digest(CRYPTO_ALGORITHMS.SHA_256, signedBytes)
  );
  const e = toBigInt(digest);

  // R has x = r; both parities of y are candidates. Q = r⁻¹(sR − eG).
  const y = squareRoot(mod(r * r * r - 3n * r + B));
  if (y === null) return [];
  const rInverse = inverse(r, N);
  const candidates = [];
  for (const candidateY of [y, mod(P - y)]) {
    const point = multiply(
      add(multiply({ x: r, y: candidateY }, s), multiply(G, N - mod(e, N))),
      rInverse
    );
    if (point === null) continue;
    if (await verifies(point, signedBytes, raw)) candidates.push(point);
  }
  return candidates;
}

/**
 * The public key behind two assertions of the same credential.
 *
 * One assertion leaves two possibilities; a second one, over another
 * challenge, leaves one. Both must come from the same passkey — pass the
 * credential id of the first to the second `navigator.credentials.get()`.
 *
 * @param {*} first
 * @param {*} second
 * @returns {Promise<{x: Uint8Array, y: Uint8Array}>} coordinates, as
 *   `WebAuthnDIDProvider.createDID` takes them
 */
export async function recoverPublicKey(first, second) {
  const [a, b] = await Promise.all([
    recoverPublicKeyCandidates(first),
    recoverPublicKeyCandidates(second),
  ]);
  const shared = a.filter((point) =>
    b.some((other) => other.x === point.x && other.y === point.y)
  );
  if (shared.length !== 1) {
    throw new WebAuthnIdentityError(
      shared.length === 0
        ? 'the two assertions do not share a public key — they are not the same credential'
        : 'the two assertions did not settle on one public key',
      { code: ERROR_CODES.WEBAUTHN_VERIFICATION_FAILED }
    );
  }
  return { x: toBytes(shared[0].x), y: toBytes(shared[0].y) };
}

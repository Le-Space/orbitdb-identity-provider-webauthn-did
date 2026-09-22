/**
 * Passkey primitives for wallets.
 *
 * A smart account that verifies P-256 WebAuthn signatures on-chain — Uniswap's
 * Calibur, through Base's webauthn-sol — can use the same passkey as the
 * OrbitDB identity. It needs the passkey's key as x/y, the credential to ask
 * for, and an assertion over a 32-byte challenge taken apart into the fields
 * such a verifier reads (webauthn-sol's `WebAuthnAuth`).
 *
 * What turns those into a transaction — key hashes, ABI encoding, the account
 * client — moves funds and stays out of this package.
 */
import { derToRawSignature, isDerSignature } from 'iso-webauthn-varsig';

import { WEBAUTHN_CLIENT_DATA_TYPES } from '../../constants.js';
import {
  WebAuthnAuthenticationError,
  WebAuthnIdentityError,
  WebAuthnNotSupportedError,
  WebAuthnVerificationError,
} from '../../errors.js';
import { buildCredentialRequestOptions } from '../../webauthn/config.js';
import { MULTICODEC, decodeDidKey } from '../../webauthn/proof-verification.js';

// secp256r1 (NIST P-256), SEC 2 §2.4.2: y² = x³ − 3x + b over GF(p), order n.
const P256_P =
  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_B =
  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
// webauthn-sol refuses any s above floor(n / 2), against malleability.
const P256_HALF_N = P256_N / 2n;

const COORDINATE_BYTES = 32;
const CHALLENGE_BYTES = 32;

const COSE_KTY_EC2 = 2;
const COSE_ALG_ES256 = -7;
const COSE_CRV_P256 = 1;

// rpIdHash (32) + flags (1) + signCount (4)
const AUTH_DATA_MIN_LENGTH = 37;
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;

const encoder = new TextEncoder();

/**
 * Bytes from the shapes a byte field arrives in: a Uint8Array or other view,
 * an ArrayBuffer, a number array, or the `{ "0": …, "1": … }` object that
 * JSON makes of a Uint8Array. Always a copy. Anything else is null.
 * @param {unknown} value
 * @returns {Uint8Array|null}
 */
function readBytes(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(
      value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength)
    );
  }

  let values;
  if (Array.isArray(value)) {
    values = value;
  } else if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    if (!keys.every((key, index) => key === String(index))) return null;
    values = keys.map((key) => value[key]);
  } else {
    return null;
  }

  const isByte = (byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255;
  return values.every(isByte) ? Uint8Array.from(values) : null;
}

/**
 * A credential's byte field as storage hands it back: bytes in any shape
 * `readBytes` takes, or base64url text (largeBlob and varsig metadata).
 * @returns {Uint8Array|null}
 */
function readField(value) {
  return typeof value === 'string' ? base64urlToBytes(value) : readBytes(value);
}

function equalBytes(a, b) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function indexOfBytes(haystack, needle) {
  for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    let j = 0;
    while (j < needle.length && haystack[i + j] === needle[j]) j += 1;
    if (j === needle.length) return i;
  }
  return -1;
}

/** base64url without padding, as WebAuthn and webauthn-sol encode it. */
function bytesToBase64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** @returns {Uint8Array|null} */
function base64urlToBytes(value) {
  const unpadded = value.replace(/=+$/, '');
  if (!/^[A-Za-z0-9_-]*$/.test(unpadded) || unpadded.length % 4 === 1) {
    return null;
  }
  const base64 = unpadded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigIntToBytes(value, length = COORDINATE_BYTES) {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

function mod(value, modulus) {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  base = mod(base, modulus);
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

/** x³ − 3x + b (mod p): what y² has to be for (x, y) to lie on the curve. */
function curveYSquared(x) {
  return mod(x * x * x - 3n * x + P256_B, P256_P);
}

function isOnCurve(x, y) {
  const xValue = bytesToBigInt(x);
  const yValue = bytesToBigInt(y);
  return (
    xValue < P256_P &&
    yValue < P256_P &&
    mod(yValue * yValue, P256_P) === curveYSquared(xValue)
  );
}

/**
 * x/y from a SEC1 point: 65 bytes uncompressed, or 33 compressed. A varsig
 * `did:key` carries the compressed form, so y is recomputed: p ≡ 3 (mod 4),
 * so a square root of y² is (y²)^((p+1)/4), and the prefix picks its parity.
 * @returns {{x: Uint8Array, y: Uint8Array}|null}
 */
function pointFromSec1(bytes) {
  if (bytes.length === 65 && bytes[0] === 0x04) {
    return { x: bytes.slice(1, 33), y: bytes.slice(33) };
  }
  if (bytes.length !== 33 || (bytes[0] !== 0x02 && bytes[0] !== 0x03)) {
    return null;
  }

  const x = bytesToBigInt(bytes.subarray(1));
  if (x >= P256_P) return null;
  const ySquared = curveYSquared(x);
  let y = modPow(ySquared, (P256_P + 1n) / 4n, P256_P);
  if (mod(y * y, P256_P) !== ySquared) return null;
  if ((y & 1n) !== BigInt(bytes[0] & 1)) {
    if (y === 0n) return null;
    y = P256_P - y;
  }
  return { x: bytes.slice(1), y: bigIntToBytes(y) };
}

/** Absent and null both count as "not stated". */
function statesOtherThan(value, expected) {
  return value !== undefined && value !== null && value !== expected;
}

/**
 * The credential's public key, if it is P-256.
 * @returns {{x: Uint8Array, y: Uint8Array}|null|undefined} undefined when
 *   the credential carries no key, null when it carries an unusable one.
 */
function readCredentialPublicKey(credential) {
  const { publicKey } = credential;
  if (publicKey === undefined || publicKey === null) return undefined;

  // Default path: COSE-style { algorithm, keyType, curve, x, y }.
  if (typeof publicKey === 'object' && ('x' in publicKey || 'y' in publicKey)) {
    // The stand-in createCredential writes when it could not read the key.
    if (publicKey.synthetic) return null;
    if (
      statesOtherThan(publicKey.algorithm, COSE_ALG_ES256) ||
      statesOtherThan(publicKey.keyType, COSE_KTY_EC2) ||
      statesOtherThan(publicKey.curve, COSE_CRV_P256)
    ) {
      return null;
    }
    const x = readField(publicKey.x);
    const y = readField(publicKey.y);
    if (x?.length !== COORDINATE_BYTES || y?.length !== COORDINATE_BYTES) {
      return null;
    }
    return { x, y };
  }

  // Varsig path: SEC1 bytes (32 bytes would be Ed25519, and is refused here).
  const bytes = readField(publicKey);
  return bytes ? pointFromSec1(bytes) : null;
}

/**
 * The key a P-256 `did:key` encodes.
 * @returns {{x: Uint8Array, y: Uint8Array}|null|undefined} undefined when
 *   the DID is absent or does not name a P-256 key (a keystore DID does not
 *   commit to the passkey), null when it names one that cannot be read.
 */
function readDidPublicKey(did) {
  if (typeof did !== 'string') return undefined;
  let decoded;
  try {
    decoded = decodeDidKey(did);
  } catch {
    return undefined;
  }
  if (decoded.codec !== MULTICODEC.P256_PUB) return undefined;
  return pointFromSec1(decoded.keyBytes);
}

/**
 * Raw credential id from `rawCredentialId` and/or `credentialId` (bytes, or
 * base64url). Where both are given they must name the same credential.
 * @returns {Uint8Array|null}
 */
function readCredentialId(credential) {
  const candidates = [credential.rawCredentialId, credential.credentialId]
    .filter((value) => value !== undefined && value !== null)
    .map(readField);
  if (candidates.length === 0 || candidates.some((id) => !id?.length)) {
    return null;
  }
  const [first, ...rest] = candidates;
  return rest.every((id) => equalBytes(id, first)) ? first : null;
}

/**
 * Describe a passkey's P-256 key the way wallet code needs it.
 *
 * Accepts a credential from either `createCredential` path, a copy restored
 * from localStorage, JSON or largeBlob, or a signer's `credential`. The key
 * comes from `publicKey` — `{ x, y }` or SEC1 bytes — or, failing that, from a
 * P-256 `did:key`; where both are present they must agree.
 *
 * Returns null, rather than something that cannot sign, for: RS256 or Ed25519
 * keys; the placeholder `createCredential` writes when it cannot read the key
 * (`synthetic: true`), and one that lost that flag, since its point is not on
 * the curve; and anything unreadable — no credential id, ids that disagree, a
 * malformed key, or no rpId.
 *
 * `rpId` is the one `createCredential` registered under; credentials from
 * before it was recorded fall back to `window.location.hostname`, the default
 * it registers under.
 *
 * @param {unknown} credential
 * @returns {{credentialId: string, rawCredentialId: Uint8Array, x: Uint8Array, y: Uint8Array, rpId: string, userVerification: 'required'}|null}
 *   `x` and `y` are 32-byte big-endian coordinates; `credentialId` is the
 *   unpadded base64url of `rawCredentialId`.
 */
export function getP256CredentialDescriptor(credential) {
  if (!credential || typeof credential !== 'object') return null;

  if (statesOtherThan(credential.algorithm, 'P-256')) return null;
  const { cose } = credential;
  if (
    cose &&
    typeof cose === 'object' &&
    (statesOtherThan(cose.kty, COSE_KTY_EC2) ||
      statesOtherThan(cose.alg, COSE_ALG_ES256) ||
      statesOtherThan(cose.crv, COSE_CRV_P256))
  ) {
    return null;
  }

  const rawCredentialId = readCredentialId(credential);
  if (!rawCredentialId) return null;

  const fromKey = readCredentialPublicKey(credential);
  const fromDid = readDidPublicKey(credential.did);
  if (fromKey === null || fromDid === null) return null;
  const point = fromKey ?? fromDid;
  if (!point) return null;
  if (
    fromKey &&
    fromDid &&
    !(equalBytes(fromKey.x, fromDid.x) && equalBytes(fromKey.y, fromDid.y))
  ) {
    return null;
  }
  if (!isOnCurve(point.x, point.y)) return null;

  const rpId =
    typeof credential.rpId === 'string' && credential.rpId
      ? credential.rpId
      : globalThis.window?.location?.hostname;
  if (typeof rpId !== 'string' || !rpId) return null;

  return {
    credentialId: bytesToBase64url(rawCredentialId),
    rawCredentialId,
    x: point.x,
    y: point.y,
    rpId,
    userVerification: 'required',
  };
}

function readDescriptor(descriptor) {
  const invalid = () =>
    new WebAuthnIdentityError(
      'signP256Challenge needs a descriptor from getP256CredentialDescriptor()'
    );
  if (!descriptor || typeof descriptor !== 'object') throw invalid();

  const rawCredentialId = readBytes(descriptor.rawCredentialId);
  const x = readBytes(descriptor.x);
  const y = readBytes(descriptor.y);
  const { rpId, credentialId } = descriptor;
  if (
    !rawCredentialId?.length ||
    x?.length !== COORDINATE_BYTES ||
    y?.length !== COORDINATE_BYTES ||
    typeof rpId !== 'string' ||
    !rpId ||
    (typeof credentialId === 'string' &&
      credentialId.replace(/=+$/, '') !== bytesToBase64url(rawCredentialId)) ||
    !isOnCurve(x, y)
  ) {
    throw invalid();
  }
  return { rawCredentialId, x, y, rpId };
}

/**
 * r and s from the ASN.1 DER an authenticator returns for ES256 (WebAuthn L2
 * §6.5.5), left-padded to 32 bytes, with s normalised to low-s.
 *
 * DER integers are minimal, so r or s is 31 bytes about once in 256 and 33
 * (a sign byte) about half the time; `derToRawSignature` handles both (#58).
 */
function readEcdsaSignature(signature) {
  if (!isDerSignature(signature)) {
    throw new WebAuthnVerificationError(
      'The assertion signature is not an ASN.1 DER ECDSA signature'
    );
  }
  let raw;
  try {
    raw = derToRawSignature(signature);
  } catch (error) {
    throw new WebAuthnVerificationError(error.message, { cause: error });
  }

  const r = bytesToBigInt(raw.subarray(0, COORDINATE_BYTES));
  let s = bytesToBigInt(raw.subarray(COORDINATE_BYTES));
  if (r === 0n || r >= P256_N || s === 0n || s >= P256_N) {
    throw new WebAuthnVerificationError('Signature r or s is out of range');
  }
  // (r, n − s) verifies wherever (r, s) does; webauthn-sol takes only the low
  // one, and the authenticator returns either.
  if (s > P256_HALF_N) s = P256_N - s;

  return { r: raw.slice(0, COORDINATE_BYTES), s: bigIntToBytes(s) };
}

async function verifiesWithKey({ x, y, r, s, authenticatorData, clientData }) {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      concatBytes(new Uint8Array([0x04]), x, y),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const clientDataHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', clientData)
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      concatBytes(r, s),
      concatBytes(authenticatorData, clientDataHash)
    );
  } catch {
    return false;
  }
}

/**
 * Sign a raw 32-byte challenge — a user operation hash, say — with the passkey
 * a descriptor names, and return the parts a P-256 WebAuthn verifier reads.
 *
 * The challenge is used as the WebAuthn challenge itself, as Calibur passes
 * its hash to webauthn-sol. The request pins `allowCredentials` to the
 * descriptor's credential — whatever `configureWebAuthn` says about
 * discoverable credentials — uses its `rpId` and requires user verification.
 *
 * Refused with a thrown error: a challenge that is not exactly 32 bytes (before
 * any prompt), an assertion from another credential (`rawId` differs), and
 * anything a verifier would refuse — client data that is not `webauthn.get`
 * over this challenge, the UP or UV flag unset, a signature that is not DER or
 * does not verify against the descriptor's x/y.
 *
 * @param {{rawCredentialId: Uint8Array, x: Uint8Array, y: Uint8Array, rpId: string}} descriptor
 *   from `getP256CredentialDescriptor`
 * @param {Uint8Array|ArrayBuffer} challenge exactly 32 bytes
 * @returns {Promise<{authenticatorData: Uint8Array, clientDataJSON: string, challengeIndex: number, typeIndex: number, r: Uint8Array, s: Uint8Array}>}
 *   `challengeIndex` and `typeIndex` are UTF-8 byte offsets in
 *   `clientDataJSON` of `"challenge":"<base64url(challenge), unpadded>"` and
 *   `"type":"webauthn.get"`; `r` and `s` are 32 bytes big-endian, `s` low.
 */
export async function signP256Challenge(descriptor, challenge) {
  const { rawCredentialId, x, y, rpId } = readDescriptor(descriptor);

  const challengeBytes =
    challenge instanceof ArrayBuffer || ArrayBuffer.isView(challenge)
      ? readBytes(challenge)
      : null;
  if (challengeBytes?.length !== CHALLENGE_BYTES) {
    throw new WebAuthnIdentityError(
      `signP256Challenge needs a challenge of exactly ${CHALLENGE_BYTES} bytes, got ${
        challengeBytes ? `${challengeBytes.length} bytes` : typeof challenge
      }`
    );
  }

  if (typeof globalThis.navigator?.credentials?.get !== 'function') {
    throw new WebAuthnNotSupportedError();
  }

  let assertion;
  try {
    assertion = await navigator.credentials.get(
      buildCredentialRequestOptions({
        challenge: challengeBytes,
        rpId,
        credentialId: rawCredentialId,
        userVerification: 'required',
        // The signature is only any use from this credential, so the browser
        // must not offer a different passkey.
        discoverableCredentials: false,
      })
    );
  } catch (error) {
    throw new WebAuthnAuthenticationError(
      error?.name === 'NotAllowedError'
        ? 'Passkey authentication was cancelled or not allowed'
        : `Passkey authentication failed: ${error?.message}`,
      { cause: error }
    );
  }
  if (!assertion) {
    throw new WebAuthnAuthenticationError('Passkey authentication failed');
  }

  const rawId = readBytes(assertion.rawId);
  if (!rawId || !equalBytes(rawId, rawCredentialId)) {
    throw new WebAuthnAuthenticationError(
      'The assertion came from a different credential than the descriptor names'
    );
  }

  const response = assertion.response ?? {};
  const authenticatorData = readBytes(response.authenticatorData);
  const clientData = readBytes(response.clientDataJSON);
  const signature = readBytes(response.signature);
  if (!authenticatorData || !clientData || !signature) {
    throw new WebAuthnVerificationError(
      'The assertion lacks authenticatorData, clientDataJSON or signature'
    );
  }

  if (authenticatorData.length < AUTH_DATA_MIN_LENGTH) {
    throw new WebAuthnVerificationError('authenticatorData is too short');
  }
  const flags = authenticatorData[32];
  if (!(flags & FLAG_USER_PRESENT) || !(flags & FLAG_USER_VERIFIED)) {
    throw new WebAuthnVerificationError(
      'The authenticator did not report user presence and verification'
    );
  }

  // Fatal and BOM-preserving, so the string encodes back to exactly the bytes
  // that were signed.
  let clientDataJSON;
  let parsed;
  try {
    clientDataJSON = new TextDecoder('utf-8', {
      fatal: true,
      ignoreBOM: true,
    }).decode(clientData);
    parsed = JSON.parse(clientDataJSON);
  } catch (error) {
    throw new WebAuthnVerificationError('clientDataJSON is not valid JSON', {
      cause: error,
    });
  }

  const encodedChallenge = bytesToBase64url(challengeBytes);
  if (
    parsed?.type !== WEBAUTHN_CLIENT_DATA_TYPES.GET ||
    parsed.challenge !== encodedChallenge
  ) {
    throw new WebAuthnVerificationError(
      'clientDataJSON is not a webauthn.get over this challenge'
    );
  }

  // Located as bytes: a verifier slices the UTF-8 encoding at these offsets.
  const typeIndex = indexOfBytes(
    clientData,
    encoder.encode(`"type":"${WEBAUTHN_CLIENT_DATA_TYPES.GET}"`)
  );
  const challengeIndex = indexOfBytes(
    clientData,
    encoder.encode(`"challenge":"${encodedChallenge}"`)
  );
  if (typeIndex < 0 || challengeIndex < 0) {
    throw new WebAuthnVerificationError(
      'clientDataJSON does not spell out its type and challenge verbatim'
    );
  }

  const { r, s } = readEcdsaSignature(signature);
  if (!(await verifiesWithKey({ x, y, r, s, authenticatorData, clientData }))) {
    throw new WebAuthnVerificationError(
      "The signature does not verify against the descriptor's public key"
    );
  }

  return { authenticatorData, clientDataJSON, challengeIndex, typeIndex, r, s };
}

/**
 * @module ProofVerification
 * @description
 * Checks that an identity's claim to a DID is backed by the key that DID
 * encodes.
 *
 * OrbitDB verifies `signatures.id` against the identity's own `publicKey`, which
 * any key satisfies for itself, and then asks the provider whether the rest
 * holds. So this is the only place where "this identity may speak for that DID"
 * is decided — and until GHSA-326j-4cc3-4rrg it decided nothing: the static
 * `verifyIdentity` looked at the type and the `did:key:` prefix, and
 * `WebAuthnDIDProvider.verify()` looked at the proof's fields. A peer holding
 * only its own key could claim any DID in any write list.
 *
 * Two kinds of DID reach here, and each is bound differently:
 *
 * - **P-256, the credential's own key** (multicodec 0x1200). The passkey signed
 *   `publicKey + signatures.id` during `createIdentity`; that WebAuthn assertion
 *   is `signatures.publicKey`. It is verified against the key the DID encodes,
 *   so no lookup is needed — the DID *is* the verification key.
 * - **Ed25519 or secp256k1, a keystore key** (`useKeystoreDID`). The DID is the
 *   signing key itself, so `publicKey` must be exactly the key it encodes;
 *   OrbitDB has already checked that key signed the id.
 *
 * Anything else — including the legacy 64-hex ids — cannot be bound to a key,
 * and is refused rather than waved through.
 *
 * ## What a proof's challenge looks like, and why
 *
 * The same passkey may sign for other protocols. Since 0.8.0 it is meant to be
 * a wallet key too, and `signP256Challenge` signs any 32 bytes it is given.
 * The first proof format made its challenge `SHA-256(credentialId ‖ data)` —
 * also 32 bytes, also just a hash. So a wallet signature over a value somebody
 * chose was, byte for byte, an identity proof for whatever that value hashed:
 * get a victim to sign one "hash" and hold a permanent identity for their DID.
 *
 * A label inside the hash would not have helped: whoever picks the 32 bytes
 * can hash the label in. What separates two protocols signed by one key has
 * to be visible in what the authenticator signs, and that is the challenge
 * itself. So a proof's challenge is no longer a bare hash:
 *
 *     "orbitdb-webauthn-did:v2:<context>:" ‖ SHA-256(len(credentialId) ‖ credentialId ‖ data)
 *
 * It is longer than 32 bytes and starts with text, so nothing that signs a
 * 32-byte challenge — a wallet, an on-chain verifier's hash — can ever produce
 * one, and a proof can never pass for a wallet signature either. The context
 * keeps an identity binding apart from other data the same class signs: a
 * proof made by `sign(data)` for an application is not an identity. The
 * credential id is length-prefixed because the proof names it and the
 * verifier cannot check it; unframed, bytes could be moved between it and the
 * data.
 *
 * The first format is still accepted unless `configureWebAuthn({
 * acceptLegacyProofs: false })` says otherwise — every identity made before
 * this is in that format, and so is everything those identities wrote. While
 * it is accepted, the hole above stays open on the verifying side.
 */
import { varint } from 'multiformats';
import { base58btc } from 'multiformats/bases/base58';
import { derToRawSignature } from 'iso-webauthn-varsig';

import { DID_KEY_PREFIX, WEBAUTHN_CLIENT_DATA_TYPES } from '../constants.js';
import { firstLegacyProofNotice, getWebAuthnConfig } from './config.js';

export const MULTICODEC = Object.freeze({
  P256_PUB: 0x1200,
  ED25519_PUB: 0xed,
  SECP256K1_PUB: 0xe7,
});

/**
 * What a proof is about. An identity binding is only ever accepted with
 * `IDENTITY`; `DATA` is what `sign(data)` makes for an application.
 */
export const PROOF_CONTEXTS = Object.freeze({
  IDENTITY: 'identity',
  DATA: 'data',
});

const PROOF_CHALLENGE_LABEL = 'orbitdb-webauthn-did:v2';
const SHA256_BYTES = 32;

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
// rpIdHash (32) + flags (1) + signCount (4)
const AUTH_DATA_MIN_LENGTH = 37;
const P1363_SIGNATURE_LENGTH = 64;

function base64urlToBytes(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function bytesToBase64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/** @param {Uint8Array} a @param {Uint8Array} b */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
}

/** @param {string} context */
function challengePrefix(context) {
  if (typeof context !== 'string' || !/^[a-z0-9-]+$/.test(context)) {
    throw new TypeError(
      'A proof context is lowercase letters, digits and hyphens'
    );
  }
  return new TextEncoder().encode(`${PROOF_CHALLENGE_LABEL}:${context}:`);
}

/**
 * The WebAuthn challenge of a proof over `data`, made by `credentialId`, in
 * `context` — see the module comment for why it has this shape.
 *
 * @param {{ credentialId: Uint8Array, data: string | Uint8Array, context?: string }} parameters
 * @returns {Promise<Uint8Array>}
 */
export async function proofChallenge({
  credentialId,
  data,
  context = PROOF_CONTEXTS.DATA,
}) {
  const prefix = challengePrefix(context);
  const id = Uint8Array.from(credentialId);
  const dataBytes =
    typeof data === 'string'
      ? new TextEncoder().encode(data)
      : Uint8Array.from(data);
  const framed = new Uint8Array(4 + id.length + dataBytes.length);
  new DataView(framed.buffer).setUint32(0, id.length);
  framed.set(id, 4);
  framed.set(dataBytes, 4 + id.length);
  return concat(prefix, await sha256(framed));
}

/**
 * Which format a proof from `sign()` is in, by its challenge: `2` for the
 * current one, `1` for the bare 32-byte hash, `null` for anything else.
 * Reads the proof; verifies nothing.
 *
 * @param {unknown} encodedProof
 * @returns {1 | 2 | null}
 */
export function proofFormat(encodedProof) {
  try {
    if (typeof encodedProof !== 'string') return null;
    const proof = JSON.parse(
      new TextDecoder().decode(base64urlToBytes(encodedProof))
    );
    const challenge = base64urlToBytes(
      JSON.parse(proof.clientDataJSON).challenge
    );
    if (challenge.length === SHA256_BYTES) return 1;
    const label = new TextEncoder().encode(`${PROOF_CHALLENGE_LABEL}:`);
    return challenge.length > label.length + SHA256_BYTES &&
      sameBytes(challenge.subarray(0, label.length), label)
      ? 2
      : null;
  } catch {
    return null;
  }
}

/**
 * Whether a proof in the first format may still pass, and — when nobody has
 * decided — say once that one did.
 * @param {boolean | undefined} override
 */
function legacyProofAllowed(override) {
  const setting = override ?? getWebAuthnConfig().acceptLegacyProofs;
  if (setting === false) return false;
  if (setting === undefined && firstLegacyProofNotice()) {
    console.warn(
      '[orbitdb-identity-provider-webauthn-did] Accepted an identity proof in the legacy format, ' +
        'whose challenge any 32-byte signature by the same passkey can stand in for. ' +
        'Set configureWebAuthn({ acceptLegacyProofs: false }) once no identity made before 0.14.0 ' +
        'has to verify, or true to accept them without this notice.'
    );
  }
  return true;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string} lowercase hex
 */
export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
    ''
  );
}

/**
 * Split a `did:key` into its multicodec and raw public key.
 * @param {string} did
 * @returns {{ codec: number, keyBytes: Uint8Array }}
 */
export function decodeDidKey(did) {
  if (typeof did !== 'string' || !did.startsWith(`${DID_KEY_PREFIX}z`)) {
    throw new Error('Not a base58btc did:key');
  }
  const bytes = base58btc.decode(did.slice(DID_KEY_PREFIX.length));
  const [codec, prefixLength] = varint.decode(bytes);
  return { codec, keyBytes: bytes.subarray(prefixLength) };
}

/**
 * A P-256 public key as raw SEC1 bytes, from either raw bytes or `{ x, y }`.
 * @param {Uint8Array|{x: ArrayLike<number>, y: ArrayLike<number>}|undefined} publicKey
 * @returns {Uint8Array|null}
 */
export function p256PublicKeyBytes(publicKey) {
  if (publicKey instanceof Uint8Array) {
    if (publicKey.length === 65 && publicKey[0] === 0x04) return publicKey;
    if (publicKey.length === 33) return publicKey;
    return null;
  }
  if (publicKey?.x && publicKey?.y) {
    const x = Uint8Array.from(publicKey.x);
    const y = Uint8Array.from(publicKey.y);
    if (x.length !== 32 || y.length !== 32) return null;
    const out = new Uint8Array(65);
    out[0] = 0x04;
    out.set(x, 1);
    out.set(y, 33);
    return out;
  }
  return null;
}

/**
 * Verify a proof produced by `WebAuthnDIDProvider.sign(data)`.
 *
 * Checks, in order: the client data type; that the challenge is the one
 * `sign()` derives for this data, this credential id and this context (see
 * the module comment), so the assertion is about this data and no other and
 * was made as a proof and not for another protocol; that the user was present
 * and verified; and the ECDSA P-256 signature over
 * `authenticatorData ‖ SHA-256(clientDataJSON)` against the given key. Never
 * throws: a malformed proof is simply not valid.
 *
 * A proof in the first format — challenge SHA-256(rawCredentialId ‖ data),
 * user presence only — passes while legacy proofs are accepted
 * (`acceptLegacyProofs` here, else `configureWebAuthn`), whatever the context.
 *
 * Origin and rpId are not checked. They defend an authentication ceremony
 * against relaying; here the question is only whether the holder of this key
 * signed this data, which the signature answers wherever it was made.
 *
 * @param {string} encodedProof base64url JSON, as returned by `sign()`
 * @param {string|Uint8Array} data what was signed
 * @param {Uint8Array} publicKeyBytes P-256 public key, SEC1
 * @param {{ context?: string, acceptLegacyProofs?: boolean | undefined }} [options]
 * @returns {Promise<boolean>}
 */
export async function verifyWebAuthnProof(
  encodedProof,
  data,
  publicKeyBytes,
  { context = PROOF_CONTEXTS.DATA, acceptLegacyProofs } = {}
) {
  try {
    if (typeof encodedProof !== 'string' || !publicKeyBytes) return false;
    const proof = JSON.parse(
      new TextDecoder().decode(base64urlToBytes(encodedProof))
    );
    const { credentialId, authenticatorData, clientDataJSON, signature } =
      proof ?? {};
    if (
      typeof credentialId !== 'string' ||
      typeof authenticatorData !== 'string' ||
      typeof clientDataJSON !== 'string' ||
      typeof signature !== 'string'
    ) {
      return false;
    }

    const clientData = JSON.parse(clientDataJSON);
    if (clientData?.type !== WEBAUTHN_CLIENT_DATA_TYPES.GET) return false;

    const dataBytes =
      typeof data === 'string'
        ? new TextEncoder().encode(data)
        : new Uint8Array(data);
    const credentialIdBytes = base64urlToBytes(credentialId);
    if (typeof clientData.challenge !== 'string') return false;
    const current = sameBytes(
      base64urlToBytes(clientData.challenge),
      await proofChallenge({
        credentialId: credentialIdBytes,
        data: dataBytes,
        context,
      })
    );
    if (!current) {
      const legacyChallenge = bytesToBase64url(
        await sha256(concat(credentialIdBytes, dataBytes))
      );
      if (clientData.challenge !== legacyChallenge) return false;
      if (!legacyProofAllowed(acceptLegacyProofs)) return false;
    }

    const authData = base64urlToBytes(authenticatorData);
    if (authData.length < AUTH_DATA_MIN_LENGTH) return false;
    if ((authData[32] & FLAG_USER_PRESENT) === 0) return false;
    // `sign()` has always asked for user verification; the first format did
    // not check that the authenticator did it.
    if (current && (authData[32] & FLAG_USER_VERIFIED) === 0) return false;

    const signedBytes = concat(
      authData,
      await sha256(new TextEncoder().encode(clientDataJSON))
    );
    // Authenticators return ES256 signatures as DER, where r and s are
    // minimal integers: one with a leading zero byte is 31 bytes long (about
    // one signature in 128). WebCrypto wants each padded to 32. The unwrapper
    // used here before did not pad, so those genuine proofs were refused — by
    // every peer, and for good, because the proof is stored and reused.
    const signatureBytes = base64urlToBytes(signature);
    const p1363 =
      signatureBytes.length === P1363_SIGNATURE_LENGTH
        ? signatureBytes
        : derToRawSignature(signatureBytes);

    const key = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      p1363,
      signedBytes
    );
  } catch {
    return false;
  }
}

/**
 * Whether an OrbitDB identity of type `webauthn` may speak for its `id`.
 * @param {{id: string, publicKey: string, signatures: {id: string, publicKey: string}}} identity
 * @returns {Promise<boolean>}
 */
export async function verifyWebAuthnIdentityBinding(identity) {
  if (
    !identity ||
    typeof identity.publicKey !== 'string' ||
    !identity.signatures
  ) {
    return false;
  }

  let decoded;
  try {
    decoded = decodeDidKey(identity.id);
  } catch {
    return false;
  }

  if (decoded.codec === MULTICODEC.P256_PUB) {
    return verifyWebAuthnProof(
      identity.signatures.publicKey,
      identity.publicKey + identity.signatures.id,
      decoded.keyBytes,
      { context: PROOF_CONTEXTS.IDENTITY }
    );
  }

  if (
    decoded.codec === MULTICODEC.ED25519_PUB ||
    decoded.codec === MULTICODEC.SECP256K1_PUB
  ) {
    return bytesToHex(decoded.keyBytes) === identity.publicKey.toLowerCase();
  }

  return false;
}

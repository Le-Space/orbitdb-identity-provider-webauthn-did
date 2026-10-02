/**
 * Calibur v1.0.0's encodings, each derived from its sources at that tag:
 *
 * - a key hash is `keccak256(abi.encode(key.keyType, keccak256(key.publicKey)))`
 *   (KeyLib.hash), and a passkey is `Key(KeyType.WebAuthnP256 = 1,
 *   abi.encode(uint256 x, uint256 y))` (KeyLib.verify decodes it so);
 * - a user operation signature is `abi.encode(bytes32 keyHash, bytes signature,
 *   bytes hookData)` (WrappedSignatureLib.decodeWithKeyHashAndHookData), where
 *   a passkey's `signature` is `abi.encode(WebAuthn.WebAuthnAuth)` (KeyLib.verify,
 *   webauthn-sol at 619f20a) over the user operation hash as the challenge;
 * - user operation calldata is `executeUserOp.selector ‖ abi.encode(BatchedCall)`
 *   (Calibur.executeUserOp removes the selector and decodes a BatchedCall);
 * - key settings pack `isAdmin` at bit 200, a 40-bit expiration at bit 160 and
 *   a hook address in the low 160 bits (SettingsLib);
 * - `execute(SignedBatchedCall, bytes)` verifies EIP-712 typed data in the
 *   domain (name "Calibur", version "1.0.0", chainId, the account, salt =
 *   saltPrefix << 160 | implementation) (EIP712.sol, SignedBatchedCallLib).
 *
 * test/calibur compares every one of them with Calibur's own libraries.
 */
import {
  bytesToHex,
  concat,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  isAddress,
  isHex,
  keccak256,
  numberToHex,
  pad,
  sha256,
  size,
  slice,
  stringToBytes,
  toFunctionSelector,
  zeroAddress,
} from 'viem';

import { caliburAbi } from './abi.js';
import {
  CALIBUR_ADDRESS,
  CALIBUR_VERSION,
  KeyType,
  ROOT_KEY_HASH,
} from './constants.js';

/**
 * @typedef {import('viem').Address} Address
 * @typedef {import('viem').Hex} Hex
 */

/**
 * A call as Calibur's `Call` struct holds it, and as viem passes calls.
 * @typedef {{ to: Address, value?: bigint | undefined, data?: Hex | undefined }} Call
 */

/**
 * A Calibur `Key`: its type and its public key, ABI-encoded.
 * @typedef {{ keyType: number, publicKey: Hex }} Key
 */

/**
 * Key settings. `expiration` is a unix timestamp in seconds (0: never);
 * `hook` is a hook contract (the zero address: none).
 * @typedef {{ isAdmin?: boolean | undefined, expiration?: number | bigint | undefined, hook?: Address | undefined }} KeySettings
 */

/**
 * A P-256 public key as 32-byte big-endian coordinates, the shape
 * `getP256CredentialDescriptor` returns (a descriptor itself will do).
 * @typedef {{ x: Uint8Array | Hex | bigint, y: Uint8Array | Hex | bigint }} P256PublicKey
 */

/**
 * webauthn-sol's `WebAuthnAuth`, as `signP256Challenge` returns it (byte
 * fields may also be hex, and numbers bigints).
 * @typedef {{
 *   authenticatorData: Uint8Array | Hex,
 *   clientDataJSON: string,
 *   challengeIndex: number | bigint,
 *   typeIndex: number | bigint,
 *   r: Uint8Array | Hex | bigint,
 *   s: Uint8Array | Hex | bigint,
 * }} WebAuthnAuth
 */

/**
 * @typedef {{
 *   authenticatorData: Hex,
 *   clientDataJSON: string,
 *   challengeIndex: bigint,
 *   typeIndex: bigint,
 *   r: bigint,
 *   s: bigint,
 * }} DecodedWebAuthnAuth
 */

/**
 * Calibur's `SignedBatchedCall`: a batch the root key (or another key) signs
 * for someone else to submit through `execute(SignedBatchedCall, bytes)`.
 * @typedef {{
 *   batchedCall: { calls: readonly Call[], revertOnFailure: boolean },
 *   nonce: bigint,
 *   keyHash: Hex,
 *   executor: Address,
 *   deadline: bigint,
 * }} SignedBatchedCall
 */

// secp256r1, SEC 2 §2.4.2
const P256_P =
  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_B =
  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
// webauthn-sol refuses any s above this, against malleability.
const P256_HALF_N = P256_N / 2n;

const UINT40_MAX = (1n << 40n) - 1n;
const AUTHENTICATOR_DATA_MIN_LENGTH = 37;

const webAuthnAuthParameter = /** @type {const} */ ({
  type: 'tuple',
  components: [
    { name: 'authenticatorData', type: 'bytes' },
    { name: 'clientDataJSON', type: 'string' },
    { name: 'challengeIndex', type: 'uint256' },
    { name: 'typeIndex', type: 'uint256' },
    { name: 'r', type: 'uint256' },
    { name: 's', type: 'uint256' },
  ],
});

const callComponents = /** @type {const} */ ([
  { name: 'to', type: 'address' },
  { name: 'value', type: 'uint256' },
  { name: 'data', type: 'bytes' },
]);

const batchedCallParameter = /** @type {const} */ ({
  type: 'tuple',
  components: [
    { name: 'calls', type: 'tuple[]', components: callComponents },
    { name: 'revertOnFailure', type: 'bool' },
  ],
});

const userOperationSignatureParameters = /** @type {const} */ ([
  { name: 'keyHash', type: 'bytes32' },
  { name: 'signature', type: 'bytes' },
  { name: 'hookData', type: 'bytes' },
]);

const wrappedSignatureParameters = /** @type {const} */ ([
  { name: 'signature', type: 'bytes' },
  { name: 'hookData', type: 'bytes' },
]);

/**
 * A function of caliburAbi that is not overloaded, by name.
 * @param {string} name
 * @returns {import('viem').AbiFunction}
 */
function abiFunction(name) {
  const item = caliburAbi.find(
    (entry) => entry.type === 'function' && entry.name === name
  );
  if (!item) throw new Error(`caliburAbi has no function ${name}`);
  return /** @type {import('viem').AbiFunction} */ (item);
}

const executeUserOpAbi = abiFunction('executeUserOp');
// execute(SignedBatchedCall, bytes), not execute(BatchedCall) or
// execute(bytes32, bytes): the one whose inputs are a tuple and bytes.
const executeSignedBatchedCallAbi = (() => {
  const item = caliburAbi.find(
    (entry) =>
      entry.type === 'function' &&
      entry.name === 'execute' &&
      entry.inputs.length === 2 &&
      entry.inputs[0].type === 'tuple'
  );
  if (!item)
    throw new Error('caliburAbi has no execute(SignedBatchedCall, bytes)');
  return /** @type {import('viem').AbiFunction} */ (item);
})();
const registerAbi = abiFunction('register');
const updateAbi = abiFunction('update');
const revokeAbi = abiFunction('revoke');

/** `executeUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32)` */
export const EXECUTE_USER_OP_SELECTOR = toFunctionSelector(executeUserOpAbi);

/**
 * An unsigned integer of at most `bytes` bytes from a Uint8Array, hex or
 * bigint.
 * @param {unknown} value
 * @param {string} name
 * @returns {bigint}
 */
function readUint(value, name, bytes = 32) {
  let result;
  if (typeof value === 'bigint') {
    result = value;
  } else if (value instanceof Uint8Array) {
    if (value.length > bytes) {
      throw new TypeError(
        `${name} has ${value.length} bytes, at most ${bytes}`
      );
    }
    result = value.length ? BigInt(bytesToHex(value)) : 0n;
  } else if (typeof value === 'string' && isHex(value, { strict: true })) {
    if (size(value) > bytes) {
      throw new TypeError(`${name} is longer than ${bytes} bytes`);
    }
    result = value === '0x' ? 0n : BigInt(value);
  } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
    result = BigInt(value);
  } else {
    throw new TypeError(`${name} must be bytes, hex or a bigint`);
  }
  if (result < 0n || result >= 1n << BigInt(bytes * 8)) {
    throw new RangeError(`${name} is out of range`);
  }
  return result;
}

/** @param {unknown} value @param {string} name @returns {Hex} */
function readBytesHex(value, name) {
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (
    typeof value === 'string' &&
    isHex(value, { strict: true }) &&
    value.length % 2 === 0
  ) {
    return /** @type {Hex} */ (value);
  }
  throw new TypeError(`${name} must be a Uint8Array or whole bytes of hex`);
}

/** @param {unknown} value @param {string} name @returns {Hex} */
function readBytes32(value, name) {
  const hex = readBytesHex(value, name);
  if (size(hex) !== 32) throw new TypeError(`${name} must be 32 bytes`);
  return hex;
}

/** @param {unknown} value @param {string} name @returns {Address} */
function readAddress(value, name) {
  if (typeof value !== 'string' || !isAddress(value, { strict: false })) {
    throw new TypeError(`${name} must be an address`);
  }
  return getAddress(value);
}

/**
 * Calls in the shape Calibur's `Call` struct needs: `to` checked, `value` and
 * `data` filled in.
 * @param {readonly Call[]} calls
 * @returns {{ to: Address, value: bigint, data: Hex }[]}
 */
export function normalizeCalls(calls) {
  if (!Array.isArray(calls)) throw new TypeError('calls must be an array');
  return calls.map((call, index) => {
    if (!call || typeof call !== 'object') {
      throw new TypeError(`calls[${index}] must be a call`);
    }
    const value = call.value ?? 0n;
    if (typeof value !== 'bigint' || value < 0n) {
      throw new TypeError(
        `calls[${index}].value must be a non-negative bigint`
      );
    }
    return {
      to: readAddress(call.to, `calls[${index}].to`),
      value,
      data: readBytesHex(call.data ?? '0x', `calls[${index}].data`),
    };
  });
}

/**
 * The Calibur key for a passkey: `Key(KeyType.WebAuthnP256, abi.encode(x, y))`.
 * The point must lie on P-256, or no signature could ever verify.
 * @param {P256PublicKey} publicKey
 * @returns {Key}
 */
export function toWebAuthnP256Key(publicKey) {
  if (!publicKey || typeof publicKey !== 'object') {
    throw new TypeError('toWebAuthnP256Key needs { x, y }');
  }
  const x = readUint(publicKey.x, 'x');
  const y = readUint(publicKey.y, 'y');
  const onCurve =
    x < P256_P &&
    y < P256_P &&
    (y * y) % P256_P ===
      (((x * x * x - 3n * x + P256_B) % P256_P) + P256_P) % P256_P;
  if (!onCurve) throw new RangeError('The public key is not a P-256 point');
  return {
    keyType: KeyType.WebAuthnP256,
    publicKey: encodeAbiParameters(
      [{ type: 'uint256' }, { type: 'uint256' }],
      [x, y]
    ),
  };
}

/**
 * The hash Calibur stores and looks a key up by (KeyLib.hash).
 * @param {Key} key
 * @returns {Hex}
 */
export function getKeyHash(key) {
  if (
    !key ||
    !Number.isInteger(key.keyType) ||
    key.keyType < 0 ||
    key.keyType > 255
  ) {
    throw new TypeError('getKeyHash needs a key with a keyType');
  }
  return keccak256(
    encodeAbiParameters(
      [{ type: 'uint8' }, { type: 'bytes32' }],
      [key.keyType, keccak256(readBytesHex(key.publicKey, 'publicKey'))]
    )
  );
}

/**
 * Pack key settings into the uint256 Calibur's `update(keyHash, settings)`
 * takes.
 * @param {KeySettings} [settings]
 * @returns {bigint}
 */
export function encodeKeySettings(settings = {}) {
  const { isAdmin = false, expiration = 0, hook = zeroAddress } = settings;
  const expiry = BigInt(expiration);
  if (expiry < 0n || expiry > UINT40_MAX) {
    throw new RangeError('expiration must fit in 40 bits');
  }
  return (
    (isAdmin ? 1n << 200n : 0n) |
    (expiry << 160n) |
    BigInt(readAddress(hook, 'hook'))
  );
}

/**
 * @param {bigint} settings
 * @returns {{ isAdmin: boolean, expiration: number, hook: Address }}
 */
export function decodeKeySettings(settings) {
  const value = readUint(settings, 'settings');
  return {
    isAdmin: ((value >> 200n) & 0xffn) !== 0n,
    expiration: Number((value >> 160n) & UINT40_MAX),
    hook: getAddress(
      pad(numberToHex(value & ((1n << 160n) - 1n)), { size: 20 })
    ),
  };
}

/**
 * `abi.encode(WebAuthn.WebAuthnAuth)`, the signature Calibur hands to
 * webauthn-sol for a WebAuthnP256 key.
 *
 * Refuses what webauthn-sol would refuse regardless of the challenge: r or s
 * outside (0, n), s above n / 2, and authenticator data too short to hold
 * its flags.
 * @param {WebAuthnAuth} auth
 * @returns {Hex}
 */
export function encodeWebAuthnAuth(auth) {
  if (!auth || typeof auth !== 'object') {
    throw new TypeError('encodeWebAuthnAuth needs the parts of an assertion');
  }
  const authenticatorData = readBytesHex(
    auth.authenticatorData,
    'authenticatorData'
  );
  if (size(authenticatorData) < AUTHENTICATOR_DATA_MIN_LENGTH) {
    throw new RangeError('authenticatorData is too short');
  }
  if (typeof auth.clientDataJSON !== 'string') {
    throw new TypeError('clientDataJSON must be a string');
  }
  const challengeIndex = readUint(auth.challengeIndex, 'challengeIndex');
  const typeIndex = readUint(auth.typeIndex, 'typeIndex');
  const r = readUint(auth.r, 'r');
  const s = readUint(auth.s, 's');
  if (r === 0n || r >= P256_N || s === 0n || s >= P256_N) {
    throw new RangeError('r or s is out of range');
  }
  if (s > P256_HALF_N) {
    throw new RangeError('s is high; webauthn-sol only accepts s <= n / 2');
  }
  return encodeAbiParameters(
    [webAuthnAuthParameter],
    [
      {
        authenticatorData,
        clientDataJSON: auth.clientDataJSON,
        challengeIndex,
        typeIndex,
        r,
        s,
      },
    ]
  );
}

/**
 * @param {Hex} signature `abi.encode(WebAuthn.WebAuthnAuth)`
 * @returns {DecodedWebAuthnAuth}
 */
export function decodeWebAuthnAuth(signature) {
  const [auth] = decodeAbiParameters([webAuthnAuthParameter], signature);
  return { ...auth };
}

/**
 * `userOp.signature` for Calibur: `abi.encode(keyHash, signature, hookData)`.
 * Calibur reverts on a signature shorter than 64 bytes, so this refuses one.
 * @param {{ keyHash: Hex, signature: Hex, hookData?: Hex | undefined }} parameters
 * @returns {Hex}
 */
export function encodeUserOperationSignature({
  keyHash,
  signature,
  hookData = '0x',
}) {
  const signatureHex = readBytesHex(signature, 'signature');
  if (size(signatureHex) < 64) {
    throw new RangeError('Calibur needs a signature of at least 64 bytes');
  }
  return encodeAbiParameters(userOperationSignatureParameters, [
    readBytes32(keyHash, 'keyHash'),
    signatureHex,
    readBytesHex(hookData, 'hookData'),
  ]);
}

/**
 * @param {Hex} wrappedSignature
 * @returns {{ keyHash: Hex, signature: Hex, hookData: Hex }}
 */
export function decodeUserOperationSignature(wrappedSignature) {
  const [keyHash, signature, hookData] = decodeAbiParameters(
    userOperationSignatureParameters,
    wrappedSignature
  );
  return { keyHash, signature, hookData };
}

/**
 * The `wrappedSignature` of `execute(SignedBatchedCall, bytes)`:
 * `abi.encode(signature, hookData)`.
 * @param {{ signature: Hex, hookData?: Hex | undefined }} parameters
 * @returns {Hex}
 */
export function encodeWrappedSignature({ signature, hookData = '0x' }) {
  const signatureHex = readBytesHex(signature, 'signature');
  if (size(signatureHex) < 64) {
    throw new RangeError('Calibur needs a signature of at least 64 bytes');
  }
  return encodeAbiParameters(wrappedSignatureParameters, [
    signatureHex,
    readBytesHex(hookData, 'hookData'),
  ]);
}

/**
 * `userOp.callData` that makes EntryPoint v0.8 call Calibur's `executeUserOp`,
 * which runs the calls as one `BatchedCall` under the key that signed the
 * user operation. With `revertOnFailure` (the default) one failing call
 * reverts them all.
 * @param {readonly Call[]} calls
 * @param {{ revertOnFailure?: boolean | undefined }} [options]
 * @returns {Hex}
 */
export function encodeExecuteUserOpCallData(calls, options = {}) {
  const { revertOnFailure = true } = options;
  return concat([
    EXECUTE_USER_OP_SELECTOR,
    encodeAbiParameters(
      [batchedCallParameter],
      [{ calls: normalizeCalls(calls), revertOnFailure }]
    ),
  ]);
}

/**
 * @param {Hex} callData
 * @returns {{ calls: { to: Address, value: bigint, data: Hex }[], revertOnFailure: boolean }}
 */
export function decodeExecuteUserOpCallData(callData) {
  if (
    size(callData) < 4 ||
    slice(callData, 0, 4).toLowerCase() !== EXECUTE_USER_OP_SELECTOR
  ) {
    throw new TypeError('The call data does not call executeUserOp');
  }
  const [batchedCall] = decodeAbiParameters(
    [batchedCallParameter],
    slice(callData, 4)
  );
  return {
    calls: batchedCall.calls.map((call) => ({ ...call })),
    revertOnFailure: batchedCall.revertOnFailure,
  };
}

/**
 * The calls that make a key usable on a Calibur account: `register(key)`, then
 * `update(keyHash, settings)` unless the settings are Calibur's defaults
 * (not admin, no expiry, no hook). Both are self-calls, so only the root key or
 * an admin key can make them.
 *
 * An admin key can call the account itself — register and revoke keys, change
 * settings, re-point the EntryPoint — which is what a passkey that replaces
 * the root key needs.
 * @param {{ account: Address, key: Key, settings?: KeySettings | undefined }} parameters
 * @returns {{ to: Address, value: bigint, data: Hex }[]}
 */
export function getRegisterKeyCalls({
  account,
  key,
  settings = { isAdmin: true },
}) {
  const to = readAddress(account, 'account');
  const keyHash = getKeyHash(key);
  const calls = [
    {
      to,
      value: 0n,
      data: encodeFunctionData({
        abi: [registerAbi],
        functionName: 'register',
        args: [key],
      }),
    },
  ];
  const packed = encodeKeySettings(settings);
  if (packed !== 0n) {
    calls.push({
      to,
      value: 0n,
      data: encodeFunctionData({
        abi: [updateAbi],
        functionName: 'update',
        args: [keyHash, packed],
      }),
    });
  }
  return calls;
}

/**
 * `revoke(keyHash)` as a self-call. The root key cannot be revoked.
 * @param {{ account: Address, keyHash: Hex }} parameters
 * @returns {{ to: Address, value: bigint, data: Hex }}
 */
export function getRevokeKeyCall({ account, keyHash }) {
  const hash = readBytes32(keyHash, 'keyHash');
  if (hash === ROOT_KEY_HASH) {
    throw new RangeError('Calibur cannot revoke its root key');
  }
  return {
    to: readAddress(account, 'account'),
    value: 0n,
    data: encodeFunctionData({
      abi: [revokeAbi],
      functionName: 'revoke',
      args: [hash],
    }),
  };
}

/**
 * The EIP-712 typed data `execute(SignedBatchedCall, bytes)` verifies, for a
 * viem `signTypedData`.
 * @param {{
 *   account: Address,
 *   chainId: number,
 *   signedBatchedCall: SignedBatchedCall,
 *   saltPrefix?: bigint | undefined,
 *   implementation?: Address | undefined,
 * }} parameters
 */
export function getSignedBatchedCallTypedData({
  account,
  chainId,
  signedBatchedCall,
  saltPrefix = 0n,
  implementation = CALIBUR_ADDRESS,
}) {
  if (!Number.isSafeInteger(chainId) || chainId < 0) {
    throw new TypeError('chainId must be a non-negative integer');
  }
  if (
    typeof saltPrefix !== 'bigint' ||
    saltPrefix < 0n ||
    saltPrefix >= 1n << 96n
  ) {
    throw new RangeError('saltPrefix must fit in 96 bits');
  }
  const { batchedCall } = signedBatchedCall;
  return /** @type {const} */ ({
    domain: {
      name: 'Calibur',
      version: CALIBUR_VERSION,
      chainId,
      verifyingContract: readAddress(account, 'account'),
      salt: pad(
        numberToHex(
          (saltPrefix << 160n) |
            BigInt(readAddress(implementation, 'implementation'))
        ),
        { size: 32 }
      ),
    },
    types: {
      SignedBatchedCall: [
        { name: 'batchedCall', type: 'BatchedCall' },
        { name: 'nonce', type: 'uint256' },
        { name: 'keyHash', type: 'bytes32' },
        { name: 'executor', type: 'address' },
        { name: 'deadline', type: 'uint256' },
      ],
      BatchedCall: [
        { name: 'calls', type: 'Call[]' },
        { name: 'revertOnFailure', type: 'bool' },
      ],
      Call: [
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'data', type: 'bytes' },
      ],
    },
    primaryType: 'SignedBatchedCall',
    message: {
      batchedCall: {
        calls: normalizeCalls(batchedCall.calls),
        revertOnFailure: batchedCall.revertOnFailure,
      },
      nonce: signedBatchedCall.nonce,
      keyHash: readBytes32(signedBatchedCall.keyHash, 'keyHash'),
      executor: readAddress(signedBatchedCall.executor, 'executor'),
      deadline: signedBatchedCall.deadline,
    },
  });
}

/**
 * Calldata for `execute(SignedBatchedCall, bytes wrappedSignature)`.
 * @param {{ signedBatchedCall: SignedBatchedCall, signature: Hex, hookData?: Hex | undefined }} parameters
 * @returns {Hex}
 */
export function encodeExecuteSignedBatchedCall({
  signedBatchedCall,
  signature,
  hookData = '0x',
}) {
  const { batchedCall } = signedBatchedCall;
  return encodeFunctionData({
    abi: [executeSignedBatchedCallAbi],
    functionName: 'execute',
    args: [
      {
        batchedCall: {
          calls: normalizeCalls(batchedCall.calls),
          revertOnFailure: batchedCall.revertOnFailure,
        },
        nonce: signedBatchedCall.nonce,
        keyHash: readBytes32(signedBatchedCall.keyHash, 'keyHash'),
        executor: readAddress(signedBatchedCall.executor, 'executor'),
        deadline: signedBatchedCall.deadline,
      },
      encodeWrappedSignature({ signature, hookData }),
    ],
  });
}

// In range, s low, and no zero bytes, so the stub costs as much calldata gas
// as a real r and s can.
const STUB_R = BigInt(`0x${'6b'.repeat(32)}`);
const STUB_S = BigInt(`0x${'5a'.repeat(32)}`);
// Chromium sometimes appends this member to clientDataJSON; the stub carries
// it so that estimates cover the longer form.
const CHROMIUM_EXTRA_MEMBER =
  ',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"';

/**
 * A user operation signature for gas estimation: the passkey's key hash and a
 * WebAuthnAuth shaped like a real assertion from `rpId` — 37 bytes of
 * authenticator data with UP and UV set, a client data JSON of the length a
 * browser produces (with Chromium's optional extra member), low-s r and s.
 *
 * validateUserOp returns SIG_VALIDATION_FAILED for it without reverting, as
 * bundlers need. It cannot run the P-256 verification itself — its challenge
 * cannot match a hash that is still being estimated, and webauthn-sol stops at
 * that check — so a real signature needs more verification gas than the stub
 * shows; `toCaliburPasskeyAccount` sets a floor for that.
 * @param {{ keyHash: Hex, rpId?: string | undefined, hookData?: Hex | undefined }} parameters
 * @returns {Hex}
 */
export function getCaliburStubSignature({
  keyHash,
  rpId = 'localhost',
  hookData = '0x',
}) {
  const authenticatorData = concat([
    sha256(stringToBytes(rpId)),
    '0x05', // UP | UV
    '0x00000000',
  ]);
  const challenge = 'A'.repeat(43); // base64url of 32 bytes, unpadded
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${challenge}","origin":"https://${rpId}","crossOrigin":false${CHROMIUM_EXTRA_MEMBER}}`;
  return encodeUserOperationSignature({
    keyHash,
    signature: encodeWebAuthnAuth({
      authenticatorData,
      clientDataJSON,
      challengeIndex: 23,
      typeIndex: 1,
      r: STUB_R,
      s: STUB_S,
    }),
    hookData,
  });
}

/**
 * The root key's stub for gas estimation: a 65-byte ECDSA signature that
 * recovers to no key of the account (the one viem uses for EOA owners).
 * @type {Hex}
 */
export const ROOT_STUB_SIGNATURE =
  '0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c';

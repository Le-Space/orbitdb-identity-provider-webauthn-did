/**
 * Calls in the shape Calibur's `Call` struct needs: `to` checked, `value` and
 * `data` filled in.
 * @param {readonly Call[]} calls
 * @returns {{ to: Address, value: bigint, data: Hex }[]}
 */
export function normalizeCalls(calls: readonly Call[]): {
  to: Address;
  value: bigint;
  data: Hex;
}[];
/**
 * The Calibur key for a passkey: `Key(KeyType.WebAuthnP256, abi.encode(x, y))`.
 * The point must lie on P-256, or no signature could ever verify.
 * @param {P256PublicKey} publicKey
 * @returns {Key}
 */
export function toWebAuthnP256Key(publicKey: P256PublicKey): Key;
/**
 * The hash Calibur stores and looks a key up by (KeyLib.hash).
 * @param {Key} key
 * @returns {Hex}
 */
export function getKeyHash(key: Key): Hex;
/**
 * Pack key settings into the uint256 Calibur's `update(keyHash, settings)`
 * takes.
 * @param {KeySettings} [settings]
 * @returns {bigint}
 */
export function encodeKeySettings(settings?: KeySettings): bigint;
/**
 * @param {bigint} settings
 * @returns {{ isAdmin: boolean, expiration: number, hook: Address }}
 */
export function decodeKeySettings(settings: bigint): {
  isAdmin: boolean;
  expiration: number;
  hook: Address;
};
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
export function encodeWebAuthnAuth(auth: WebAuthnAuth): Hex;
/**
 * @param {Hex} signature `abi.encode(WebAuthn.WebAuthnAuth)`
 * @returns {DecodedWebAuthnAuth}
 */
export function decodeWebAuthnAuth(signature: Hex): DecodedWebAuthnAuth;
/**
 * `userOp.signature` for Calibur: `abi.encode(keyHash, signature, hookData)`.
 * Calibur reverts on a signature shorter than 64 bytes, so this refuses one.
 * @param {{ keyHash: Hex, signature: Hex, hookData?: Hex | undefined }} parameters
 * @returns {Hex}
 */
export function encodeUserOperationSignature({
  keyHash,
  signature,
  hookData,
}: {
  keyHash: Hex;
  signature: Hex;
  hookData?: Hex | undefined;
}): Hex;
/**
 * @param {Hex} wrappedSignature
 * @returns {{ keyHash: Hex, signature: Hex, hookData: Hex }}
 */
export function decodeUserOperationSignature(wrappedSignature: Hex): {
  keyHash: Hex;
  signature: Hex;
  hookData: Hex;
};
/**
 * The `wrappedSignature` of `execute(SignedBatchedCall, bytes)`:
 * `abi.encode(signature, hookData)`.
 * @param {{ signature: Hex, hookData?: Hex | undefined }} parameters
 * @returns {Hex}
 */
export function encodeWrappedSignature({
  signature,
  hookData,
}: {
  signature: Hex;
  hookData?: Hex | undefined;
}): Hex;
/**
 * `userOp.callData` that makes EntryPoint v0.8 call Calibur's `executeUserOp`,
 * which runs the calls as one `BatchedCall` under the key that signed the
 * user operation. With `revertOnFailure` (the default) one failing call
 * reverts them all.
 * @param {readonly Call[]} calls
 * @param {{ revertOnFailure?: boolean | undefined }} [options]
 * @returns {Hex}
 */
export function encodeExecuteUserOpCallData(
  calls: readonly Call[],
  options?: {
    revertOnFailure?: boolean | undefined;
  }
): Hex;
/**
 * @param {Hex} callData
 * @returns {{ calls: { to: Address, value: bigint, data: Hex }[], revertOnFailure: boolean }}
 */
export function decodeExecuteUserOpCallData(callData: Hex): {
  calls: {
    to: Address;
    value: bigint;
    data: Hex;
  }[];
  revertOnFailure: boolean;
};
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
  settings,
}: {
  account: Address;
  key: Key;
  settings?: KeySettings | undefined;
}): {
  to: Address;
  value: bigint;
  data: Hex;
}[];
/**
 * `revoke(keyHash)` as a self-call. The root key cannot be revoked.
 * @param {{ account: Address, keyHash: Hex }} parameters
 * @returns {{ to: Address, value: bigint, data: Hex }}
 */
export function getRevokeKeyCall({
  account,
  keyHash,
}: {
  account: Address;
  keyHash: Hex;
}): {
  to: Address;
  value: bigint;
  data: Hex;
};
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
  saltPrefix,
  implementation,
}: {
  account: Address;
  chainId: number;
  signedBatchedCall: SignedBatchedCall;
  saltPrefix?: bigint | undefined;
  implementation?: Address | undefined;
}): {
  readonly domain: {
    readonly name: 'Calibur';
    readonly version: '1.0.0';
    readonly chainId: number;
    readonly verifyingContract: `0x${string}`;
    readonly salt: `0x${string}`;
  };
  readonly types: {
    readonly SignedBatchedCall: readonly [
      {
        readonly name: 'batchedCall';
        readonly type: 'BatchedCall';
      },
      {
        readonly name: 'nonce';
        readonly type: 'uint256';
      },
      {
        readonly name: 'keyHash';
        readonly type: 'bytes32';
      },
      {
        readonly name: 'executor';
        readonly type: 'address';
      },
      {
        readonly name: 'deadline';
        readonly type: 'uint256';
      },
    ];
    readonly BatchedCall: readonly [
      {
        readonly name: 'calls';
        readonly type: 'Call[]';
      },
      {
        readonly name: 'revertOnFailure';
        readonly type: 'bool';
      },
    ];
    readonly Call: readonly [
      {
        readonly name: 'to';
        readonly type: 'address';
      },
      {
        readonly name: 'value';
        readonly type: 'uint256';
      },
      {
        readonly name: 'data';
        readonly type: 'bytes';
      },
    ];
  };
  readonly primaryType: 'SignedBatchedCall';
  readonly message: {
    readonly batchedCall: {
      readonly calls: {
        to: Address;
        value: bigint;
        data: Hex;
      }[];
      readonly revertOnFailure: boolean;
    };
    readonly nonce: bigint;
    readonly keyHash: `0x${string}`;
    readonly executor: `0x${string}`;
    readonly deadline: bigint;
  };
};
/**
 * Calldata for `execute(SignedBatchedCall, bytes wrappedSignature)`.
 * @param {{ signedBatchedCall: SignedBatchedCall, signature: Hex, hookData?: Hex | undefined }} parameters
 * @returns {Hex}
 */
export function encodeExecuteSignedBatchedCall({
  signedBatchedCall,
  signature,
  hookData,
}: {
  signedBatchedCall: SignedBatchedCall;
  signature: Hex;
  hookData?: Hex | undefined;
}): Hex;
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
  rpId,
  hookData,
}: {
  keyHash: Hex;
  rpId?: string | undefined;
  hookData?: Hex | undefined;
}): Hex;
/** `executeUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32)` */
export const EXECUTE_USER_OP_SELECTOR: `0x${string}`;
/**
 * The root key's stub for gas estimation: a 65-byte ECDSA signature that
 * recovers to no key of the account (the one viem uses for EOA owners).
 * @type {Hex}
 */
export const ROOT_STUB_SIGNATURE: Hex;
export type Address = import('viem').Address;
export type Hex = import('viem').Hex;
/**
 * A call as Calibur's `Call` struct holds it, and as viem passes calls.
 */
export type Call = {
  to: Address;
  value?: bigint | undefined;
  data?: Hex | undefined;
};
/**
 * A Calibur `Key`: its type and its public key, ABI-encoded.
 */
export type Key = {
  keyType: number;
  publicKey: Hex;
};
/**
 * Key settings. `expiration` is a unix timestamp in seconds (0: never);
 * `hook` is a hook contract (the zero address: none).
 */
export type KeySettings = {
  isAdmin?: boolean | undefined;
  expiration?: number | bigint | undefined;
  hook?: Address | undefined;
};
/**
 * A P-256 public key as 32-byte big-endian coordinates, the shape
 * `getP256CredentialDescriptor` returns (a descriptor itself will do).
 */
export type P256PublicKey = {
  x: Uint8Array | Hex | bigint;
  y: Uint8Array | Hex | bigint;
};
/**
 * webauthn-sol's `WebAuthnAuth`, as `signP256Challenge` returns it (byte
 * fields may also be hex, and numbers bigints).
 */
export type WebAuthnAuth = {
  authenticatorData: Uint8Array | Hex;
  clientDataJSON: string;
  challengeIndex: number | bigint;
  typeIndex: number | bigint;
  r: Uint8Array | Hex | bigint;
  s: Uint8Array | Hex | bigint;
};
export type DecodedWebAuthnAuth = {
  authenticatorData: Hex;
  clientDataJSON: string;
  challengeIndex: bigint;
  typeIndex: bigint;
  r: bigint;
  s: bigint;
};
/**
 * Calibur's `SignedBatchedCall`: a batch the root key (or another key) signs
 * for someone else to submit through `execute(SignedBatchedCall, bytes)`.
 */
export type SignedBatchedCall = {
  batchedCall: {
    calls: readonly Call[];
    revertOnFailure: boolean;
  };
  nonce: bigint;
  keyHash: Hex;
  executor: Address;
  deadline: bigint;
};

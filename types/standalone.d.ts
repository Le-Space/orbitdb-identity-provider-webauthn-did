export type WebAuthnAlgorithm = 'Ed25519' | 'P-256';
export type AuthenticatorType = 'platform' | 'cross-platform' | 'any';

export interface ByteArchive {
  id?: string;
  keys?: Record<string, Uint8Array | number[]>;
  [key: string]: unknown;
}

export interface EncryptionResult {
  ciphertext: Uint8Array;
  iv: Uint8Array;
}

export interface WebAuthnVarsigCredential {
  credentialId: Uint8Array | ArrayBuffer | ArrayLike<number>;
  did: string;
  publicKey: Uint8Array;
  algorithm: WebAuthnAlgorithm;
  cose?: unknown;
  /** Relying party id the credential is registered under. */
  rpId?: string;
  [key: string]: unknown;
}

export interface WebAuthnSignerOptions {
  userId?: string;
  displayName?: string;
  /**
   * Which authenticators the browser offers: the device's own, a security key
   * or phone, or every kind. Default `'any'`: the request names none.
   */
  authenticatorType?: AuthenticatorType;
  /** The WebAuthn name for `authenticatorType`; the two must not disagree. */
  authenticatorAttachment?: AuthenticatorAttachment;
  /** Not read: a registration always requires user verification. */
  userVerification?: UserVerificationRequirement;
  forceP256?: boolean;
  domain?: string;
  [key: string]: unknown;
}

export interface UcantoSignerLike {
  sign(payload: Uint8Array): Promise<unknown>;
  did(): string;
  toDIDKey(): string;
  signatureAlgorithm: 'EdDSA' | 'ES256';
  signatureCode: number;
  encode(): Uint8Array;
  toArchive(): { id: string; keys: Record<string, Uint8Array> };
  export(): never;
}

export class StandaloneWebAuthnVarsigSigner {
  credential: WebAuthnVarsigCredential;
  did: string;
  publicKey: Uint8Array;
  algorithm: WebAuthnAlgorithm;
  type: 'webauthn-varsig';

  constructor(credential: WebAuthnVarsigCredential);
  getDid(): string;
  getCredentialId(): Uint8Array;
  sign(data: string | Uint8Array, domainLabel?: string): Promise<Uint8Array>;
  verify(
    signature: Uint8Array,
    data: string | Uint8Array,
    domainLabel?: string
  ): Promise<boolean>;
  toUcantoSigner(options?: { domainLabel?: string }): UcantoSignerLike;
}

export class WebAuthnEd25519Signer extends StandaloneWebAuthnVarsigSigner {
  constructor(
    credentialId: Uint8Array | ArrayBuffer | ArrayLike<number>,
    did: string,
    publicKey: Uint8Array
  );
}

export class WebAuthnP256Signer extends StandaloneWebAuthnVarsigSigner {
  constructor(
    credentialId: Uint8Array | ArrayBuffer | ArrayLike<number>,
    did: string,
    publicKey: Uint8Array
  );
}

export function createWebAuthnSigner(
  options?: WebAuthnSignerOptions
): Promise<StandaloneWebAuthnVarsigSigner>;

export function createWebAuthnEd25519Signer(
  options?: WebAuthnSignerOptions
): Promise<StandaloneWebAuthnVarsigSigner>;

export function createWebAuthnP256Signer(
  options?: WebAuthnSignerOptions
): Promise<StandaloneWebAuthnVarsigSigner>;

/**
 * Rejects when the registration fails — a cancelled prompt, an unknown
 * `authenticatorType`. It never resolved to `null`, though this said it would.
 */
export function createWebAuthnEd25519Credential(
  userId: string,
  displayName: string,
  options?: { authenticatorType?: AuthenticatorType }
): Promise<StandaloneWebAuthnVarsigSigner>;

export function checkEd25519Support(): Promise<boolean>;

export interface WebAuthnHardwareSignerInfo {
  did: string;
  credentialId: Uint8Array;
  publicKey: Uint8Array;
  algorithm: WebAuthnAlgorithm;
  [key: string]: unknown;
}

export class WebAuthnHardwareSignerService {
  constructor(options?: Record<string, unknown>);
}

export function getStoredWebAuthnHardwareSignerInfo(
  key?: string
): WebAuthnHardwareSignerInfo | null;

export function storeWebAuthnCredentialSafe(
  credential: Record<string, unknown>,
  key?: string
): void;

export function loadWebAuthnCredentialSafe(
  key?: string
): Record<string, unknown> | null;

export function clearWebAuthnCredentialSafe(key?: string): void;

export function extractPrfSeedFromCredential(
  credential: Record<string, unknown>,
  options?: {
    rpId?: string;
    prfInput?: Uint8Array;
    discoverableCredentials?: boolean;
  }
): Promise<
  { seed: Uint8Array; source: 'prf' } | { seed: null; source: 'none' }
>;

/** A passkey's P-256 key, as wallet code needs it. */
export interface P256CredentialDescriptor {
  /** Unpadded base64url of `rawCredentialId`. */
  credentialId: string;
  rawCredentialId: Uint8Array;
  /** Public key x coordinate: 32 bytes, big-endian. */
  x: Uint8Array;
  /** Public key y coordinate: 32 bytes, big-endian. */
  y: Uint8Array;
  rpId: string;
  /** `signP256Challenge` always requires user verification. */
  userVerification: 'required';
}

/**
 * An assertion over a 32-byte challenge, in the fields of webauthn-sol's
 * `WebAuthnAuth` (the verifier Uniswap's Calibur uses).
 */
export interface P256ChallengeSignature {
  authenticatorData: Uint8Array;
  clientDataJSON: string;
  /** UTF-8 byte offset of `"challenge":"<base64url(challenge)>"` in `clientDataJSON`. */
  challengeIndex: number;
  /** UTF-8 byte offset of `"type":"webauthn.get"` in `clientDataJSON`. */
  typeIndex: number;
  /** 32 bytes, big-endian. */
  r: Uint8Array;
  /** 32 bytes, big-endian, normalised to low-s (s ≤ n/2). */
  s: Uint8Array;
}

/**
 * Describe a credential's P-256 key, from either `createCredential` path or a
 * stored copy. `null` for RS256 or Ed25519 keys, the placeholder key written
 * when registration could not read the public key, and anything unreadable.
 */
export function getP256CredentialDescriptor(
  credential: unknown
): P256CredentialDescriptor | null;

/**
 * Sign exactly 32 bytes with the descriptor's passkey (`allowCredentials`
 * pinned, user verification required). Rejects an assertion from another
 * credential, and anything that would not verify against `x`/`y`.
 */
export function signP256Challenge(
  descriptor: P256CredentialDescriptor,
  challenge: Uint8Array | ArrayBuffer
): Promise<P256ChallengeSignature>;

export interface WorkerKeystoreClient {
  initWithPrfSeed(prfSeed: Uint8Array): Promise<void>;
  /** Derive the Ed25519 signer from the PRF seed inside the worker; only the public half comes back. */
  deriveSigner(
    prfSeed: Uint8Array
  ): Promise<{ did: string; publicKey: Uint8Array }>;
  generateEd25519Identity(): Promise<{
    did: string;
    publicKey: Uint8Array;
    archive: ByteArchive;
  }>;
  loadArchive(archive: ByteArchive): Promise<void>;
  encrypt(plaintext: Uint8Array): Promise<EncryptionResult>;
  decrypt(ciphertext: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
  sign(data: Uint8Array): Promise<Uint8Array>;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
  encryptArchive(archive: ByteArchive): Promise<EncryptionResult>;
  decryptArchive(ciphertext: Uint8Array, iv: Uint8Array): Promise<ByteArchive>;
  destroy(): void;
}

export interface WorkerKeystoreOptions {
  workerFactory?: () => Worker;
}

export function createWorkerKeystoreClient(
  options?: WorkerKeystoreOptions
): WorkerKeystoreClient;

export function isWorkerKeystoreAvailable(): boolean;

export function createEd25519DidFromPublicKey(
  publicKeyBytes: Uint8Array
): string;

export function getDefaultWorkerKeystoreClient(
  options?: WorkerKeystoreOptions
): WorkerKeystoreClient;

export function resetDefaultWorkerKeystoreClient(): void;

export function initEd25519KeystoreWithPrfSeed(
  prfSeed: Uint8Array,
  options?: WorkerKeystoreOptions
): Promise<void>;

export function generateWorkerEd25519DID(
  options?: WorkerKeystoreOptions
): Promise<{ did: string; publicKey: Uint8Array; archive: ByteArchive }>;

export function loadWorkerEd25519Archive(
  archive: ByteArchive,
  options?: WorkerKeystoreOptions
): Promise<void>;

export function keystoreEncrypt(
  plaintext: Uint8Array,
  options?: WorkerKeystoreOptions
): Promise<EncryptionResult>;

export function keystoreDecrypt(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  options?: WorkerKeystoreOptions
): Promise<Uint8Array>;

export function keystoreSign(
  data: Uint8Array,
  options?: WorkerKeystoreOptions
): Promise<Uint8Array>;

export function keystoreVerify(
  data: Uint8Array,
  signature: Uint8Array,
  options?: WorkerKeystoreOptions
): Promise<boolean>;

export function encryptArchive(
  archive: ByteArchive,
  options?: WorkerKeystoreOptions
): Promise<EncryptionResult>;

export function decryptArchive(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  options?: WorkerKeystoreOptions
): Promise<ByteArchive>;

/** A signer for `createSessionKeystore({ signer })` and the provider's `signer` option; `sign` runs in the worker. */
export function createWorkerSigner(
  client: WorkerKeystoreClient,
  derived: { did: string; publicKey: Uint8Array }
): {
  type: 'Ed25519';
  did: string;
  publicKey: Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
};

/**
 * One read of the passkey's PRF output, and the keys derived from it. Read it
 * once and derive everything from that answer: each read is a touch.
 */
export function readPrfOutput(
  credential: {
    rawCredentialId: Uint8Array | ArrayBuffer | number[];
    /** The input the credential was registered with, if it has its own. */
    prfInput?: Uint8Array;
    [key: string]: unknown;
  },
  options?: {
    /** Defaults to this page's hostname. */
    rpId?: string;
    /** Overrides the credential's input. Never a random one: see the docs. */
    prfInput?: Uint8Array;
  }
): Promise<Uint8Array>;

/** HKDF-SHA-256, empty salt. `info` is part of the data format: version it. */
export function deriveSubkey(
  prfOutput: Uint8Array,
  info: string,
  options?: { /** 1 to 8160 bytes; default 32. */ length?: number }
): Promise<Uint8Array>;

/** A non-extractable AES-GCM-256 key whose material is `deriveSubkey(prfOutput, info)`. */
export function deriveAesKey(
  prfOutput: Uint8Array,
  info: string
): Promise<CryptoKey>;

/**
 * A secret several authenticators can open: a random vault key seals the
 * payload, and each authenticator has a slot holding that key. Plain JSON,
 * nothing secret in the clear.
 */
export interface Vault {
  version: 1;
  algorithm: 'AES-GCM';
  /** 16 random bytes, hex. */
  id: string;
  payload: { iv: string; ciphertext: string };
  slots: Array<{
    /** SHA-256 of the authenticator's raw credential id, hex. */
    kid: string;
    iv: string;
    ciphertext: string;
  }>;
}

/** One authenticator's way into a vault. */
export interface VaultSlotKey {
  /** `deriveAesKey(prfOutput, '<app>/vault-slot/v1')`, or 32 raw bytes. */
  slotKey: CryptoKey | Uint8Array;
  rawCredentialId: Uint8Array;
}

/** A new vault with one slot, for the authenticator that creates it. */
export function createVault(
  payload: Uint8Array,
  firstSlot: VaultSlotKey
): Promise<{ vault: Vault; vaultKey: Uint8Array }>;

/** Throws `VaultError`: `VAULT_NO_SLOT`, `VAULT_LOCKED`, `VAULT_MALFORMED`. */
export function openVault(
  vault: Vault,
  slot: VaultSlotKey
): Promise<{ payload: Uint8Array; vaultKey: Uint8Array }>;

/** A new record with one more slot. Throws `VAULT_SLOT_EXISTS`, `VAULT_LOCKED`. */
export function addSlot(
  vault: Vault,
  vaultKey: Uint8Array,
  slot: VaultSlotKey
): Promise<Vault>;

/**
 * A new record without that authenticator's slot. Revokes nothing already
 * opened. Throws `VAULT_NO_SLOT`, `VAULT_LAST_SLOT`.
 */
export function removeSlot(
  vault: Vault,
  rawCredentialId: Uint8Array
): Promise<Vault>;

/** A new record with a new payload, same key, same slots. Throws `VAULT_LOCKED`. */
export function replacePayload(
  vault: Vault,
  vaultKey: Uint8Array,
  payload: Uint8Array
): Promise<Vault>;

/** The slot id an authenticator is filed under. */
export function slotIdFor(rawCredentialId: Uint8Array): Promise<string>;

/** What a store says in public about one authenticator's slot. */
export interface VaultSlotInfo {
  /** `slotIdFor(rawCredentialId)`. */
  kid: string;
  /** The authenticator's name, as the application gave it. */
  label: string;
  /** The raw credential id, base64url, as WebAuthn writes it. */
  credentialId: string;
  /** ISO 8601. */
  addedAt: string;
  [field: string]: unknown;
}

/** One vault as a keeper stores it. Fields it does not know are kept. */
export interface VaultRecord {
  vault: Vault;
  slots: VaultSlotInfo[];
  /** Slot ids taken out here: refused, never given a new vault. */
  removed: string[];
  [field: string]: unknown;
}

/** An open vault. Holds the vault key: keep it in memory only. */
export interface OpenedVault {
  record: VaultRecord;
  payload: Uint8Array;
  vaultKey: Uint8Array;
  /** The slot id of the authenticator that opened it. */
  kid: string;
  /** Made by this `open`. */
  created: boolean;
  /** Came from `find`, and is kept here now. */
  found: boolean;
}

/** An authenticator's answer: its PRF output, for its credential. */
export interface VaultPasskey {
  prfOutput: Uint8Array;
  rawCredentialId: Uint8Array;
  label?: string;
}

export interface VaultKeeper {
  /** Every record kept, read anew. Throws `VAULT_STORE_UNREADABLE`. */
  records(): VaultRecord[];
  /** Whether a vault here has this authenticator's slot, without asking it. */
  status(
    rawCredentialId: Uint8Array
  ): Promise<{ kid: string; here: boolean; removed: boolean }>;
  /**
   * Open the vault this authenticator has a slot in; else one `find` returns;
   * else a new one holding `create()`. Throws `VAULT_SLOT_REMOVED` for an
   * authenticator removed here, `VAULT_NO_SLOT` without `create`.
   */
  open(
    unlock: VaultPasskey & {
      create?: () => Uint8Array | Promise<Uint8Array>;
      find?: (kid: string) => Promise<VaultRecord | null | undefined>;
    }
  ): Promise<OpenedVault>;
  /** A slot for one more authenticator. Throws `VAULT_SLOT_EXISTS`. */
  addPasskey(opened: OpenedVault, passkey: VaultPasskey): Promise<OpenedVault>;
  /**
   * Take a slot out by its id; refused here from then on. Revokes nothing
   * already opened. Throws `VAULT_SLOT_IN_USE` for the opener's own.
   */
  removePasskey(opened: OpenedVault, kid: string): Promise<OpenedVault>;
  /**
   * A new vault key and id, a slot for every authenticator that stays — each
   * answers — and the same or a new payload.
   */
  renew(
    opened: OpenedVault,
    change: {
      answers: Array<Omit<VaultPasskey, 'label'>>;
      removed?: string[];
      payload?: Uint8Array;
    }
  ): Promise<OpenedVault>;
  /** A new payload, same vault key, same slots. */
  replacePayload(
    opened: OpenedVault,
    payload: Uint8Array
  ): Promise<OpenedVault>;
}

/**
 * Where an application keeps its vaults — anything with `getItem` and
 * `setItem` — and what every unlock does with them. `slotInfo` is part of the
 * data format, e.g. `myapp/vault-slot/v1`.
 */
export function createVaultKeeper(options: {
  storage: Pick<Storage, 'getItem' | 'setItem'>;
  key: string;
  slotInfo: string;
  now?: () => Date;
}): VaultKeeper;

/** A 32-byte root as vault payload: `{"version":1,"root":"<hex>"}`. */
export function rootPayload(root: Uint8Array): Uint8Array;

/** The root a `rootPayload` holds. Throws `VAULT_MALFORMED` for anything else. */
export function rootOf(payload: Uint8Array): Uint8Array;

/**
 * An Ed25519 signer derived from a secret — an identity that is nobody's
 * passkey, e.g. the books every key of their owner writes as. Same secret and
 * `info`, same DID everywhere. Use with `createSessionKeystore({ signer })`
 * and the provider's `signer` option.
 */
export function createSecretSigner(
  secret: Uint8Array,
  options: { info: string }
): Promise<{
  did: string;
  type: 'Ed25519';
  publicKey: Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
}>;

export type VaultErrorCode =
  | 'VAULT_MALFORMED'
  | 'VAULT_NO_SLOT'
  | 'VAULT_LOCKED'
  | 'VAULT_SLOT_EXISTS'
  | 'VAULT_LAST_SLOT'
  | 'VAULT_STORE_UNREADABLE'
  | 'VAULT_SLOT_REMOVED'
  | 'VAULT_SLOT_IN_USE';

/** The authenticator answered without a PRF output; nothing stands in for it. */
export class PrfUnavailableError extends Error {
  code: 'PRF_UNAVAILABLE';
}

/** A vault refused; `code` says why. */
export class VaultError extends Error {
  code: VaultErrorCode;
}

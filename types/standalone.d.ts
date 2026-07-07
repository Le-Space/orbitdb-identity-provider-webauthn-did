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
  [key: string]: unknown;
}

export interface WebAuthnSignerOptions {
  userId?: string;
  displayName?: string;
  authenticatorType?: AuthenticatorType;
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

export function createWebAuthnEd25519Credential(
  userId: string,
  displayName: string,
  options?: { authenticatorType?: AuthenticatorType }
): Promise<StandaloneWebAuthnVarsigSigner | null>;

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
  credential: Record<string, unknown>
): Uint8Array | null;

export interface WorkerKeystoreClient {
  initWithPrfSeed(prfSeed: Uint8Array): Promise<void>;
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

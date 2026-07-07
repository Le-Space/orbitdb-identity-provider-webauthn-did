import type * as VerificationUtils from './verification.d.ts';

export type WebAuthnAlgorithm = 'Ed25519' | 'P-256';
export type KeystoreEncryptionMethod = 'prf' | 'largeBlob' | 'hmac-secret';
export type AuthenticatorType = 'platform' | 'cross-platform' | 'any';

export const ERROR_CODES: Readonly<{
  WEBAUTHN_NOT_SUPPORTED: 'WEBAUTHN_NOT_SUPPORTED';
  WEBAUTHN_CREDENTIAL_CREATE_FAILED: 'WEBAUTHN_CREDENTIAL_CREATE_FAILED';
  WEBAUTHN_AUTHENTICATION_FAILED: 'WEBAUTHN_AUTHENTICATION_FAILED';
  WEBAUTHN_VERIFICATION_FAILED: 'WEBAUTHN_VERIFICATION_FAILED';
  KEYSTORE_ENCRYPTION_FAILED: 'KEYSTORE_ENCRYPTION_FAILED';
  VARSIG_VERIFICATION_FAILED: 'VARSIG_VERIFICATION_FAILED';
  INVALID_INPUT: 'INVALID_INPUT';
}>;

export const IDENTITY_TYPES: Readonly<{
  WEBAUTHN: 'webauthn';
  WEBAUTHN_VARSIG: 'webauthn-varsig';
}>;

export const KEY_TYPES: Readonly<{
  ED25519: 'Ed25519';
  P256: 'P-256';
  SECP256K1: 'secp256k1';
}>;

export const KEYSTORE_ENCRYPTION_METHODS: Readonly<{
  PRF: 'prf';
  LARGE_BLOB: 'largeBlob';
  HMAC_SECRET: 'hmac-secret';
}>;

export const STORAGE_KEYS: Readonly<{
  WEBAUTHN_CREDENTIAL: 'webauthn-credential';
  WEBAUTHN_CREDENTIAL_SAFE: 'webauthn_credential_info';
  WEBAUTHN_VARSIG_CREDENTIAL: 'webauthn-varsig-credential';
  WEBAUTHN_HARDWARE_SIGNER: 'webauthn_ed25519_hardware_signer';
}>;

export const WEBAUTHN_CLIENT_DATA_TYPES: Readonly<{
  GET: 'webauthn.get';
  CREATE: 'webauthn.create';
}>;

export const CRYPTO_ALGORITHMS: Readonly<{
  AES_GCM: 'AES-GCM';
  HKDF: 'HKDF';
  SHA_256: 'SHA-256';
  ED25519: 'Ed25519';
}>;

export const DID_KEY_PREFIX: 'did:key:';

export class WebAuthnIdentityError extends Error {
  code: string;
  cause?: unknown;
  constructor(message: string, options?: { code?: string; cause?: unknown });
}

export class WebAuthnNotSupportedError extends WebAuthnIdentityError {
  constructor(message?: string, options?: { code?: string; cause?: unknown });
}
export class WebAuthnCredentialError extends WebAuthnIdentityError {
  constructor(message: string, options?: { code?: string; cause?: unknown });
}
export class WebAuthnAuthenticationError extends WebAuthnIdentityError {
  constructor(message: string, options?: { code?: string; cause?: unknown });
}
export class WebAuthnVerificationError extends WebAuthnIdentityError {
  constructor(message: string, options?: { code?: string; cause?: unknown });
}
export class KeystoreEncryptionError extends WebAuthnIdentityError {
  constructor(message: string, options?: { code?: string; cause?: unknown });
}
export class VarsigVerificationError extends WebAuthnIdentityError {
  constructor(message: string, options?: { code?: string; cause?: unknown });
}

export interface WebAuthnPublicKey {
  algorithm: number;
  keyType: number | string;
  curve: number | string;
  x: Uint8Array;
  y: Uint8Array;
}

export interface WebAuthnCredentialInfo {
  credentialId: string;
  rawCredentialId: Uint8Array;
  publicKey: WebAuthnPublicKey | Uint8Array;
  userId?: string;
  displayName?: string;
  attestationObject?: Uint8Array;
  prfInput?: Uint8Array;
  did?: string;
  algorithm?: WebAuthnAlgorithm;
  [key: string]: unknown;
}

export interface CreateCredentialOptions {
  userId?: string;
  displayName?: string;
  domain?: string;
  encryptKeystore?: boolean;
  keystoreEncryptionMethod?: KeystoreEncryptionMethod;
  discoverableCredentials?: boolean;
  authenticatorType?: AuthenticatorType;
  authenticatorAttachment?: AuthenticatorAttachment;
  userVerification?: UserVerificationRequirement;
  [key: string]: unknown;
}

export interface WebAuthnConfig {
  discoverableCredentials?: boolean;
  userVerification?: UserVerificationRequirement;
  authenticatorAttachment?: AuthenticatorAttachment;
  residentKey?: ResidentKeyRequirement;
  requireResidentKey?: boolean;
  [key: string]: unknown;
}

export interface WebAuthnSupportStatus {
  supported: boolean;
  platformAuthenticator: boolean;
  error: string | null;
  message: string;
}

export interface LargeBlobPayload {
  type: string;
  version?: number;
  [key: string]: unknown;
}

export interface EncryptionResult {
  ciphertext: Uint8Array;
  iv: Uint8Array;
}

export interface WrappedSecretKey {
  wrappedSK: Uint8Array;
  wrappingIV: Uint8Array;
  salt: Uint8Array;
  prfSource?: string;
}

export interface EncryptedKeystoreData {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  credentialId: string;
  publicKey?: WebAuthnPublicKey | Uint8Array;
  wrappedSK?: Uint8Array;
  wrappingIV?: Uint8Array;
  salt?: Uint8Array;
  encryptionMethod?: KeystoreEncryptionMethod;
  keyType?: string;
  timestamp?: number;
  [key: string]: unknown;
}

export interface ExtensionSupport {
  largeBlob: boolean;
  hmacSecret: boolean;
}

export class WebAuthnDIDProvider {
  credentialId: string;
  publicKey: WebAuthnPublicKey | Uint8Array;
  rawCredentialId: Uint8Array;
  type: 'webauthn';

  constructor(credentialInfo: WebAuthnCredentialInfo);
  static isSupported(): boolean;
  static isPlatformAuthenticatorAvailable(): Promise<boolean>;
  static createCredential(
    options?: CreateCredentialOptions
  ): Promise<WebAuthnCredentialInfo>;
  static extractPublicKey(
    credential: PublicKeyCredential
  ): Promise<WebAuthnPublicKey>;
  static createDID(credentialInfo: WebAuthnCredentialInfo): Promise<string>;
  static arrayBufferToBase64url(buffer: ArrayBuffer | ArrayBufferView): string;
  static base64urlToArrayBuffer(base64url: string): ArrayBuffer;
  sign(data: string | Uint8Array): Promise<string>;
  verify(signatureData: string): Promise<boolean>;
}

export class OrbitDBWebAuthnIdentityProvider {
  constructor(options?: Record<string, unknown>);
  getId(options?: Record<string, unknown>): Promise<string>;
  signIdentity(
    data: string | Uint8Array,
    options?: Record<string, unknown>
  ): Promise<unknown>;
  static verifyIdentity(identity: unknown): Promise<boolean>;
}

export function OrbitDBWebAuthnIdentityProviderFunction(
  options?: Record<string, unknown>
): OrbitDBWebAuthnIdentityProvider;

export function registerWebAuthnProvider(): boolean;

export function checkWebAuthnSupport(): Promise<WebAuthnSupportStatus>;

export function configureWebAuthn(config: WebAuthnConfig): WebAuthnConfig;

export function getWebAuthnConfig(): WebAuthnConfig;

export function resetWebAuthnConfig(): WebAuthnConfig;

export function createDidLargeBlobPayload(
  credentialInfo: WebAuthnCredentialInfo
): LargeBlobPayload;

export function parseDidLargeBlobPayload(
  payload: unknown
): WebAuthnCredentialInfo;

export function createVarsigLargeBlobPayload(
  credentialInfo: WebAuthnCredentialInfo
): LargeBlobPayload;

export function parseVarsigLargeBlobPayload(
  payload: unknown
): WebAuthnCredentialInfo;

export function readLargeBlobMetadata(
  options?: Record<string, unknown>
): Promise<unknown>;

export function writeLargeBlobMetadata(
  credentialId: Uint8Array,
  payload: unknown,
  options?: Record<string, unknown>
): Promise<unknown>;

export function storeWebAuthnCredential(
  credential: WebAuthnCredentialInfo,
  key?: string
): void;

export function loadWebAuthnCredential(
  key?: string
): WebAuthnCredentialInfo | null;

export function clearWebAuthnCredential(key?: string): void;

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

export function generateSecretKey(): Uint8Array;

export function encryptWithAESGCM(
  data: Uint8Array,
  sk: Uint8Array
): Promise<EncryptionResult>;

export function decryptWithAESGCM(
  ciphertext: Uint8Array,
  sk: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array>;

export function addLargeBlobToCredentialOptions<
  T extends Record<string, unknown>,
>(
  credentialOptions: T,
  sk: Uint8Array
): T & { extensions: Record<string, unknown> };

export function addPRFToCredentialOptions<T extends Record<string, unknown>>(
  credentialOptions: T,
  prfInput?: Uint8Array
): {
  credentialOptions: T & { extensions: Record<string, unknown> };
  prfInput: Uint8Array;
};

export function retrieveSKFromLargeBlob(
  credentialId: Uint8Array,
  rpId: string
): Promise<Uint8Array>;

export function addHmacSecretToCredentialOptions<
  T extends Record<string, unknown>,
>(credentialOptions: T): T & { extensions: Record<string, unknown> };

export function wrapSKWithHmacSecret(
  credentialId: Uint8Array,
  sk: Uint8Array,
  rpId: string
): Promise<WrappedSecretKey>;

export function wrapSKWithPRF(
  credentialId: Uint8Array,
  sk: Uint8Array,
  rpId: string,
  prfInput?: Uint8Array
): Promise<WrappedSecretKey>;

export function unwrapSKWithHmacSecret(
  credentialId: Uint8Array,
  wrappedSK: Uint8Array,
  wrappingIV: Uint8Array,
  salt: Uint8Array,
  rpId: string
): Promise<Uint8Array>;

export function unwrapSKWithPRF(
  credentialId: Uint8Array,
  wrappedSK: Uint8Array,
  wrappingIV: Uint8Array,
  salt: Uint8Array,
  rpId: string
): Promise<Uint8Array>;

export function storeEncryptedKeystore(
  data: EncryptedKeystoreData,
  credentialId: string
): Promise<void>;

export function loadEncryptedKeystore(
  credentialId: string
): Promise<EncryptedKeystoreData>;

export function clearEncryptedKeystore(credentialId: string): Promise<void>;

export function checkExtensionSupport(): Promise<ExtensionSupport>;

export class WebAuthnVarsigProvider {
  constructor(credential: Record<string, unknown>);
  sign(data: string | Uint8Array, domainLabel?: string): Promise<Uint8Array>;
  verify(
    signature: Uint8Array,
    publicKey: Uint8Array,
    data: string | Uint8Array,
    domainLabel?: string
  ): Promise<boolean>;
}

export function createWebAuthnVarsigIdentity(
  options?: Record<string, unknown>
): Promise<unknown>;

export function createWebAuthnVarsigIdentities(
  options?: Record<string, unknown>
): Promise<unknown>;

export function encodeIdentityValue(identity: unknown): Uint8Array;
export function decodeVarsigIdentityFromBytes(bytes: Uint8Array): unknown;
export function verifyVarsigIdentity(identity: unknown): Promise<boolean>;
export function createIpfsIdentityStorage(
  options?: Record<string, unknown>
): unknown;
export function wrapWithVarsigVerification(value: unknown): unknown;

export const DEFAULT_DOMAIN_LABELS: Record<string, string>;

export function storeWebAuthnVarsigCredential(
  credential: Record<string, unknown>,
  key?: string
): void;

export function loadWebAuthnVarsigCredential(
  key?: string
): Record<string, unknown> | null;

export function clearWebAuthnVarsigCredential(key?: string): void;

export function isUnsupportedVarsigEnvelopeError(error: unknown): boolean;

export interface VerificationResult {
  success: boolean;
  error?: string | null;
  timestamp: number;
  [key: string]: unknown;
}

export interface DataEntryVerificationOptions<TEntry = unknown> {
  matchFn?: (entryInDatabase: unknown, expectedEntry: TEntry) => boolean;
  checkLog?: boolean;
}

export function verifyDatabaseUpdate(
  database: unknown,
  identityHash: string,
  expectedWebAuthnDID: string
): Promise<VerificationResult>;

export function verifyIdentityStorage(
  identities: unknown,
  identity: { id: string; hash: string; [key: string]: unknown },
  timeoutMs?: number
): Promise<VerificationResult>;

export function verifyDataEntries<TEntry extends { id: string }>(
  database: unknown,
  dataEntries: TEntry[],
  expectedWebAuthnDID: string,
  options?: DataEntryVerificationOptions<TEntry>
): Promise<Map<string, VerificationResult>>;

export function isValidWebAuthnDID(did: string): boolean;

export function extractWebAuthnDIDSuffix(did: string): string | null;

export function compareWebAuthnDIDs(did1: string, did2: string): boolean;

export function createVerificationResult(
  success: boolean,
  details?: Record<string, unknown>
): VerificationResult;

export { VerificationUtils };

declare const defaultExport: {
  WebAuthnDIDProvider: typeof WebAuthnDIDProvider;
  OrbitDBWebAuthnIdentityProvider: typeof OrbitDBWebAuthnIdentityProvider;
  OrbitDBWebAuthnIdentityProviderFunction: typeof OrbitDBWebAuthnIdentityProviderFunction;
  registerWebAuthnProvider: typeof registerWebAuthnProvider;
  checkWebAuthnSupport: typeof checkWebAuthnSupport;
  storeWebAuthnCredential: typeof storeWebAuthnCredential;
  storeWebAuthnCredentialSafe: typeof storeWebAuthnCredentialSafe;
  loadWebAuthnCredentialSafe: typeof loadWebAuthnCredentialSafe;
  clearWebAuthnCredentialSafe: typeof clearWebAuthnCredentialSafe;
  extractPrfSeedFromCredential: typeof extractPrfSeedFromCredential;
  loadWebAuthnCredential: typeof loadWebAuthnCredential;
  clearWebAuthnCredential: typeof clearWebAuthnCredential;
  VerificationUtils: typeof VerificationUtils;
};

export default defaultExport;

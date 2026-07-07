export type KeystoreEncryptionMethod = 'prf' | 'largeBlob' | 'hmac-secret';

export interface WebAuthnPublicKey {
  algorithm: number;
  keyType: number | string;
  curve: number | string;
  x: Uint8Array;
  y: Uint8Array;
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

export interface OrbitDBWebAuthnIdentityProviderOptions {
  webauthnCredential?: Record<string, unknown>;
  keystore?: unknown;
  usePersistentKey?: boolean;
  useKeystoreDID?: boolean;
  keyType?: string;
  keystoreKeyType?: string;
  encryptKeystore?: boolean;
  keystoreEncryptionMethod?: KeystoreEncryptionMethod;
  [key: string]: unknown;
}

export class OrbitDBWebAuthnIdentityProvider {
  constructor(options?: OrbitDBWebAuthnIdentityProviderOptions);
  getId(): Promise<string>;
  signIdentity(
    data: string | Uint8Array,
    options?: Record<string, unknown>
  ): Promise<unknown>;
  static verifyIdentity(identity: unknown): Promise<boolean>;
}

export function OrbitDBWebAuthnIdentityProviderFunction(
  options?: OrbitDBWebAuthnIdentityProviderOptions
): OrbitDBWebAuthnIdentityProvider;

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

declare const defaultExport: {
  generateSecretKey: typeof generateSecretKey;
  encryptWithAESGCM: typeof encryptWithAESGCM;
  decryptWithAESGCM: typeof decryptWithAESGCM;
  addLargeBlobToCredentialOptions: typeof addLargeBlobToCredentialOptions;
  addPRFToCredentialOptions: typeof addPRFToCredentialOptions;
  retrieveSKFromLargeBlob: typeof retrieveSKFromLargeBlob;
  addHmacSecretToCredentialOptions: typeof addHmacSecretToCredentialOptions;
  wrapSKWithHmacSecret: typeof wrapSKWithHmacSecret;
  wrapSKWithPRF: typeof wrapSKWithPRF;
  unwrapSKWithHmacSecret: typeof unwrapSKWithHmacSecret;
  unwrapSKWithPRF: typeof unwrapSKWithPRF;
  storeEncryptedKeystore: typeof storeEncryptedKeystore;
  loadEncryptedKeystore: typeof loadEncryptedKeystore;
  clearEncryptedKeystore: typeof clearEncryptedKeystore;
  checkExtensionSupport: typeof checkExtensionSupport;
};

export default defaultExport;

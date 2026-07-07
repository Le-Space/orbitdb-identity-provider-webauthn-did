export const IDENTITY_TYPES = Object.freeze({
  WEBAUTHN: 'webauthn',
  WEBAUTHN_VARSIG: 'webauthn-varsig',
});

export const KEY_TYPES = Object.freeze({
  ED25519: 'Ed25519',
  P256: 'P-256',
  SECP256K1: 'secp256k1',
});

export const KEYSTORE_ENCRYPTION_METHODS = Object.freeze({
  PRF: 'prf',
  LARGE_BLOB: 'largeBlob',
  HMAC_SECRET: 'hmac-secret',
});

export const STORAGE_KEYS = Object.freeze({
  WEBAUTHN_CREDENTIAL: 'webauthn-credential',
  WEBAUTHN_CREDENTIAL_SAFE: 'webauthn_credential_info',
  WEBAUTHN_VARSIG_CREDENTIAL: 'webauthn-varsig-credential',
  WEBAUTHN_HARDWARE_SIGNER: 'webauthn_ed25519_hardware_signer',
});

export const WEBAUTHN_CLIENT_DATA_TYPES = Object.freeze({
  GET: 'webauthn.get',
  CREATE: 'webauthn.create',
});

export const CRYPTO_ALGORITHMS = Object.freeze({
  AES_GCM: 'AES-GCM',
  HKDF: 'HKDF',
  SHA_256: 'SHA-256',
  ED25519: 'Ed25519',
});

export const DID_KEY_PREFIX = 'did:key:';

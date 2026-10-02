export const ERROR_CODES = Object.freeze({
  WEBAUTHN_NOT_SUPPORTED: 'WEBAUTHN_NOT_SUPPORTED',
  WEBAUTHN_CREDENTIAL_CREATE_FAILED: 'WEBAUTHN_CREDENTIAL_CREATE_FAILED',
  WEBAUTHN_AUTHENTICATION_FAILED: 'WEBAUTHN_AUTHENTICATION_FAILED',
  WEBAUTHN_VERIFICATION_FAILED: 'WEBAUTHN_VERIFICATION_FAILED',
  KEYSTORE_ENCRYPTION_FAILED: 'KEYSTORE_ENCRYPTION_FAILED',
  VARSIG_VERIFICATION_FAILED: 'VARSIG_VERIFICATION_FAILED',
  INVALID_INPUT: 'INVALID_INPUT',
  VAULT_MALFORMED: 'VAULT_MALFORMED',
  VAULT_NO_SLOT: 'VAULT_NO_SLOT',
  VAULT_LOCKED: 'VAULT_LOCKED',
  VAULT_SLOT_EXISTS: 'VAULT_SLOT_EXISTS',
  VAULT_LAST_SLOT: 'VAULT_LAST_SLOT',
});

export class WebAuthnIdentityError extends Error {
  constructor(message, { code = ERROR_CODES.INVALID_INPUT, cause } = {}) {
    super(message);
    this.name = 'WebAuthnIdentityError';
    this.code = code;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

export class WebAuthnNotSupportedError extends WebAuthnIdentityError {
  constructor(
    message = 'WebAuthn is not supported in this browser',
    options = {}
  ) {
    super(message, {
      ...options,
      code: options.code || ERROR_CODES.WEBAUTHN_NOT_SUPPORTED,
    });
    this.name = 'WebAuthnNotSupportedError';
  }
}

export class WebAuthnCredentialError extends WebAuthnIdentityError {
  constructor(message, options = {}) {
    super(message, {
      ...options,
      code: options.code || ERROR_CODES.WEBAUTHN_CREDENTIAL_CREATE_FAILED,
    });
    this.name = 'WebAuthnCredentialError';
  }
}

export class WebAuthnAuthenticationError extends WebAuthnIdentityError {
  constructor(message, options = {}) {
    super(message, {
      ...options,
      code: options.code || ERROR_CODES.WEBAUTHN_AUTHENTICATION_FAILED,
    });
    this.name = 'WebAuthnAuthenticationError';
  }
}

export class WebAuthnVerificationError extends WebAuthnIdentityError {
  constructor(message, options = {}) {
    super(message, {
      ...options,
      code: options.code || ERROR_CODES.WEBAUTHN_VERIFICATION_FAILED,
    });
    this.name = 'WebAuthnVerificationError';
  }
}

export class KeystoreEncryptionError extends WebAuthnIdentityError {
  constructor(message, options = {}) {
    super(message, {
      ...options,
      code: options.code || ERROR_CODES.KEYSTORE_ENCRYPTION_FAILED,
    });
    this.name = 'KeystoreEncryptionError';
  }
}

/**
 * The authenticator produced no PRF output. Nothing else can stand in for
 * it: a key derived from a value anyone can read (the credential id used to
 * be that stand-in) is not a secret, so callers decide what to do without
 * PRF instead of getting a "wrapped" key that is not.
 */
export class PrfUnavailableError extends KeystoreEncryptionError {
  constructor(message = 'PRF output unavailable', options) {
    super(message, options);
    this.name = 'PrfUnavailableError';
    this.code = 'PRF_UNAVAILABLE';
  }
}

/**
 * A vault refused: it is not a vault (`VAULT_MALFORMED`), this authenticator
 * has no slot in it (`VAULT_NO_SLOT`), the key does not open it or it was
 * altered (`VAULT_LOCKED`), the authenticator already has a slot
 * (`VAULT_SLOT_EXISTS`), or the slot is the last one (`VAULT_LAST_SLOT`).
 */
export class VaultError extends KeystoreEncryptionError {
  constructor(message, options = {}) {
    super(message, {
      ...options,
      code: options.code || ERROR_CODES.VAULT_MALFORMED,
    });
    this.name = 'VaultError';
  }
}

export class VarsigVerificationError extends WebAuthnIdentityError {
  constructor(message, options = {}) {
    super(message, {
      ...options,
      code: options.code || ERROR_CODES.VARSIG_VERIFICATION_FAILED,
    });
    this.name = 'VarsigVerificationError';
  }
}

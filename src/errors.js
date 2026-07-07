export const ERROR_CODES = Object.freeze({
  WEBAUTHN_NOT_SUPPORTED: 'WEBAUTHN_NOT_SUPPORTED',
  WEBAUTHN_CREDENTIAL_CREATE_FAILED: 'WEBAUTHN_CREDENTIAL_CREATE_FAILED',
  WEBAUTHN_AUTHENTICATION_FAILED: 'WEBAUTHN_AUTHENTICATION_FAILED',
  WEBAUTHN_VERIFICATION_FAILED: 'WEBAUTHN_VERIFICATION_FAILED',
  KEYSTORE_ENCRYPTION_FAILED: 'KEYSTORE_ENCRYPTION_FAILED',
  VARSIG_VERIFICATION_FAILED: 'VARSIG_VERIFICATION_FAILED',
  INVALID_INPUT: 'INVALID_INPUT',
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

export class VarsigVerificationError extends WebAuthnIdentityError {
  constructor(message, options = {}) {
    super(message, {
      ...options,
      code: options.code || ERROR_CODES.VARSIG_VERIFICATION_FAILED,
    });
    this.name = 'VarsigVerificationError';
  }
}

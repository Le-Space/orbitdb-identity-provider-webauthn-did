const DEFAULT_WEBAUTHN_CONFIG = Object.freeze({
  discoverableCredentials: true,
});

let webauthnConfig = { ...DEFAULT_WEBAUTHN_CONFIG };

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function normalizeWebAuthnConfig(options = {}) {
  const normalized = {};

  if (hasOwn(options, 'discoverableCredentials')) {
    normalized.discoverableCredentials = Boolean(
      options.discoverableCredentials
    );
  }

  return normalized;
}

export function configureWebAuthn(options = {}) {
  webauthnConfig = {
    ...webauthnConfig,
    ...normalizeWebAuthnConfig(options),
  };
  return getWebAuthnConfig();
}

export function resetWebAuthnConfig() {
  webauthnConfig = { ...DEFAULT_WEBAUTHN_CONFIG };
  return getWebAuthnConfig();
}

export function getWebAuthnConfig() {
  return { ...webauthnConfig };
}

export function resolveWebAuthnConfig(options = {}) {
  return {
    ...webauthnConfig,
    ...normalizeWebAuthnConfig(options),
  };
}

export function buildAuthenticatorSelection(options = {}) {
  const {
    discoverableCredentials,
    authenticatorAttachment,
    userVerification = 'required',
  } = resolveWebAuthnConfig(options);

  return {
    ...(authenticatorAttachment ? { authenticatorAttachment } : {}),
    requireResidentKey: discoverableCredentials,
    residentKey: discoverableCredentials ? 'required' : 'discouraged',
    userVerification,
  };
}

export function buildCredentialRequestOptions(options = {}) {
  const {
    rpId,
    challenge,
    userVerification = 'required',
    credentialId,
    mediation,
    extensions,
  } = options;
  const { discoverableCredentials } = resolveWebAuthnConfig(options);

  if (!discoverableCredentials && !credentialId) {
    throw new Error(
      'credentialId is required when discoverableCredentials is disabled'
    );
  }

  const publicKey = {
    challenge,
    ...(rpId ? { rpId } : {}),
    userVerification,
    ...(extensions ? { extensions } : {}),
    ...(!discoverableCredentials && credentialId
      ? {
          allowCredentials: [
            {
              id: credentialId,
              type: 'public-key',
            },
          ],
        }
      : {}),
  };

  return {
    publicKey,
    ...(mediation ? { mediation } : {}),
  };
}

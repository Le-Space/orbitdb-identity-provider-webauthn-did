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

const AUTHENTICATOR_TYPES = ['platform', 'cross-platform', 'any'];
const AUTHENTICATOR_ATTACHMENTS = ['platform', 'cross-platform'];

/**
 * The attachment a registration asks for: `authenticatorType` —
 * `'platform'` (the device's own authenticator), `'cross-platform'` (a
 * security key or a phone) or `'any'` — or its WebAuthn name
 * `authenticatorAttachment`, which has no word for "any".
 *
 * A value this does not know is refused rather than ignored: a typo would
 * otherwise quietly offer every authenticator, or none the caller meant.
 *
 * @param {Object} [options]
 * @param {'platform'|'cross-platform'|'any'} [options.authenticatorType]
 * @param {'platform'|'cross-platform'} [options.authenticatorAttachment]
 * @param {'platform'|'cross-platform'|'any'} [fallback='any'] - When neither
 *   is given.
 * @returns {'platform'|'cross-platform'|undefined} `undefined` for any
 *   authenticator: the request then names none.
 */
export function resolveAuthenticatorAttachment(
  { authenticatorType, authenticatorAttachment } = {},
  fallback = 'any'
) {
  if (
    authenticatorType != null &&
    !AUTHENTICATOR_TYPES.includes(authenticatorType)
  ) {
    throw new TypeError(
      `authenticatorType must be one of ${AUTHENTICATOR_TYPES.join(', ')}, not '${authenticatorType}'`
    );
  }
  if (
    authenticatorAttachment != null &&
    !AUTHENTICATOR_ATTACHMENTS.includes(authenticatorAttachment)
  ) {
    throw new TypeError(
      `authenticatorAttachment must be one of ${AUTHENTICATOR_ATTACHMENTS.join(', ')}, not '${authenticatorAttachment}'`
    );
  }
  if (
    authenticatorType != null &&
    authenticatorAttachment != null &&
    authenticatorType !== authenticatorAttachment
  ) {
    throw new TypeError(
      `authenticatorType '${authenticatorType}' and authenticatorAttachment '${authenticatorAttachment}' disagree; give one`
    );
  }
  const choice = authenticatorType ?? authenticatorAttachment ?? fallback;
  return choice === 'any' ? undefined : choice;
}

/**
 * `authenticatorSelection` for a registration. Only the discoverable-credential
 * policy comes from `options` and `configureWebAuthn`, and user verification is
 * always required; an `authenticatorAttachment` or `userVerification` in
 * `options` is not read. This used to destructure both as if it read them,
 * which is how two registrations came to name values that never reached the
 * browser. A registration that wants an attachment adds it itself — see
 * `resolveAuthenticatorAttachment`.
 */
export function buildAuthenticatorSelection(options = {}) {
  const { discoverableCredentials } = resolveWebAuthnConfig(options);

  return {
    requireResidentKey: discoverableCredentials,
    residentKey: discoverableCredentials ? 'required' : 'discouraged',
    userVerification: 'required',
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

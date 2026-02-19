function ensureUint8Array(value, fieldName) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  if (value && typeof value === 'object') return new Uint8Array(Object.values(value));
  throw new Error(`Invalid ${fieldName}: expected Uint8Array-compatible value`);
}

/**
 * Persist WebAuthn credential info while excluding transient PRF seed material.
 * @param {Object} credential
 * @param {string} [key]
 */
export function storeWebAuthnCredentialSafe(credential, key = 'webauthn_credential_info') {
  if (!credential || typeof credential !== 'object') {
    throw new Error('storeWebAuthnCredentialSafe requires a credential object');
  }

  const rest = { ...credential };
  delete rest.prfSeed;
  localStorage.setItem(key, JSON.stringify(rest));
}

/**
 * Load WebAuthn credential info and normalize known byte fields.
 * @param {string} [key]
 * @returns {Object|null}
 */
export function loadWebAuthnCredentialSafe(key = 'webauthn_credential_info') {
  const raw = localStorage.getItem(key);
  if (!raw) return null;

  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object') return null;

  const normalized = { ...parsed };

  if (normalized.rawCredentialId) {
    normalized.rawCredentialId = ensureUint8Array(normalized.rawCredentialId, 'rawCredentialId');
  }

  if (normalized.prfInput) {
    normalized.prfInput = ensureUint8Array(normalized.prfInput, 'prfInput');
  }

  if (normalized.publicKey && typeof normalized.publicKey === 'object') {
    normalized.publicKey = { ...normalized.publicKey };
    if (normalized.publicKey.x) {
      normalized.publicKey.x = ensureUint8Array(normalized.publicKey.x, 'publicKey.x');
    }
    if (normalized.publicKey.y) {
      normalized.publicKey.y = ensureUint8Array(normalized.publicKey.y, 'publicKey.y');
    }
  }

  return normalized;
}

/**
 * Remove persisted WebAuthn credential info.
 * @param {string} [key]
 */
export function clearWebAuthnCredentialSafe(key = 'webauthn_credential_info') {
  localStorage.removeItem(key);
}

/**
 * Extract PRF seed from a credential via WebAuthn get() with PRF extension.
 * Falls back to rawCredentialId if PRF is unavailable.
 * @param {Object} credential
 * @param {{rpId?: string, prfInput?: Uint8Array}} [options]
 * @returns {Promise<{seed: Uint8Array, source: 'prf'|'credentialId'}>}
 */
export async function extractPrfSeedFromCredential(credential, options = {}) {
  if (!credential || typeof credential !== 'object') {
    throw new Error('extractPrfSeedFromCredential requires a credential object');
  }

  const rawCredentialId = ensureUint8Array(
    credential.rawCredentialId || credential.credentialId,
    'rawCredentialId'
  );
  const rpId = options.rpId || window.location.hostname;
  const prfInput = options.prfInput || credential.prfInput || crypto.getRandomValues(new Uint8Array(32));

  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id: rawCredentialId, type: 'public-key' }],
        rpId,
        userVerification: 'required',
        extensions: {
          prf: {
            eval: { first: prfInput }
          }
        }
      }
    });

    const prfResult = assertion?.getClientExtensionResults?.()?.prf?.results?.first;
    if (prfResult) {
      return { seed: new Uint8Array(prfResult), source: 'prf' };
    }
  } catch {
    // Fall through to credentialId fallback.
  }

  return { seed: rawCredentialId, source: 'credentialId' };
}

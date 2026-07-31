/**
 * @module WebAuthnDebugLog
 * @description
 * Describes a WebAuthn credential or assertion for debugging without putting
 * its contents anywhere.
 *
 * This replaces three copies of a helper that wrote the whole credential to
 * `console` on every `navigator.credentials.create()` and `.get()` —
 * unconditionally, in production code paths. Two reasons that mattered:
 *
 * - `getClientExtensionResults()` was logged verbatim. Since 0.4.1 the PRF
 *   extension is requested on every credential, so that object can carry the
 *   PRF output, which is the material both the keystore encryption and the
 *   OrbitDB signing key are derived from.
 * - `rawId` is a stable per-user, per-RP identifier. Emitting it on every call
 *   put it into any console capture, error reporter or session replay the
 *   embedding app happens to run.
 *
 * What is logged here is shape, not content: byte lengths, presence flags, and
 * which extensions came back. Enough to tell "the authenticator returned no PRF
 * result" from "the assertion never happened", which is what these logs were
 * ever used for.
 *
 * See issue #22.
 */
import { logger } from '@libp2p/logger';

const log = logger('orbitdb-identity-provider-webauthn-did:webauthn');

/**
 * Byte length of an ArrayBuffer or view, or null when absent.
 * @param {ArrayBuffer|ArrayBufferView|null|undefined} value - Buffer-ish value.
 * @returns {number|null} Length in bytes, or null.
 */
function byteLength(value) {
  if (!value) return null;
  if (typeof value.byteLength === 'number') return value.byteLength;
  if (typeof value.length === 'number') return value.length;
  return null;
}

/**
 * Names of the extensions that returned results, without their values.
 *
 * The names alone are diagnostic — they say whether PRF engaged. The values are
 * key material and never belong in a log.
 *
 * @param {PublicKeyCredential} credential - Credential or assertion.
 * @returns {string[]|null} Extension names, or null if unavailable.
 */
function extensionNames(credential) {
  try {
    const results = credential?.getClientExtensionResults?.();
    return results ? Object.keys(results) : null;
  } catch {
    return null;
  }
}

/**
 * Describe a WebAuthn response by shape alone.
 *
 * Every value here is a length, a boolean or an extension name. Nothing
 * derived from credential bytes, and no extension values. Exported so the
 * redaction can be asserted in tests rather than assumed.
 *
 * @param {PublicKeyCredential} credential - Credential or assertion.
 * @returns {Object} Redacted description.
 */
export function describeWebAuthnResponse(credential) {
  const response = credential?.response;

  return {
    type: credential?.type ?? null,
    rawIdBytes: byteLength(credential?.rawId),
    clientDataJSONBytes: byteLength(response?.clientDataJSON),
    // Registration only.
    attestationObjectBytes: byteLength(response?.attestationObject),
    hasGetPublicKey: typeof response?.getPublicKey === 'function',
    // Assertion only.
    authenticatorDataBytes: byteLength(response?.authenticatorData),
    signatureBytes: byteLength(response?.signature),
    hasUserHandle: Boolean(response?.userHandle),
    extensions: extensionNames(credential),
  };
}

/**
 * Log the shape of a WebAuthn response.
 *
 * Goes through the package debug logger, so it is off unless
 * `DEBUG=orbitdb-identity-provider-webauthn-did*` is set, and it never writes
 * credential contents.
 *
 * @param {string} label - What produced the response.
 * @param {PublicKeyCredential} credential - Credential or assertion.
 */
export function logWebAuthnResponse(label, credential) {
  if (!log.enabled) return;
  log('%s returned: %o', label, describeWebAuthnResponse(credential));
}

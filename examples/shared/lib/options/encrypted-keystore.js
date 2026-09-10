/**
 * Option 2 — a keystore DID on a keystore that forgets.
 *
 * The DID is that of an OrbitDB keystore key (Ed25519 by default), and the
 * key stays off disk in one of two ways:
 *
 * - sealed: on the first login the provider derives the key and seals a copy
 *   with the passkey's PRF output (AES-GCM) into localStorage; later logins
 *   unseal it into the session keystore. Without PRF nothing is sealed, and
 *   `provider.encryptionState` says so — there is no fallback.
 * - worker signer: the page hands the PRF output to a Web Worker, which
 *   derives the key and keeps it. The session keystore answers for the
 *   signer's DID with an object that signs in the worker, so the page never
 *   holds the key.
 *
 * Both need `createSessionKeystore()`. OrbitDB's default keystore writes
 * every key to IndexedDB in clear, which made `encryptKeystore` decoration.
 *
 * Suite: tests/ed25519-encrypted-keystore-e2e.test.js
 */
import { Identities, useIdentityProvider } from '@orbitdb/core';
import {
  OrbitDBWebAuthnIdentityProviderFunction,
  createSessionKeystore,
} from '@le-space/orbitdb-identity-provider-webauthn-did';

/**
 * @param {Object} params
 * @param {Object} params.ipfs - Helia, so identities are stored as blocks
 * @param {Object} params.credential - The stored WebAuthn credential
 * @param {boolean} [params.useKeystoreDID] - Keystore DID instead of the
 *   passkey's P-256 one. Off, this is option 1 on a keystore that forgets.
 * @param {'secp256k1'|'Ed25519'} [params.keystoreKeyType]
 * @param {boolean} [params.encryptKeystore] - Seal the key with the passkey
 * @param {'prf'|'largeBlob'|'hmac-secret'} [params.encryptionMethod]
 * @param {Object|null} [params.signer] - From createWorkerSigner(); the
 *   worker then holds the key and the sealing options do not apply
 * @returns {Promise<{identities: Object, identity: Object, keystore: Object, provider: Object}>}
 *   The provider instance is returned for `provider.encryptionState`.
 */
export async function createSessionKeystoreIdentity({
  ipfs,
  credential,
  useKeystoreDID = true,
  keystoreKeyType = 'Ed25519',
  encryptKeystore = true,
  encryptionMethod = 'prf',
  signer = null,
}) {
  useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);

  // One keystore for the identities and for OrbitDB alike.
  const keystore = await createSessionKeystore({
    signer: signer ?? undefined,
  });
  const identities = await Identities({ ipfs, keystore });

  const factory = OrbitDBWebAuthnIdentityProviderFunction({
    webauthnCredential: credential,
    keystore,
    useKeystoreDID: signer ? true : useKeystoreDID,
    keystoreKeyType: signer ? 'Ed25519' : keystoreKeyType,
    encryptKeystore: signer ? false : encryptKeystore,
    keystoreEncryptionMethod: encryptionMethod,
    signer,
  });

  // OrbitDB keeps the provider instance to itself; the factory is wrapped to
  // catch it, because `encryptionState` lives on it.
  let provider = null;
  const identity = await identities.createIdentity({
    provider: async () => {
      provider = await factory();
      return provider;
    },
  });

  return { identities, identity, keystore, provider };
}

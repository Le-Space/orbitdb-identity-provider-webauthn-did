/**
 * OrbitDB's verified-identity cache keyed by the wrong thing, worked around.
 *
 * `Identities.verifyIdentity` (@orbitdb/core 4) remembers a verified identity
 * under `signatures.id` and, on a hit, answers `isEqual(identity, cached)`.
 * With this provider the PRF-derived signing key gives the *same*
 * `signatures.id` in every session of a passkey, while `signatures.publicKey`
 * — the WebAuthn assertion that binds the key to the DID — is new per session.
 * So once one session's identity is in the cache, every other session of the
 * same passkey is refused: "Could not append entry: Key … is not allowed to
 * write to the log". Whichever session's entries are verified first owns the
 * cache: after a join (a restore from backup), after a sync (a peer that held
 * the list), or simply the browser's own earlier entries coming back.
 *
 * Seen in Le-Space/belege's restore (belege#259) and in simple-todo's
 * archived01 (a phone restoring a laptop's archive, Le-Space/simple-todo#79).
 * Upstream: orbitdb/orbitdb#1258. The right fix is a cache keyed by identity
 * hash; until OrbitDB has it, this is the provider's own answer, so that no
 * application has to carry a copy.
 *
 * Where OrbitDB says no, an identity of this provider is checked again the way
 * an uncached one would be: the shape (`isIdentity`), the id signature over
 * the public key (`identities.verify`), and this provider's binding of the key
 * to the DID (`verifyIdentity`, the check GHSA-326j-4cc3-4rrg added). Other
 * providers' identities, and anything that fails those checks, stay refused.
 */
import { OrbitDBWebAuthnIdentityProviderFunction } from './provider.js';

/**
 * OrbitDB's own shape check (`identities/identity.js`, `isIdentity`), kept
 * here rather than imported: this file is reachable from the `./keystore`
 * entry, which does not load `@orbitdb/core` at import time — the peer
 * dependency is the application's, and @orbitdb/core 4.0.0 cannot even be
 * imported from a bare install (it uses `it-drain` without declaring it).
 *
 * @param {any} identity
 */
function isIdentity(identity) {
  return Boolean(
    identity &&
    identity.id &&
    identity.hash &&
    identity.bytes &&
    identity.publicKey &&
    identity.signatures &&
    identity.signatures.id &&
    identity.signatures.publicKey &&
    identity.type
  );
}

/**
 * Wrap an `Identities` instance so that another session of the same passkey
 * is verified rather than refused. Idempotent in effect; wrapping twice only
 * checks twice.
 *
 * @template {{ verifyIdentity: (identity: any) => Promise<boolean>, verify: (signature: string, publicKey: string, data: string) => Promise<boolean> }} T
 * @param {T} identities - from `Identities(...)` (or `createIdentities` below)
 * @returns {T} the same instance, its `verifyIdentity` replaced
 */
export function withoutStaleIdentityCache(identities) {
  if (
    !identities ||
    typeof identities.verifyIdentity !== 'function' ||
    typeof identities.verify !== 'function'
  ) {
    throw new TypeError(
      'withoutStaleIdentityCache needs an OrbitDB Identities instance (verifyIdentity, verify)'
    );
  }
  const cached = identities.verifyIdentity;
  identities.verifyIdentity = async (identity) => {
    if (await cached(identity)) return true;
    if (
      !isIdentity(identity) ||
      identity.type !== OrbitDBWebAuthnIdentityProviderFunction.type
    ) {
      return false;
    }
    const { id, publicKey, signatures } = identity;
    if (!(await identities.verify(signatures.id, publicKey, id))) return false;
    return OrbitDBWebAuthnIdentityProviderFunction.verifyIdentity(identity);
  };
  return identities;
}

/**
 * `Identities(options)` from @orbitdb/core, already wrapped: what an
 * application that builds identities for a passkey should call. The peer
 * dependency is loaded when this is called, not when the module is.
 *
 * @param {Record<string, unknown>} [options] - `{ ipfs, keystore, storage, path }`, as OrbitDB takes them
 */
export async function createIdentities(options) {
  const { Identities } = await import('@orbitdb/core');
  return withoutStaleIdentityCache(await Identities(options));
}

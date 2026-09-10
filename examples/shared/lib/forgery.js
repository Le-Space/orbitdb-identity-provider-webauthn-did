/**
 * Two forgeries the verifier must refuse, so a demo can show that it does.
 *
 * Nothing here talks to a peer. Both checks run against the same code a
 * peer would run on an entry it received, which is the point: a green badge
 * only means something if the same verifier turns red on a forgery.
 */
import { KeyStore, MemoryStorage } from '@orbitdb/core';
import { signMessage } from '@orbitdb/core/src/key-store.js';

import { verifyEntry } from './verification.js';

const toHex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * Take a genuine entry, change its text, and verify it.
 *
 * The signature covers the payload, so the changed entry must fail the
 * signature check — for a keystore signature and a varsig alike.
 *
 * @returns {Promise<{rejected: boolean, result: Object, text: string}|null>}
 *   null when the database is empty.
 */
export async function tamperedEntryRejected({ database, identities }) {
  let first = null;
  for await (const item of database.iterator({ amount: 1 })) {
    first = item;
    break;
  }
  if (!first) return null;
  const entry = await database.log.get(first.hash);
  const text = `${entry.payload?.value?.text ?? ''} (edited by nobody)`;
  const tampered = {
    ...entry,
    payload: {
      ...entry.payload,
      value: { ...(entry.payload?.value ?? {}), text },
    },
  };
  const result = await verifyEntry({
    entry: tampered,
    identities,
    access: database.access,
  });
  return { rejected: result.checks.signature === false, result, text };
}

/**
 * Build an identity that claims the owner's DID but holds only a key of its
 * own, and ask the verifier.
 *
 * Up to 0.5.1 the answer was "yes" for any `webauthn` identity whose id
 * looked like a DID (GHSA-326j-4cc3-4rrg); for varsig identities the id was
 * never compared with the key until 0.5.3.
 *
 * @param {Object} params
 * @param {Object} params.identities - The database's identities object.
 * @param {Object} params.identity - The owner's identity, whose DID is claimed.
 * @returns {Promise<{rejected: boolean, claimed: string}>}
 */
export async function impostorRejected({ identities, identity }) {
  let forged;
  if (identity.type === 'webauthn-varsig') {
    // A varsig identity carries raw key bytes; a random key with junk
    // signatures is what an attacker without the passkey can produce.
    forged = {
      id: identity.id,
      type: identity.type,
      publicKey: crypto.getRandomValues(new Uint8Array(32)),
      signatures: {
        id: crypto.getRandomValues(new Uint8Array(64)),
        publicKey: crypto.getRandomValues(new Uint8Array(64)),
      },
    };
  } else {
    // A keystore identity: a real key of the attacker's own, signing the
    // victim's DID, so OrbitDB's own consistency check (`signatures.id`
    // against `publicKey`) passes and only the provider's binding can refuse.
    const keystore = await KeyStore({ storage: await MemoryStorage() });
    try {
      const key = await keystore.createKey('impostor');
      forged = {
        id: identity.id,
        type: identity.type,
        publicKey: toHex(key.publicKey.raw),
        signatures: {
          id: await signMessage(key, identity.id),
          publicKey: 'not-a-proof',
        },
      };
    } finally {
      await keystore.close();
    }
  }
  let accepted;
  try {
    accepted = await identities.verifyIdentity(forged);
  } catch {
    accepted = false;
  }
  return { rejected: accepted !== true, claimed: identity.id };
}

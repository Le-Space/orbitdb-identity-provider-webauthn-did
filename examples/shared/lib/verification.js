/**
 * What "Verified" has to mean before a demo may say it.
 *
 * The badge these demos used to show compared the database's identity with
 * itself — the same object on both sides — and reported "passed" whenever
 * anything threw. It never looked at an entry's signature or at who wrote
 * it. This does, with the same three checks OrbitDB's access controller
 * makes when it decides whether to accept an entry from a peer, plus one
 * the controller leaves to the log:
 *
 *   signature    — `entry.sig` is a valid signature over the entry by
 *                  `entry.key`, the writer's public key (Entry.verify)
 *   binding      — the identity document the entry names carries that same
 *                  public key
 *   identity     — that document verifies: for a passkey identity, the
 *                  WebAuthn assertion binds the key to the DID (0.5.2+); for
 *                  a keystore DID, the DID is the key; for varsig, both
 *                  signatures come from the key the DID encodes
 *   writeAccess  — the writer's DID is in the database's write list
 *
 * All local: the identity block is in the blockstore because this peer
 * either created it or received it with the entry.
 */
import { Entry } from '@orbitdb/core';

const toHex = (value) =>
  value instanceof Uint8Array
    ? Array.from(value, (b) => b.toString(16).padStart(2, '0')).join('')
    : String(value ?? '');

/**
 * @param {Object} params
 * @param {Object} params.entry - A log entry (`database.log.get(hash)`).
 * @param {Object} params.identities - The identities object the database was
 *   opened with; it knows how to verify this identity type.
 * @param {Object} [params.access] - The database's access controller.
 * @returns {Promise<{ok: boolean, writer: string|null, entryHash: string,
 *   identityHash: string|null, checks: Record<string, boolean|null>,
 *   error: string|null, at: number}>}
 */
export async function verifyEntry({ entry, identities, access }) {
  const checks = {
    signature: null,
    binding: null,
    identity: null,
    writeAccess: null,
  };
  let writer = null;
  let error = null;

  try {
    checks.signature = await Entry.verify(identities, entry);
  } catch (e) {
    checks.signature = false;
    error = e.message;
  }

  try {
    const identity = await identities.getIdentity(entry.identity);
    if (!identity) {
      checks.binding = checks.identity = checks.writeAccess = false;
      error ??= 'identity block not found';
    } else {
      writer = identity.id;
      checks.binding = toHex(identity.publicKey) === toHex(entry.key);
      checks.identity = await identities.verifyIdentity(identity);
      const write = access?.write ?? [];
      checks.writeAccess = write.includes('*') || write.includes(identity.id);
    }
  } catch (e) {
    checks.binding ??= false;
    checks.identity ??= false;
    checks.writeAccess ??= false;
    error ??= e.message;
  }

  return {
    ok: Object.values(checks).every((c) => c === true),
    writer,
    entryHash: entry.hash,
    identityHash: entry.identity ?? null,
    checks,
    error,
    at: Date.now(),
  };
}

/**
 * Verify the entry behind every current key of a key-value database.
 *
 * @param {Object} params
 * @param {Object} params.database - An open OrbitDB key-value database.
 * @param {Object} params.identities - As for `verifyEntry`.
 * @returns {Promise<{byKey: Map<string, Object>, all: boolean}>} One result
 *   per key, and whether every one of them passed.
 */
export async function verifyDatabase({ database, identities }) {
  const byKey = new Map();
  for await (const { key, hash } of database.iterator()) {
    const entry = await database.log.get(hash);
    byKey.set(
      key,
      entry
        ? await verifyEntry({ entry, identities, access: database.access })
        : {
            ok: false,
            writer: null,
            entryHash: hash,
            identityHash: null,
            checks: {},
            error: 'entry not in log',
            at: Date.now(),
          }
    );
  }
  return { byKey, all: [...byKey.values()].every((r) => r.ok) };
}

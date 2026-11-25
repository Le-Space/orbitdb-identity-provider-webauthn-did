# WebAuthn DID and OrbitDB Identity

Which DID an identity has, which key signs its entries, how a peer checks
that the two belong together, and how the DID relates to the identity hash.

## Two Identity Values

1. **DID**: Deterministic identifier from your WebAuthn, keystore or signer public key
2. **Identity Hash**: IPFS CID of the complete identity object in database entries

## DID Creation

### WebAuthn P-256 DID

```javascript
// Example: did:key with P-256 public key (multicodec 0x1200)
'did:key:zDnaerx9CtfPpYYn5FcfKUfCAdgUcBhXM94YX9PidT23cRgRe';
```

### Ed25519/secp256k1 Keystore DID

```javascript
// Example: did:key with Ed25519 public key (multicodec 0xed)
'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
```

DIDs are deterministic - always the same for the same credential/keystore.

### Signer DID

With the provider's `signer` option the identity is an Ed25519 key that signs
elsewhere, and the DID is that key's `did:key` (multicodec 0xed, as above):

- **Worker signer** — `createWorkerSigner(client, await client.deriveSigner(prfOutput))`.
  The Web Worker derives the key from the passkey's PRF output with HKDF and
  keeps it; the page gets the public key and a `sign()` that asks the worker.
  The same PRF output gives the same key every session.
- **Secret signer** — `createSecretSigner(secret, { info })`. The key is
  derived with HKDF-SHA-256 from at least 32 bytes of secret under `info`, and
  stays inside `sign()`. The same secret and `info` give the same DID on every
  device, whichever passkey opened the vault the secret is kept in; no passkey
  stands behind it.

OrbitDB gets the keystore from `createSessionKeystore({ signer })`, which
answers `getKey(did)` with an object whose `sign()` calls the signer, so no
private key enters the keystore.

## Which Key Signs the Entries

OrbitDB signs every entry with the key its keystore returns for the identity's
`id`. Which key that is depends on the option:

| DID                         | Key in the keystore under the DID                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------------- |
| Passkey P-256 (the default) | a key derived from the passkey's PRF output: secp256k1, or Ed25519 with `signingKeyType: 'Ed25519'` |
| Keystore DID                | the key the DID encodes                                                                             |
| Signer DID                  | a stand-in with the public key the DID encodes, whose `sign()` calls the signer                     |

On the default path the provider seeds the keystore before OrbitDB asks for
the key. It reads the passkey's PRF output (or takes the `prfOutput` the
application already read) and derives the key with HKDF-SHA-256, the DID mixed
into the info string. The same passkey therefore gives the same signing key,
and the same identity document, on every device. A key already in the keystore
for the DID is never replaced. Without PRF, OrbitDB generates a random
secp256k1 key, which stays on that device. The derived key sits in OrbitDB's
keystore unencrypted; `encryptKeystore` does not cover it.

## Identity Object

OrbitDB wraps your DID in an identity object:

```javascript
{
  id: 'did:key:zDnaerx9CtfPpYYn5FcfKUfCAdgUcBhXM94YX9PidT23cRgRe',
  type: 'webauthn',
  publicKey: '02a1b2…', // hex: the signing key from the keystore, not the passkey's
  signatures: {
    id: '3044022…', // the signing key over `id`
    publicKey: 'eyJjcmVk…' // over `publicKey + signatures.id`, see below
  }
}
```

`signatures.publicKey` is a WebAuthn assertion of the passkey for a passkey
DID and a keystore DID; it is made once and stored, so the document stays the
same from session to session. With a signer it is the signer's own signature,
and no passkey is asked.

## Identity Hash

The identity object is CBOR-encoded, hashed (SHA-256), and stored in IPFS:

```javascript
// Example: IPFS CID of identity object
'zdpuAseKQt3ZanUES4jJmPsvzV1ARNdnaMFRaetR7X3S6MLKH';
```

## Relationship

Database events show the identity hash:

```javascript
{
  address: {
    identity: 'zdpuAseKQt3ZanUES4jJmPsvzV1ARNdnaMFRaetR7X3S6MLKH';
  }
}
```

Your identity shows the DID:

```javascript
{
  id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
}
```

**These are the same identity.** The identity hash is the IPFS CID of the object containing your DID.

## What a Peer Checks

OrbitDB first checks `signatures.id` against `publicKey`, which any key
passes for itself. Whether that key may speak for the DID is decided by the
provider's `verifyIdentity` (`verifyWebAuthnIdentityBinding` in
`src/webauthn/proof-verification.js`), by the DID's multicodec:

- **P-256 (0x1200), the passkey DID.** `signatures.publicKey` must be a
  WebAuthn assertion by the key the DID encodes, over
  `publicKey + signatures.id`. That binds the derived signing key to the
  passkey.
- **Ed25519 (0xed) or secp256k1 (0xe7) — keystore DIDs and signers.** The
  keystore-DID rule: `publicKey` must be exactly the key the DID encodes.
  OrbitDB has already checked that this key signed the `id`, so
  `signatures.publicKey` is not read. A worker signer and a secret signer
  pass by construction.
- Any other DID is refused.

Each entry is then verified against the identity's `publicKey`. Varsig
identities (`type: 'webauthn-varsig'`) are checked by `verifyVarsigIdentity`
instead: both signatures are varsigs of the passkey, against the key the DID
encodes.

## Checking an Identity Hash

```javascript
import * as Block from 'multiformats/block';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { CID } from 'multiformats/cid';
import { base58btc } from 'multiformats/bases/base58';

async function verifyIdentityRelationship(ipfs, identityHash, expectedDID) {
  const cid = CID.parse(identityHash, base58btc);
  const bytes = await ipfs.blockstore.get(cid);
  const { value } = await Block.decode({
    bytes,
    codec: dagCbor,
    hasher: sha256,
  });

  return value.id === expectedDID;
}
```

## Security

- **Integrity**: Identity hash ensures object hasn't been tampered with
- **Determinism**: DID is always the same for the same credential/keystore
- **Verification**: Oplog entries can be verified against expected DID
- **Access Control**: Efficient permission checks using identity hash

## Debugging

- Log both DID and identity hash
- Use verification function to check correspondence
- Ensure IPFS connectivity
- Verify identity object signatures

## Usage Examples

### Database Event Handler

```javascript
database.events.on('update', async (address, entry) => {
  const isValid = await verifyIdentityRelationship(
    ipfs,
    address.identity,
    expectedDID
  );
});
```

### Access Controller

```javascript
const canAppend = async (entry) => {
  const writerIdentity = await identities.getIdentity(entry.identity);
  return allowedDIDs.includes(writerIdentity.id);
};
```

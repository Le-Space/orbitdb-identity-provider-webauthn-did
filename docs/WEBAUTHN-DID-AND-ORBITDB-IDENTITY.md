# WebAuthn DID and OrbitDB Identity

Explains the relationship between DIDs and OrbitDB identity hashes.

## Two Identity Values

1. **DID**: Deterministic identifier from your WebAuthn or keystore public key
2. **Identity Hash**: IPFS CID of the complete identity object in database entries

## DID Creation

### WebAuthn P-256 DID

```javascript
// Example: did:key with P-256 public key (multicodec 0x1200)
"did:key:zDnaerx9CtfPpYYn5FcfKUfCAdgUcBhXM94YX9PidT23cRgRe"
```

### Ed25519/secp256k1 Keystore DID

```javascript
// Example: did:key with Ed25519 public key (multicodec 0xed)
"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
```

DIDs are deterministic - always the same for the same credential/keystore.

## Identity Object

OrbitDB wraps your DID in an identity object:

```javascript
{
  id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  type: 'webauthn',
  publicKey: { /* public key bytes */ },
  signatures: {
    id: '3044022...',
    publicKey: '3045022...'
  }
}
```

## Identity Hash

The identity object is CBOR-encoded, hashed (SHA-256), and stored in IPFS:

```javascript
// Example: IPFS CID of identity object
"zdpuAseKQt3ZanUES4jJmPsvzV1ARNdnaMFRaetR7X3S6MLKH"
```

## Relationship

Database events show the identity hash:

```javascript
{
  address: {
    identity: "zdpuAseKQt3ZanUES4jJmPsvzV1ARNdnaMFRaetR7X3S6MLKH"
  }
}
```

Your identity shows the DID:

```javascript
{
  id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
}
```

**These are the same identity.** The identity hash is the IPFS CID of the object containing your DID.

## Verification

```javascript
import * as Block from 'multiformats/block'
import * as dagCbor from '@ipld/dag-cbor'
import { sha256 } from 'multiformats/hashes/sha2'
import { CID } from 'multiformats/cid'
import { base58btc } from 'multiformats/bases/base58'

async function verifyIdentityRelationship(ipfs, identityHash, expectedDID) {
  const cid = CID.parse(identityHash, base58btc);
  const bytes = await ipfs.blockstore.get(cid);
  const { value } = await Block.decode({ bytes, codec: dagCbor, hasher: sha256 });
  
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

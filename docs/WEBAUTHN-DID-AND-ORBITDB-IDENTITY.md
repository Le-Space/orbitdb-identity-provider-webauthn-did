# WebAuthn DID and OrbitDB Identity Hash Relationship

This document explains the important relationship between WebAuthn DIDs created by this identity provider and the identity hashes that appear in OrbitDB oplog entries.

## Overview

When using the WebAuthn Identity Provider with OrbitDB, there are **two different but related identity values** that you'll encounter:

1. **WebAuthn DID**: The deterministic identifier created from your WebAuthn public key
2. **OrbitDB Identity Hash**: The IPFS hash of the complete identity object used in database entries

## The Relationship

### WebAuthn DID Creation

Your WebAuthn identity provider creates a DID like this:

```javascript
// Example WebAuthn DID
"did:webauthn:f63abbd8d467f1d42d4e14168844568c"
```

This DID is **deterministic** - it's always the same for the same WebAuthn credential because it's derived from the public key coordinates:

```javascript
static createDID(credentialInfo) {
  const pubKey = credentialInfo.publicKey;
  const xHex = Array.from(pubKey.x)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  const yHex = Array.from(pubKey.y)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  const didSuffix = (xHex + yHex).slice(0, 32);
  return `did:webauthn:${didSuffix}`;
}
```

### OrbitDB Identity Object Creation

OrbitDB then wraps your WebAuthn DID in a complete identity object:

```javascript
{
  id: 'did:webauthn:f63abbd8d467f1d42d4e14168844568c',
  type: 'webauthn',
  publicKey: {
    algorithm: -7,
    x: Uint8Array([...]),
    y: Uint8Array([...]),
    keyType: 2,
    curve: 1
  },
  signatures: {
    id: '3044022...',      // Signature of the DID
    publicKey: '3045022...' // Signature of the public key
  }
}
```

### OrbitDB Identity Hash Creation

This complete identity object is then:

1. **Encoded using CBOR** (Concise Binary Object Representation)
2. **Hashed using SHA-256**
3. **Stored in IPFS** with a CID (Content Identifier)
4. **Used in oplog entries** for access control and verification

```javascript
// Example OrbitDB Identity Hash (IPFS CID)
"zdpuAseKQt3ZanUES4jJmPsvzV1ARNdnaMFRaetR7X3S6MLKH"
```

## Real-World Example

When you see a database update event like this:

```javascript
{
  address: {
    identity: "zdpuAseKQt3ZanUES4jJmPsvzV1ARNdnaMFRaetR7X3S6MLKH",
    // ... other fields
  }
}
```

And your identity shows:

```javascript
{
  identityId: 'did:webauthn:f63abbd8d467f1d42d4e14168844568c'
}
```

**These are the same identity!** The relationship is:

- **`zdpuAseKQt3ZanUES4jJmPsvzV1ARNdnaMFRaetR7X3S6MLKH`** = IPFS hash of the identity object
- **`did:webauthn:f63abbd8d467f1d42d4e14168844568c`** = The actual WebAuthn DID inside that object

## Verification Process

To verify this relationship, you can:

1. **Fetch the identity object** from IPFS using the hash
2. **Extract the DID** from the `id` field
3. **Compare it** with your WebAuthn DID

```javascript
import * as Block from 'multiformats/block'
import * as dagCbor from '@ipld/dag-cbor'
import { sha256 } from 'multiformats/hashes/sha2'
import { CID } from 'multiformats/cid'
import { base58btc } from 'multiformats/bases/base58'

async function verifyIdentityRelationship(ipfs, identityHash, expectedWebAuthnDID) {
  try {
    // Parse the identity hash as a CID
    const cid = CID.parse(identityHash, base58btc);
    
    // Fetch the identity object from IPFS
    const bytes = await ipfs.blockstore.get(cid);
    
    // Decode the CBOR-encoded identity object
    const { value } = await Block.decode({ 
      bytes, 
      codec: dagCbor, 
      hasher: sha256 
    });
    
    // Extract the DID from the identity object
    const actualDID = value.id;
    
    // Verify the relationship
    const matches = actualDID === expectedWebAuthnDID;
    
    console.log('Identity Verification:', {
      identityHash,
      expectedWebAuthnDID,
      actualDID,
      matches,
      identityType: value.type,
      hasPublicKey: !!value.publicKey,
      hasSignatures: !!value.signatures
    });
    
    return matches;
    
  } catch (error) {
    console.error('Identity verification failed:', error);
    return false;
  }
}
```

## Security Implications

This dual-identity system provides several security benefits:

1. **Integrity**: The OrbitDB identity hash ensures the complete identity object hasn't been tampered with
2. **Determinism**: The WebAuthn DID is always the same for the same credential
3. **Verification**: You can always verify that an oplog entry came from the expected WebAuthn credential
4. **Access Control**: OrbitDB can efficiently check permissions using the identity hash

## Debugging Tips

When debugging identity-related issues:

1. **Always log both values**: The WebAuthn DID and OrbitDB identity hash
2. **Use the verification function**: Check that they correspond to the same identity
3. **Check IPFS connectivity**: Identity verification requires IPFS access
4. **Verify signatures**: Ensure the identity object signatures are valid

## Common Patterns

### In Database Event Handlers

```javascript
database.events.on('update', async (address, entry) => {
  const identityHash = address.identity;
  const isValid = await verifyIdentityRelationship(
    ipfs, 
    identityHash, 
    orbitdbInstances.identity.id
  );
  
  if (!isValid) {
    console.warn('Identity verification failed for database update!');
  }
});
```

### In Access Controllers

```javascript
const canAppend = async (entry) => {
  const writerIdentity = await identities.getIdentity(entry.identity);
  
  // The writerIdentity.id will be the WebAuthn DID
  console.log('Writer WebAuthn DID:', writerIdentity.id);
  console.log('Entry Identity Hash:', entry.identity);
  
  return allowedDIDs.includes(writerIdentity.id);
};
```

## Summary

Understanding this relationship is crucial for:
- **Debugging**: Knowing which identity value corresponds to what
- **Security**: Properly verifying the source of database operations
- **Development**: Building robust access control and verification systems

The key takeaway: **WebAuthn DID** is your identity, **OrbitDB Identity Hash** is how OrbitDB stores and references that identity in the distributed system.
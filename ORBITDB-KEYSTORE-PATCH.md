# OrbitDB Keystore Patch

## Overview
This project patches `@orbitdb/core` to enable Ed25519 key generation in addition to the hardcoded secp256k1 default. The patch allows our `keystoreKeyType` parameter to function correctly.

## What Changed
**File**: `node_modules/@orbitdb/core/src/key-store.js`  
**Function**: `createKey(id, type = 'secp256k1')`  
**Version**: `@orbitdb/core@3.0.2`

### Before
```javascript
const createKey = async (id) => {
  if (!id) {
    throw new Error('id needed to create a key')
  }
  const keyPair = await generateKeyPair('secp256k1')
  // ...
}
```

### After
```javascript
const createKey = async (id, type = 'secp256k1') => {
  if (!id) {
    throw new Error('id needed to create a key')
  }
  
  // Validate key type
  const validTypes = ['Ed25519', 'secp256k1', 'RSA', 'ECDSA']
  if (!validTypes.includes(type)) {
    throw new Error(`Invalid key type: ${type}. Supported types: ${validTypes.join(', ')}`)
  }
  
  const keyPair = await generateKeyPair(type)
  // ...
}
```

## Why This Patch Is Needed
OrbitDB's keystore hardcoded `'secp256k1'` as the only key type, preventing the creation of Ed25519 keys. However:
- **libp2p/crypto already supports Ed25519**: The underlying `@libp2p/crypto` library has full Ed25519 support via `generateKeyPair('Ed25519')`
- **Our feature requires it**: The `keystoreKeyType` parameter in `OrbitDBWebAuthnIdentityProvider` needs to pass the key type to the keystore
- **Ed25519 benefits**: Smaller keys (32 bytes), faster signatures, and cleaner DID format (`did:key:z6Mk...` vs `did:key:zQ3sh...`)

## How It Works
The patch is managed by [patch-package](https://github.com/ds300/patch-package):

1. **Installation**: `npm install` automatically runs `patch-package` via the `postinstall` script
2. **Patch file**: `patches/@orbitdb+core+3.0.2.patch` contains the diff
3. **Application**: The patch is applied to `node_modules/@orbitdb/core/src/key-store.js` after every npm install

## Affected Projects
This patch must be applied in **two locations**:
1. **Root project**: `/patches/@orbitdb+core+3.0.2.patch` + `postinstall` script in root `package.json`
2. **Demo**: `/examples/ed25519-encrypted-keystore-demo/patches/@orbitdb+core+3.0.2.patch` + `postinstall` script in demo `package.json`

Both locations have their own `node_modules/@orbitdb/core` installation.

## Maintenance

### If OrbitDB Updates
If you update `@orbitdb/core` to a newer version:

1. Check if the new version supports key type parameter natively:
   ```javascript
   // Test in node:
   const keystore = await KeyStore()
   await keystore.createKey('test-id', 'Ed25519') // Does this work?
   ```

2. If native support exists, **remove the patch**:
   - Delete `patches/@orbitdb+core+*.patch`
   - Remove `postinstall` script from `package.json`
   - Remove `patch-package` from `devDependencies`

3. If still needed, **regenerate the patch**:
   ```bash
   # Manually edit node_modules/@orbitdb/core/src/key-store.js
   npx patch-package @orbitdb/core
   
   # Copy to demo
   cp patches/@orbitdb+core+*.patch examples/ed25519-encrypted-keystore-demo/patches/
   ```

### Updating the Patch
To modify the patch:
1. Edit `node_modules/@orbitdb/core/src/key-store.js` manually
2. Run `npx patch-package @orbitdb/core`
3. Copy updated patch to demo: `cp patches/@orbitdb+core+*.patch examples/ed25519-encrypted-keystore-demo/patches/`
4. Test: `npm run test:encrypted-keystore`

## Verification
To verify the patch is working:

```bash
npm run test:encrypted-keystore
```

Look for:
- ✅ **Ed25519 DID format**: `did:key:z6Mk...` (not `did:key:zQ3sh...`)
- ✅ **Console logs**: `Created WebAuthn identity: {id: did:key:z6Mk...`
- ✅ **Test assertion**: "Ed25519 DID format (z6Mk): FOUND"

## Upstream Contribution
This patch should be contributed back to OrbitDB:
- **Repository**: https://github.com/orbitdb/orbitdb
- **Issue**: Can create issue via `npx patch-package @orbitdb/core --create-issue`
- **PR**: Submit PR adding optional `type` parameter to `createKey()`

Benefits for upstream:
- Enables all libp2p-supported key types (Ed25519, RSA, ECDSA)
- Backward compatible (defaults to secp256k1)
- Minimal change (8 lines)
- No breaking changes

## Technical Details

### Key Types Supported
- **Ed25519**: Modern, fast, 32-byte keys → `did:key:z6Mk...`
- **secp256k1**: Bitcoin/Ethereum compatible, 33/65-byte keys → `did:key:zQ3sh...`
- **RSA**: Traditional, larger keys
- **ECDSA**: Generic elliptic curve

### DID Format Changes
With Ed25519:
```
Before: did:key:zQ3shc7L8KKX8okkSWezbkMWc4mT8tMXquawChREDDFmsX7Gw (secp256k1)
After:  did:key:z6MkkqzxTKH8kqZ1hPqyKj1BvXz9xqZqz... (Ed25519)
```

### Usage in Code
```javascript
const provider = OrbitDBWebAuthnIdentityProviderFunction({
  webauthnCredential: credential,
  useKeystoreDID: true,
  keystore: orbitdb.keystore,
  keystoreKeyType: 'Ed25519', // ← This now works!
  encryptKeystore: true,
  keystoreEncryptionMethod: 'hmac-secret'
})
```

## Related Files
- **Patch**: `patches/@orbitdb+core+3.0.2.patch`
- **Implementation**: `src/index.js:512,521,572` (keystoreKeyType parameter)
- **Demo UI**: `examples/ed25519-encrypted-keystore-demo/src/lib/WebAuthnTodo.svelte:52,508-532`
- **Tests**: `tests/ed25519-encrypted-keystore-e2e.test.js`
- **Plan**: `.planosaurus/plans/a4d0954e-db1e-4c1d-b4c1-13a9c05f45e7.md`

## License
Same as OrbitDB: MIT

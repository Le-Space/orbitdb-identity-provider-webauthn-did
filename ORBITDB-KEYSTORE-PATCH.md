# OrbitDB Keystore Patch

This project no longer patches `@orbitdb/core`.

OrbitDB 4.0.0 still hardcodes `keystore.createKey()` to `secp256k1`, so the WebAuthn provider now avoids that method for typed keys. When `keystoreKeyType` requests Ed25519, the provider generates the libp2p key itself with `generateKeyPair('Ed25519')` and stores it via OrbitDB's public `keystore.addKey()` API.

The old `patch-package` files for `@orbitdb/core@3.0.2` were removed during the OrbitDB 4 / libp2p 3 / Helia 7 upgrade.

Verification command used during the migration:

```bash
node --input-type=module -e "import KeyStore from './node_modules/@orbitdb/core/src/key-store.js'; import { generateKeyPair } from '@libp2p/crypto/keys'; const storage = new Map(); const keystore = await KeyStore({ storage: { put: async (k, v) => storage.set(k, v), get: async (k) => storage.get(k), del: async (k) => storage.delete(k), close: async () => {}, clear: async () => storage.clear() } }); const key = await generateKeyPair('Ed25519'); await keystore.addKey('ed25519-smoke', { privateKey: key.raw }); const stored = await keystore.getKey('ed25519-smoke'); console.log('keystore smoke', stored.type, stored.publicKey.raw.length); await keystore.close();"
```

Expected output:

```text
keystore smoke Ed25519 32
```

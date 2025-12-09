/**
 * Example: Using WebAuthn-Protected Secret Key with @orbitdb/simple-encryption
 * 
 * This demonstrates how to use the WebAuthn-encrypted keystore's secret key
 * to encrypt OrbitDB database content using @orbitdb/simple-encryption.
 * 
 * Benefits:
 * - Single biometric prompt protects both keystore AND database content
 * - Content-level encryption for sensitive data
 * - Hardware-backed encryption key
 */

import { createOrbitDB } from '@orbitdb/core';
import { createHelia } from 'helia';
import { SimpleEncryption } from '@orbitdb/simple-encryption';
import { 
  OrbitDBWebAuthnIdentityProviderFunction,
  generateSecretKey,
  retrieveSKFromLargeBlob,
  unwrapSKWithHmacSecret,
  loadEncryptedKeystore
} from 'orbitdb-identity-provider-webauthn-did';

/**
 * Convert 32-byte secret key to base64 string for use with SimpleEncryption
 */
function secretKeyToPassword(sk) {
  return btoa(String.fromCharCode(...sk));
}

/**
 * Setup: Create encrypted keystore with WebAuthn
 */
async function setupWithEncryptedKeystore(credential, orbitdb) {
  console.log('🔐 Setting up WebAuthn-encrypted keystore...');

  // Generate secret key (32 bytes)
  const sk = generateSecretKey();
  
  // Create identity with encrypted keystore
  const identity = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: credential,
      useKeystoreDID: true,
      keystoreKeyType: 'Ed25519',
      keystore: orbitdb.keystore,
      encryptKeystore: true,
      keystoreEncryptionMethod: 'largeBlob', // or 'hmac-secret'
      secretKey: sk  // Provide the SK for encryption
    })
  });

  console.log('✅ Identity created with encrypted keystore');
  console.log('🆔 DID:', identity.id);

  // Convert SK to password for SimpleEncryption
  const password = secretKeyToPassword(sk);

  // Create encryption instances for database
  const dataEncryption = await SimpleEncryption({ password });
  const replicationEncryption = await SimpleEncryption({ password });
  
  const encryption = {
    data: dataEncryption,
    replication: replicationEncryption
  };

  // Open encrypted database
  const db = await orbitdb.open('my-encrypted-db', {
    type: 'keyvalue',
    AccessController: orbitdb.access.IPFSAccessController({ write: [identity.id] }),
    encryption  // Both keystore AND content are now encrypted!
  });

  console.log('✅ Database opened with content encryption');
  console.log('📊 Database address:', db.address);

  // Store some sensitive data
  await db.put('secret', 'This content is encrypted with WebAuthn-protected key');
  
  return { identity, db, sk };
}

/**
 * Later: Unlock and access encrypted database
 */
async function unlockAndAccessDatabase(credential, orbitdb, dbAddress) {
  console.log('🔓 Unlocking encrypted keystore with WebAuthn...');

  // Load the encrypted keystore metadata
  const encryptedData = await loadEncryptedKeystore(credential.id);
  
  // Retrieve the secret key using WebAuthn (ONE biometric prompt)
  let sk;
  if (encryptedData.encryptionMethod === 'largeBlob') {
    sk = await retrieveSKFromLargeBlob(
      credential.rawId,
      window.location.hostname
    );
  } else {
    sk = await unwrapSKWithHmacSecret(
      credential.rawId,
      encryptedData.wrappedSK,
      encryptedData.wrappingIV,
      encryptedData.salt,
      window.location.hostname
    );
  }

  console.log('✅ Secret key retrieved from WebAuthn');

  // Create identity (keystore will be decrypted automatically)
  const identity = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({
      webauthnCredential: credential,
      useKeystoreDID: true,
      keystoreKeyType: 'Ed25519',
      keystore: orbitdb.keystore,
      encryptKeystore: true,
      keystoreEncryptionMethod: encryptedData.encryptionMethod,
      secretKey: sk
    })
  });

  console.log('✅ Identity unlocked:', identity.id);

  // Use the SAME secret key for database content decryption
  const password = secretKeyToPassword(sk);
  
  const dataEncryption = await SimpleEncryption({ password });
  const replicationEncryption = await SimpleEncryption({ password });
  
  const encryption = {
    data: dataEncryption,
    replication: replicationEncryption
  };

  // Open the encrypted database
  const db = await orbitdb.open(dbAddress, { encryption });

  console.log('✅ Database opened with decryption');

  // Read encrypted data
  const value = await db.get('secret');
  console.log('📖 Decrypted value:', value);

  return { identity, db };
}

/**
 * Complete example
 */
async function main() {
  // Setup Helia and OrbitDB
  const ipfs = await createHelia();
  const orbitdb = await createOrbitDB({ ipfs });

  // 1. Create WebAuthn credential (first time)
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'My App', id: window.location.hostname },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: 'user@example.com',
        displayName: 'User'
      },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required'
      },
      timeout: 60000
    }
  });

  console.log('✅ WebAuthn credential created');

  // 2. Setup encrypted keystore and database
  const { db, sk } = await setupWithEncryptedKeystore(credential, orbitdb);

  // Add more data
  await db.put('api-key', 'sk-secret-123456');
  await db.put('private-note', 'This is my private note');

  console.log('\n📊 All data in database:', await db.all());

  // Close database
  await db.close();

  // 3. Later: Unlock with biometric and access encrypted data
  console.log('\n🔄 Simulating app restart...\n');

  const { db: unlockedDb } = await unlockAndAccessDatabase(
    credential,
    orbitdb,
    db.address
  );

  console.log('\n📊 Decrypted data:', await unlockedDb.all());

  // Cleanup
  await unlockedDb.close();
  await orbitdb.stop();
  await ipfs.stop();
}

// Run if this is the main module
if (typeof window !== 'undefined') {
  // Browser environment
  window.runSimpleEncryptionExample = main;
  console.log('Run: window.runSimpleEncryptionExample()');
} else {
  // Node environment - just export
  console.log('This example is meant to run in a browser with WebAuthn support');
}

export { setupWithEncryptedKeystore, unlockAndAccessDatabase };

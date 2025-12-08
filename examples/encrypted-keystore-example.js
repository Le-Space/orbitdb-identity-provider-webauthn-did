/**
 * Example: Using WebAuthn-Encrypted Keystore
 * 
 * This example demonstrates how to use the encrypted keystore feature
 * to protect OrbitDB private keys with WebAuthn hardware security.
 * 
 * Features demonstrated:
 * - Creating encrypted keystores with largeBlob extension
 * - Creating encrypted keystores with hmac-secret extension
 * - Unlocking keystores with biometric authentication
 * - Using Ed25519 DID from encrypted keystore
 * - Session management and keystore lifecycle
 */

import { createOrbitDB } from '@orbitdb/core';
import { createHelia } from 'helia';
import { 
  WebAuthnDIDProvider, 
  OrbitDBWebAuthnIdentityProviderFunction,
  KeystoreEncryption
} from '../src/index.js';

// ============================================================================
// Example 1: Basic Encrypted Keystore (largeBlob)
// ============================================================================

async function exampleBasicEncryptedKeystore() {
  console.log('=== Example 1: Basic Encrypted Keystore (largeBlob) ===\n');

  // Step 1: Create WebAuthn credential
  console.log('Step 1: Creating WebAuthn credential...');
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'alice@example.com',
    displayName: 'Alice',
    encryptKeystore: true,              // Enable encryption
    keystoreEncryptionMethod: 'largeBlob'
  });
  console.log('✅ WebAuthn credential created\n');

  // Step 2: Initialize OrbitDB
  console.log('Step 2: Initializing OrbitDB...');
  const ipfs = await createHelia({ /* config */ });
  const orbitdb = await createOrbitDB({ ipfs });
  console.log('✅ OrbitDB initialized\n');

  // Step 3: Create identity with encrypted keystore
  console.log('Step 3: Creating identity with encrypted keystore...');
  const identity = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential,
      useKeystoreDID: true,              // Use Ed25519 DID from keystore
      keystore: orbitdb.keystore,
      encryptKeystore: true,             // 🔐 Enable keystore encryption
      keystoreEncryptionMethod: 'largeBlob'  // Use largeBlob extension
    })
  });
  console.log(`✅ Identity created with encrypted keystore`);
  console.log(`   DID: ${identity.id.substring(0, 40)}...\n`);

  console.log('Benefits:');
  console.log('- 🔐 Keystore private key encrypted with AES-GCM');
  console.log('- 🔑 Secret key (SK) stored in WebAuthn authenticator');
  console.log('- 🛡️ Protected from XSS, malicious extensions, device theft');
  console.log('- 👆 One biometric prompt per session\n');

  return { orbitdb, identity };
}

// ============================================================================
// Example 2: Encrypted Keystore with hmac-secret
// ============================================================================

async function exampleHmacSecretEncryption() {
  console.log('=== Example 2: Encrypted Keystore (hmac-secret) ===\n');

  // Step 1: Create credential with hmac-secret
  console.log('Step 1: Creating WebAuthn credential with hmac-secret...');
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'bob@example.com',
    displayName: 'Bob',
    encryptKeystore: true,
    keystoreEncryptionMethod: 'hmac-secret'  // Use hmac-secret instead
  });
  console.log('✅ WebAuthn credential created\n');

  // Step 2: Initialize OrbitDB
  const ipfs = await createHelia({ /* config */ });
  const orbitdb = await createOrbitDB({ ipfs });

  // Step 3: Create identity with hmac-secret encryption
  console.log('Step 2: Creating identity with hmac-secret encryption...');
  const identity = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential,
      useKeystoreDID: true,
      keystore: orbitdb.keystore,
      encryptKeystore: true,
      keystoreEncryptionMethod: 'hmac-secret'
    })
  });
  console.log(`✅ Identity created`);
  console.log(`   DID: ${identity.id.substring(0, 40)}...\n`);

  console.log('Benefits of hmac-secret:');
  console.log('- 🌐 Broader browser support (Chrome, Firefox, Edge)');
  console.log('- 🔄 Deterministic key unwrapping');
  console.log('- 🔐 Secret key wrapped, not stored directly\n');

  return { orbitdb, identity };
}

// ============================================================================
// Example 3: Complete Workflow with Encrypted Keystore
// ============================================================================

async function exampleCompleteWorkflow() {
  console.log('=== Example 3: Complete Workflow with Encrypted Keystore ===\n');

  // SESSION START
  console.log('=== SESSION START ===\n');

  // Step 1: Create WebAuthn credential
  console.log('Step 1: Creating WebAuthn credential...');
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'carol@example.com',
    displayName: 'Carol'
  });
  console.log('✅ WebAuthn credential created (🔐 biometric prompt)\n');

  // Step 2: Initialize OrbitDB
  console.log('Step 2: Initializing OrbitDB...');
  const ipfs = await createHelia({ /* config */ });
  const orbitdb = await createOrbitDB({ ipfs });
  console.log('✅ OrbitDB initialized\n');

  // Step 3: Create encrypted identity
  console.log('Step 3: Creating identity with encrypted keystore...');
  const identity = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential,
      useKeystoreDID: true,
      keystore: orbitdb.keystore,
      encryptKeystore: true,
      keystoreEncryptionMethod: 'largeBlob'
    })
  });
  console.log('✅ Identity created and keystore encrypted\n');
  console.log('   📝 Behind the scenes:');
  console.log('   - Generated Ed25519 keypair');
  console.log('   - Generated random AES-GCM secret key (SK)');
  console.log('   - Encrypted private key with SK');
  console.log('   - Stored SK in WebAuthn authenticator');
  console.log('   - Stored ciphertext in localStorage\n');

  // Step 4: Open database
  console.log('Step 4: Opening database...');
  const db = await orbitdb.open('encrypted-database', {
    type: 'documents',
    identity: identity
  });
  console.log('✅ Database opened\n');

  // Step 5: Perform operations (no additional prompts!)
  console.log('Step 5: Performing database operations...');
  await db.put({ _id: 'item1', name: 'First Item', encrypted: true });
  await db.put({ _id: 'item2', name: 'Second Item', encrypted: true });
  await db.put({ _id: 'item3', name: 'Third Item', encrypted: true });
  console.log('✅ Added 3 items (no biometric prompts - using unlocked keystore)\n');

  // Step 6: Verify data
  console.log('Step 6: Verifying data...');
  const items = await db.all();
  console.log(`✅ Retrieved ${items.length} items from database\n`);

  // SESSION END
  console.log('=== SESSION END ===\n');
  console.log('When session ends:');
  console.log('- Keystore locked automatically');
  console.log('- Unlocked keypair cleared from memory');
  console.log('- Only encrypted ciphertext remains in storage');
  console.log('- Next session requires biometric authentication to unlock\n');

  return { orbitdb, identity, db };
}

// ============================================================================
// Example 4: Session Management and Re-authentication
// ============================================================================

async function exampleSessionManagement() {
  console.log('=== Example 4: Session Management ===\n');

  // FIRST SESSION
  console.log('--- First Session ---\n');

  // Create and setup encrypted keystore
  const credential1 = await WebAuthnDIDProvider.createCredential({
    userId: 'dave@example.com',
    displayName: 'Dave'
  });
  console.log('✅ First session: Credential created (🔐 biometric prompt)\n');

  const ipfs1 = await createHelia({ /* config */ });
  const orbitdb1 = await createOrbitDB({ ipfs: ipfs1 });

  const identity1 = await orbitdb1.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential1,
      useKeystoreDID: true,
      keystore: orbitdb1.keystore,
      encryptKeystore: true,
      keystoreEncryptionMethod: 'largeBlob'
    })
  });
  console.log('✅ First session: Identity created with encrypted keystore');
  console.log(`   DID: ${identity1.id.substring(0, 40)}...\n`);

  // Use the database
  const db1 = await orbitdb1.open('my-database', { type: 'documents', identity: identity1 });
  await db1.put({ _id: 'session1-item', data: 'Created in first session' });
  console.log('✅ First session: Database operations completed\n');

  // End first session
  console.log('First session ended. Keystore locked.\n');

  // SECOND SESSION (reload/restart)
  console.log('--- Second Session (After Reload) ---\n');

  // Load stored credential
  const storedCredential = loadWebAuthnCredential(); // Load from localStorage
  console.log('✅ Second session: Loaded credential from storage\n');

  // Re-initialize OrbitDB
  const ipfs2 = await createHelia({ /* config */ });
  const orbitdb2 = await createOrbitDB({ ipfs: ipfs2 });

  // Re-create identity (will unlock keystore with biometric)
  console.log('Unlocking keystore... (🔐 biometric prompt)\n');
  const identity2 = await orbitdb2.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: storedCredential,
      useKeystoreDID: true,
      keystore: orbitdb2.keystore,
      encryptKeystore: true,
      keystoreEncryptionMethod: 'largeBlob'
    })
  });
  console.log('✅ Second session: Keystore unlocked with biometric authentication');
  console.log(`   DID: ${identity2.id.substring(0, 40)}... (same as first session)\n`);

  // Continue using the database
  const db2 = await orbitdb2.open('my-database', { type: 'documents', identity: identity2 });
  const items = await db2.all();
  console.log(`✅ Second session: Retrieved ${items.length} items from previous session\n`);

  console.log('Summary:');
  console.log('- Same DID across sessions (persistent identity)');
  console.log('- Keystore remains encrypted between sessions');
  console.log('- One biometric prompt per session to unlock');
  console.log('- All data accessible after re-authentication\n');
}

// ============================================================================
// Example 5: Checking Extension Support
// ============================================================================

async function exampleCheckSupport() {
  console.log('=== Example 5: Checking Extension Support ===\n');

  const support = await KeystoreEncryption.checkExtensionSupport();

  console.log('Browser Support:');
  console.log(`- largeBlob:   ${support.largeBlob ? '✅ Supported' : '❌ Not Supported'}`);
  console.log(`- hmac-secret: ${support.hmacSecret ? '✅ Supported' : '❌ Not Supported'}\n`);

  // Choose encryption method based on support
  let encryptionMethod;
  if (support.largeBlob) {
    encryptionMethod = 'largeBlob';
    console.log('✅ Using largeBlob (preferred method)\n');
  } else if (support.hmacSecret) {
    encryptionMethod = 'hmac-secret';
    console.log('✅ Using hmac-secret (fallback method)\n');
  } else {
    console.log('❌ No encryption extensions supported\n');
    console.log('Falling back to unencrypted keystore');
    console.log('⚠️ Consider upgrading browser or using hardware security key\n');
    return null;
  }

  // Create identity with supported method
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'auto-detect@example.com',
    displayName: 'Auto Detect User',
    encryptKeystore: true,
    keystoreEncryptionMethod: encryptionMethod
  });

  console.log(`✅ Created credential with ${encryptionMethod} encryption\n`);

  return { encryptionMethod, credential };
}

// ============================================================================
// Example 6: Comparison - Encrypted vs Unencrypted
// ============================================================================

async function exampleComparison() {
  console.log('=== Example 6: Comparison - Encrypted vs Unencrypted ===\n');

  // UNENCRYPTED (Current Default)
  console.log('--- Without Encryption (Default) ---\n');
  
  const credential1 = await WebAuthnDIDProvider.createCredential({
    userId: 'unencrypted@example.com',
    displayName: 'Unencrypted User'
  });

  const ipfs1 = await createHelia({ /* config */ });
  const orbitdb1 = await createOrbitDB({ ipfs: ipfs1 });

  const identity1 = await orbitdb1.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential1,
      useKeystoreDID: true,
      keystore: orbitdb1.keystore
      // encryptKeystore: false (default)
    })
  });

  console.log('❌ Keystore stored in plaintext');
  console.log('❌ Vulnerable to XSS attacks');
  console.log('❌ Vulnerable to malicious extensions');
  console.log('❌ Vulnerable if IndexedDB copied\n');

  // ENCRYPTED
  console.log('--- With Encryption (New Feature) ---\n');

  const credential2 = await WebAuthnDIDProvider.createCredential({
    userId: 'encrypted@example.com',
    displayName: 'Encrypted User',
    encryptKeystore: true,
    keystoreEncryptionMethod: 'largeBlob'
  });

  const ipfs2 = await createHelia({ /* config */ });
  const orbitdb2 = await createOrbitDB({ ipfs: ipfs2 });

  const identity2 = await orbitdb2.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential2,
      useKeystoreDID: true,
      keystore: orbitdb2.keystore,
      encryptKeystore: true,               // ✅ Enable encryption
      keystoreEncryptionMethod: 'largeBlob'
    })
  });

  console.log('✅ Keystore encrypted with AES-GCM 256-bit');
  console.log('✅ Protected from XSS (SK not in memory)');
  console.log('✅ Protected from extensions (SK in hardware)');
  console.log('✅ IndexedDB theft useless (ciphertext only)');
  console.log('✅ Biometric required to unlock\n');

  console.log('Recommendation: Always use encryption for production applications!\n');
}

// ============================================================================
// Main execution
// ============================================================================

async function main() {
  console.log('\n' + '='.repeat(80));
  console.log('WebAuthn-Encrypted Keystore Examples');
  console.log('='.repeat(80) + '\n');

  try {
    // Run examples
    // await exampleBasicEncryptedKeystore();
    // await exampleHmacSecretEncryption();
    // await exampleCompleteWorkflow();
    // await exampleSessionManagement();
    await exampleCheckSupport();
    // await exampleComparison();

    console.log('='.repeat(80));
    console.log('All examples completed successfully!');
    console.log('='.repeat(80) + '\n');

  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export {
  exampleBasicEncryptedKeystore,
  exampleHmacSecretEncryption,
  exampleCompleteWorkflow,
  exampleSessionManagement,
  exampleCheckSupport,
  exampleComparison
};

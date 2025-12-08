/**
 * Example: Using Ed25519 DID from OrbitDB Keystore
 * 
 * This example demonstrates how to use the `useKeystoreDID` flag to create
 * an Ed25519 DID from the OrbitDB keystore instead of a P-256 DID from WebAuthn.
 * 
 * This is useful when you want:
 * - Better UCAN compatibility with Ed25519
 * - The DID to be derived from the keystore that signs database operations
 * - WebAuthn only for authentication, not DID generation
 */

import { createOrbitDB } from '@orbitdb/core';
import { createHelia } from 'helia';
import { createLibp2p } from 'libp2p';
import { 
  WebAuthnDIDProvider, 
  OrbitDBWebAuthnIdentityProviderFunction 
} from '../src/index.js';

// ============================================================================
// Example 1: Default behavior (P-256 DID from WebAuthn)
// ============================================================================

async function exampleDefaultP256DID() {
  console.log('=== Example 1: Default P-256 DID from WebAuthn ===\n');

  // Create WebAuthn credential
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'alice@example.com',
    displayName: 'Alice'
  });
  console.log('✅ WebAuthn credential created');

  // Create IPFS and OrbitDB instances
  const ipfs = await createHelia({ /* config */ });
  const orbitdb = await createOrbitDB({ ipfs });

  // Create identity with default P-256 DID from WebAuthn
  const identity = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential 
    })
  });

  console.log(`DID: ${identity.id}`);
  console.log('✅ This is a P-256 DID derived from the WebAuthn public key\n');

  return { orbitdb, identity };
}

// ============================================================================
// Example 2: Ed25519 DID from Keystore (NEW FEATURE)
// ============================================================================

async function exampleEd25519KeystoreDID() {
  console.log('=== Example 2: Ed25519 DID from OrbitDB Keystore ===\n');

  // Create WebAuthn credential (still used for authentication)
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'bob@example.com',
    displayName: 'Bob'
  });
  console.log('✅ WebAuthn credential created (used for authentication only)');

  // Create IPFS and OrbitDB instances
  const ipfs = await createHelia({ /* config */ });
  const orbitdb = await createOrbitDB({ ipfs });

  // Get the keystore instance
  const keystore = orbitdb.keystore;
  console.log('✅ OrbitDB keystore retrieved');

  // Create identity with Ed25519 DID from keystore
  const identity = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential,
      useKeystoreDID: true,  // 🎯 Enable Ed25519 DID from keystore
      keystore: keystore      // 🎯 Pass the keystore instance
    })
  });

  console.log(`DID: ${identity.id}`);
  console.log('✅ This is an Ed25519 DID derived from the OrbitDB keystore\n');
  console.log('ℹ️  The DID is created from the same Ed25519 key that signs database operations');
  console.log('ℹ️  WebAuthn is still used for authentication and session establishment\n');

  return { orbitdb, identity };
}

// ============================================================================
// Example 3: Full workflow with Ed25519 keystore DID
// ============================================================================

async function exampleFullWorkflow() {
  console.log('=== Example 3: Full Workflow with Ed25519 Keystore DID ===\n');

  // Step 1: Create WebAuthn credential (biometric prompt)
  console.log('Step 1: Creating WebAuthn credential...');
  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'carol@example.com',
    displayName: 'Carol'
  });
  console.log('✅ WebAuthn credential created\n');

  // Step 2: Initialize OrbitDB
  console.log('Step 2: Initializing OrbitDB...');
  const ipfs = await createHelia({ /* config */ });
  const orbitdb = await createOrbitDB({ ipfs });
  console.log('✅ OrbitDB initialized\n');

  // Step 3: Create identity with Ed25519 keystore DID
  console.log('Step 3: Creating identity with Ed25519 keystore DID...');
  const identity = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential,
      useKeystoreDID: true,
      keystore: orbitdb.keystore
    })
  });
  console.log(`✅ Identity created with DID: ${identity.id.substring(0, 40)}...\n`);

  // Step 4: Open a database with the Ed25519-based identity
  console.log('Step 4: Opening database...');
  const db = await orbitdb.open('my-database', {
    type: 'documents',
    identity: identity
  });
  console.log('✅ Database opened\n');

  // Step 5: Add data (signed with Ed25519 keystore key)
  console.log('Step 5: Adding data to database...');
  await db.put({ _id: 'item1', name: 'First Item', value: 100 });
  await db.put({ _id: 'item2', name: 'Second Item', value: 200 });
  console.log('✅ Data added (signed with Ed25519 keystore key)\n');

  // Step 6: Verify the data
  console.log('Step 6: Verifying data...');
  const items = await db.all();
  console.log(`✅ Retrieved ${items.length} items from database\n`);

  console.log('=== Workflow Complete ===\n');
  console.log('Summary:');
  console.log('- WebAuthn: Used for authentication and session establishment');
  console.log('- Ed25519 Keystore: Used for DID generation and signing database operations');
  console.log('- Identity DID: Derived from Ed25519 keystore public key');
  console.log('- Database entries: Signed with Ed25519 keystore private key\n');

  return { orbitdb, identity, db };
}

// ============================================================================
// Comparison: P-256 vs Ed25519 DIDs
// ============================================================================

async function compareP256vsEd25519() {
  console.log('=== Comparison: P-256 vs Ed25519 DIDs ===\n');

  const credential = await WebAuthnDIDProvider.createCredential({
    userId: 'comparison@example.com',
    displayName: 'Comparison User'
  });

  const ipfs = await createHelia({ /* config */ });
  const orbitdb = await createOrbitDB({ ipfs });

  // Create P-256 DID (default)
  const identityP256 = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential 
    })
  });

  // Create Ed25519 DID (with flag)
  const identityEd25519 = await orbitdb.identities.createIdentity({
    provider: OrbitDBWebAuthnIdentityProviderFunction({ 
      webauthnCredential: credential,
      useKeystoreDID: true,
      keystore: orbitdb.keystore
    })
  });

  console.log('P-256 DID (from WebAuthn):');
  console.log(`  ${identityP256.id}\n`);
  console.log('  ✓ Derived from WebAuthn P-256 public key');
  console.log('  ✓ Hardware-backed authentication');
  console.log('  ✗ Different key than database operations\n');

  console.log('Ed25519 DID (from Keystore):');
  console.log(`  ${identityEd25519.id}\n`);
  console.log('  ✓ Derived from Ed25519 keystore public key');
  console.log('  ✓ Same key that signs database operations');
  console.log('  ✓ Better UCAN compatibility');
  console.log('  ✓ Unified key management\n');

  return { identityP256, identityEd25519 };
}

// ============================================================================
// Main execution
// ============================================================================

async function main() {
  console.log('\n' + '='.repeat(80));
  console.log('OrbitDB WebAuthn Identity Provider - Ed25519 Keystore DID Examples');
  console.log('='.repeat(80) + '\n');

  try {
    // Run examples
    // await exampleDefaultP256DID();
    // await exampleEd25519KeystoreDID();
    // await exampleFullWorkflow();
    await compareP256vsEd25519();

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
  exampleDefaultP256DID,
  exampleEd25519KeystoreDID,
  exampleFullWorkflow,
  compareP256vsEd25519
};

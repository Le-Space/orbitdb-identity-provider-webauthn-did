import { createOrbitDB, Identities, useIdentityProvider } from '@orbitdb/core';
import { createLibp2p } from 'libp2p';
import { createHelia } from 'helia';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { webSockets } from '@libp2p/websockets';
import { webRTC } from '@libp2p/webrtc';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { identify } from '@libp2p/identify';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { all } from '@libp2p/websockets/filters';
import { LevelBlockstore } from 'blockstore-level';
import { LevelDatastore } from 'datastore-level';
import { 
  OrbitDBWebAuthnIdentityProviderFunction,
  OrbitDBWebAuthnIdentityProvider,
  KeystoreEncryption,
  getEncryptionProof,
  getFullEncryptionStatus
} from '@le-space/orbitdb-identity-provider-webauthn-did';

/**
 * Creates a browser-compatible libp2p instance with optimal configuration
 * for WebRTC, WebSocket, and circuit relay connections
 */
export async function createLibp2pInstance() {
  return await createLibp2p({
    addresses: {
      listen: [
        '/p2p-circuit', // Essential for relay connections
        '/webrtc', // WebRTC for direct connections
      ],
    },
    transports: [
      webSockets({
        filter: all,
      }),
      webRTC({
        rtcConfiguration: {
          iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:global.stun.twilio.com:3478' },
          ],
        },
      }),
      circuitRelayTransport({
        discoverRelays: 2, // Discover more relays
        maxReservations: 2, // Allow more reservations
      }),
    ],
    connectionEncryption: [noise()],
    streamMuxers: [yamux()],
    services: {
      identify: identify(),
      pubsub: gossipsub({
        emitSelf: true, // Enable to see our own messages
        allowPublishToZeroTopicPeers: true,
      }),
    },
    connectionManager: {
      maxConnections: 20,
      minConnections: 1,
    },
  });
}

/**
 * Creates a Helia IPFS instance with persistent Level storage
 * @param {Libp2p} libp2p - The libp2p instance to use
 */
export async function createHeliaInstance(libp2p) {
  return await createHelia({
    libp2p,
    blockstore: new LevelBlockstore('./orbitdb/blocks'),
    datastore: new LevelDatastore('./orbitdb/data'),
  });
}

/**
 * Registers the WebAuthn identity provider with OrbitDB
 */
export function registerWebAuthnProvider() {
  useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
}

/**
 * Creates an OrbitDB identities instance
 */
export async function createIdentitiesInstance() {
  return await Identities();
}

/**
 * Creates a WebAuthn identity using the provided credential
 * @param {Object} identities - The OrbitDB identities instance
 * @param {Object} credential - The WebAuthn credential
 * @param {Object} orbitdb - The OrbitDB instance (for keystore access)
 * @param {Object} options - Additional options
 * @param {boolean} options.useKeystoreDID - Use persistent DID from OrbitDB keystore (instead of WebAuthn P-256)
 * @param {string} options.keystoreKeyType - Key type: 'secp256k1' or 'Ed25519'
 * @param {boolean} options.encryptKeystore - Enable keystore encryption
 * @param {string} options.encryptionMethod - Encryption method ('prf', 'hmac-secret', or 'largeBlob')
 */
export async function createWebAuthnIdentity(identities, credential, orbitdb = null, options = {}) {
  console.log('🔍 createWebAuthnIdentity called with options:', options);
  
  const {
    useKeystoreDID = false,
    keystoreKeyType = 'secp256k1',
    encryptKeystore = false,
    encryptionMethod = 'prf'
  } = options;
  
  console.log('🔍 Destructured options:', {
    useKeystoreDID,
    keystoreKeyType,
    encryptKeystore,
    encryptionMethod,
    hasOrbitdb: !!orbitdb,
    hasKeystore: !!orbitdb?.keystore
  });
  
  // Create the provider instance directly so we can call createEncryptedKeystore()
  const provider = new OrbitDBWebAuthnIdentityProvider({
    webauthnCredential: credential,
    useKeystoreDID: useKeystoreDID,
    keystore: orbitdb ? orbitdb.keystore : null,
    keystoreKeyType: keystoreKeyType,
    encryptKeystore: encryptKeystore,
    keystoreEncryptionMethod: encryptionMethod,
  });
  
  console.log('🔍 Provider created, checking encryption condition:', {
    encryptKeystore,
    hasKeystore: !!orbitdb?.keystore,
    shouldEncrypt: encryptKeystore && !!orbitdb?.keystore
  });
  
  // If encryption is enabled, create and unlock the encrypted keystore
  if (encryptKeystore && orbitdb?.keystore) {
    try {
      console.log('🔐 Creating encrypted keystore with', encryptionMethod, '...');
      await provider.createEncryptedKeystore();
      console.log('🔓 Unlocking encrypted keystore...');
      await provider.unlockEncryptedKeystore();
      console.log('✅ Encrypted keystore created and unlocked successfully');
    } catch (error) {
      console.error('❌ Failed to setup encrypted keystore:', error.message);
      console.error('   Full error:', error);
      // Continue anyway - encryption is optional but user should know it failed
    }
  } else {
    console.log('⏭️ Skipping encryption:', {
      reason: !encryptKeystore ? 'encryptKeystore is false' : 'no keystore available',
      encryptKeystore,
      hasKeystore: !!orbitdb?.keystore
    });
  }
  
  // Create identity using a provider function that returns our existing instance
  // Add the type property that OrbitDB expects
  const providerFn = async () => provider;
  providerFn.type = 'webauthn';
  
  return await identities.createIdentity({
    provider: providerFn,
  });
}

/**
 * Creates an OrbitDB instance with WebAuthn identity
 * @param {Object} ipfs - The Helia IPFS instance
 * @param {Object} identities - The OrbitDB identities instance
 * @param {Object} identity - The WebAuthn identity
 */
export async function createOrbitDBInstance(ipfs, identities, identity) {
  return await createOrbitDB({
    ipfs,
    identities,
    identity,
  });
}

/**
 * Complete OrbitDB setup with WebAuthn authentication
 * @param {Object} credential - The WebAuthn credential
 * @param {Object} options - Configuration options
 * @param {boolean} options.useKeystoreDID - Use persistent DID from OrbitDB keystore (instead of WebAuthn P-256)
 * @param {string} options.keystoreKeyType - Key type: 'secp256k1' or 'Ed25519'
 * @param {boolean} options.encryptKeystore - Enable keystore encryption
 * @param {string} options.encryptionMethod - Encryption method
 * @returns {Object} Contains orbitdb, ipfs, identity, and identities instances
 */
export async function setupOrbitDB(credential, options = {}) {
  console.log('🚀 setupOrbitDB called with options:', options);
  
  // Create libp2p instance
  console.log('🔍 Creating libp2p instance...');
  const libp2p = await createLibp2pInstance();

  // Create Helia instance
  console.log('🔍 Creating Helia instance...');
  const ipfs = await createHeliaInstance(libp2p);

  // Register WebAuthn provider
  console.log('🔍 Registering WebAuthn provider...');
  registerWebAuthnProvider();

  // Create identities instance with IPFS for proper storage
  const identities = await Identities({ ipfs });

  // Create OrbitDB instance first (needed for keystore access)
  const tempOrbitdb = await createOrbitDB({ ipfs, identities });
  console.log('🔍 tempOrbitdb created, keystore:', !!tempOrbitdb?.keystore);

  // Create WebAuthn identity with encryption options
  console.log('🔍 Calling createWebAuthnIdentity with options:', options);
  const identity = await createWebAuthnIdentity(identities, credential, tempOrbitdb, options);
  
  console.log('🔍 Created WebAuthn identity:', {
    id: identity.id,
    type: identity.type,
    hash: identity.hash,
    didType: options.useKeystoreDID ? `${options.keystoreKeyType} (from keystore)` : 'P-256 (from WebAuthn)',
    encrypted: options.encryptKeystore ? `Yes (${options.encryptionMethod})` : 'No'
  });
  
  // Log cryptographic proof of encryption if enabled
  let encryptionProof = null;
  console.log('🔍 Encryption proof credentialId:', credential.credentialId);
  console.log('🔍 Encryption proof encryptKeystore:', options.encryptKeystore);
  if (options.encryptKeystore && credential.credentialId) {
    try {
      console.log('🔍 Getting full encryption status...');
      encryptionProof = await getFullEncryptionStatus(credential.credentialId);
      console.log('🔍 Encryption proof:', encryptionProof);
      if (encryptionProof && encryptionProof.encrypted) {
        console.log('🔐 ENCRYPTION PROOF - Cryptographic Evidence:');
        console.log('┌─────────────────────────────────────────────────────────────────┐');
        console.log('│ KEYSTORE ENCRYPTION VERIFIED                                    │');
        console.log('├─────────────────────────────────────────────────────────────────┤');
        console.log(`│ Method: ${(encryptionProof.method || 'unknown').padEnd(54)}│`);
        console.log(`│ Algorithm: ${(encryptionProof.algorithm || 'AES-GCM-256').padEnd(51)}│`);
        console.log(`│ Key Derivation: ${(encryptionProof.keyDerivation || '').slice(0, 45).padEnd(45)}│`);
        console.log('├─────────────────────────────────────────────────────────────────┤');
        console.log(`│ Ciphertext Hash: ${(encryptionProof.ciphertextHash || '').slice(0, 44).padEnd(44)}│`);
        console.log(`│ Ciphertext Size: ${String((encryptionProof.ciphertextLength || 0) + ' bytes').padEnd(44)}│`);
        console.log(`│ IV Hash: ${(encryptionProof.ivHash || '').slice(0, 52).padEnd(52)}│`);
        if (encryptionProof.hmacSecretUsed) {
          console.log('├─────────────────────────────────────────────────────────────────┤');
          console.log('│ HMAC-SECRET EXTENSION PROOF:                                    │');
          console.log(`│ Salt Hash: ${(encryptionProof.saltHash || '').slice(0, 50).padEnd(50)}│`);
          console.log(`│ Wrapped SK Hash: ${(encryptionProof.wrappedSKHash || '').slice(0, 44).padEnd(44)}│`);
          console.log(`│ Hardware-bound: YES (WebAuthn authenticator)                    │`);
        }
        console.log('├─────────────────────────────────────────────────────────────────┤');
        console.log(`│ Security: ${(encryptionProof.securityLevel || 'Hardware-backed').padEnd(51)}│`);
        console.log(`│ Storage: ${(encryptionProof.storage || 'IndexedDB').padEnd(52)}│`);
        console.log(`│ Timestamp: ${new Date(encryptionProof.timestamp || Date.now()).toISOString().padEnd(50)}│`);
        console.log('└─────────────────────────────────────────────────────────────────┘');
        
        // Also log the full proof object for detailed inspection
        console.log('🔐 Full encryption proof object:', encryptionProof);
      } else {
        console.warn('⚠️ Encryption enabled but keystore not found in IndexedDB:', encryptionProof?.reason || 'Unknown reason');
        console.log('ℹ️ This may happen on first run - the encrypted keystore will be created during identity setup');
      }
    } catch (error) {
      console.warn('⚠️ Could not generate encryption proof:', error.message);
    }
  }
  
  // Try to verify our identity is in the identities store
  try {
    const storedIdentity = await identities.getIdentity(identity.hash);
    console.log('✅ Identity found in identities store:', !!storedIdentity);
    if (storedIdentity) {
      console.log('📊 Stored identity details:', {
        id: storedIdentity.id,
        type: storedIdentity.type
      });
    }
  } catch (error) {
    console.warn('⚠️ Could not retrieve identity from store:', error.message);
  }

  // Create OrbitDB instance
  const orbitdb = await createOrbitDBInstance(ipfs, identities, identity);

  return {
    orbitdb,
    ipfs,
    identity,
    identities,
    encryptionProof, // Include cryptographic proof of encryption
  };
}

/**
 * Cleanup function to properly shut down all instances
 * @param {Object} instances - Object containing orbitdb, ipfs instances
 */
export async function cleanup({ orbitdb, ipfs, database = null }) {
  try {
    if (database) {
      await database.close();
    }

    if (orbitdb) {
      await orbitdb.stop();
    }

    if (ipfs) {
      await ipfs.stop();
    }
  } catch (error) {
    console.error('Error during cleanup:', error);
    // Continue with cleanup even if some operations fail
  }
}

/**
 * Reset database state by clearing IndexedDB
 */
export async function resetDatabaseState() {
  try {
    console.log('🗑️ Clearing IndexedDB...');
    if ('databases' in indexedDB) {
      const databases = await indexedDB.databases();
      for (const db of databases) {
        if (
          db.name.includes('orbitdb') ||
          db.name.includes('helia') ||
          db.name.includes('webauthn')
        ) {
          console.log('🗑️ Deleting database:', db.name);
          indexedDB.deleteDatabase(db.name);
        }
      }
    }
  } catch (error) {
    console.error('Error clearing IndexedDB:', error);
    throw error;
  }
}


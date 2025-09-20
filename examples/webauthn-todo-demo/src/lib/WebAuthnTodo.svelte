<script>
  import { onMount } from 'svelte';
  import { createOrbitDB, Identities, useIdentityProvider, IPFSAccessController } from '@orbitdb/core';
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
    WebAuthnDIDProvider,
    OrbitDBWebAuthnIdentityProviderFunction,
    registerWebAuthnProvider,
    checkWebAuthnSupport
  } from './orbitdb-identity-provider-webauthn-did.js';
  import {
    Button,
    Tile,
    InlineNotification,
    Loading,
    ProgressIndicator,
    ProgressStep,
  } from 'carbon-components-svelte';
  import {
    Checkmark,
    Warning,
  } from 'carbon-icons-svelte';

  let orbitdb = null;
  let ipfs = null;
  let database = null;
  let todos = [];
  let newTodo = '';
  let credential = null;
  let identity = null;
  let identities = null;
  let isAuthenticated = false;
  let loading = false;
  let status = 'Checking WebAuthn support...';
  let support = null;
  let webAuthnSupported = false;
  let webAuthnPlatformAvailable = false;
  let webAuthnSupportMessage = '';
  let webAuthnChecking = true;

  onMount(async () => {
    await initializeWebAuthn();
  });

  async function initializeWebAuthn() {
    try {
      status = 'Checking WebAuthn support...';
      support = await checkWebAuthnSupport();
      webAuthnSupported = support.supported;
      webAuthnPlatformAvailable = support.platformAuthenticator;
      webAuthnSupportMessage = support.message;
      
      if (!support.supported) {
        status = `WebAuthn not supported: ${support.message}`;
        return;
      }
      
      status = support.message;
      
      // Check if we have stored credentials
      const storedCredential = localStorage.getItem('webauthn-credential');
      if (storedCredential) {
        try {
          const parsed = JSON.parse(storedCredential);
          // Properly deserialize Uint8Arrays for credential data AND public key coordinates
          credential = {
            ...parsed,
            rawCredentialId: new Uint8Array(parsed.rawCredentialId),
            attestationObject: new Uint8Array(parsed.attestationObject),
            publicKey: {
              ...parsed.publicKey,
              x: new Uint8Array(parsed.publicKey.x),
              y: new Uint8Array(parsed.publicKey.y)
            }
          };
          status = 'Credential found, ready to authenticate!';
        } catch (error) {
          console.warn('Failed to load credential from localStorage:', error);
          localStorage.removeItem('webauthn-credential');
        }
      }
      
    } catch (error) {
      console.error('WebAuthn initialization failed:', error);
      status = `Error: ${error.message}`;
    } finally {
      webAuthnChecking = false;
    }
  }

  async function createCredential() {
    try {
      loading = true;
      status = 'Creating WebAuthn credential...';
      
      credential = await WebAuthnDIDProvider.createCredential({
        userId: `todo-user-${Date.now()}`,
        displayName: 'TODO App User'
      });
      
      // Store credential for future use (with proper serialization for all Uint8Arrays)
      const serializedCredential = {
        ...credential,
        rawCredentialId: Array.from(credential.rawCredentialId),
        attestationObject: Array.from(credential.attestationObject),
        publicKey: {
          ...credential.publicKey,
          x: Array.from(credential.publicKey.x),
          y: Array.from(credential.publicKey.y)
        }
      };
      localStorage.setItem('webauthn-credential', JSON.stringify(serializedCredential));
      
      status = 'Credential created successfully!';
    } catch (error) {
      console.error('Credential creation failed:', error);
      status = `Failed to create credential: ${error.message}`;
    } finally {
      loading = false;
    }
  }

  async function authenticate() {
    try {
      loading = true;
      status = 'Creating libp2p instance...';
      
      // Create libp2p instance with browser-compatible configuration (from original template)
      const libp2p = await createLibp2p({
        addresses: {
          listen: [
            '/p2p-circuit', // Essential for relay connections
            '/webrtc' // WebRTC for direct connections
          ]
        },
        transports: [
          webSockets({
            filter: all
          }),
          webRTC({
            rtcConfiguration: {
              iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:global.stun.twilio.com:3478' }
              ]
            }
          }),
          circuitRelayTransport({
            discoverRelays: 2, // Discover more relays
            maxReservations: 2 // Allow more reservations
          })
        ],
        connectionEncryption: [noise()],
        streamMuxers: [yamux()],
        services: {
          identify: identify(),
          pubsub: gossipsub({ 
            emitSelf: true, // Enable to see our own messages
            allowPublishToZeroTopicPeers: true 
          })
        },
        connectionManager: {
          maxConnections: 20,
          minConnections: 1
        }
      });
      
      status = 'Creating IPFS instance...';
      // Create Helia instance with libp2p and persistent Level storage
      ipfs = await createHelia({
        libp2p,
        blockstore: new LevelBlockstore('./orbitdb/blocks'),
        datastore: new LevelDatastore('./orbitdb/data')
      });
      
      status = 'Registering WebAuthn provider...';
      // Register the WebAuthn provider (exactly like in original)
      useIdentityProvider(OrbitDBWebAuthnIdentityProviderFunction);
      
      status = 'Creating identities instance...';
      // Create OrbitDB identities instance
      identities = await Identities();
      
      status = 'Creating WebAuthn identity...';
      // Create the identity using OrbitDB's standard identity creation (like original)
      identity = await identities.createIdentity({
        provider: OrbitDBWebAuthnIdentityProviderFunction({ webauthnCredential: credential })
      });
      
      
      status = 'Creating OrbitDB instance...';
      // Create OrbitDB instance with WebAuthn identity and identities (like original)
      orbitdb = await createOrbitDB({
        ipfs: ipfs,
        identities: identities,
        identity: identity
      });
      
      status = 'Opening TODO database...';
      
      // Open TODO database with keyvalue type and access controller (like original)
      const writePermissions = [identity.id];
      console.log('🔓 Database access configuration:', {
        writePermissions,
        identityId: identity.id,
        identityType: identity.type
      });
      
      console.log('📝 Opening database "webauthn-todos"...');
      database = await Promise.race([
        orbitdb.open('webauthn-todos', {
          type: 'keyvalue',
          create: true,
          sync: true,
          accessController: IPFSAccessController({ 
            write: writePermissions
          })
        }),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Database open timeout after 15 seconds')), 15000)
        )
      ]);
      
      console.log('✅ Database opened successfully:', {
        name: database.name,
        address: database.address,
        type: database.type,
        identityId: database.identity?.id,
        accessControllerType: database.access?.type
      });
      
      // Set up database event listeners for debugging
      database.events.on('join', (address, entry) => {
        console.log('🔗 Database JOIN event:', { address, entry: entry?.key });
      });
      
      database.events.on('update', (address) => {
        console.log('🔄 Database UPDATE event:', { address });
      });
      
      database.events.on('error', (error) => {
        console.error('❌ Database ERROR event:', error);
      });
      
      // Load existing todos
      console.log('📋 Loading existing todos...');
      await loadTodos();
      
      isAuthenticated = true;
      status = 'Successfully authenticated with biometric security!';
      
    } catch (error) {
      console.error('Authentication failed:', error);
      
      // Handle specific error types
      if (error instanceof AggregateError) {
        console.error('AggregateError details:', {
          errors: error.errors,
          errorCount: error.errors?.length
        });
        
        // Check if it's a database loading issue
        const hasLoadingErrors = error.errors?.some(e => 
          e.message?.includes('all') || 
          e.message?.includes('timeout') || 
          e.message?.includes('sync')
        );
        
        if (hasLoadingErrors) {
          status = 'Database loading failed - network or sync issues. Try resetting database.';
        } else {
          status = `Multiple errors occurred: ${error.errors?.map(e => e.message).join(', ')}`;
        }
      } else {
        status = `Authentication failed: ${error.message}`;
      }
    } finally {
      loading = false;
    }
  }

  async function loadTodos() {
    if (!database) return;
    
    try {
      console.log('📊 Loading todos from database:', {
        databaseName: database.name,
        databaseAddress: database.address,
        databaseType: database.type,
        identityId: database.identity?.id,
        accessController: database.access?.type
      });
      
      console.log('⏳ Calling database.all()...');
      const allTodos = await Promise.race([
        database.all(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Database.all() timeout after 10 seconds')), 10000)
        )
      ]);
      
      console.log('✅ Database.all() completed, entries found:', allTodos.length);
      
      todos = allTodos
        .map(entry => {
          console.log('📝 Todo entry:', { key: entry.key, value: entry.value });
          return entry.value;
        })
        .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
        
      console.log('📋 Todos loaded successfully:', todos.length);
    } catch (error) {
      console.error('❌ Failed to load todos:', error);
      console.error('Error details:', {
        message: error.message,
        name: error.name,
        stack: error.stack?.slice(0, 500)
      });
      
      // If it's a timeout or connection issue, suggest reset
      if (error.message.includes('timeout') || error.message.includes('rejected')) {
        status = 'Database loading failed - try resetting database state';
      }
    }
  }

  async function addTodo() {
    if (!newTodo.trim() || !database) return;
    
    try {
      loading = true;
      
      // 🧪 DEBUG: Test direct WebAuthn call before OrbitDB operation
      console.log('🧪 [DEBUG] Testing direct WebAuthn call before adding TODO...');
      try {
        const testChallenge = crypto.getRandomValues(new Uint8Array(32));
        console.log('🧪 [DEBUG] Calling navigator.credentials.get directly - this should show biometric prompt!');
        
        const directAuth = await navigator.credentials.get({
          publicKey: {
            challenge: testChallenge,
            allowCredentials: [{
              id: credential.rawCredentialId,
              type: 'public-key'
            }],
            userVerification: 'required',
            timeout: 60000
          }
        });
        
        console.log('🧪 [DEBUG] Direct WebAuthn auth successful:', {
          hasResponse: !!directAuth?.response,
          hasAuthenticatorData: !!directAuth?.response?.authenticatorData
        });
      } catch (directAuthError) {
        console.warn('🧪 [DEBUG] Direct WebAuthn auth failed:', directAuthError.message);
      }
      
      const todoId = `todo-${Date.now()}`;
      const todo = {
        id: todoId,
        text: newTodo.trim(),
        completed: false,
        createdAt: new Date().toISOString()
      };
      
      console.log('🧪 [DEBUG] Now calling OrbitDB database.put() - this should also trigger biometric prompt...');
      await database.put(todoId, todo);
      await loadTodos();
      
      newTodo = '';
      status = 'TODO added successfully!';
      
    } catch (error) {
      console.error('Failed to add todo:', error);
      status = `Failed to add TODO: ${error.message}`;
    } finally {
      loading = false;
    }
  }

  async function toggleTodo(todo) {
    if (!database) return;
    
    try {
      loading = true;
      
      const updatedTodo = {
        ...todo,
        completed: !todo.completed
      };
      
      await database.put(todo.id, updatedTodo);
      await loadTodos();
      
    } catch (error) {
      console.error('Failed to toggle todo:', error);
    } finally {
      loading = false;
    }
  }

  async function deleteTodo(todo) {
    if (!database) return;
    
    try {
      loading = true;
      
      await database.del(todo.id);
      await loadTodos();
      
    } catch (error) {
      console.error('Failed to delete todo:', error);
    } finally {
      loading = false;
    }
  }

  async function resetDatabase() {
    try {
      loading = true;
      status = 'Resetting database state...';
      
      console.log('🗑️ Resetting database state...');
      
      // Close current connections
      if (database) {
        await database.close();
        database = null;
      }
      
      if (orbitdb) {
        await orbitdb.stop();
        orbitdb = null;
      }
      
      if (ipfs) {
        await ipfs.stop();
        ipfs = null;
      }
      
      // Clear IndexedDB
      console.log('🗑️ Clearing IndexedDB...');
      if ('databases' in indexedDB) {
        const databases = await indexedDB.databases();
        for (const db of databases) {
          if (db.name.includes('orbitdb') || db.name.includes('helia') || db.name.includes('webauthn')) {
            console.log('🗑️ Deleting database:', db.name);
            indexedDB.deleteDatabase(db.name);
          }
        }
      }
      
      // Reset state
      todos = [];
      isAuthenticated = false;
      // Keep credential but reset everything else
      identity = null;
      identities = null;
      
      status = 'Database reset complete - ready to authenticate again';
      console.log('✅ Database reset completed');
      
    } catch (error) {
      console.error('❌ Error during database reset:', error);
      status = `Reset error: ${error.message}`;
    } finally {
      loading = false;
    }
  }

  async function logout() {
    try {
      if (database) {
        await database.close();
        database = null;
      }
      
      if (orbitdb) {
        await orbitdb.stop();
        orbitdb = null;
      }
      
      if (ipfs) {
        await ipfs.stop();
        ipfs = null;
      }
      
      todos = [];
      isAuthenticated = false;
      credential = null;
      identity = null;
      identities = null;
      localStorage.removeItem('webauthn-credential');
      status = 'Logged out successfully';
    } catch (error) {
      console.error('Error during logout:', error);
      // Force clear state even if cleanup fails
      orbitdb = null;
      ipfs = null;
      database = null;
      todos = [];
      isAuthenticated = false;
      credential = null;
      identity = null;
      identities = null;
      localStorage.removeItem('webauthn-credential');
      status = 'Logged out (with cleanup errors)';
    }
  }
</script>

<div style="max-width: 64rem; margin: 0 auto;">
  <!-- Status Display -->
  <Tile light style="margin-bottom: 1rem;">
    <div style="display: flex; align-items: center; gap: 0.75rem;">
      {#if loading}
        <Loading small description="Loading..." />
      {:else if webAuthnSupported}
        <Checkmark size={20} />
      {:else}
        <Warning size={20} />
      {/if}
      <span>{status}</span>
    </div>
    
    {#if webAuthnPlatformAvailable}
      <InlineNotification 
        kind="success"
        title="Biometric authentication available"
        hideCloseButton
        lowContrast
        style="margin-top: 0.5rem;"
      />
    {/if}
  </Tile>

  {#if !isAuthenticated}
    <!-- Authentication Section -->
    <Tile light>
      <h2 style="font-size: 1.5rem; font-weight: bold; margin-bottom: 1rem;">
        Secure WebAuthn Authentication
      </h2>
      
      {#if !credential}
        <p style="margin-bottom: 1.5rem;">
          Create a WebAuthn credential to secure your TODO list with biometric authentication.
        </p>
        <Button 
          on:click={createCredential}
          disabled={loading || !webAuthnSupported}
          kind="primary"
        >
          {loading ? 'Creating...' : 'Create Credential'}
        </Button>
      {:else}
        <p style="margin-bottom: 1.5rem;">
          Use your biometric authentication to access your secure TODO list.
        </p>
        <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
          <Button
            on:click={authenticate}
            disabled={loading}
            kind="primary"
          >
            {loading ? 'Authenticating...' : 'Authenticate with WebAuthn'}
          </Button>
          
          {#if status.includes('failed') || status.includes('timeout')}
            <Button
              on:click={resetDatabase}
              disabled={loading}
              kind="danger-tertiary"
              size="small"
            >
              Reset Database
            </Button>
          {/if}
        </div>
      {/if}
    </Tile>
  {:else}
    <!-- TODO Application -->
    <Tile light>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <h2 style="font-size: 1.5rem; font-weight: bold;">My Secure TODOs</h2>
        <div style="display: flex; gap: 0.5rem;">
          <Button
            on:click={resetDatabase}
            kind="danger-tertiary"
            size="small"
            disabled={loading}
          >
            {loading ? 'Resetting...' : 'Reset DB'}
          </Button>
          <Button
            on:click={logout}
            kind="ghost"
            size="small"
          >
            Logout
          </Button>
        </div>
      </div>

      <!-- Add New TODO -->
      <div style="display: flex; gap: 0.75rem; margin-bottom: 1.5rem;">
        <input
          type="text"
          bind:value={newTodo}
          placeholder="Add a new TODO..."
          on:keydown={(e) => e.key === 'Enter' && addTodo()}
          style="flex: 1; padding: 0.5rem 1rem; border: 1px solid var(--cds-border-subtle); border-radius: 0.5rem; font-size: 1rem; background: var(--cds-field); color: var(--cds-text-primary);"
        />
        <Button
          on:click={addTodo}
          disabled={loading || !newTodo.trim()}
          kind="primary"
        >
          {loading ? '...' : 'Add'}
        </Button>
      </div>

      <!-- TODO List -->
      {#if todos.length === 0}
        <div style="text-align: center; padding: 3rem 0; color: var(--cds-text-secondary);">
          <div style="font-size: 2.5rem; margin-bottom: 1rem;">📝</div>
          <p>No TODOs yet. Add your first one above!</p>
        </div>
      {:else}
        <div style="display: flex; flex-direction: column; gap: 0.75rem;">
          {#each todos as todo}
            <div style="display: flex; align-items: center; gap: 0.75rem; padding: 1rem; background-color: var(--cds-layer-accent); border-radius: 0.5rem; border: 1px solid var(--cds-border-subtle);">
              <button
                on:click={() => toggleTodo(todo)}
                style="flex-shrink: 0; background: none; border: none; cursor: pointer;"
                disabled={loading}
              >
                {#if todo.completed}
                  <div style="width: 1.25rem; height: 1.25rem; background-color: var(--cds-support-success); border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                    <svg style="width: 0.75rem; height: 0.75rem; color: white;" fill="currentColor" viewBox="0 0 20 20">
                      <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                    </svg>
                  </div>
                {:else}
                  <div style="width: 1.25rem; height: 1.25rem; border: 2px solid var(--cds-border-subtle); border-radius: 50%;"></div>
                {/if}
              </button>
              
              <span style="flex: 1; color: {todo.completed ? 'var(--cds-text-secondary)' : 'var(--cds-text-primary)'}; {todo.completed ? 'text-decoration: line-through;' : ''}">
                {todo.text}
              </span>
              
              <button
                on:click={() => deleteTodo(todo)}
                disabled={loading}
                style="color: var(--cds-support-error); background: none; border: none; cursor: pointer; padding: 0.25rem;"
              >
                <svg style="width: 1rem; height: 1rem;" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>
          {/each}
        </div>
        
        <div style="margin-top: 1.5rem; font-size: 0.875rem; color: var(--cds-text-secondary); text-align: center;">
          {todos.length} total • {todos.filter(t => t.completed).length} completed
        </div>
      {/if}
    </Tile>
  {/if}

  <!-- Info Section -->
  <Tile light style="margin-top: 2rem; background-color: var(--cds-layer-accent);">
    <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--cds-text-primary); margin-bottom: 0.75rem;">
      🔐 WebAuthn Security Features
    </h3>
    <ul style="list-style: none; padding: 0; margin: 0; color: var(--cds-text-secondary);">
      <li style="margin-bottom: 0.5rem; font-size: 0.875rem;">✅ Hardware-secured authentication (Face ID, Touch ID, Windows Hello)</li>
      <li style="margin-bottom: 0.5rem; font-size: 0.875rem;">✅ Private keys never leave your device</li>
      <li style="margin-bottom: 0.5rem; font-size: 0.875rem;">✅ Decentralized data storage with OrbitDB</li>
      <li style="margin-bottom: 0.5rem; font-size: 0.875rem;">✅ No passwords or usernames required</li>
    </ul>
  </Tile>
</div>
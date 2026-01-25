<script>
  import { onMount } from 'svelte';
  import {
    WebAuthnDIDProvider,
    checkWebAuthnSupport,
    KeystoreEncryption,
  } from '@le-space/orbitdb-identity-provider-webauthn-did';

  import { setupOrbitDB, cleanup, resetDatabaseState } from './libp2p.js';
import {
    openTodoDatabase,
    loadTodos,
    addTodo,
    toggleTodo,
    deleteTodo,
    getTodoStats,
    getIdentityVerifications,
    getVerificationForTodo,
  } from './database.js';
  import {
    Button,
    Tile,
    InlineNotification,
    Loading,
  } from 'carbon-components-svelte';
  import { Checkmark, Warning } from 'carbon-icons-svelte';
  import IdentityVerificationBadge from './components/IdentityVerificationBadge.svelte';

  // Core instances
  let orbitdbInstances = null; // Will contain { orbitdb, ipfs, identity, identities }
  let database = null;

  // UI state
  let todos = [];
  let newTodo = '';
  let credential = null;
  let isAuthenticated = false;
  let loading = false;
  let status = 'Checking WebAuthn support...';
  
  // Identity verification tracking (not stored in database)
  let todoVerifications = new Map(); // Map<todoId, {verified: boolean, timestamp: number, identityHash: string}>

  // WebAuthn support detection
  let webAuthnSupported = false;
  let webAuthnPlatformAvailable = false;
  
  // NEW: Encryption options
  let useEncryption = true; // Enable encryption by default
  let encryptionMethod = 'prf'; // 'prf' (default), 'largeBlob', or 'hmac-secret'
  let useKeystoreDID = true; // Use persistent DID from OrbitDB keystore (instead of WebAuthn P-256)
  let keystoreKeyType = 'Ed25519'; // Key type: 'secp256k1' or 'Ed25519' (default: Ed25519)
  let extensionSupport = { largeBlob: false, hmacSecret: false };
  
  // Encryption proof state (cryptographic evidence)
  let encryptionProof = null;

  // Computed values
  $: todoStats = getTodoStats(todos);

  // UI helper functions
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      status = 'DID copied to clipboard!';
      // Reset status after a few seconds
      setTimeout(() => {
        if (status === 'DID copied to clipboard!') {
          status = 'Successfully authenticated with biometric security!';
        }
      }, 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
      status = 'Failed to copy DID to clipboard';
    }
  }

  onMount(async () => {
    // Expose utilities to window for E2E testing
    if (typeof window !== 'undefined') {
      window.KeystoreEncryption = KeystoreEncryption;
    }
    
    await initializeWebAuthn();
    await checkEncryptionSupport();
  });
  
  async function checkEncryptionSupport() {
    try {
      extensionSupport = await KeystoreEncryption.checkExtensionSupport();
      console.log('Encryption extension support:', extensionSupport);
      
      // Auto-select best encryption method (PRF is preferred for platform authenticators)
      if (extensionSupport.prf) {
        encryptionMethod = 'prf';
      } else if (extensionSupport.largeBlob) {
        encryptionMethod = 'largeBlob';
      } else if (extensionSupport.hmacSecret) {
        encryptionMethod = 'hmac-secret';
      } else {
        useEncryption = false; // Disable if no support
        console.warn('No encryption extensions supported');
      }
    } catch (error) {
      console.error('Failed to check encryption support:', error);
    }
  }

  async function initializeWebAuthn() {
    try {
      status = 'Checking WebAuthn support...';
      const support = await checkWebAuthnSupport();
      webAuthnSupported = support.supported;
      webAuthnPlatformAvailable = support.platformAuthenticator;

      if (!support.supported) {
        status = `WebAuthn not supported: ${support.message}`;
        return;
      }

      status = support.message;

      // Load stored credential
      credential = loadStoredCredential();
      if (credential) {
        status = 'Credential found, ready to authenticate!';
      }
    } catch (error) {
      console.error('WebAuthn initialization failed:', error);
      status = `Error: ${error.message}`;
    }
  }

  function loadStoredCredential() {
    try {
      const storedCredential = localStorage.getItem('webauthn-credential');
      if (storedCredential) {
        const parsed = JSON.parse(storedCredential);
        // Properly deserialize Uint8Arrays for credential data AND public key coordinates
        return {
          ...parsed,
          rawCredentialId: new Uint8Array(parsed.rawCredentialId),
          attestationObject: new Uint8Array(parsed.attestationObject),
          publicKey: {
            ...parsed.publicKey,
            x: new Uint8Array(parsed.publicKey.x),
            y: new Uint8Array(parsed.publicKey.y),
          },
        };
      }
    } catch (error) {
      console.warn('Failed to load credential from localStorage:', error);
      localStorage.removeItem('webauthn-credential');
    }
    return null;
  }

  async function createCredential() {
    try {
      loading = true;
      status = 'Creating WebAuthn credential...';

      credential = await WebAuthnDIDProvider.createCredential({
        userId: `todo-user-${Date.now()}`,
        displayName: 'TODO App User',
      });

      // Store credential for future use
      storeCredential(credential);

      status = 'Credential created successfully!';
    } catch (error) {
      console.error('Credential creation failed:', error);
      status = `Failed to create credential: ${error.message}`;
    } finally {
      loading = false;
    }
  }

  function storeCredential(credential) {
    const serializedCredential = {
      ...credential,
      rawCredentialId: Array.from(credential.rawCredentialId),
      attestationObject: Array.from(credential.attestationObject),
      publicKey: {
        ...credential.publicKey,
        x: Array.from(credential.publicKey.x),
        y: Array.from(credential.publicKey.y),
      },
    };
    localStorage.setItem(
      'webauthn-credential',
      JSON.stringify(serializedCredential)
    );
  }

  async function authenticate() {
    try {
      loading = true;

      status = 'Setting up OrbitDB...';
      // Use the extracted setupOrbitDB function with encryption options
      orbitdbInstances = await setupOrbitDB(credential, {
        useKeystoreDID: useKeystoreDID,
        keystoreKeyType: keystoreKeyType,
        encryptKeystore: useEncryption,
        encryptionMethod: encryptionMethod
      });
      
      // Capture encryption proof for UI display
      encryptionProof = orbitdbInstances.encryptionProof;

      status = 'Opening TODO database...';
      // Use the extracted openTodoDatabase function
      database = await openTodoDatabase(
        orbitdbInstances.orbitdb,
        orbitdbInstances.identity,
        orbitdbInstances.identities
      );

      status = 'Loading existing todos...';
      // Use the extracted loadTodos function
      await refreshTodos();

      isAuthenticated = true;
      status = 'Successfully authenticated with biometric security!';
    } catch (error) {
      console.error('Authentication failed:', error);
      status = handleAuthenticationError(error);
    } finally {
      loading = false;
    }
  }

  function handleAuthenticationError(error) {
    if (error instanceof AggregateError) {
      console.error('AggregateError details:', {
        errors: error.errors,
        errorCount: error.errors?.length,
      });

      const hasLoadingErrors = error.errors?.some(
        (e) =>
          e.message?.includes('all') ||
          e.message?.includes('timeout') ||
          e.message?.includes('sync')
      );

      if (hasLoadingErrors) {
        return 'Database loading failed - network or sync issues. Try resetting database.';
      } else {
        return `Multiple errors occurred: ${error.errors?.map((e) => e.message).join(', ')}`;
      }
    } else {
      return `Authentication failed: ${error.message}`;
    }
  }

  async function refreshTodos() {
    if (!database) return;

    try {
      todos = await loadTodos(database);
      
      // Refresh verification states after loading todos
      if (todos.length > 0) {
        console.log(`📋 Loaded ${todos.length} todos, scheduling verification...`);
        setTimeout(() => refreshVerificationStates(), 100); // Small delay to let database settle
      } else {
        console.log('📋 No todos loaded, skipping verification');
      }
    } catch (error) {
      console.error('❌ Failed to load todos:', error);
      // If it's a timeout or connection issue, suggest reset
      if (
        error.message.includes('timeout') ||
        error.message.includes('rejected')
      ) {
        status = 'Database loading failed - try resetting database state';
      }
    }
  }

  async function handleAddTodo() {
    if (!newTodo.trim() || !database) return;

    try {
      loading = true;

      await addTodo(database, newTodo, credential);
      await refreshTodos();
      
      // Refresh verification states after a short delay to allow database events to process
      setTimeout(() => refreshVerificationStates(), 2000);

      newTodo = '';
      status = 'TODO added successfully!';
    } catch (error) {
      console.error('Failed to add todo:', error);
      status = `Failed to add TODO: ${error.message}`;
    } finally {
      loading = false;
    }
  }

  async function handleToggleTodo(todo) {
    if (!database) return;

    try {
      loading = true;

      await toggleTodo(database, todo);
      await refreshTodos();
    } catch (error) {
      console.error('Failed to toggle todo:', error);
    } finally {
      loading = false;
    }
  }

  async function handleDeleteTodo(todo) {
    if (!database) return;

    try {
      loading = true;

      await deleteTodo(database, todo);
      await refreshTodos();
    } catch (error) {
      console.error('Failed to delete todo:', error);
    } finally {
      loading = false;
    }
  }

  async function handleResetDatabase() {
    try {
      loading = true;
      status = 'Resetting database state...';

      console.log('🗑️ Resetting database state...');

      // Close current connections using extracted cleanup function
      if (orbitdbInstances) {
        await cleanup({ ...orbitdbInstances, database });
      }

      // Clear IndexedDB using extracted function
      await resetDatabaseState();

      // Reset state
      todos = [];
      isAuthenticated = false;
      database = null;
      orbitdbInstances = null;

      status = 'Database reset complete - ready to authenticate again';
      console.log('✅ Database reset completed');
    } catch (error) {
      console.error('❌ Error during database reset:', error);
      status = `Reset error: ${error.message}`;
    } finally {
      loading = false;
    }
  }

  async function refreshVerificationStates() {
    console.log('🔄 Starting refreshVerificationStates...');
    
    // First, get states from the global store (from database events)
    const globalVerifications = getIdentityVerifications();
    console.log(`💾 Found ${globalVerifications.size} verifications in global store`);
    
    // Clear and update with global state
    todoVerifications.clear();
    for (const [todoId, verification] of globalVerifications) {
      todoVerifications.set(todoId, verification);
      console.log(`✅ Loaded verification for ${todoId}: ${verification.success ? 'PASSED' : 'FAILED'}`);
    }
    
    // For todos that don't have verification yet, use the simple verification approach
    if (database && orbitdbInstances?.identity?.id) {
      try {
        // Use the single verification approach
        const { verifyTodos } = await import('./verification.js');
        
        // Find todos that need verification
        const unverifiedTodos = todos.filter(todo => !todoVerifications.has(todo.id));
        
        if (unverifiedTodos.length > 0) {
          console.log(`🔍 Running verification for ${unverifiedTodos.length} todos...`);
          
          const newVerifications = await verifyTodos(
            database,
            unverifiedTodos, 
            orbitdbInstances.identity.id
          );
          
          // Add new verifications to our map
          for (const [todoId, verification] of newVerifications) {
            todoVerifications.set(todoId, verification);
          }
        }
      } catch (error) {
        console.error('Error during simple verification:', error);
      }
    }
    
    // Trigger reactivity
    todoVerifications = todoVerifications;
    
    console.log('🔄 Refreshed verification states:', todoVerifications.size, 'todos verified');
  }

  async function handleLogout() {
    try {
      // Clean up connections
      if (orbitdbInstances) {
        await cleanup({ ...orbitdbInstances, database });
      }

      // Clear all state
      todos = [];
      todoVerifications.clear();
      isAuthenticated = false;
      credential = null;
      database = null;
      orbitdbInstances = null;
      encryptionProof = null;
      localStorage.removeItem('webauthn-credential');
      status = 'Logged out successfully';
    } catch (error) {
      console.error('Error during logout:', error);
      // Force clear state even if cleanup fails
      todos = [];
      todoVerifications.clear();
      isAuthenticated = false;
      credential = null;
      database = null;
      orbitdbInstances = null;
      encryptionProof = null;
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
        OrbitDB WebAuthn Demo DID
      </h2>

      {#if !credential}
        <p style="margin-bottom: 1.5rem;">
          Create a WebAuthn credential to secure your TODO list with biometric
          authentication.
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
        
        <!-- NEW: Encryption Options -->
        <div style="background: var(--cds-layer-accent); padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem; border: 1px solid var(--cds-border-subtle);">
          <h3 style="font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; color: var(--cds-text-primary);">
            🔐 Security Options
          </h3>
          
          <div style="display: flex; flex-direction: column; gap: 0.75rem;">
            <!-- DID Source Selection -->
            <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
              <input
                type="checkbox"
                bind:checked={useKeystoreDID}
                disabled={loading}
                style="cursor: pointer;"
              />
              <span style="color: var(--cds-text-primary);">Use persistent keystore identity</span>
              <span style="font-size: 0.75rem; color: var(--cds-text-secondary);">🗄️ Instead of WebAuthn P-256</span>
            </label>
            
            <!-- Show info when keystore DID is NOT selected -->
            {#if !useKeystoreDID}
              <div style="padding-left: 1.5rem; padding: 0.5rem; background: var(--cds-layer); border-radius: 0.25rem; border-left: 3px solid var(--cds-interactive);">
                <span style="font-size: 0.75rem; color: var(--cds-text-secondary);">
                  ℹ️ Will use <strong style="color: var(--cds-text-primary);">P-256 DID</strong> from WebAuthn credential
                  <code style="font-size: 0.7rem; opacity: 0.8;">(did:key:zDna...)</code>
                </span>
              </div>
            {/if}
            
            <!-- Keystore Key Type Selection -->
            {#if useKeystoreDID}
              <div style="padding-left: 1.5rem; display: flex; flex-direction: column; gap: 0.5rem;">
                <span style="font-size: 0.875rem; font-weight: 500; color: var(--cds-text-primary);">Keystore Key Type:</span>
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                  <input
                    type="radio"
                    bind:group={keystoreKeyType}
                    value="secp256k1"
                    disabled={loading}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">secp256k1</span>
                  <span style="font-size: 0.75rem; color: var(--cds-text-secondary);">
                    ⚡ Ethereum compatible, did:key:zQ3sh...
                  </span>
                </label>
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                  <input
                    type="radio"
                    bind:group={keystoreKeyType}
                    value="Ed25519"
                    disabled={loading}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">Ed25519</span>
                  <span style="font-size: 0.75rem; color: var(--cds-text-secondary);">
                    🚀 Faster, smaller, did:key:z6Mk...
                  </span>
                </label>
              </div>
            {/if}
            
            <!-- Encryption Option -->
            <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
              <input
                type="checkbox"
                bind:checked={useEncryption}
                disabled={loading || (!extensionSupport.prf && !extensionSupport.largeBlob && !extensionSupport.hmacSecret)}
                style="cursor: pointer;"
              />
              <span style="color: var(--cds-text-primary);">Encrypt keystore with WebAuthn</span>
              <span style="font-size: 0.75rem; color: var(--cds-text-secondary);">🔐 Hardware protection</span>
            </label>
            
            <!-- Encryption Method -->
            {#if useEncryption}
              <div style="padding-left: 1.5rem; display: flex; flex-direction: column; gap: 0.5rem;">
                <span style="font-size: 0.875rem; font-weight: 500; color: var(--cds-text-primary);">Encryption Method:</span>
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                  <input
                    type="radio"
                    bind:group={encryptionMethod}
                    value="prf"
                    disabled={loading || !extensionSupport.prf}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">PRF (recommended)</span>
                  <span style="font-size: 0.75rem; color: var(--cds-text-secondary);">
                    {extensionSupport.prf ? '✅ Supported' : '❌ Not supported'}
                  </span>
                </label>
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                  <input
                    type="radio"
                    bind:group={encryptionMethod}
                    value="largeBlob"
                    disabled={loading || !extensionSupport.largeBlob}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">largeBlob</span>
                  <span style="font-size: 0.75rem; color: var(--cds-text-secondary);">
                    {extensionSupport.largeBlob ? '✅ Supported' : '❌ Not supported'}
                  </span>
                </label>
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                  <input
                    type="radio"
                    bind:group={encryptionMethod}
                    value="hmac-secret"
                    disabled={loading || !extensionSupport.hmacSecret}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">hmac-secret</span>
                  <span style="font-size: 0.75rem; color: var(--cds-text-secondary);">
                    {extensionSupport.hmacSecret ? '✅ Supported' : '❌ Not supported'}
                  </span>
                </label>
              </div>
            {/if}
            
            <!-- Benefits Summary -->
            {#if useKeystoreDID || useEncryption || !useKeystoreDID}
              <div style="margin-top: 0.5rem; padding: 0.75rem; background: var(--cds-layer); border-radius: 0.25rem;">
                <span style="font-size: 0.75rem; font-weight: 600; color: var(--cds-text-secondary);">ENABLED FEATURES:</span>
                <ul style="font-size: 0.75rem; color: var(--cds-text-primary); margin-top: 0.25rem; padding-left: 1.25rem;">
                  {#if useKeystoreDID}
                    <li>Persistent {keystoreKeyType} DID from OrbitDB keystore</li>
                    {#if keystoreKeyType === 'Ed25519'}
                      <li>Ed25519: Faster signing, smaller keys (32 bytes)</li>
                    {:else}
                      <li>secp256k1: Ethereum/Bitcoin compatible</li>
                    {/if}
                  {:else}
                    <li>P-256 DID from WebAuthn credential</li>
                    <li>Hardware-backed ECDSA signatures</li>
                  {/if}
                  {#if useEncryption}
                    <li>🔐 Keystore encrypted with <strong>AES-GCM 256-bit</strong></li>
                    <li>🔑 Secret key derived via <strong>WebAuthn {encryptionMethod}</strong></li>
                    <li>🛡️ Hardware-bound protection (authenticator)</li>
                  {/if}
                </ul>
              </div>
            {/if}
          </div>
        </div>
        
        <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
          <Button on:click={authenticate} disabled={loading} kind="primary">
            {loading ? 'Authenticating...' : 'Authenticate with WebAuthn'}
          </Button>

          {#if status.includes('failed') || status.includes('timeout')}
            <Button
              on:click={handleResetDatabase}
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
      <div style="margin-bottom: 1.5rem;">
        <div
          style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;"
        >
          <div style="flex: 1;">
            <h2
              style="font-size: 1.5rem; font-weight: bold; margin-bottom: 0.5rem;"
            >
              OrbitDB WebAuthn Demo DID
            </h2>
            {#if orbitdbInstances?.identity?.id}
              <div
                style="background: var(--cds-layer-accent); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--cds-border-subtle); margin-bottom: 1rem;"
              >
                <div
                  style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;"
                >
                  <span
                    style="font-size: 0.75rem; font-weight: 600; color: var(--cds-text-secondary); text-transform: uppercase; letter-spacing: 0.05em;"
                    >WebAuthn DID</span
                  >
                  <button
                    on:click={() =>
                      copyToClipboard(orbitdbInstances.identity.id)}
                    style="background: none; border: none; cursor: pointer; padding: 0.25rem; color: var(--cds-text-secondary); border-radius: 0.25rem; transition: all 0.2s ease;"
                    title="Copy DID to clipboard"
                    aria-label="Copy DID to clipboard"
                    on:mouseenter={(e) =>
                      (e.target.style.background = 'var(--cds-layer-hover)')}
                    on:mouseleave={(e) => (e.target.style.background = 'none')}
                  >
                    <svg
                      style="width: 0.875rem; height: 0.875rem;"
                      fill="currentColor"
                      viewBox="0 0 20 20"
                    >
                      <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"
                      ></path>
                      <path
                        d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"
                      ></path>
                    </svg>
                  </button>
                </div>
                <code
                  style="font-size: 0.8rem; color: var(--cds-text-primary); word-break: break-all; font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;"
                >
                  {orbitdbInstances.identity.id}
                </code>
              </div>
              
              <!-- Encryption Proof Display -->
              {#if encryptionProof && encryptionProof.encrypted}
                <div
                  style="background: linear-gradient(135deg, var(--cds-layer-accent) 0%, var(--cds-layer) 100%); padding: 0.75rem; border-radius: 0.5rem; border: 2px solid var(--cds-support-success); margin-bottom: 1rem;"
                >
                  <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                    <span style="font-size: 1rem;">🔐</span>
                    <span style="font-size: 0.75rem; font-weight: 700; color: var(--cds-support-success); text-transform: uppercase; letter-spacing: 0.1em;">
                      ENCRYPTION VERIFIED
                    </span>
                  </div>
                  
                  <div style="display: grid; gap: 0.5rem; font-size: 0.7rem; font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;">
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0.5rem; background: var(--cds-layer); border-radius: 0.25rem;">
                      <span style="color: var(--cds-text-secondary);">Method:</span>
                      <span style="color: var(--cds-text-primary); font-weight: 600;">{encryptionProof.method}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0.5rem; background: var(--cds-layer); border-radius: 0.25rem;">
                      <span style="color: var(--cds-text-secondary);">Algorithm:</span>
                      <span style="color: var(--cds-text-primary); font-weight: 600;">{encryptionProof.algorithm}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0.5rem; background: var(--cds-layer); border-radius: 0.25rem;">
                      <span style="color: var(--cds-text-secondary);">Ciphertext:</span>
                      <span style="color: var(--cds-text-primary);">{encryptionProof.ciphertextLength} bytes</span>
                    </div>
                    <div style="padding: 0.25rem 0.5rem; background: var(--cds-layer); border-radius: 0.25rem;">
                      <span style="color: var(--cds-text-secondary); display: block;">Ciphertext Hash (SHA-256):</span>
                      <span style="color: var(--cds-support-info); word-break: break-all; font-size: 0.65rem;">{encryptionProof.ciphertextHash}</span>
                    </div>
                    
                    {#if encryptionProof.hmacSecretUsed}
                      <div style="margin-top: 0.25rem; padding: 0.5rem; background: linear-gradient(90deg, rgba(0,128,0,0.1) 0%, transparent 100%); border-left: 3px solid var(--cds-support-success); border-radius: 0 0.25rem 0.25rem 0;">
                        <div style="font-size: 0.7rem; font-weight: 600; color: var(--cds-support-success); margin-bottom: 0.25rem;">
                          ✓ HMAC-SECRET EXTENSION ACTIVE
                        </div>
                        <div style="display: flex; justify-content: space-between; padding: 0.125rem 0;">
                          <span style="color: var(--cds-text-secondary);">Salt Hash:</span>
                          <span style="color: var(--cds-text-primary); font-size: 0.6rem;">{encryptionProof.saltHash?.slice(0, 16)}...</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; padding: 0.125rem 0;">
                          <span style="color: var(--cds-text-secondary);">Wrapped Key:</span>
                          <span style="color: var(--cds-text-primary); font-size: 0.6rem;">{encryptionProof.wrappedSKHash?.slice(0, 16)}...</span>
                        </div>
                        <div style="color: var(--cds-text-secondary); font-size: 0.6rem; margin-top: 0.25rem;">
                          🔒 Key derivation bound to WebAuthn authenticator hardware
                        </div>
                      </div>
                    {/if}
                    
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0.5rem; background: var(--cds-layer); border-radius: 0.25rem;">
                      <span style="color: var(--cds-text-secondary);">Security:</span>
                      <span style="color: var(--cds-support-success); font-weight: 600;">Hardware-backed</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0.5rem; background: var(--cds-layer); border-radius: 0.25rem;">
                      <span style="color: var(--cds-text-secondary);">Storage:</span>
                      <span style="color: var(--cds-text-primary);">{encryptionProof.storage || 'IndexedDB'}</span>
                    </div>
                  </div>
                </div>
              {/if}
            {/if}
          </div>
          <div style="display: flex; gap: 0.5rem; align-self: flex-start;">
            <Button
              on:click={refreshVerificationStates}
              kind="tertiary"
              size="small"
              disabled={loading || todos.length === 0}
            >
              Refresh Verification
            </Button>
            <Button
              on:click={handleResetDatabase}
              kind="danger-tertiary"
              size="small"
              disabled={loading}
            >
              {loading ? 'Resetting...' : 'Reset DB'}
            </Button>
            <Button on:click={handleLogout} kind="ghost" size="small">
              Logout
            </Button>
          </div>
        </div>
      </div>

      <!-- Add New TODO -->
      <div style="display: flex; gap: 0.75rem; margin-bottom: 1.5rem;">
        <input
          type="text"
          bind:value={newTodo}
          placeholder="Add a new TODO..."
          on:keydown={(e) => e.key === 'Enter' && handleAddTodo()}
          style="flex: 1; padding: 0.5rem 1rem; border: 1px solid var(--cds-border-subtle); border-radius: 0.5rem; font-size: 1rem; background: var(--cds-field); color: var(--cds-text-primary);"
        />
        <Button
          on:click={handleAddTodo}
          disabled={loading || !newTodo.trim()}
          kind="primary"
        >
          {loading ? '...' : 'Add'}
        </Button>
      </div>

      <!-- TODO List -->
      {#if todos.length === 0}
        <div
          style="text-align: center; padding: 3rem 0; color: var(--cds-text-secondary);"
        >
          <div style="font-size: 2.5rem; margin-bottom: 1rem;">📝</div>
          <p>No TODOs yet. Add your first one above!</p>
        </div>
      {:else}
        <div style="display: flex; flex-direction: column; gap: 0.75rem;">
          {#each todos as todo (todo.id)}
            <div
              style="display: flex; align-items: center; gap: 0.75rem; padding: 1rem; background-color: var(--cds-layer-accent); border-radius: 0.5rem; border: 1px solid var(--cds-border-subtle);"
            >
              <button
                on:click={() => handleToggleTodo(todo)}
                style="flex-shrink: 0; background: none; border: none; cursor: pointer;"
                disabled={loading}
              >
                {#if todo.completed}
                  <div
                    style="width: 1.25rem; height: 1.25rem; background-color: var(--cds-support-success); border-radius: 50%; display: flex; align-items: center; justify-content: center;"
                  >
                    <svg
                      style="width: 0.75rem; height: 0.75rem; color: white;"
                      fill="currentColor"
                      viewBox="0 0 20 20"
                    >
                      <path
                        fill-rule="evenodd"
                        d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                        clip-rule="evenodd"
                      />
                    </svg>
                  </div>
                {:else}
                  <div
                    style="width: 1.25rem; height: 1.25rem; border: 2px solid var(--cds-border-subtle); border-radius: 50%;"
                  ></div>
                {/if}
              </button>

              <span
                style="flex: 1; color: {todo.completed
                  ? 'var(--cds-text-secondary)'
                  : 'var(--cds-text-primary)'}; {todo.completed
                  ? 'text-decoration: line-through;'
                  : ''}"
              >
                {todo.text}
              </span>
              
              <!-- Identity Verification Badge -->
              {#if todoVerifications.has(todo.id)}
                {@const verification = todoVerifications.get(todo.id)}
                <IdentityVerificationBadge
                  identityHash={verification.identityHash}
                  webAuthnDID={orbitdbInstances?.identity?.id}
                  verificationState={verification.success}
                  timestamp={verification.timestamp}
                />
              {:else}
                <IdentityVerificationBadge
                  identityHash="pending..."
                  webAuthnDID={orbitdbInstances?.identity?.id}
                  verificationState={null}
                  timestamp={Date.now()}
                />
              {/if}

              <button
                on:click={() => handleDeleteTodo(todo)}
                disabled={loading}
                style="color: var(--cds-support-error); background: none; border: none; cursor: pointer; padding: 0.25rem;"
                aria-label="Delete TODO item"
              >
                <svg
                  style="width: 1rem; height: 1rem;"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fill-rule="evenodd"
                    d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                    clip-rule="evenodd"
                  />
                </svg>
              </button>
            </div>
          {/each}
        </div>

        <div
          style="margin-top: 1.5rem; font-size: 0.875rem; color: var(--cds-text-secondary); text-align: center;"
        >
          {todoStats.total} total • {todoStats.completed} completed
        </div>
      {/if}
    </Tile>
  {/if}

  <!-- Info Section -->
  <Tile
    light
    style="margin-top: 2rem; background-color: var(--cds-layer-accent);"
  >
    <h3
      style="font-size: 1.125rem; font-weight: 600; color: var(--cds-text-primary); margin-bottom: 0.75rem;"
    >
      🔐 WebAuthn Security Features
    </h3>
    <ul
      style="list-style: none; padding: 0; margin: 0; color: var(--cds-text-secondary);"
    >
      <li style="margin-bottom: 0.5rem; font-size: 0.875rem;">
        ✅ Hardware-secured authentication (Face ID, Touch ID, Windows Hello)
      </li>
      <li style="margin-bottom: 0.5rem; font-size: 0.875rem;">
        ✅ Private keys never leave your device
      </li>
      <li style="margin-bottom: 0.5rem; font-size: 0.875rem;">
        ✅ Decentralized data storage with OrbitDB
      </li>
      <li style="margin-bottom: 0.5rem; font-size: 0.875rem;">
        ✅ No passwords or usernames required
      </li>
    </ul>
    
    {#if encryptionProof && encryptionProof.encrypted}
      <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--cds-border-subtle);">
        <h4 style="font-size: 0.875rem; font-weight: 600; color: var(--cds-text-primary); margin-bottom: 0.5rem;">
          🔑 Keystore Encryption (Cryptographic Proof)
        </h4>
        <p style="font-size: 0.75rem; color: var(--cds-text-secondary); margin-bottom: 0.5rem;">
          Your OrbitDB keystore private key is encrypted using <strong>AES-GCM 256-bit</strong> encryption. 
          {#if encryptionProof.hmacSecretUsed}
            The encryption key is derived using the <strong>WebAuthn hmac-secret extension</strong>, which means:
          {:else}
            The encryption key is stored using <strong>WebAuthn largeBlob extension</strong>, which means:
          {/if}
        </p>
        <ul style="font-size: 0.75rem; color: var(--cds-text-secondary); margin: 0; padding-left: 1.25rem;">
          {#if encryptionProof.hmacSecretUsed}
            <li>🔒 The decryption key is <strong>derived from your authenticator hardware</strong></li>
            <li>🔒 Even if someone steals your encrypted keystore, they <strong>cannot decrypt it</strong> without your authenticator</li>
            <li>🔒 Each authentication generates the same HMAC output (deterministic)</li>
          {:else}
            <li>🔒 The decryption key is <strong>stored inside your authenticator</strong></li>
            <li>🔒 The key can only be retrieved with biometric authentication</li>
          {/if}
          <li>🔒 Protected from XSS attacks, malicious browser extensions, and data theft</li>
          <li>💾 Encrypted keystore stored in <strong>IndexedDB</strong> (not localStorage)</li>
        </ul>
      </div>
    {/if}
  </Tile>
</div>

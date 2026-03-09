<script>
  import { onDestroy, onMount } from 'svelte';
  import {
    WebAuthnDIDProvider,
    checkWebAuthnSupport,
    KeystoreEncryption,
  } from '@le-space/orbitdb-identity-provider-webauthn-did';
  import {
    extractPrfSeedFromCredential,
    getDefaultWorkerKeystoreClient,
    isWorkerKeystoreAvailable,
    resetDefaultWorkerKeystoreClient,
  } from '@le-space/orbitdb-identity-provider-webauthn-did/standalone';

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
  let encryptionMethod = 'largeBlob'; // or 'hmac-secret'
  let useKeystoreDID = true; // Use persistent DID from OrbitDB keystore (instead of WebAuthn P-256)
  let keystoreKeyType = 'Ed25519'; // Key type: 'secp256k1' or 'Ed25519' (default: Ed25519)
  let extensionSupport = { largeBlob: false, hmacSecret: false };
  let useWorkerKeystore = false;
  let workerAvailable = false;
  let workerClient = null;
  let workerStatus = 'idle';
  let workerDid = null;
  let workerSeedSource = null;
  let workerArchiveRestored = false;
  let workerSignatureVerified = null;
  let workerLastOperation = null;
  let workerLastSignatureLength = 0;
  let workerProbeCount = 0;
  let activeSigningBackend = 'main-thread-provider';

  const WORKER_ARCHIVE_STORAGE_KEY = 'worker-keystore-archive';
  const WORKER_ARCHIVE_META_KEY = 'worker-keystore-meta';

  // Computed values
  $: todoStats = getTodoStats(todos);
  $: workerModeSupported =
    workerAvailable &&
    useKeystoreDID &&
    keystoreKeyType === 'Ed25519';
  $: if (!workerModeSupported) {
    useWorkerKeystore = false;
  }

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
    workerAvailable = isWorkerKeystoreAvailable();

    // Expose utilities to window for E2E testing
    if (typeof window !== 'undefined') {
      const { addPRFToCredentialOptions, wrapSKWithPRF, unwrapSKWithPRF } =
        KeystoreEncryption;
      window.KeystoreEncryption = {
        ...KeystoreEncryption,
        addPRFToCredentialOptions,
        wrapSKWithPRF,
        unwrapSKWithPRF,
      };
      window.__encryptedKeystoreDemo = {
        getState: () => ({
          credentialReady: Boolean(credential),
          isAuthenticated,
          useKeystoreDID,
          keystoreKeyType,
          useEncryption,
          encryptionMethod,
          workerAvailable,
          workerModeSupported,
          useWorkerKeystore,
          workerStatus,
          workerDid,
          workerSeedSource,
          workerArchiveRestored,
          workerSignatureVerified,
          workerLastOperation,
          workerLastSignatureLength,
          workerProbeCount,
          activeSigningBackend,
          orbitdbIdentityDid: orbitdbInstances?.identity?.id || null,
        }),
        clearWorkerArchive: () => {
          clearWorkerArchiveStorage();
        },
      };
    }

    await initializeWebAuthn();
    await checkEncryptionSupport();
  });

  onDestroy(() => {
    resetWorkerClient();
  });

  async function checkEncryptionSupport() {
    try {
      extensionSupport = await KeystoreEncryption.checkExtensionSupport();
      console.log('Encryption extension support:', extensionSupport);

      // Auto-select best encryption method
      if (extensionSupport.largeBlob) {
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

  function resetWorkerClient() {
    workerClient = null;
    resetDefaultWorkerKeystoreClient();
  }

  function clearWorkerArchiveStorage() {
    localStorage.removeItem(WORKER_ARCHIVE_STORAGE_KEY);
    localStorage.removeItem(WORKER_ARCHIVE_META_KEY);
  }

  function persistWorkerArchive(ciphertext, iv, did) {
    localStorage.setItem(
      WORKER_ARCHIVE_STORAGE_KEY,
      JSON.stringify({
        ciphertext: Array.from(ciphertext),
        iv: Array.from(iv),
      })
    );
    localStorage.setItem(
      WORKER_ARCHIVE_META_KEY,
      JSON.stringify({
        did,
      })
    );
  }

  function loadStoredWorkerArchive() {
    try {
      const payloadRaw = localStorage.getItem(WORKER_ARCHIVE_STORAGE_KEY);
      if (!payloadRaw) return null;
      const payload = JSON.parse(payloadRaw);
      const metaRaw = localStorage.getItem(WORKER_ARCHIVE_META_KEY);
      const meta = metaRaw ? JSON.parse(metaRaw) : {};
      return {
        ciphertext: new Uint8Array(payload.ciphertext || []),
        iv: new Uint8Array(payload.iv || []),
        did: meta.did || null,
      };
    } catch (error) {
      console.warn('Failed to load stored worker archive:', error);
      clearWorkerArchiveStorage();
      return null;
    }
  }

  async function runWorkerSignatureProbe(operation, payload) {
    if (!workerClient) {
      return;
    }

    const data = new TextEncoder().encode(JSON.stringify(payload));
    const signature = await workerClient.sign(data);
    const verified = await workerClient.verify(data, signature);
    workerLastOperation = operation;
    workerLastSignatureLength = signature.length;
    workerSignatureVerified = verified;
    workerProbeCount += 1;
    workerStatus = verified ? 'ready' : 'verification-failed';
  }

  async function initializeWorkerKeystore() {
    if (!useWorkerKeystore) {
      activeSigningBackend = 'main-thread-provider';
      workerStatus = 'disabled';
      workerDid = null;
      workerSeedSource = null;
      workerArchiveRestored = false;
      workerSignatureVerified = null;
      workerLastOperation = null;
      workerLastSignatureLength = 0;
      resetWorkerClient();
      return;
    }

    workerStatus = 'initializing';
    workerArchiveRestored = false;
    workerSignatureVerified = null;
    workerLastOperation = null;
    workerLastSignatureLength = 0;
    resetWorkerClient();
    workerClient = getDefaultWorkerKeystoreClient();

    const { seed, source } = await extractPrfSeedFromCredential(credential, {
      prfInput: credential.prfInput,
    });
    workerSeedSource = source;
    await workerClient.initWithPrfSeed(seed);

    const storedArchive = loadStoredWorkerArchive();
    if (storedArchive) {
      const archive = await workerClient.decryptArchive(
        storedArchive.ciphertext,
        storedArchive.iv
      );
      await workerClient.loadArchive(archive);
      workerDid = storedArchive.did;
      workerArchiveRestored = true;
      workerStatus = 'restored';
    } else {
      const generated = await workerClient.generateEd25519Identity();
      workerDid = generated.did;
      const encryptedArchive = await workerClient.encryptArchive(
        generated.archive
      );
      persistWorkerArchive(
        encryptedArchive.ciphertext,
        encryptedArchive.iv,
        generated.did
      );
      workerArchiveRestored = false;
      workerStatus = 'ready';
    }

    activeSigningBackend = 'worker-keystore';
    await runWorkerSignatureProbe('authenticate', {
      phase: 'authenticate',
      orbitdbIdentityDid: orbitdbInstances?.identity?.id || null,
      workerDid,
    });
  }

  async function createCredential() {
    try {
      loading = true;
      status = 'Creating WebAuthn credential...';

      credential = await WebAuthnDIDProvider.createCredential({
        userId: `todo-user-${Date.now()}`,
        displayName: 'TODO App User',
        encryptKeystore: useEncryption,
        keystoreEncryptionMethod: encryptionMethod,
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
      activeSigningBackend = 'main-thread-provider';

      status = 'Setting up OrbitDB...';
      // Use the extracted setupOrbitDB function with encryption options
      orbitdbInstances = await setupOrbitDB(credential, {
        useKeystoreDID: useKeystoreDID,
        keystoreKeyType: keystoreKeyType,
        encryptKeystore: useEncryption,
        encryptionMethod: encryptionMethod,
      });

      await initializeWorkerKeystore();

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

      const hasHmacErrors = error.errors?.some((e) =>
        e.message?.includes('hmac-secret')
      );
      if (hasHmacErrors) {
        return 'hmac-secret is not available for this credential. Recreate the credential with hmac-secret enabled or use largeBlob.';
      }

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
    }

    if (error?.message?.includes('hmac-secret')) {
      return 'hmac-secret is not available for this credential. Recreate the credential with hmac-secret enabled or use largeBlob.';
    }

    return `Authentication failed: ${error.message}`;
  }

  async function refreshTodos() {
    if (!database) return;

    try {
      todos = await loadTodos(database);

      // Refresh verification states after loading todos
      if (todos.length > 0) {
        console.log(
          `📋 Loaded ${todos.length} todos, scheduling verification...`
        );
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
      if (useWorkerKeystore) {
        await runWorkerSignatureProbe('add-todo', {
          id: `probe-${Date.now()}`,
          text: newTodo.trim(),
        });
      }
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
      if (useWorkerKeystore) {
        await runWorkerSignatureProbe('toggle-todo', {
          id: todo.id,
          completed: !todo.completed,
        });
      }
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
      if (useWorkerKeystore) {
        await runWorkerSignatureProbe('delete-todo', {
          id: todo.id,
        });
      }
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
      resetWorkerClient();
      workerStatus = 'idle';
      workerDid = null;
      workerSeedSource = null;
      workerArchiveRestored = false;
      workerSignatureVerified = null;
      workerLastOperation = null;
      workerLastSignatureLength = 0;
      workerProbeCount = 0;
      activeSigningBackend = 'main-thread-provider';

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
    console.log(
      `💾 Found ${globalVerifications.size} verifications in global store`
    );

    // Clear and update with global state
    todoVerifications.clear();
    for (const [todoId, verification] of globalVerifications) {
      todoVerifications.set(todoId, verification);
      console.log(
        `✅ Loaded verification for ${todoId}: ${verification.success ? 'PASSED' : 'FAILED'}`
      );
    }

    // For todos that don't have verification yet, use the simple verification approach
    if (database && orbitdbInstances?.identity?.id) {
      try {
        // Use the single verification approach
        const { verifyTodos } = await import('./verification.js');

        // Find todos that need verification
        const unverifiedTodos = todos.filter(
          (todo) => !todoVerifications.has(todo.id)
        );

        if (unverifiedTodos.length > 0) {
          console.log(
            `🔍 Running verification for ${unverifiedTodos.length} todos...`
          );

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

    console.log(
      '🔄 Refreshed verification states:',
      todoVerifications.size,
      'todos verified'
    );
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
      resetWorkerClient();
      workerStatus = 'idle';
      workerDid = null;
      workerSeedSource = null;
      workerArchiveRestored = false;
      workerSignatureVerified = null;
      workerLastOperation = null;
      workerLastSignatureLength = 0;
      workerProbeCount = 0;
      activeSigningBackend = 'main-thread-provider';
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
      resetWorkerClient();
      workerStatus = 'idle';
      workerDid = null;
      workerSeedSource = null;
      workerArchiveRestored = false;
      workerSignatureVerified = null;
      workerLastOperation = null;
      workerLastSignatureLength = 0;
      workerProbeCount = 0;
      activeSigningBackend = 'main-thread-provider';
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
        <div
          style="background: var(--cds-layer-accent); padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem; border: 1px solid var(--cds-border-subtle);"
        >
          <h3
            style="font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; color: var(--cds-text-primary);"
          >
            🔐 Security Options
          </h3>

          <div style="display: flex; flex-direction: column; gap: 0.75rem;">
            <!-- DID Source Selection -->
            <label
              style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;"
            >
              <input
                type="checkbox"
                bind:checked={useKeystoreDID}
                disabled={loading}
                style="cursor: pointer;"
              />
              <span style="color: var(--cds-text-primary);"
                >Use persistent keystore identity</span
              >
              <span
                style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                >🗄️ Instead of WebAuthn P-256</span
              >
            </label>

            <!-- Show info when keystore DID is NOT selected -->
            {#if !useKeystoreDID}
              <div
                style="padding-left: 1.5rem; padding: 0.5rem; background: var(--cds-layer); border-radius: 0.25rem; border-left: 3px solid var(--cds-interactive);"
              >
                <span
                  style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                >
                  ℹ️ Will use <strong style="color: var(--cds-text-primary);"
                    >P-256 DID</strong
                  >
                  from WebAuthn credential
                  <code style="font-size: 0.7rem; opacity: 0.8;"
                    >(did:key:zDna...)</code
                  >
                </span>
              </div>
            {/if}

            <!-- Keystore Key Type Selection -->
            {#if useKeystoreDID}
              <div
                style="padding-left: 1.5rem; display: flex; flex-direction: column; gap: 0.5rem;"
              >
                <span
                  style="font-size: 0.875rem; font-weight: 500; color: var(--cds-text-primary);"
                  >Keystore Key Type:</span
                >
                <label
                  style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;"
                >
                  <input
                    type="radio"
                    bind:group={keystoreKeyType}
                    value="secp256k1"
                    disabled={loading}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">secp256k1</span>
                  <span
                    style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                  >
                    ⚡ Ethereum compatible, did:key:zQ3sh...
                  </span>
                </label>
                <label
                  style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;"
                >
                  <input
                    type="radio"
                    bind:group={keystoreKeyType}
                    value="Ed25519"
                    disabled={loading}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">Ed25519</span>
                  <span
                    style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                  >
                    🚀 Faster, smaller, did:key:z6Mk...
                  </span>
                </label>
              </div>
            {/if}

            <!-- Encryption Option -->
            <label
              style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;"
            >
              <input
                type="checkbox"
                bind:checked={useEncryption}
                disabled={loading ||
                  (!extensionSupport.largeBlob && !extensionSupport.hmacSecret)}
                style="cursor: pointer;"
              />
              <span style="color: var(--cds-text-primary);"
                >Encrypt keystore with WebAuthn</span
              >
              <span
                style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                >🔐 Hardware protection</span
              >
            </label>

            <label
              style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;"
            >
              <input
                type="checkbox"
                bind:checked={useWorkerKeystore}
                disabled={loading || !workerModeSupported}
                style="cursor: pointer;"
                data-testid="worker-mode-toggle"
              />
              <span style="color: var(--cds-text-primary);"
                >Use worker-backed Ed25519 keystore</span
              >
              <span
                style="font-size: 0.75rem; color: var(--cds-text-secondary);"
              >
                {#if workerModeSupported}
                  🧵 Sign outside main thread
                {:else if !workerAvailable}
                  ❌ Web Workers unavailable
                {:else}
                  ℹ️ Requires Ed25519 keystore identity
                {/if}
              </span>
            </label>

            <!-- Encryption Method -->
            {#if useEncryption}
              <div
                style="padding-left: 1.5rem; display: flex; flex-direction: column; gap: 0.5rem;"
              >
                <span
                  style="font-size: 0.875rem; font-weight: 500; color: var(--cds-text-primary);"
                  >Encryption Method:</span
                >
                <label
                  style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;"
                >
                  <input
                    type="radio"
                    bind:group={encryptionMethod}
                    value="largeBlob"
                    disabled={loading || !extensionSupport.largeBlob}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">largeBlob</span>
                  <span
                    style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                  >
                    {extensionSupport.largeBlob
                      ? '✅ Supported'
                      : '❌ Not supported'}
                  </span>
                </label>
                <label
                  style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;"
                >
                  <input
                    type="radio"
                    bind:group={encryptionMethod}
                    value="hmac-secret"
                    disabled={loading || !extensionSupport.hmacSecret}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);"
                    >hmac-secret</span
                  >
                  <span
                    style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                  >
                    {extensionSupport.hmacSecret
                      ? '✅ Supported'
                      : '❌ Not supported'}
                  </span>
                </label>
              </div>
            {/if}

            <!-- Benefits Summary -->
            {#if useKeystoreDID || useEncryption || !useKeystoreDID}
              <div
                style="margin-top: 0.5rem; padding: 0.75rem; background: var(--cds-layer); border-radius: 0.25rem;"
              >
                <span
                  style="font-size: 0.75rem; font-weight: 600; color: var(--cds-text-secondary);"
                  >ENABLED FEATURES:</span
                >
                <ul
                  style="font-size: 0.75rem; color: var(--cds-text-primary); margin-top: 0.25rem; padding-left: 1.25rem;"
                >
                  {#if useKeystoreDID}
                    <li>
                      Persistent {keystoreKeyType} DID from OrbitDB keystore
                    </li>
                    {#if useWorkerKeystore}
                      <li>Worker-backed Ed25519 signer initialized from passkey seed</li>
                    {/if}
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
                    <li>Keystore encrypted with AES-GCM 256-bit</li>
                    <li>Secret key protected by WebAuthn hardware</li>
                    <li>Protected from XSS, extensions, theft</li>
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
                <div
                  style="display: flex; flex-direction: column; gap: 0.35rem; margin-top: 0.75rem;"
                >
                  <div data-testid="signing-backend">
                    <strong>Active keystore mode:</strong> {activeSigningBackend}
                  </div>
                  <div data-testid="worker-status">
                    <strong>Worker keystore:</strong> {workerStatus}
                  </div>
                  {#if workerDid}
                    <div data-testid="worker-did">
                      <strong>Worker signer DID:</strong> <code>{workerDid}</code>
                    </div>
                  {/if}
                  {#if useWorkerKeystore}
                    <div data-testid="worker-archive-status">
                      <strong>Worker archive:</strong>
                      {workerArchiveRestored ? 'restored from storage' : 'created for this session'}
                    </div>
                    <div data-testid="worker-seed-source">
                      <strong>Seed source:</strong> {workerSeedSource}
                    </div>
                    <div data-testid="worker-probe-status">
                      <strong>Last worker probe:</strong>
                      {workerLastOperation || 'none'} /
                      {workerSignatureVerified === null
                        ? 'not-run'
                        : workerSignatureVerified
                          ? 'verified'
                          : 'failed'} /
                      {workerLastSignatureLength} bytes
                    </div>
                  {/if}
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
  </Tile>
</div>

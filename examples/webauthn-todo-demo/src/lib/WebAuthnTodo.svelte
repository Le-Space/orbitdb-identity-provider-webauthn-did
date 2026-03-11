<script>
  import { onMount } from 'svelte';
  import {
    WebAuthnDIDProvider,
    checkWebAuthnSupport,
    checkExtensionSupport,
  } from '@le-space/orbitdb-identity-provider-webauthn-did';
  import { getWebAuthnConfig } from '../../../../src/webauthn/config.js';
  import {
    createDidLargeBlobPayload,
    parseDidLargeBlobPayload,
    readLargeBlobMetadata,
    writeLargeBlobMetadata,
  } from '../../../../src/webauthn/large-blob-metadata.js';

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
  let webAuthnConfig = getWebAuthnConfig();

  console.log('webAuthnConfig', webAuthnConfig);
  let recoverySteps = [];
  let lastAssertionDiagnostics = {
    seen: false,
    omittedAllowCredentials: null,
    mediation: null,
    rpId: null,
  };

  // Identity verification tracking (not stored in database)
  let todoVerifications = new Map(); // Map<todoId, {verified: boolean, timestamp: number, identityHash: string}>

  // WebAuthn support detection
  let webAuthnSupported = false;
  let webAuthnPlatformAvailable = false;
  let extensionSupport = { largeBlob: false, hmacSecret: false };
  let currentRpId = 'unknown';

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
    currentRpId = window.location.hostname;
    installAssertionDiagnostics();
    await initializeWebAuthn();
  });

  function installAssertionDiagnostics() {
    if (
      typeof navigator === 'undefined' ||
      !navigator.credentials ||
      typeof navigator.credentials.get !== 'function'
    ) {
      return;
    }

    const credentialsApi = navigator.credentials;
    if (credentialsApi.__discoverableDiagnosticsInstalled) {
      webAuthnConfig = getWebAuthnConfig();
      return;
    }

    const originalGet = credentialsApi.get.bind(credentialsApi);
    credentialsApi.get = async (options) => {
      const publicKey = options?.publicKey || {};
      lastAssertionDiagnostics = {
        seen: true,
        omittedAllowCredentials: !(
          Array.isArray(publicKey.allowCredentials) &&
          publicKey.allowCredentials.length > 0
        ),
        mediation: options?.mediation || null,
        rpId: publicKey.rpId || window.location.hostname,
      };
      webAuthnConfig = getWebAuthnConfig();
      return originalGet(options);
    };
    credentialsApi.__discoverableDiagnosticsInstalled = true;
    webAuthnConfig = getWebAuthnConfig();
  }

  async function initializeWebAuthn() {
    try {
      status = 'Checking WebAuthn support...';
      const support = await checkWebAuthnSupport();
      extensionSupport = await checkExtensionSupport();
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

  function bytesEqual(left, right) {
    if (!left || !right || left.length !== right.length) return false;
    for (let i = 0; i < left.length; i += 1) {
      if (left[i] !== right[i]) return false;
    }
    return true;
  }

  function startRecoveryStepLog(title) {
    console.log('[Recovery Step]', { label: title, status: 'running' });
    recoverySteps = [{ label: title, status: 'running', detail: '' }];
  }

  function pushRecoveryStep(label, status, detail = '') {
    console.log('[Recovery Step]', { label, status, detail });
    recoverySteps = [...recoverySteps, { label, status, detail }];
  }

  function markInitialStep(status, detail = '') {
    if (recoverySteps.length === 0) return;
    console.log('[Recovery Step]', {
      label: recoverySteps[0].label,
      status,
      detail,
    });
    recoverySteps = [
      { ...recoverySteps[0], status, detail },
      ...recoverySteps.slice(1),
    ];
  }

  function logWebAuthnResponse(label, credential) {
    const response = credential?.response;
    const getPublicKeyResult =
      typeof response?.getPublicKey === 'function'
        ? response.getPublicKey()
        : null;

    console.group(`[WebAuthn Debug] ${label}`);
    console.log('credential', credential);
    console.log('credential.id', credential?.id);
    console.log('credential.type', credential?.type);
    console.log('credential.rawId', credential?.rawId);
    console.log('credential.response', response);
    console.log('response.clientDataJSON', response?.clientDataJSON);
    console.log('response.attestationObject', response?.attestationObject);
    console.log('response.authenticatorData', response?.authenticatorData);
    console.log('response.signature', response?.signature);
    console.log('response.userHandle', response?.userHandle);
    console.log(
      'response.getPublicKey exists',
      typeof response?.getPublicKey === 'function'
    );
    console.log('response.getPublicKey()', getPublicKeyResult);
    console.log(
      'client extension results',
      credential?.getClientExtensionResults?.() || null
    );
    console.groupEnd();
  }

  async function useExistingPasskey() {
    try {
      loading = true;
      status = 'Checking for an existing passkey on this device...';
      startRecoveryStepLog('Start discoverable passkey recovery');
      markInitialStep('success', 'Started recovery flow');
      pushRecoveryStep(
        'Check largeBlob support',
        extensionSupport.largeBlob ? 'success' : 'warning',
        extensionSupport.largeBlob
          ? 'Browser reports largeBlob support'
          : 'Browser did not report largeBlob support'
      );

      pushRecoveryStep(
        'Run discoverable authentication with largeBlob read',
        'running',
        'Waiting for passkey selection'
      );
      const { assertion, blob, extensionResults } = await readLargeBlobMetadata({
        rpId: window.location.hostname,
        discoverableCredentials: true,
      });
      console.log('[Recovery Step] largeBlob read result', {
        blobLength: blob?.byteLength || 0,
        extensionResults,
      });
      recoverySteps = recoverySteps.map((step, index) =>
        index === recoverySteps.length - 1
          ? {
              ...step,
              status: assertion ? 'success' : 'error',
              detail: assertion
                ? 'Authenticator returned an assertion'
                : 'No assertion returned',
            }
          : step
      );

      if (!assertion) {
        status = 'No existing passkey was returned by WebAuthn.';
        return;
      }

      logWebAuthnResponse('demo useExistingPasskey navigator.credentials.get()', assertion);

      pushRecoveryStep(
        'Read largeBlob metadata',
        blob ? 'success' : 'warning',
        blob
          ? `Recovered ${blob.byteLength} bytes from largeBlob`
          : 'No largeBlob metadata found on this credential'
      );

      if (blob) {
        const recovered = parseDidLargeBlobPayload(blob);
        pushRecoveryStep(
          'Parse identity metadata',
          'success',
          recovered.did
            ? `Recovered DID ${recovered.did}`
            : 'Recovered public key metadata from largeBlob'
        );
        credential = {
          ...recovered,
          attestationObject: new Uint8Array(),
        };
        storeCredential(credential);
        pushRecoveryStep(
          'Bind recovered credential locally',
          'success',
          'Stored recovered metadata in localStorage for future reuse'
        );
        status =
          'Recovered OrbitDB identity metadata from largeBlob. Ready to authenticate.';
        return;
      }

      const discoveredCredentialId = new Uint8Array(assertion.rawId);
      const storedCredential = loadStoredCredential();
      const localMatch =
        storedCredential &&
        bytesEqual(storedCredential.rawCredentialId, discoveredCredentialId);
      pushRecoveryStep(
        'Fallback to local metadata match',
        localMatch ? 'success' : 'warning',
        localMatch
          ? 'Matched discoverable credential against localStorage metadata'
          : 'No matching local metadata found for this credential'
      );

      if (localMatch) {
        credential = storedCredential;
        status =
          'Existing passkey matched locally stored OrbitDB identity metadata. Ready to authenticate.';
        return;
      }

      credential = null;
      status =
        'Passkey found, but no recoverable OrbitDB identity metadata was found in largeBlob or local storage.';
    } catch (error) {
      console.error('Existing passkey lookup failed:', error);
      pushRecoveryStep('Recovery failed', 'error', error.message);
      status = `Failed to use existing passkey: ${error.message}`;
    } finally {
      loading = false;
    }
  }

  async function createCredential() {
    try {
      loading = true;
      status = 'Creating WebAuthn credential...';
      startRecoveryStepLog('Create new passkey and persist recovery metadata');

      credential = await WebAuthnDIDProvider.createCredential({
        userId: `todo-user-${Date.now()}`,
        displayName: 'TODO App User',
      });
      markInitialStep('success', 'Passkey registration completed');

      const did = await WebAuthnDIDProvider.createDID(credential);
      pushRecoveryStep('Derive DID from public key', 'success', did);

      if (extensionSupport.largeBlob) {
        const payload = createDidLargeBlobPayload(credential, did);
        pushRecoveryStep(
          'Write identity metadata to largeBlob',
          'running',
          `Writing ${payload.byteLength} bytes`
        );
        const { extensionResults } = await writeLargeBlobMetadata({
          credentialId: credential.rawCredentialId,
          rpId: window.location.hostname,
          payload,
        });
        console.log('[Recovery Step] largeBlob write result', {
          extensionResults,
        });
        recoverySteps = recoverySteps.map((step, index) =>
          index === recoverySteps.length - 1
            ? {
                ...step,
                status: 'success',
                detail: 'largeBlob write completed',
              }
            : step
        );
      } else {
        pushRecoveryStep(
          'Write identity metadata to largeBlob',
          'warning',
          'Skipped because largeBlob support is not available'
        );
      }

      // Store credential for future use
      storeCredential(credential);
      pushRecoveryStep(
        'Store local fallback metadata',
        'success',
        'Saved credential metadata to localStorage'
      );

      status = 'Credential created successfully!';
    } catch (error) {
      console.error('Credential creation failed:', error);
      pushRecoveryStep('Create credential failed', 'error', error.message);
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
      // Use the extracted setupOrbitDB function
      orbitdbInstances = await setupOrbitDB(credential);

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

    <div
      style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--cds-border-subtle);"
    >
      <div style="font-size: 0.75rem; font-weight: 600; margin-bottom: 0.5rem;">
        Discoverable Credential Diagnostics
      </div>
      <div style="font-size: 0.875rem; color: var(--cds-text-secondary);">
        <div>
          Global config: <strong
            >{webAuthnConfig.discoverableCredentials
              ? 'discoverable'
              : 'non-discoverable'}</strong
          >
        </div>
        <div>
          Last assertion:
          <strong>
            {#if !lastAssertionDiagnostics.seen}
              no assertion yet
            {:else if lastAssertionDiagnostics.omittedAllowCredentials}
              omitted `allowCredentials`
            {:else}
              included `allowCredentials`
            {/if}
          </strong>
        </div>
        <div>
          RP ID: <code>{lastAssertionDiagnostics.rpId || currentRpId}</code>
        </div>
      </div>
    </div>

    {#if recoverySteps.length > 0}
      <div
        style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--cds-border-subtle);"
      >
        <div style="font-size: 0.75rem; font-weight: 600; margin-bottom: 0.5rem;">
          Recovery Steps
        </div>
        <div style="font-size: 0.875rem; color: var(--cds-text-secondary);">
          {#each recoverySteps as step}
            <div style="margin-bottom: 0.35rem;">
              <strong>{step.status.toUpperCase()}</strong> {step.label}{step.detail ? `: ${step.detail}` : ''}
            </div>
          {/each}
        </div>
      </div>
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
        <Button
          on:click={useExistingPasskey}
          disabled={loading || !webAuthnSupported}
          kind="secondary"
          style="margin-left: 0.75rem;"
        >
          {loading ? 'Checking...' : 'Use Existing Passkey'}
        </Button>
      {:else}
        <p style="margin-bottom: 1.5rem;">
          Use your biometric authentication to access your secure TODO list.
        </p>
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
                data-testid="toggle-todo"
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

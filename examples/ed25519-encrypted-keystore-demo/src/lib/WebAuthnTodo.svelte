<script>
  import { onDestroy, onMount } from 'svelte';
  import {
    WebAuthnDIDProvider,
    checkWebAuthnSupport,
    KeystoreEncryption,
  } from '@le-space/orbitdb-identity-provider-webauthn-did';
  import {
    createWorkerSigner,
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
  } from './database.js';
  import {
    Button,
    Tile,
    InlineNotification,
    Loading,
  } from 'carbon-components-svelte';
  import { Checkmark, Warning } from 'carbon-icons-svelte';
  import IdentityVerificationBadge from '$shared/IdentityVerificationBadge.svelte';
  import ForgeryCheck from '$shared/ForgeryCheck.svelte';
  import { verifyDatabase } from '$shared/lib/verification.js';
  import {
    installPromptCounter,
    promptCounts,
  } from '$shared/lib/prompt-counter.js';

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
  let todoVerifications = new Map(); // Map<todoId, verifyEntry result> — see $shared/lib/verification.js

  // WebAuthn support detection
  let webAuthnSupported = false;
  let webAuthnPlatformAvailable = false;

  // NEW: Encryption options
  let useEncryption = true; // Enable encryption by default
  let encryptionMethod = 'prf'; // 'prf', 'largeBlob' or 'hmac-secret'
  let useKeystoreDID = true; // Use persistent DID from OrbitDB keystore (instead of WebAuthn P-256)
  let keystoreKeyType = 'Ed25519'; // Key type: 'secp256k1' or 'Ed25519' (default: Ed25519)
  // `known: false` means the browser could not tell us, which is not the same
  // as "unsupported" — see checkEncryptionSupport().
  let extensionSupport = {
    prf: false,
    largeBlob: false,
    hmacSecret: false,
    known: false,
  };
  // What the authenticator agreed to during registration, which is a different
  // question from what the browser can negotiate. Null until a credential
  // exists. A platform authenticator commonly answers yes to PRF and no to
  // hmac-secret on a browser that advertises both.
  let credentialSupport = null;
  let useWorkerKeystore = false;
  let workerAvailable = false;
  let workerClient = null;
  let workerStatus = 'idle';
  let workerDid = null;
  let workerSeedSource = null;
  // 'session-keystore': the sealed key, unlocked into a keystore that lives in
  // memory for the session. 'worker-signer': the key is derived in a Web
  // Worker each session and never exists in this page; OrbitDB signs through
  // it. Read from the provider after authenticating, not assumed.
  let activeSigningBackend = 'session-keystore';
  let signer = null;
  let encryptionState = null; // provider.encryptionState
  let signingKey = null; // { type, where }
  let identityHash = null;

  // Computed values
  $: todoStats = getTodoStats(todos);
  $: workerModeSupported =
    workerAvailable && useKeystoreDID && keystoreKeyType === 'Ed25519';
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
    installPromptCounter();
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
          activeSigningBackend,
          encryptionState,
          identityHash,
          signingKey,
          orbitdbIdentityDid: orbitdbInstances?.identity?.id || null,
        }),
      };
    }

    // Client capabilities first, then the credential. The order matters:
    // initializeWebAuthn() loads a stored credential and lets its recorded
    // answer refine the choice, and checkEncryptionSupport() picks a method
    // from the browser's view alone — running it second would undo that.
    await checkEncryptionSupport();
    await initializeWebAuthn();
  });

  onDestroy(() => {
    resetWorkerClient();
  });

  // The method values and the support-object keys do not spell the extension
  // the same way; keep the translation in one place rather than at each use.
  const SUPPORT_KEY = {
    prf: 'prf',
    largeBlob: 'largeBlob',
    'hmac-secret': 'hmacSecret',
  };
  const METHOD_PREFERENCE = ['prf', 'largeBlob', 'hmac-secret'];

  // Four states. Once a credential exists its answer overrules the browser's:
  // the browser saying yes only means it would pass the request along.
  //
  // Takes a method value ('prf', 'largeBlob', 'hmac-secret'), the same
  // vocabulary as methodAvailable() and the radio bindings. It briefly took a
  // boolean instead, and the call sites kept passing `extensionSupport.prf` —
  // so the lookup became `extensionSupport[true]`, undefined, and every method
  // rendered "Not supported" on a browser that supported all three.
  function supportLabel(method) {
    const name = SUPPORT_KEY[method];
    if (credentialSupport) {
      if (credentialSupport[name]) return '✅ Supported';
      if (extensionSupport[name]) return '⚠️ Browser yes, this passkey no';
      return '❌ Not supported';
    }
    if (extensionSupport[name]) return '✅ Supported';
    return extensionSupport.known ? '❌ Not supported' : '❓ Unknown';
  }

  // May the method be offered at all? Before a credential exists we go by the
  // browser and keep anything it cannot vouch for selectable. Afterwards the
  // authenticator decides, because it is the one that has to deliver.
  function methodAvailable(method) {
    const name = SUPPORT_KEY[method];
    if (credentialSupport) return credentialSupport[name] === true;
    return !extensionSupport.known || extensionSupport[name] === true;
  }

  /**
   * Adopt what the authenticator agreed to, and step off a method it refused.
   *
   * Without this the UI keeps promising a method the ceremony will not honour —
   * which is how "hmac-secret ✅ Supported" ends in "No hmac-secret output from
   * credential" (issue #9).
   */
  function applyCredentialSupport(support) {
    if (!support) return;
    credentialSupport = support;
    console.log('Authenticator extension support:', support);

    if (methodAvailable(encryptionMethod)) return;

    const fallback = METHOD_PREFERENCE.find((method) =>
      methodAvailable(method)
    );

    if (fallback) {
      console.warn(
        `Authenticator does not support ${encryptionMethod}; falling back to ${fallback}`
      );
      encryptionMethod = fallback;
    } else {
      console.warn(
        'Authenticator supports none of the encryption extensions; keystore encryption disabled'
      );
      useEncryption = false;
    }
  }

  async function checkEncryptionSupport() {
    try {
      extensionSupport = await KeystoreEncryption.checkExtensionSupport();
      console.log('Encryption extension support:', extensionSupport);

      // Auto-select best encryption method. PRF first: it is what the library
      // itself defaults to, and it derives the key from the authenticator
      // instead of storing a wrapped one.
      if (extensionSupport.prf) {
        encryptionMethod = 'prf';
      } else if (extensionSupport.largeBlob) {
        encryptionMethod = 'largeBlob';
      } else if (extensionSupport.hmacSecret) {
        encryptionMethod = 'hmac-secret';
      } else if (extensionSupport.known) {
        useEncryption = false; // The browser told us it supports none of them.
        console.warn('No encryption extensions supported');
      } else {
        // The browser has no getClientCapabilities(), so it cannot say in
        // advance. Attempting the ceremony is the only way to find out, and
        // it is better than refusing a feature that may well work.
        encryptionMethod = 'prf';
        console.warn(
          'Extension support could not be determined; attempting PRF anyway'
        );
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
        // Credentials registered before this was recorded carry no answer, so
        // the browser's view stands until the next registration.
        applyCredentialSupport(credential.extensionSupport);
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
          // Without this the reloaded prfInput stayed a plain object; the
          // browser refused it as a PRF input, the library fell back to the
          // credential ID as the seed without a word, and the worker archive
          // sealed under the real PRF seed could no longer be opened.
          ...(parsed.prfInput
            ? {
                prfInput: Uint8Array.from(
                  Array.isArray(parsed.prfInput)
                    ? parsed.prfInput
                    : Object.values(parsed.prfInput)
                ),
              }
            : {}),
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

  function resetWorkerState() {
    workerStatus = useWorkerKeystore ? 'idle' : 'disabled';
    workerDid = null;
    workerSeedSource = null;
    signer = null;
    activeSigningBackend = 'session-keystore';
    resetWorkerClient();
  }

  // The worker derives its Ed25519 key from the passkey's PRF output, keeps
  // it, and hands out only the public half; OrbitDB signs through it. Nothing
  // is stored — next session the same passkey derives the same key. Without
  // PRF there is no seed and no fallback: the mode refuses rather than sign
  // with something derived from a value anyone can read.
  async function prepareWorkerSigner() {
    workerStatus = 'initializing';
    resetWorkerClient();
    workerClient = getDefaultWorkerKeystoreClient();
    const { seed, source } = await extractPrfSeedFromCredential(credential, {
      prfInput: credential.prfInput,
    });
    workerSeedSource = source;
    if (source !== 'prf') {
      workerStatus = 'no-prf';
      throw new Error(
        'This authenticator returned no PRF output; the worker signer needs it.'
      );
    }
    const derived = await workerClient.deriveSigner(seed);
    workerDid = derived.did;
    workerStatus = 'ready';
    return createWorkerSigner(workerClient, derived);
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

      // The ceremony has now answered what the browser could only guess at.
      applyCredentialSupport(credential.extensionSupport);

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
      // The PRF input decides the worker's seed. JSON.stringify turns a
      // Uint8Array into {"0": …}, which the load below did not turn back.
      ...(credential.prfInput
        ? { prfInput: Array.from(credential.prfInput) }
        : {}),
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
      resetWorkerState();

      if (useWorkerKeystore) {
        status = 'Deriving the signing key in the worker...';
        signer = await prepareWorkerSigner();
      }

      status = 'Setting up OrbitDB...';
      // Use the extracted setupOrbitDB function with encryption options
      orbitdbInstances = await setupOrbitDB(credential, {
        useKeystoreDID: useKeystoreDID,
        keystoreKeyType: keystoreKeyType,
        encryptKeystore: useEncryption,
        encryptionMethod: encryptionMethod,
        signer,
      });
      activeSigningBackend = signer ? 'worker-signer' : 'session-keystore';
      encryptionState = orbitdbInstances.provider?.encryptionState ?? null;
      identityHash = orbitdbInstances.identity.hash;
      const key = await orbitdbInstances.keystore.getKey(
        orbitdbInstances.identity.id
      );
      signingKey = key
        ? {
            type: key.type,
            where: signer ? 'in the Web Worker' : 'in memory for this session',
          }
        : null;

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
      resetWorkerClient();
      workerStatus = 'idle';
      workerDid = null;
      workerSeedSource = null;
      signer = null;
      encryptionState = null;
      identityHash = null;
      signingKey = null;
      activeSigningBackend = 'session-keystore';

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
    if (!database || !orbitdbInstances?.identities) return;
    try {
      const { byKey } = await verifyDatabase({
        database,
        identities: orbitdbInstances.identities,
      });
      todoVerifications = byKey;
    } catch (error) {
      console.error('❌ Verification failed:', error);
    }
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
      signer = null;
      encryptionState = null;
      identityHash = null;
      signingKey = null;
      activeSigningBackend = 'session-keystore';
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
      signer = null;
      encryptionState = null;
      identityHash = null;
      signingKey = null;
      activeSigningBackend = 'session-keystore';
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
        OrbitDB Encrypted Keystore Demo
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
                  (extensionSupport.known &&
                    !extensionSupport.prf &&
                    !extensionSupport.largeBlob &&
                    !extensionSupport.hmacSecret)}
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
                >Sign in a Web Worker (key derived from the passkey, never in
                this page)</span
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
                    value="prf"
                    disabled={loading || !methodAvailable('prf')}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">PRF</span>
                  <span
                    style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                  >
                    {supportLabel('prf')}
                  </span>
                </label>
                <label
                  style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;"
                >
                  <input
                    type="radio"
                    bind:group={encryptionMethod}
                    value="largeBlob"
                    disabled={loading || !methodAvailable('largeBlob')}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);">largeBlob</span>
                  <span
                    style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                  >
                    {supportLabel('largeBlob')}
                  </span>
                </label>
                <label
                  style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;"
                >
                  <input
                    type="radio"
                    bind:group={encryptionMethod}
                    value="hmac-secret"
                    disabled={loading || !methodAvailable('hmac-secret')}
                    style="cursor: pointer;"
                  />
                  <span style="color: var(--cds-text-primary);"
                    >hmac-secret</span
                  >
                  <span
                    style="font-size: 0.75rem; color: var(--cds-text-secondary);"
                  >
                    {supportLabel('hmac-secret')}
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
                      <li>
                        Ed25519 key derived from the passkey inside a Web
                        Worker; OrbitDB signs through it, the page never holds
                        it
                      </li>
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
                  {#if useEncryption && !useWorkerKeystore}
                    <li>
                      Keystore key sealed with AES-GCM-256, the wrapping key
                      from the passkey's PRF output
                    </li>
                    <li>
                      Unlocked into a keystore that lives in memory for the
                      session — no unlocked copy at rest
                    </li>
                    <li>
                      Without PRF nothing is sealed, and the panel says so
                    </li>
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
              OrbitDB Encrypted Keystore Demo
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
          <ForgeryCheck
            {database}
            identities={orbitdbInstances?.identities}
            identity={orbitdbInstances?.identity}
          />
          <dl class="identity-facts">
            <dt>Signing backend</dt>
            <dd data-testid="signing-backend">{activeSigningBackend}</dd>
            <dt>Signing key</dt>
            <dd data-testid="signing-key-type">
              {signingKey ? `${signingKey.type}, ${signingKey.where}` : '—'}
            </dd>
            <dt>At rest</dt>
            <dd
              data-testid="encryption-state"
              data-enabled={encryptionState?.enabled ?? ''}
            >
              {#if !encryptionState}
                —
              {:else if encryptionState.enabled}
                a copy sealed by the passkey ({encryptionState.method}) in
                localStorage, unlocked once per session; OrbitDB's keystore is
                in memory only
              {:else if encryptionState.reason === 'external-signer'}
                nothing — the key is derived in the worker each session and
                never written anywhere
              {:else if encryptionState.reason === 'prf-unavailable'}
                <span style="color: var(--cds-support-error);"
                  >NOT encrypted — this authenticator has no PRF, and nothing
                  stands in for it</span
                >
              {:else}
                not requested
              {/if}
            </dd>
            <dt>Identity document</dt>
            <dd data-testid="identity-hash">{identityHash ?? '—'}</dd>
            <dt>WebAuthn prompts this session</dt>
            <dd data-testid="prompt-count">
              create {$promptCounts.create} · get {$promptCounts.get}
            </dd>
            {#if useWorkerKeystore}
              <dt>Worker</dt>
              <dd data-testid="worker-status">{workerStatus}</dd>
              {#if workerDid}
                <dt>Worker signer DID</dt>
                <dd data-testid="worker-did"><code>{workerDid}</code></dd>
              {/if}
              <dt>Seed source</dt>
              <dd data-testid="worker-seed-source">
                {workerSeedSource ?? '—'}
              </dd>
            {/if}
          </dl>
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

              <!-- What the verifier found for the entry behind this todo -->
              <IdentityVerificationBadge
                result={todoVerifications.get(todo.id) ?? null}
              />

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
      🔐 Encrypted Keystore Security Features
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

<style>
  .identity-facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 1rem;
    margin: 0.75rem 0 0;
    font-size: 0.8rem;
  }
  .identity-facts dt {
    color: var(--cds-text-secondary);
  }
  .identity-facts dd {
    margin: 0;
    word-break: break-all;
  }
</style>

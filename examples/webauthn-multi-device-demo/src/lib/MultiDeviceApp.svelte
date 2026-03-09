<script>
  import { onMount, onDestroy } from 'svelte';
  import {
    checkWebAuthnSupport,
    WebAuthnDIDProvider,
    WebAuthnVarsigProvider,
    storeWebAuthnCredential,
    loadWebAuthnCredential,
    clearWebAuthnCredential,
    storeWebAuthnVarsigCredential,
    loadWebAuthnVarsigCredential,
    clearWebAuthnVarsigCredential,
  } from '@le-space/orbitdb-identity-provider-webauthn-did';
  import {
    storeWebAuthnCredentialSafe,
    loadWebAuthnCredentialSafe,
    clearWebAuthnCredentialSafe,
  } from '@le-space/orbitdb-identity-provider-webauthn-did/standalone';
  import { MultiDeviceManager } from '@le-space/orbitdb-identity-provider-webauthn-did/multi-device/manager';
  import { setupOrbitDB, registerPairingHandler, getQRPayload, cleanup, IDENTITY_MODES } from '$lib/libp2p.js';
  import { saveDbAddress, getDbAddress } from '$lib/database.js';

  import SetupView from '$lib/components/SetupView.svelte';
  import PairView from '$lib/components/PairView.svelte';
  import GrantConfirmView from '$lib/components/GrantConfirmView.svelte';

  // ── State ────────────────────────────────────────────────────────────────────
  let appMode = 'initial'; // 'initial' | 'link-or-create' | 'ready'
  let isLogin = false;
  let loading = false;
  let status = '';
  let error = '';
  let webAuthnSupported = true;
  let webAuthnMessage = '';
  let identityMode = IDENTITY_MODES.KEYSTORE_ED25519;

  // OrbitDB state
  let manager = null; // MultiDeviceManager instance
  let credential = null; // WebAuthn credential
  let dbAddress = null;
  let devices = [];
  let qrPayload = null;
  let runtimeInfo = {
    signingBackend: 'main-thread-provider',
    algorithm: 'Ed25519',
    identityType: 'webauthn',
    worker: null,
  };

  // Pairing confirm dialog
  let pendingRequest = null;
  let pendingResolve = null;

  // Sync polling backstop
  let syncPollInterval = null;
  const IDENTITY_MODE_STORAGE_KEY = 'multi-device-identity-mode';

  const IDENTITY_MODE_LABELS = {
    [IDENTITY_MODES.KEYSTORE_ED25519]: 'Ed25519 Keystore',
    [IDENTITY_MODES.WORKER_ED25519]: 'Worker Ed25519',
    [IDENTITY_MODES.VARSIG_ED25519]: 'Varsig Ed25519',
    [IDENTITY_MODES.VARSIG_P256]: 'Varsig P-256',
  };

  // ── QR payload watcher — show QR immediately, update when relay addresses arrive ─
  function startWatchingQR() {
    if (!manager) return;
    
    qrPayload = manager.getPeerInfo();
    console.log('[qr-watch] started. peerId:', qrPayload.peerId);
    console.log('[qr-watch] initial multiaddrs (' + qrPayload.multiaddrs.length + '):', qrPayload.multiaddrs);

    const pollInterval = setInterval(() => {
      if (!manager) {
        clearInterval(pollInterval);
        return;
      }
      try {
        const payload = manager.getPeerInfo();
        if (JSON.stringify(payload.multiaddrs) !== JSON.stringify(qrPayload?.multiaddrs ?? [])) {
          console.log('[qr-watch] address change detected by poll — updating QR');
          qrPayload = payload;
        }
      } catch (e) {
        // Manager might not be ready yet
      }
    }, 3000);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────
  async function refreshDevices() {
    if (manager) {
      devices = await manager.listDevices();
    }
  }

  function isVarsigMode(mode = identityMode) {
    return (
      mode === IDENTITY_MODES.VARSIG_ED25519 ||
      mode === IDENTITY_MODES.VARSIG_P256
    );
  }

  function isWorkerMode(mode = identityMode) {
    return mode === IDENTITY_MODES.WORKER_ED25519;
  }

  function persistIdentityMode() {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(IDENTITY_MODE_STORAGE_KEY, identityMode);
    }
  }

  function setIdentityMode(mode) {
    identityMode = mode;
    persistIdentityMode();
  }

  function loadStoredCredentialForMode(mode = identityMode) {
    try {
      if (mode === IDENTITY_MODES.KEYSTORE_ED25519) {
        return loadWebAuthnCredential();
      }
      if (mode === IDENTITY_MODES.WORKER_ED25519) {
        return loadWebAuthnCredentialSafe('multi-device-worker-credential');
      }
      return loadWebAuthnVarsigCredential(`multi-device-${mode}-credential`);
    } catch (error) {
      console.warn('Failed to load stored credential for mode:', mode, error);
      clearStoredCredentialForMode(mode);
      return null;
    }
  }

  function storeCredentialForMode(mode, value) {
    if (mode === IDENTITY_MODES.KEYSTORE_ED25519) {
      storeWebAuthnCredential(value);
      return;
    }
    if (mode === IDENTITY_MODES.WORKER_ED25519) {
      storeWebAuthnCredentialSafe(value, 'multi-device-worker-credential');
      return;
    }
    storeWebAuthnVarsigCredential(value, `multi-device-${mode}-credential`);
  }

  function clearStoredCredentialForMode(mode = identityMode) {
    if (mode === IDENTITY_MODES.KEYSTORE_ED25519) {
      clearWebAuthnCredential();
      return;
    }
    if (mode === IDENTITY_MODES.WORKER_ED25519) {
      clearWebAuthnCredentialSafe('multi-device-worker-credential');
      return;
    }
    clearWebAuthnVarsigCredential(`multi-device-${mode}-credential`);
  }

  async function detectExistingCredentialForMode(mode = identityMode) {
    if (isVarsigMode(mode)) {
      const stored = loadStoredCredentialForMode(mode);
      return { hasCredentials: Boolean(stored), credential: stored };
    }

    const result = await WebAuthnDIDProvider.detectExistingCredential();
    if (!result.hasCredentials || !result.credential) {
      return result;
    }

    return {
      hasCredentials: true,
      credential: {
        credentialId: WebAuthnDIDProvider.arrayBufferToBase64url(result.credential.rawId),
        rawCredentialId: new Uint8Array(result.credential.rawId),
      },
    };
  }

  async function createCredentialForMode(mode = identityMode) {
    if (isVarsigMode(mode)) {
      return WebAuthnVarsigProvider.createCredential({
        userId: `device-${Date.now()}`,
        displayName: 'Multi-Device User',
        forceP256: mode === IDENTITY_MODES.VARSIG_P256,
      });
    }

    return WebAuthnDIDProvider.createCredential({
      userId: `device-${Date.now()}`,
      displayName: 'Multi-Device User',
      encryptKeystore: true,
      keystoreEncryptionMethod: 'prf',
    });
  }

  async function setupOrbitDbForCurrentMode() {
    const orbitdbState = await setupOrbitDB(credential, {
      identityMode,
      encryptKeystore: true,
      keystoreEncryptionMethod: 'prf',
    });

    runtimeInfo = orbitdbState.runtimeInfo || runtimeInfo;

    manager = await MultiDeviceManager.createFromExisting({
      credential,
      orbitdb: orbitdbState.orbitdb,
      ipfs: orbitdbState.ipfs,
      libp2p: orbitdbState.ipfs.libp2p,
      identity: orbitdbState.identity,
      onPairingRequest: handleIncomingPairRequest,
      onDeviceJoined: refreshDevices,
      onDeviceLinked: refreshDevices,
    });

    return orbitdbState;
  }

  function startSyncPolling() {
    stopSyncPolling();
    syncPollInterval = setInterval(async () => {
      if (manager && appMode === 'ready') {
        await refreshDevices();
      }
    }, 5000);
  }

  function stopSyncPolling() {
    if (syncPollInterval) {
      clearInterval(syncPollInterval);
      syncPollInterval = null;
    }
  }

  // ── Start button handler — detects login state and flows ──────────────────────
  async function handleStart() {
    loading = true;
    error = '';

    try {
      status = 'Checking for existing passkey…';
      const result = await detectExistingCredentialForMode(identityMode);

      if (result.hasCredentials && result.credential) {
        credential = result.credential;
        
        const existingDbAddress = getDbAddress();
        
        if (existingDbAddress) {
          // LOGIN FLOW: User has passkey + DB exists
          status = 'Authenticating with existing passkey…';
          isLogin = true;
          
          // Setup OrbitDB with existing credential
          await setupOrbitDbForCurrentMode();
          
          await manager.openExistingDb(existingDbAddress);
          dbAddress = manager._dbAddress;
          
          startWatchingQR();
          await refreshDevices();

          appMode = 'ready';
          startSyncPolling();
          status = 'Logged in! Show QR code to link a new device.';
        } else {
          // User has passkey but no local DB - ask: link to existing or create new
          // Setup OrbitDB first so manager can work
          status = 'Setting up…';
          await setupOrbitDbForCurrentMode();
          
          appMode = 'link-or-create';
          status = 'Existing passkey found. Would you like to link to an existing device or create a new setup?';
          isLogin = false;
        }
      } else {
        // No existing credential - create new one, then ask user what to do
        status = 'Creating new credential…';
        isLogin = false;
        
        credential = await createCredentialForMode(identityMode);
        storeCredentialForMode(identityMode, credential);

        // Don't setup OrbitDB yet - let user choose first
        appMode = 'link-or-create';
        status = 'New device set up. Would you like to link to an existing device or create a new setup?';
      }

    } catch (err) {
      error = err.message;
      status = '';
      console.error('[start] error:', err);
    } finally {
      loading = false;
    }
  }

  // ── Incoming pairing request handler (Device A side) ─────────────────────────
  async function handleIncomingPairRequest(request) {
    return new Promise((resolve) => {
      pendingRequest = request;
      pendingResolve = resolve;
    });
  }

  async function handleConfirmDecision(event) {
    const decision = event.detail; // 'granted' | 'rejected'
    pendingRequest = null;
    if (pendingResolve) {
      pendingResolve(decision);
      pendingResolve = null;
    }
    if (decision === 'granted') {
      await refreshDevices();
    }
  }

  // ── Link or Create choice handlers ─────────────────────────────────────────────
  async function handleLinkToExisting() {
    loading = true;
    error = '';
    status = 'Setting up to link to existing device…';
    
    try {
      // If manager doesn't exist yet (new credential case), create it first
      if (!manager) {
        await setupOrbitDbForCurrentMode();
      }
      
      // Show PairView for scanning QR / pasting JSON
      loading = false;
      status = 'Ready. Scan or paste Device A\'s QR code.';
    } catch (err) {
      error = err.message;
      loading = false;
      console.error('[link] error:', err);
    }
  }

  async function handleCreateNewSetup() {
    loading = true;
    error = '';
    status = 'Creating new device setup…';
    
    try {
      // If manager doesn't exist yet (new credential case), create it first
      if (!manager) {
        await setupOrbitDbForCurrentMode();
      }
      
      const created = await manager.createNew();
      dbAddress = created.dbAddress;
      
      saveDbAddress(dbAddress);
      startWatchingQR();
      await refreshDevices();

      appMode = 'ready';
      startSyncPolling();
      status = 'Ready! Show QR code to link a new device.';
    } catch (err) {
      error = err.message;
      console.error('[create] error:', err);
    } finally {
      loading = false;
    }
  }

  async function ensureManagerReady() {
    if (manager) return manager;
    if (!credential) throw new Error('Credential not initialized');

    const orbitdbState = await setupOrbitDB(credential, {
      identityMode,
      encryptKeystore: true,
      keystoreEncryptionMethod: 'prf',
    });

    runtimeInfo = orbitdbState.runtimeInfo || runtimeInfo;

    manager = await MultiDeviceManager.createFromExisting({
      credential,
      orbitdb: orbitdbState.orbitdb,
      ipfs: orbitdbState.ipfs,
      libp2p: orbitdbState.ipfs.libp2p,
      identity: orbitdbState.identity,
      onPairingRequest: handleIncomingPairRequest,
      onDeviceJoined: refreshDevices,
      onDeviceLinked: refreshDevices,
    });

    return manager;
  }

  async function handlePairFromLink(event) {
    const { qrPayload: qr } = event.detail;

    loading = true;
    error = '';
    status = 'Connecting to Device A…';

    try {
      const result = await manager.linkToDevice(qr);

      if (result.type === 'granted') {
        status = 'Access granted! Opening shared database…';
        dbAddress = result.dbAddress;
        
        saveDbAddress(dbAddress);
        await refreshDevices();

        startWatchingQR();

        appMode = 'ready';
        startSyncPolling();
        status = 'Linked successfully! You can now access the shared database.';
      } else {
        error = `Pairing rejected: ${result.reason || 'Unknown reason'}`;
      }
    } catch (err) {
      error = err.message;
      console.error('[pair] error:', err);
    } finally {
      loading = false;
    }
  }

  // ── WebAuthn support check ───────────────────────────────────────────────────
  onMount(async () => {
    if (typeof localStorage !== 'undefined') {
      identityMode =
        localStorage.getItem(IDENTITY_MODE_STORAGE_KEY) ||
        IDENTITY_MODES.KEYSTORE_ED25519;
    }
    const support = await checkWebAuthnSupport();
    webAuthnSupported = support.supported;
    if (!support.supported) {
      const isInsecure = typeof window !== 'undefined' &&
        window.location.protocol !== 'https:' &&
        window.location.hostname !== 'localhost';
      webAuthnMessage = isInsecure
        ? 'WebAuthn requires HTTPS. Access this page via https:// or use localhost.'
        : (support.message || 'WebAuthn is not supported in this browser.');
    }
  });

  // ── window.__multiDevice test API ────────────────────────────────────────────
  onMount(() => {
    if (typeof window !== 'undefined' && window.__testMode) {
      window.__multiDevice = {
        getState: () => ({
          appMode,
          identityMode,
          identityModeLabel: IDENTITY_MODE_LABELS[identityMode],
          peerId: manager ? manager.getPeerInfo()?.peerId : null,
          devicesDbAddress: dbAddress,
          deviceCount: devices.length,
          signingBackend: runtimeInfo.signingBackend,
          didAlgorithm: runtimeInfo.algorithm,
          identityType: runtimeInfo.identityType,
          identity: manager?._identity ? { id: manager._identity.id } : null,
          worker: runtimeInfo.worker,
        }),

        getQRPayload: () => manager ? manager.getPeerInfo() : null,

        // Device A: simulate an incoming pairing request
        // `approve` controls whether a new unknown device is accepted (default: true)
        simulateIncomingRequest: async (requestMsg, { approve = true } = {}) => {
          if (!manager || !manager._devicesDb) throw new Error('Device registry not initialized');

          // Temporarily override the pairing callback to respect the `approve` test option
          const savedCallback = manager._onPairingRequest;
          manager._onPairingRequest = async () => (approve ? 'granted' : 'rejected');

          try {
            const result = await manager.processIncomingPairingRequest(requestMsg);
            await refreshDevices();
            return result;
          } finally {
            manager._onPairingRequest = savedCallback;
          }
        },

        // Test setup: create new DB as Device A (bypasses UI, for use after clicking Start)
        setupAsDeviceA: async () => {
          await ensureManagerReady();
          const created = await manager.createNew();
          dbAddress = created.dbAddress;
          saveDbAddress(dbAddress);
          startWatchingQR();
          await refreshDevices();
          appMode = 'ready';
          startSyncPolling();
          return dbAddress;
        },

        // Device B: open DB by address after receiving granted
        openByAddress: async (address) => {
          if (!manager) throw new Error('Manager not initialized');
          await manager.openExistingDb(address);
          dbAddress = manager._dbAddress;
          await refreshDevices();
          return dbAddress;
        },

        // Direct grants for test scenarios
        grantAccess: async (entry) => {
          if (!manager || !manager._devicesDb) throw new Error('Device registry not initialized');
          await refreshDevices();
        },

        getDevicesDbAddress: () => dbAddress,
        listDevices: () => devices,
        getManager: () => manager,
        setIdentityMode: (mode) => {
          setIdentityMode(mode);
        },
      };
      console.log('[test] window.__multiDevice API exposed');
    }
  });

  onDestroy(async () => {
    stopSyncPolling();
    if (manager) {
      await manager.close();
    }
  });
</script>

<div class="app-container">
  <!-- WebAuthn support banner -->
  {#if !webAuthnSupported}
    <div class="webauthn-warning">
      <strong>⚠️ WebAuthn not available</strong>
      <p>{webAuthnMessage}</p>
      {#if webAuthnMessage.includes('HTTPS')}
        <p class="hint">
          To test on mobile: expose the dev server with a tool like
          <code>ngrok http 5173</code> and open the HTTPS URL on your phone.
        </p>
      {/if}
    </div>
  {/if}

  <!-- Initial state: Single Start button -->
  {#if appMode === 'initial'}
    <div class="initial-view">
      <h2>Multi-Device OrbitDB</h2>
      <p class="subtitle">
        Link multiple devices to share a single OrbitDB identity and database
        using WebAuthn hardware credentials.
      </p>

      <div class="mode-selector" data-testid="identity-mode-selector">
        {#each Object.values(IDENTITY_MODES) as mode}
          <button
            type="button"
            class:selected={identityMode === mode}
            data-testid={`identity-mode-${mode}`}
            on:click={() => setIdentityMode(mode)}
            disabled={loading}
          >
            {IDENTITY_MODE_LABELS[mode]}
          </button>
        {/each}
      </div>
      
      {#if error}
        <div class="error-banner">{error}</div>
      {/if}

      {#if status}
        <div class="status-banner">{status}</div>
      {/if}

      <button 
        class="btn-primary start-btn" 
        on:click={handleStart} 
        disabled={loading || !webAuthnSupported}
      >
        {loading ? 'Starting…' : '🚀 Start'}
      </button>
    </div>

  <!-- Link or Create choice -->
  {:else if appMode === 'link-or-create'}
    <div class="link-or-create-view">
      <h2>Link or Create?</h2>
      <p class="subtitle">
        Set up your new device. Would you like to:
      </p>

      <p class="mode-pill" data-testid="active-identity-mode">
        Mode: {IDENTITY_MODE_LABELS[identityMode]}
      </p>
      
      {#if error}
        <div class="error-banner">{error}</div>
      {/if}

      {#if status}
        <div class="status-banner">{status}</div>
      {/if}

      {#if !manager}
        <div class="choice-buttons">
          <button 
            class="btn-secondary" 
            on:click={handleLinkToExisting}
            disabled={loading}
          >
            📲 Link to Existing Device
          </button>
          <button 
            class="btn-primary" 
            on:click={handleCreateNewSetup}
            disabled={loading}
          >
            ➕ Create New Setup
          </button>
        </div>
        <p class="hint">
          <small>Link to existing: Use Device A's QR code to access your shared database.<br/>
          Create new: This device becomes Device A with a fresh database.</small>
        </p>
      {:else}
        <!-- OrbitDB is set up, show PairView to scan QR -->
        <PairView
          {devices}
          {dbAddress}
          {status}
          {error}
          {loading}
          on:pair={handlePairFromLink}
          on:error={(e) => { error = e.detail; }}
        />
      {/if}
    </div>

  <!-- Ready state: Show QR code and devices -->
  {:else if appMode === 'ready'}
    <SetupView
      {qrPayload}
      {devices}
      {dbAddress}
      {status}
      {error}
      {loading}
    />
  {/if}

  <!-- Grant confirmation overlay (Device A) -->
  {#if pendingRequest}
    <GrantConfirmView
      request={pendingRequest}
      on:decision={handleConfirmDecision}
    />
  {/if}
</div>

<style>
  .app-container {
    max-width: 600px;
    margin: 0 auto;
    padding: 1.5rem;
  }

  .mode-selector {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.75rem;
    margin: 1rem 0 1.25rem;
  }

  .mode-selector button,
  .mode-pill {
    border: 1px solid #cbd5e1;
    border-radius: 999px;
    background: #f8fafc;
    color: #0f172a;
    padding: 0.65rem 0.9rem;
    font-size: 0.95rem;
  }

  .mode-selector button.selected {
    background: #0f172a;
    border-color: #0f172a;
    color: #fff;
  }

  .mode-pill {
    display: inline-block;
    margin: 0 0 1rem;
  }

  .webauthn-warning {
    padding: 1rem 1.25rem;
    background: #fff8e1;
    border: 1px solid #f59e0b;
    border-radius: 0.5rem;
    margin-bottom: 1.25rem;
    color: #78350f;
  }

  .webauthn-warning strong {
    display: block;
    margin-bottom: 0.25rem;
    font-size: 1rem;
  }

  .webauthn-warning p {
    margin: 0.25rem 0 0;
    font-size: 0.875rem;
  }

  .webauthn-warning .hint {
    margin-top: 0.5rem;
    font-size: 0.8rem;
    opacity: 0.8;
  }

  .webauthn-warning code {
    background: rgba(0,0,0,0.1);
    padding: 0.1rem 0.3rem;
    border-radius: 0.2rem;
    font-family: monospace;
  }

  .initial-view {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    align-items: center;
    text-align: center;
    padding: 2rem 0;
  }

  .start-btn {
    padding: 1rem 2.5rem;
    font-size: 1.25rem;
  }

  .link-or-create-view {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    align-items: center;
    text-align: center;
    padding: 2rem 0;
  }

  .choice-buttons {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    width: 100%;
    max-width: 320px;
  }

  .hint {
    color: var(--cds-text-secondary, #666);
    max-width: 320px;
  }

  .error-banner {
    padding: 0.75rem 1rem;
    background: #fde8e8;
    border: 1px solid #e74c3c;
    border-radius: 0.4rem;
    color: #c0392b;
    width: 100%;
    max-width: 400px;
  }

  .status-banner {
    padding: 0.75rem 1rem;
    background: #e8f4fd;
    border: 1px solid #3498db;
    border-radius: 0.4rem;
    color: #2471a3;
    width: 100%;
    max-width: 400px;
  }

  h2 {
    margin: 0;
    font-size: 1.5rem;
  }

  .subtitle {
    color: var(--cds-text-secondary, #555);
    margin: 0;
    max-width: 400px;
  }

  .btn-primary {
    padding: 0.875rem 1.5rem;
    background: linear-gradient(135deg, #4f46e5, #7c3aed);
    color: white;
    border: none;
    border-radius: 0.5rem;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
    width: 100%;
  }

  .btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .btn-secondary {
    padding: 0.875rem 1.5rem;
    background: var(--cds-layer, #e8e8e8);
    color: var(--cds-text-primary, #333);
    border: 1px solid var(--cds-border-subtle, #ccc);
    border-radius: 0.5rem;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
    width: 100%;
  }

  .btn-secondary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  button:hover {
    opacity: 0.88;
  }
</style>

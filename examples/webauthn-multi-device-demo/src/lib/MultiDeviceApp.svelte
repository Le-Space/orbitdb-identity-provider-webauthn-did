<script>
  import { onMount, onDestroy } from 'svelte';
  import {
    checkWebAuthnSupport,
    WebAuthnDIDProvider,
  } from '@le-space/orbitdb-identity-provider-webauthn-did';
  import { MultiDeviceManager } from '@le-space/orbitdb-identity-provider-webauthn-did/multi-device/manager';
  import { setupOrbitDB, registerPairingHandler, getQRPayload, cleanup } from '$lib/libp2p.js';
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

  // OrbitDB state
  let manager = null; // MultiDeviceManager instance
  let dbAddress = null;
  let devices = [];
  let qrPayload = null;

  // Pairing confirm dialog
  let pendingRequest = null;
  let pendingResolve = null;

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
        console.log('[qr-watch] poll tick — multiaddrs (' + payload.multiaddrs.length + '):', payload.multiaddrs);
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

  // ── Start button handler — detects login state and flows ──────────────────────
  async function handleStart() {
    loading = true;
    error = '';

    try {
      status = 'Checking for existing passkey…';
      const result = await WebAuthnDIDProvider.detectExistingCredential();

      let credential;
      if (result.hasCredentials && result.credential) {
        credential = {
          credentialId: WebAuthnDIDProvider.arrayBufferToBase64url(result.credential.rawId),
          rawCredentialId: new Uint8Array(result.credential.rawId),
        };
        
        const existingDbAddress = getDbAddress();
        
        if (existingDbAddress) {
          // LOGIN FLOW: User has passkey + DB exists
          status = 'Authenticating with existing passkey…';
          isLogin = true;
          
          // Setup OrbitDB with existing credential
          const orbitdbState = await setupOrbitDB(credential, {
            encryptKeystore: true,
            keystoreEncryptionMethod: 'prf',
          });
          
          // Create manager from existing setup
          manager = await MultiDeviceManager.createFromExisting({
            credential,
            orbitdb: orbitdbState.orbitdb,
            ipfs: orbitdbState.ipfs,
            libp2p: orbitdbState.ipfs.libp2p,
            identity: orbitdbState.identity,
            onPairingRequest: handleIncomingPairRequest,
          });
          
          await manager.openExistingDb(existingDbAddress);
          dbAddress = manager._dbAddress;
          
          startWatchingQR();
          await refreshDevices();
          
          appMode = 'ready';
          status = 'Logged in! Show QR code to link a new device.';
        } else {
          // User has passkey but no local DB - ask: link to existing or create new
          // Setup OrbitDB first so manager can work
          status = 'Setting up…';
          const orbitdbState = await setupOrbitDB(credential, {
            encryptKeystore: true,
            keystoreEncryptionMethod: 'prf',
          });
          
          manager = await MultiDeviceManager.createFromExisting({
            credential,
            orbitdb: orbitdbState.orbitdb,
            ipfs: orbitdbState.ipfs,
            libp2p: orbitdbState.ipfs.libp2p,
            identity: orbitdbState.identity,
            onPairingRequest: handleIncomingPairRequest,
          });
          
          appMode = 'link-or-create';
          status = 'Existing passkey found. Would you like to link to an existing device or create a new setup?';
          isLogin = false;
        }
      } else {
        // No existing credential - create new one (new user)
        status = 'Creating new credential…';
        isLogin = false;
        
        credential = await WebAuthnDIDProvider.createCredential({
          userId: `device-${Date.now()}`,
          displayName: 'Multi-Device User',
          encryptKeystore: true,
          keystoreEncryptionMethod: 'prf',
        });

        status = 'Setting up OrbitDB identity (biometric prompt will appear)…';
        const orbitdbState = await setupOrbitDB(credential, {
          encryptKeystore: true,
          keystoreEncryptionMethod: 'prf',
        });

        manager = await MultiDeviceManager.createFromExisting({
          credential,
          orbitdb: orbitdbState.orbitdb,
          ipfs: orbitdbState.ipfs,
          libp2p: orbitdbState.ipfs.libp2p,
          identity: orbitdbState.identity,
          onPairingRequest: handleIncomingPairRequest,
        });
        
        const created = await manager.createNew();
        dbAddress = created.dbAddress;
        
        saveDbAddress(dbAddress);
        startWatchingQR();
        await refreshDevices();
        
        appMode = 'ready';
        status = 'Ready! Show QR code to link a new device.';
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
      // Manager already created in handleStart with restore() result
      // Just need to wait for OrbitDB to be ready
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
      const created = await manager.createNew();
      dbAddress = created.dbAddress;
      
      saveDbAddress(dbAddress);
      startWatchingQR();
      await refreshDevices();
      
      appMode = 'ready';
      status = 'Ready! Show QR code to link a new device.';
    } catch (err) {
      error = err.message;
      console.error('[create] error:', err);
    } finally {
      loading = false;
    }
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
          peerId: manager ? manager.getPeerInfo()?.peerId : null,
          devicesDbAddress: dbAddress,
          deviceCount: devices.length,
          identity: manager?._identity ? { id: manager._identity.id } : null,
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
          if (!manager) throw new Error('Manager not initialized');
          const created = await manager.createNew();
          dbAddress = manager._dbAddress;
          await refreshDevices();
          appMode = 'ready';
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
      };
      console.log('[test] window.__multiDevice API exposed');
    }
  });

  onDestroy(async () => {
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
        You have an existing passkey but no local database. Would you like to:
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

  button:hover {
    opacity: 0.88;
  }
</style>

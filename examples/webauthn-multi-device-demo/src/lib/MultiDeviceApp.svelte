<script>
  import { onMount, onDestroy } from 'svelte';
  import {
    WebAuthnDIDProvider,
    checkWebAuthnSupport,
    grantDeviceWriteAccess,
    registerDevice,
    listDevices,
    getDeviceByCredentialId,
    sendPairingRequest,
    detectDeviceLabel,
  } from '@le-space/orbitdb-identity-provider-webauthn-did';
  import { setupOrbitDB, registerPairingHandler, getQRPayload, cleanup } from '$lib/libp2p.js';
  import { openDevicesDB, registerCurrentDevice, loadDevices, saveDbAddress, getDbAddress } from '$lib/database.js';

  import SetupView from '$lib/components/SetupView.svelte';
  import GrantConfirmView from '$lib/components/GrantConfirmView.svelte';

  // ── State ────────────────────────────────────────────────────────────────────
  let appMode = 'initial'; // 'initial' | 'ready'
  let isLogin = false;
  let loading = false;
  let status = '';
  let error = '';
  let webAuthnSupported = true;
  let webAuthnMessage = '';

  // OrbitDB state
  let orbitdbState = null; // { orbitdb, ipfs, identity }
  let devicesDb = null;
  let devices = [];
  let dbAddress = null;
  let qrPayload = null;
  let credential = null;

  // Pairing confirm dialog
  let pendingRequest = null;
  let pendingResolve = null;

  // libp2p address watcher (for Fix 3: multiaddrs initially empty)
  let addrUpdateListener = null;
  let addrPollInterval = null;

  // ── Address watcher — show QR immediately, update when relay addresses arrive ─
  function startWatchingAddresses(libp2p) {
    // Always show QR immediately (peerId is known from the start)
    qrPayload = getQRPayload(libp2p);
    console.log('[addr-watch] started. peerId:', qrPayload.peerId);
    console.log('[addr-watch] initial multiaddrs (' + qrPayload.multiaddrs.length + '):', qrPayload.multiaddrs);

    // Event-based: self:peer:update fires when announced addresses change
    const handler = () => {
      const payload = getQRPayload(libp2p);
      console.log('[addr-watch] self:peer:update → multiaddrs (' + payload.multiaddrs.length + '):', payload.multiaddrs);
      qrPayload = payload;
    };
    libp2p.addEventListener('self:peer:update', handler);
    addrUpdateListener = { libp2p, handler };

    // Polling fallback every 3 s — self:peer:update may not fire for all
    // relay reservation events in all libp2p v2 versions
    addrPollInterval = setInterval(() => {
      const payload = getQRPayload(libp2p);
      console.log('[addr-watch] poll tick — multiaddrs (' + payload.multiaddrs.length + '):', payload.multiaddrs);
      if (JSON.stringify(payload.multiaddrs) !== JSON.stringify(qrPayload?.multiaddrs ?? [])) {
        console.log('[addr-watch] address change detected by poll — updating QR');
        qrPayload = payload;
      }
    }, 3000);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────
  async function refreshDevices() {
    if (devicesDb) {
      devices = await loadDevices(devicesDb);
    }
  }

  // ── Start button handler — detects login state and flows ──────────────────────
  async function handleStart() {
    loading = true;
    error = '';

    try {
      // Step 1: Try to detect existing credential
      status = 'Checking for existing passkey…';
      const result = await WebAuthnDIDProvider.detectExistingCredential();

      if (result.hasCredentials && result.credential) {
        // Normalize credential to match format createCredential() returns
        const rawCred = result.credential;
        credential = {
          credentialId: WebAuthnDIDProvider.arrayBufferToBase64url(rawCred.rawId),
          rawCredentialId: new Uint8Array(rawCred.rawId),
        };
        
        // User has existing passkey - check if DB exists locally
        const existingDbAddress = getDbAddress();
        
        if (existingDbAddress) {
          // LOGIN FLOW: User has passkey + DB exists
          status = 'Authenticating with existing passkey…';
          isLogin = true;
          
          // Setup OrbitDB with existing credential (will prompt for biometric)
          orbitdbState = await setupOrbitDB(credential, {
            encryptKeystore: true,
            keystoreEncryptionMethod: 'prf',
          });
          
          // Open existing DB
          devicesDb = await openDevicesDB(orbitdbState.orbitdb, orbitdbState.identity, existingDbAddress);
          dbAddress = devicesDb.address;
          
          // Setup pairing handler (for adding new devices)
          await registerPairingHandler(
            orbitdbState.ipfs.libp2p,
            devicesDb,
            handleIncomingPairRequest
          );
          
          startWatchingAddresses(orbitdbState.ipfs.libp2p);
          await refreshDevices();
          
          appMode = 'ready';
          status = 'Logged in! Show QR code to link a new device.';
        } else {
          // User has passkey but no local DB - treat as new Device A setup
          status = 'Existing passkey found. Setting up OrbitDB…';
          isLogin = false;
          
          // Setup OrbitDB with existing credential
          orbitdbState = await setupOrbitDB(credential, {
            encryptKeystore: true,
            keystoreEncryptionMethod: 'prf',
          });
          
          // Create new device registry (first device)
          devicesDb = await openDevicesDB(orbitdbState.orbitdb, orbitdbState.identity);
          dbAddress = devicesDb.address;
          
          // Save DB address for future logins
          saveDbAddress(dbAddress);
          
          // Register self
          await registerCurrentDevice(devicesDb, credential, orbitdbState.identity, 'Device A');
          
          // Setup pairing handler
          await registerPairingHandler(
            orbitdbState.ipfs.libp2p,
            devicesDb,
            handleIncomingPairRequest
          );
          
          startWatchingAddresses(orbitdbState.ipfs.libp2p);
          await refreshDevices();
          
          appMode = 'ready';
          status = 'Ready! Show QR code to link a new device.';
        }
      } else {
        // No existing credential - create new one (new user)
        status = 'No existing passkey. Creating new credential…';
        isLogin = false;
        
        // Create new credential
        credential = await WebAuthnDIDProvider.createCredential({
          userId: `device-a-${Date.now()}`,
          displayName: 'Multi-Device User (Device A)',
          encryptKeystore: true,
          keystoreEncryptionMethod: 'prf',
        });

        // Setup OrbitDB
        status = 'Setting up OrbitDB identity (biometric prompt will appear)…';
        orbitdbState = await setupOrbitDB(credential, {
          encryptKeystore: true,
          keystoreEncryptionMethod: 'prf',
        });

        // Create device registry
        devicesDb = await openDevicesDB(orbitdbState.orbitdb, orbitdbState.identity);
        dbAddress = devicesDb.address;
        
        // Save DB address for future logins
        saveDbAddress(dbAddress);

        // Register self
        await registerCurrentDevice(devicesDb, credential, orbitdbState.identity, 'Device A');

        // Setup pairing handler
        await registerPairingHandler(
          orbitdbState.ipfs.libp2p,
          devicesDb,
          handleIncomingPairRequest
        );

        startWatchingAddresses(orbitdbState.ipfs.libp2p);
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
          peerId: orbitdbState?.ipfs?.libp2p?.peerId?.toString() || null,
          devicesDbAddress: dbAddress,
          deviceCount: devices.length,
          identity: orbitdbState?.identity ? { id: orbitdbState.identity.id } : null,
        }),

        getQRPayload: () =>
          orbitdbState?.ipfs?.libp2p ? getQRPayload(orbitdbState.ipfs.libp2p) : null,

        // Device A: simulate an incoming pairing request (auto-approve or check known)
        simulateIncomingRequest: async (requestMsg) => {
          if (!devicesDb) throw new Error('Device registry not initialized');
          const isKnown = await getDeviceByCredentialId(
            devicesDb,
            requestMsg.identity.credentialId
          );
          if (isKnown) {
            return { type: 'granted', orbitdbAddress: dbAddress };
          }
          // Auto-approve for test
          await grantDeviceWriteAccess(devicesDb, requestMsg.identity.id);
          await registerDevice(devicesDb, {
            credential_id: requestMsg.identity.credentialId,
            public_key: requestMsg.identity.publicKey || null,
            device_label: requestMsg.identity.deviceLabel || 'Test Device',
            created_at: Date.now(),
            status: 'active',
            ed25519_did: requestMsg.identity.id,
          });
          await refreshDevices();
          return { type: 'granted', orbitdbAddress: dbAddress };
        },

        // Device B: open DB by address after receiving granted
        openByAddress: async (address) => {
          if (!orbitdbState) throw new Error('OrbitDB not initialized');
          devicesDb = await openDevicesDB(orbitdbState.orbitdb, orbitdbState.identity, address);
          dbAddress = devicesDb.address;
          await refreshDevices();
          return dbAddress;
        },

        // Direct grants for test scenarios
        grantAccess: async (entry) => {
          if (!devicesDb) throw new Error('Device registry not initialized');
          await grantDeviceWriteAccess(devicesDb, entry.id);
          await registerDevice(devicesDb, {
            credential_id: entry.credentialId,
            public_key: entry.publicKey || null,
            device_label: entry.deviceLabel || 'Test Device',
            created_at: Date.now(),
            status: 'active',
            ed25519_did: entry.id,
          });
          await refreshDevices();
        },

        getDevicesDbAddress: () => dbAddress,
        listDevices: () => devices,
      };
      console.log('[test] window.__multiDevice API exposed');
    }
  });

  onDestroy(async () => {
    if (addrPollInterval) {
      clearInterval(addrPollInterval);
      addrPollInterval = null;
    }
    if (addrUpdateListener) {
      addrUpdateListener.libp2p.removeEventListener('self:peer:update', addrUpdateListener.handler);
    }
    if (orbitdbState) {
      await cleanup({ ...orbitdbState, database: devicesDb });
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

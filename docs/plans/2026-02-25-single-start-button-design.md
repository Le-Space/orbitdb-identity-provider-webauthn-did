# Single "Start" Button Login Flow Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the current 3-view flow (choose/setup/pair) in the multi-device demo with a single "Start" button that handles login detection automatically.

**Architecture:** Use `navigator.credentials.get()` to detect existing passkeys. If credentials exist and localStorage has a stored DB address, treat as login and show QR. Otherwise, create new credential and setup as Device A.

**Tech Stack:** Svelte, WebAuthn (navigator.credentials), localStorage

---

## Implementation Tasks

### Task 1: Add DB address storage helpers to database.js

**Files:**
- Modify: `examples/webauthn-multi-device-demo/src/lib/database.js`

**Step 1: Add localStorage helpers**

Add these functions to `database.js`:

```javascript
const DB_ADDRESS_STORAGE_KEY = 'orbitdb-multi-device-db-address';

export function saveDbAddress(address) {
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(DB_ADDRESS_STORAGE_KEY, address);
  }
}

export function getDbAddress() {
  if (typeof localStorage !== 'undefined') {
    return localStorage.getItem(DB_ADDRESS_STORAGE_KEY);
  }
  return null;
}

export function clearDbAddress() {
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(DB_ADDRESS_STORAGE_KEY);
  }
}
```

**Step 2: Commit**

```bash
git add examples/webauthn-multi-device-demo/src/lib/database.js
git commit -m "feat: add localStorage helpers for DB address persistence"
```

---

### Task 2: Add credential detection function to WebAuthn provider

**Files:**
- Modify: `src/webauthn/provider.js`

**Step 1: Add credential detection function**

Add this static method to the `WebAuthnDIDProvider` class in `src/webauthn/provider.js` (around line 50, after `isPlatformAuthenticatorAvailable`):

```javascript
/**
 * Check if any WebAuthn credentials exist for this origin.
 * Calls navigator.credentials.get() with empty allowCredentials to trigger
 * the browser's passkey selector without requiring a specific credential.
 * @returns {Promise<{hasCredentials: boolean, credential?: Object}>}
 *   hasCredentials: true if user has existing passkeys
 *   credential: the credential if user selects one, undefined if cancelled
 */
static async detectExistingCredential() {
  if (!window.PublicKeyCredential) {
    return { hasCredentials: false };
  }

  try {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: 10000,
        userVerification: 'preferred',
        allowCredentials: [], // Empty triggers passkey selector
      },
    });

    if (credential) {
      return { hasCredentials: true, credential };
    }
    return { hasCredentials: false };
  } catch (error) {
    // User cancelled or no credentials
    if (error.name === 'NotAllowedError') {
      return { hasCredentials: false };
    }
    throw error;
  }
}
```

**Step 2: Export the new method**

Ensure `detectExistingCredential` is exported (it should be since it's a static method on the exported class).

**Step 3: Commit**

```bash
git add src/webauthn/provider.js
git commit -m "feat: add detectExistingCredential method to WebAuthnDIDProvider"
```

---

### Task 3: Refactor MultiDeviceApp.svelte with single Start button

**Files:**
- Modify: `examples/webauthn-multi-device-demo/src/lib/MultiDeviceApp.svelte`

**Step 1: Add imports for new functions**

Add to the import section:
```javascript
import { detectExistingCredential } from '@le-space/orbitdb-identity-provider-webauthn-did';
import { saveDbAddress, getDbAddress } from '$lib/database.js';
```

**Step 2: Simplify state**

Replace the `view` state and related code:
- Remove: `let view = 'choose';`
- Remove: `chooseSetup()` and `choosePair()` functions
- Replace with: Single state variable for app mode

```javascript
// App mode: 'initial' | 'setup' | 'ready' (logged in)
let appMode = 'initial';
let isLogin = false; // true if existing user, false if new setup
```

**Step 3: Add the Start button handler**

Replace the choose view with a single Start button and handler:

```javascript
async function handleStart() {
  loading = true;
  error = '';

  try {
    // Step 1: Try to detect existing credential
    status = 'Checking for existing passkey…';
    const result = await detectExistingCredential();

    if (result.hasCredentials && result.credential) {
      // User has existing passkey - check if DB exists locally
      const existingDbAddress = getDbAddress();
      
      if (existingDbAddress) {
        // LOGIN FLOW: User has passkey + DB exists
        status = 'Authenticating with existing passkey…';
        isLogin = true;
        credential = result.credential;
        
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
        // They need to setup OrbitDB which will create a new identity
        status = 'Existing passkey found. Setting up OrbitDB…';
        isLogin = false;
        credential = result.credential;
        
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
```

**Step 4: Update template to use single Start button**

Replace the view-based template with:

```svelte
<div class="app-container">
  <!-- WebAuthn support banner -->
  {#if !webAuthnSupported}
    <div class="webauthn-warning">
      <strong>⚠️ WebAuthn not available</strong>
      <p>{webAuthnMessage}</p>
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
```

**Step 5: Add CSS for new views**

Add these styles:

```css
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
```

**Step 6: Commit**

```bash
git add examples/webauthn-multi-device-demo/src/lib/MultiDeviceApp.svelte
git commit -m "feat: implement single Start button with login detection"
```

---

### Task 4: Run lint and verify

**Step 1: Run lint**

```bash
cd .worktrees/single-start-button && pnpm run lint
```

Expected: PASS (no errors)

**Step 2: Commit**

```bash
git commit -m "chore: lint passes"
```

---

### Task 5: Test the implementation

**Step 1: Start the demo server**

```bash
cd .worktrees/single-start-button && pnpm run demo
```

**Step 2: Verify manually**

1. Open http://localhost:5173
2. Click "Start" button
3. First time: Should create credential + setup as Device A
4. Refresh page, click "Start" again
5. Should detect existing passkey and log in directly

**Step 3: Commit**

```bash
git commit -m "test: manual verification complete"
```

---

## Summary

| Task | Files Modified | Description |
|------|----------------|-------------|
| 1 | `database.js` | Add localStorage helpers for DB address |
| 2 | `src/webauthn/provider.js` | Add `detectExistingCredential()` method |
| 3 | `MultiDeviceApp.svelte` | Replace 3-view flow with single Start button |
| 4 | - | Run lint |
| 5 | - | Manual test |

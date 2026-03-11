<script>
  import { createEventDispatcher } from 'svelte';
  import DeviceList from './DeviceList.svelte';
  import QRScanner from './QRScanner.svelte';
  import PairingTimeline from './PairingTimeline.svelte';
  import IdentityDebugPanel from './IdentityDebugPanel.svelte';
  import QRCode from './QRCode.svelte';
  import ConnectedPeers from './ConnectedPeers.svelte';

  export let devices = [];
  export let dbAddress = null;
  export let qrPayload = null;
  export let status = '';
  export let error = '';
  export let loading = false;
  export let pairingEvents = [];
  export let identityDebug = {};
  export let connectedPeers = [];
  export let canCreateSetup = false;

  const dispatch = createEventDispatcher();

  let qrJsonInput = '';
  let inputMode = 'scan'; // 'scan' | 'paste'
  let panelMode = 'connect'; // 'connect' | 'share'

  function parsePairingInput(rawInput) {
    const trimmed = rawInput?.trim?.() || '';
    if (!trimmed) {
      throw new Error('Please paste a Device A payload or peer ID.');
    }

    try {
      const parsed = JSON.parse(trimmed);
      if (!parsed?.peerId || typeof parsed.peerId !== 'string') {
        throw new Error('Payload JSON must include a peerId string.');
      }
      return {
        peerId: parsed.peerId.trim(),
        multiaddrs: Array.isArray(parsed.multiaddrs) ? parsed.multiaddrs : [],
      };
    } catch (error) {
      const looksLikePeerId =
        !trimmed.startsWith('{') &&
        !trimmed.startsWith('[') &&
        /^[1-9A-HJ-NP-Za-km-z]{20,}$/.test(trimmed);

      if (looksLikePeerId) {
        return {
          peerId: trimmed,
          multiaddrs: [],
        };
      }

      throw error;
    }
  }

  function handleScanResult(event) {
    qrJsonInput = event.detail;
    let payload;
    try {
      payload = parsePairingInput(qrJsonInput);
    } catch {
      dispatch('error', 'Scanned data is not a valid Device A payload or peer ID.');
      return;
    }
    dispatch('pair', { qrPayload: payload });
  }

  function handlePair() {
    let qrPayload;
    try {
      qrPayload = parsePairingInput(qrJsonInput);
    } catch {
      dispatch('error', 'Invalid input. Paste the Device A JSON payload or only its peer ID.');
      return;
    }
    dispatch('pair', { qrPayload });
  }

  function handleCreateSetup() {
    dispatch('createSetup');
  }
</script>

<div class="pair-view">
  <h2>Link to Existing Device</h2>
  <p class="subtitle">
    Switch between connecting to another device and sharing this device with QR or JSON.
  </p>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if status}
    <div class="status-banner">{status}</div>
  {/if}

  <div class="step">
    <div class="mode-toggle">
      <button
        class="mode-btn"
        class:active={panelMode === 'connect'}
        on:click={() => (panelMode = 'connect')}
      >
        Connect
      </button>
      <button
        class="mode-btn"
        class:active={panelMode === 'share'}
        on:click={() => (panelMode = 'share')}
      >
        Share QR / JSON
      </button>
    </div>

    {#if panelMode === 'connect'}
      <h3>Connect to Device A</h3>
      <div class="mode-toggle">
        <button
          class="mode-btn"
          class:active={inputMode === 'scan'}
          on:click={() => (inputMode = 'scan')}
        >
          📷 Scan QR
        </button>
        <button
          class="mode-btn"
          class:active={inputMode === 'paste'}
          on:click={() => (inputMode = 'paste')}
        >
          📋 Paste JSON
        </button>
      </div>

      {#if inputMode === 'scan'}
        <QRScanner on:scan={handleScanResult} />
        <p class="mode-hint">Point camera at Device A's QR code. Pairing starts automatically.</p>
      {:else}
        <textarea
          bind:value={qrJsonInput}
          placeholder='Paste Device A JSON payload or only its peer ID'
          rows="4"
          disabled={loading}
        ></textarea>
        <button class="btn-primary" on:click={handlePair} disabled={loading || !qrJsonInput.trim()}>
          {loading ? 'Connecting…' : '📲 Send Pairing Request'}
        </button>
      {/if}
    {:else}
      <h3>Share This Device</h3>
      {#if !dbAddress}
        <p class="mode-hint">
          Create a new shared setup on this device, then let another device scan the QR code or paste the JSON payload.
        </p>
        <ConnectedPeers peers={connectedPeers} />
        <button class="btn-primary" on:click={handleCreateSetup} disabled={loading || !canCreateSetup}>
          {loading ? 'Creating…' : '➕ Create New Setup Here'}
        </button>
        {#if !canCreateSetup}
          <p class="mode-hint">
            Waiting for at least one libp2p peer connection before enabling setup sharing.
          </p>
        {/if}
      {:else}
        <div class="success-banner">
          ✅ Shared setup ready on this device.
        </div>

        <div class="db-address">
          <strong>DB Address:</strong>
          <code>{dbAddress}</code>
        </div>

        <div class="share-grid">
          <div class="share-card">
            <h4>Scan QR</h4>
            <QRCode payload={qrPayload} />
          </div>
          <div class="share-card">
            <h4>Copy JSON</h4>
            <textarea rows="8" readonly value={qrPayload ? JSON.stringify(qrPayload, null, 2) : ''}></textarea>
          </div>
        </div>
        <ConnectedPeers peers={connectedPeers} />
      {/if}
    {/if}
  </div>

  {#if dbAddress}
    <DeviceList {devices} />
  {/if}

  <IdentityDebugPanel debug={identityDebug} />
  <PairingTimeline entries={pairingEvents} title="Pairing and Replication Log" />
</div>

<style>
  .pair-view {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  h2 {
    margin: 0;
  }

  .subtitle {
    color: var(--cds-text-secondary, #555);
    margin: 0;
  }

  .step {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding: 1rem;
    border: 1px solid var(--cds-border-subtle, #ddd);
    border-radius: 0.5rem;
  }

  .step h3 {
    margin: 0;
    font-size: 0.9rem;
    color: var(--cds-text-secondary, #555);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .mode-toggle {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .mode-btn {
    padding: 0.45rem 0.9rem;
    background: var(--cds-layer, #f0f0f0);
    border: 1px solid var(--cds-border-subtle, #ccc);
    border-radius: 0.4rem;
    font-size: 0.85rem;
    cursor: pointer;
    transition: background 0.15s;
  }

  .mode-btn.active {
    background: #4f46e5;
    color: white;
    border-color: #4f46e5;
  }

  .mode-hint {
    font-size: 0.8rem;
    color: var(--cds-text-helper, #888);
    margin: 0;
  }

  textarea {
    width: 100%;
    padding: 0.5rem;
    font-family: monospace;
    font-size: 0.8rem;
    border: 1px solid var(--cds-border-subtle, #ccc);
    border-radius: 0.4rem;
    background: var(--cds-layer, #f9f9f9);
    resize: vertical;
    box-sizing: border-box;
  }

  .share-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1rem;
    width: 100%;
  }

  .share-card {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding: 0.75rem;
    border: 1px solid var(--cds-border-subtle, #ddd);
    border-radius: 0.5rem;
    background: var(--cds-layer, #fafafa);
  }

  .share-card h4 {
    margin: 0;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--cds-text-helper, #666);
  }

  .btn-primary {
    padding: 0.65rem 1.25rem;
    background: linear-gradient(135deg, #4f46e5, #7c3aed);
    color: white;
    border: none;
    border-radius: 0.5rem;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    align-self: flex-start;
    transition: opacity 0.2s;
  }

  .btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .error-banner {
    padding: 0.75rem 1rem;
    background: #fde8e8;
    border: 1px solid #e74c3c;
    border-radius: 0.4rem;
    color: #c0392b;
  }

  .status-banner {
    padding: 0.75rem 1rem;
    background: #e8f4fd;
    border: 1px solid #3498db;
    border-radius: 0.4rem;
    color: #2471a3;
  }

  .success-banner {
    padding: 0.75rem 1rem;
    background: #eafaf1;
    border: 1px solid #27ae60;
    border-radius: 0.4rem;
    color: #1e8449;
    font-weight: 600;
  }

  .db-address {
    font-size: 0.85rem;
    word-break: break-all;
    color: var(--cds-text-secondary, #555);
  }

  .db-address code {
    display: block;
    margin-top: 0.25rem;
    font-size: 0.75rem;
    background: var(--cds-layer-02, #f4f4f4);
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
  }
</style>

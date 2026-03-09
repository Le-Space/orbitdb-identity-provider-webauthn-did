<script>
  import { createEventDispatcher } from 'svelte';
  import QRCode from './QRCode.svelte';
  import DeviceList from './DeviceList.svelte';
  import PairingTimeline from './PairingTimeline.svelte';
  import IdentityDebugPanel from './IdentityDebugPanel.svelte';
  import ConnectedPeers from './ConnectedPeers.svelte';

  export let qrPayload = null;
  export let devices = [];
  export let dbAddress = null;
  export let status = '';
  export let error = '';
  export let loading = false;
  export let pairingEvents = [];
  export let identityDebug = {};
  export let connectedPeers = [];

  const dispatch = createEventDispatcher();

  function handleSetup() {
    dispatch('setup');
  }

  function handleRepair() {
    dispatch('repair');
  }

  function handleRetrySync() {
    dispatch('retrySync');
  }
</script>

<div class="setup-view">
  <h2>P2P Passkey Manager</h2>
  <p class="subtitle">
    Use your WebAuthn credential to manage the shared device registry and scan
    QR codes to link other devices.
  </p>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if status}
    <div class="status-banner">{status}</div>
  {/if}

  {#if !dbAddress}
    <button class="btn-primary" on:click={handleSetup} disabled={loading}>
      {loading ? 'Setting up…' : '🔐 Set Up as First Device'}
    </button>
  {:else}
    <div class="success-banner">
      ✅ Device registry created!
    </div>

    <div class="db-address">
      <strong>DB Address:</strong>
      <code data-testid="db-address">{dbAddress}</code>
    </div>

    <ConnectedPeers peers={connectedPeers} />

    {#if devices.length === 0}
      <div class="warning-banner">
        Local registry is still empty on this device. This is not just a UI refresh issue: the current browser has not read back any device entries yet.
      </div>

      <div class="recovery-actions">
        <button class="btn-secondary" on:click={handleRetrySync} disabled={loading}>
          Retry Local Sync
        </button>
        <button class="btn-primary" on:click={handleRepair} disabled={loading}>
          Re-pair / Recover From Another Device
        </button>
      </div>
    {/if}

    <div class="qr-section">
      <h3>Show QR Code to Link Another Device</h3>
      <QRCode payload={qrPayload} />
      <div class="json-share">
        <h4>Copy JSON</h4>
        <textarea
          rows="8"
          readonly
          value={qrPayload ? JSON.stringify(qrPayload, null, 2) : ''}
          aria-label="QR payload JSON"
        ></textarea>
      </div>
      {#if qrPayload && qrPayload.multiaddrs && qrPayload.multiaddrs.length === 0}
        <p class="relay-notice">
          ⏳ Connecting to relay servers… QR updates automatically when ready.
          Cross-network pairing requires relay addresses.
        </p>
        <details class="addr-debug">
          <summary>Debug — peer ID (no relay addrs yet)</summary>
          <code>{qrPayload.peerId}</code>
        </details>
      {:else if qrPayload && qrPayload.multiaddrs && qrPayload.multiaddrs.length > 0}
        <p class="relay-ready">✅ {qrPayload.multiaddrs.length} relay addr{qrPayload.multiaddrs.length > 1 ? 's' : ''} ready — cross-network pairing enabled</p>
        <details class="addr-debug">
          <summary>Debug — multiaddrs ({qrPayload.multiaddrs.length})</summary>
          {#each qrPayload.multiaddrs as addr}
            <code>{addr}</code>
          {/each}
        </details>
      {/if}
    </div>

    <DeviceList {devices} />
    <IdentityDebugPanel debug={identityDebug} />
    <PairingTimeline entries={pairingEvents} title="Pairing and Replication Log" />
  {/if}
</div>

<style>
  .setup-view {
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

  .btn-primary {
    padding: 0.75rem 1.5rem;
    background: linear-gradient(135deg, #4f46e5, #7c3aed);
    color: white;
    border: none;
    border-radius: 0.5rem;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
    align-self: flex-start;
  }

  .btn-secondary {
    padding: 0.75rem 1.5rem;
    background: #eef2ff;
    color: #312e81;
    border: 1px solid #c7d2fe;
    border-radius: 0.5rem;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
    align-self: flex-start;
  }

  .btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .btn-secondary:disabled {
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

  .warning-banner {
    padding: 0.75rem 1rem;
    background: #fff7ed;
    border: 1px solid #f97316;
    border-radius: 0.4rem;
    color: #9a3412;
  }

  .recovery-actions {
    display: flex;
    gap: 0.75rem;
    flex-wrap: wrap;
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

  .qr-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    padding: 1rem;
    background: var(--cds-layer, #f9f9f9);
    border-radius: 0.75rem;
    border: 1px solid var(--cds-border-subtle, #ddd);
  }

  .qr-section h3 {
    margin: 0;
    font-size: 0.95rem;
  }

  .json-share {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
  }

  .json-share h4 {
    margin: 0;
    font-size: 0.82rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #666;
  }

  .json-share textarea {
    width: 100%;
    padding: 0.6rem;
    font-family: monospace;
    font-size: 0.78rem;
    border: 1px solid #d1d5db;
    border-radius: 0.5rem;
    background: #f8fafc;
    resize: vertical;
    box-sizing: border-box;
  }

  .relay-notice {
    font-size: 0.78rem;
    color: #92400e;
    background: #fef3c7;
    border: 1px solid #f59e0b;
    border-radius: 0.35rem;
    padding: 0.4rem 0.65rem;
    margin: 0;
    text-align: center;
    max-width: 240px;
  }

  .relay-ready {
    font-size: 0.78rem;
    color: #065f46;
    margin: 0;
  }

  .addr-debug {
    font-size: 0.72rem;
    color: #555;
    max-width: 260px;
    text-align: left;
  }

  .addr-debug summary {
    cursor: pointer;
    color: #888;
  }

  .addr-debug code {
    display: block;
    word-break: break-all;
    background: #f0f0f0;
    padding: 0.15rem 0.3rem;
    border-radius: 0.2rem;
    margin-top: 0.2rem;
    font-size: 0.65rem;
  }
</style>

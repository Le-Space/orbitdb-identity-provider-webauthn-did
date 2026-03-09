<script>
  import { createEventDispatcher } from 'svelte';
  import QRCode from './QRCode.svelte';
  import DeviceList from './DeviceList.svelte';

  export let qrPayload = null;
  export let devices = [];
  export let dbAddress = null;
  export let status = '';
  export let error = '';
  export let loading = false;

  const dispatch = createEventDispatcher();

  function handleSetup() {
    dispatch('setup');
  }
</script>

<div class="setup-view">
  <h2>Device A — First Device Setup</h2>
  <p class="subtitle">
    Create your WebAuthn credential, initialize the shared device registry, and
    display a QR code so other devices can join.
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

    <div class="qr-section">
      <h3>Show QR Code to Link Another Device</h3>
      <QRCode payload={qrPayload} />
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

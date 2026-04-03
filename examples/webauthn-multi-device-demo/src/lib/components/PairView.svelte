<script>
  import { createEventDispatcher } from 'svelte';
  import DeviceList from './DeviceList.svelte';
  import QRScanner from './QRScanner.svelte';

  export let devices = [];
  export let dbAddress = null;
  export let status = '';
  export let error = '';
  export let loading = false;

  const dispatch = createEventDispatcher();

  let qrJsonInput = '';
  let inputMode = 'scan'; // 'scan' | 'paste'

  function handleScanResult(event) {
    qrJsonInput = event.detail;
    let payload;
    try {
      payload = JSON.parse(qrJsonInput);
    } catch {
      dispatch('error', 'Scanned data is not valid QR payload JSON.');
      return;
    }
    dispatch('pair', { qrPayload: payload });
  }

  function handlePair() {
    let qrPayload;
    try {
      qrPayload = JSON.parse(qrJsonInput.trim());
    } catch {
      dispatch('error', 'Invalid QR payload JSON. Please paste the JSON from the QR code.');
      return;
    }
    dispatch('pair', { qrPayload });
  }
</script>

<div class="pair-view">
  <h2>Link to Existing Device</h2>
  <p class="subtitle">
    Scan (or paste) Device A's QR code to request access to the shared database.
  </p>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if status}
    <div class="status-banner">{status}</div>
  {/if}

  {#if !dbAddress}
    <div class="step">
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
          placeholder=''
          rows="4"
          disabled={loading}
        ></textarea>
        <button class="btn-primary" on:click={handlePair} disabled={loading || !qrJsonInput.trim()}>
          {loading ? 'Connecting…' : '📲 Send Pairing Request'}
        </button>
      {/if}
    </div>
  {:else}
    <div class="success-banner">
      ✅ Paired successfully! Connected to shared database.
    </div>

    <div class="db-address">
      <strong>DB Address:</strong>
      <code>{dbAddress}</code>
    </div>

    <DeviceList {devices} />
  {/if}
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

  .btn-secondary {
    padding: 0.65rem 1.25rem;
    background: var(--cds-layer, #e8e8e8);
    color: var(--cds-text-primary, #333);
    border: 1px solid var(--cds-border-subtle, #ccc);
    border-radius: 0.5rem;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    align-self: flex-start;
    transition: opacity 0.2s;
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

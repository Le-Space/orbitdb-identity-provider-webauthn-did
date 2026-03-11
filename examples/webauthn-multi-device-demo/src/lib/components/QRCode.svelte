<script>
  import { onMount, onDestroy } from 'svelte';
  import QRCode from 'qrcode';

  /** JSON-serialisable payload to encode in the QR code */
  export let payload = null;
  export let showRawPayload = false;

  let canvasEl;
  let payloadStr = '';

  $: {
    payloadStr = payload ? JSON.stringify(payload) : '';
    if (canvasEl && payloadStr) {
      renderQR(payloadStr);
    }
  }

  async function renderQR(text) {
    try {
      await QRCode.toCanvas(canvasEl, text, {
        width: 240,
        margin: 2,
        color: { dark: '#000000', light: '#ffffff' },
      });
    } catch (err) {
      console.error('QR render error:', err);
    }
  }

  onMount(() => {
    if (payloadStr) renderQR(payloadStr);
  });
</script>

<div class="qr-wrapper">
  {#if payloadStr}
    <!--
      data-testid="qr-payload" holds the raw JSON so Playwright can extract it
      without needing to decode the actual QR image.
    -->
    <canvas bind:this={canvasEl} data-testid="qr-payload" data-payload={payloadStr}></canvas>
    {#if showRawPayload}
      <code>{payloadStr}</code>
    {/if}
  {:else}
    <div class="placeholder">QR code will appear here</div>
  {/if}
</div>

<style>
  .qr-wrapper {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
  }

  canvas {
    border-radius: 0.5rem;
    border: 1px solid var(--cds-border-subtle, #ddd);
  }

  .placeholder {
    width: 240px;
    height: 240px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 2px dashed var(--cds-border-subtle, #ccc);
    border-radius: 0.5rem;
    color: var(--cds-text-helper, #888);
    font-size: 0.875rem;
    text-align: center;
    padding: 1rem;
  }

</style>

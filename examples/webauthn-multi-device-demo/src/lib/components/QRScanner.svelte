<script>
  import { onDestroy, createEventDispatcher, tick } from 'svelte';

  const dispatch = createEventDispatcher();

  let scanning = false;
  let videoEl;
  let canvasEl;
  let mediaStream = null;
  let rafId = null;
  let scanError = '';
  let jsQRLib = null;

  async function startScan() {
    scanError = '';
    scanning = true;
    await tick(); // Wait for video element to render

    try {
      if (!jsQRLib) {
        const mod = await import('jsqr');
        jsQRLib = mod.default;
      }
      mediaStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' } },
      });
      videoEl.srcObject = mediaStream;
      await videoEl.play();
      scanFrame();
    } catch (err) {
      scanning = false;
      scanError =
        err.name === 'NotAllowedError'
          ? 'Camera permission denied. Please allow camera access and try again.'
          : 'Camera unavailable: ' + err.message;
    }
  }

  function scanFrame() {
    if (!scanning) return;
    if (videoEl.readyState < videoEl.HAVE_ENOUGH_DATA) {
      rafId = requestAnimationFrame(scanFrame);
      return;
    }
    canvasEl.width = videoEl.videoWidth;
    canvasEl.height = videoEl.videoHeight;
    const ctx = canvasEl.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(videoEl, 0, 0);
    const imgData = ctx.getImageData(0, 0, canvasEl.width, canvasEl.height);
    const code = jsQRLib(imgData.data, imgData.width, imgData.height);
    if (code) {
      stopScan();
      dispatch('scan', code.data);
    } else {
      rafId = requestAnimationFrame(scanFrame);
    }
  }

  function stopScan() {
    scanning = false;
    if (rafId) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
    if (mediaStream) {
      mediaStream.getTracks().forEach((t) => t.stop());
      mediaStream = null;
    }
  }

  onDestroy(stopScan);
</script>

<div class="scanner">
  {#if !scanning}
    <button class="btn-scan" on:click={startScan}>📷 Scan QR Code</button>
    {#if scanError}
      <p class="scan-error">{scanError}</p>
    {/if}
  {:else}
    <div class="viewfinder">
      <!-- svelte-ignore a11y-media-has-caption -->
      <video bind:this={videoEl} playsinline muted></video>
      <canvas bind:this={canvasEl} style="display:none"></canvas>
      <div class="scan-overlay">
        <div class="scan-frame"></div>
      </div>
    </div>
    <button class="btn-cancel" on:click={stopScan}>✕ Cancel</button>
  {/if}
</div>

<style>
  .scanner {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
    width: 100%;
  }

  .viewfinder {
    position: relative;
    width: 100%;
    max-width: 300px;
    border-radius: 0.5rem;
    overflow: hidden;
    background: #000;
  }

  video {
    width: 100%;
    display: block;
  }

  .scan-overlay {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .scan-frame {
    width: 65%;
    aspect-ratio: 1;
    border: 3px solid rgba(255, 255, 255, 0.85);
    border-radius: 0.75rem;
    box-shadow: 0 0 0 9999px rgba(0, 0, 0, 0.35);
  }

  .btn-scan {
    padding: 0.65rem 1.25rem;
    background: var(--cds-layer, #e8e8e8);
    color: var(--cds-text-primary, #333);
    border: 1px solid var(--cds-border-subtle, #ccc);
    border-radius: 0.5rem;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
  }

  .btn-scan:hover {
    opacity: 0.85;
  }

  .btn-cancel {
    padding: 0.45rem 1rem;
    background: transparent;
    color: var(--cds-text-secondary, #555);
    border: 1px solid var(--cds-border-subtle, #ccc);
    border-radius: 0.4rem;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .scan-error {
    font-size: 0.85rem;
    color: #c0392b;
    margin: 0;
  }
</style>

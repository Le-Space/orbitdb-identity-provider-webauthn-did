<script>
  import { TooltipDefinition, OverflowMenu, Button } from "carbon-components-svelte";
  import { Checkmark, Warning, Time, Information } from "carbon-icons-svelte";

  export let identityHash;
  export let webAuthnDID;
  export let verificationState = null;
  export let timestamp = null;

  let showDetails = false;

  function getStatusInfo() {
    if (verificationState === true) {
      return {
        icon: Checkmark,
        color: "var(--cds-support-success)",
        text: "Verified",
        tooltip: webAuthnDID ? `Signed by: ${webAuthnDID.slice(0, 20)}...` : "Signed with your secure key"
      };
    } else if (verificationState === false) {
      return {
        icon: Warning,
        color: "var(--cds-support-error)", 
        text: "Unverified",
        tooltip: "Could not verify signature"
      };
    } else {
      return {
        icon: Time,
        color: "var(--cds-text-helper)",
        text: "Verifying...",
        tooltip: "Checking signature..."
      };
    }
  }

  $: statusInfo = getStatusInfo();
</script>

<div class="verification-badge">
  <!-- Simple Badge with Tooltip -->
  <TooltipDefinition
    align="center"
    direction="top"
    tabindex={0}
  >
    <div slot="trigger" class="badge-container">
      <div class="badge-pill" style="background-color: {statusInfo.color}20; border-color: {statusInfo.color};">
        <svelte:component this={statusInfo.icon} size={12} style="color: {statusInfo.color}" />
        <span class="badge-text" style="color: {statusInfo.color}">{statusInfo.text}</span>
      </div>
      
      <!-- Progressive Disclosure - Info Button -->
      {#if verificationState !== null}
        <button 
          class="info-button" 
          on:click|stopPropagation={() => showDetails = !showDetails}
          aria-label="Show verification details"
        >
          <Information size={14} />
        </button>
      {/if}
    </div>
    
    <div class="tooltip-content">
      {statusInfo.tooltip}
    </div>
  </TooltipDefinition>

  <!-- Progressive Disclosure Details -->
  {#if showDetails && verificationState !== null}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <!-- svelte-ignore a11y-no-static-element-interactions -->
    <div class="details-overlay" on:click={() => showDetails = false} role="button" tabindex="0" on:keydown={(e) => e.key === 'Escape' && (showDetails = false)}>
      <!-- svelte-ignore a11y-click-events-have-key-events -->
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="details-panel" on:click|stopPropagation role="dialog" aria-modal="true">
        <div class="details-header">
          <h6>Verification Details</h6>
          <button class="close-button" on:click={() => showDetails = false}>×</button>
        </div>
        
        <div class="details-content">
          <div class="detail-row">
            <span class="label">Status:</span>
            <span class="value" style="color: {statusInfo.color}">
              {statusInfo.text}
            </span>
          </div>
          
          <div class="detail-row">
            <span class="label">WebAuthn DID:</span>
            <span class="value mono">{webAuthnDID}</span>
          </div>
          
          <div class="detail-row">
            <span class="label">Timestamp:</span>
            <span class="value">{new Date(timestamp).toLocaleString()}</span>
          </div>
          
          <details class="technical-details">
            <summary>Advanced Details</summary>
            <div class="tech-content">
              <div class="detail-row">
                <span class="label">Database signature:</span>
                <span class="value mono">{identityHash}</span>
              </div>
            </div>
          </details>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .verification-badge {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
  }

  .badge-container {
    display: flex;
    align-items: center;
    gap: 0.25rem;
  }

  .badge-pill {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.125rem 0.5rem;
    border-radius: 12px;
    border: 1px solid;
    font-size: 0.75rem;
    font-weight: 500;
    transition: all 0.2s ease;
  }

  .badge-text {
    font-size: 0.75rem;
    font-weight: 500;
  }

  .info-button {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 20px;
    height: 20px;
    border: none;
    border-radius: 50%;
    background: var(--cds-layer-hover);
    color: var(--cds-text-secondary);
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .info-button:hover {
    background: var(--cds-layer-selected);
    color: var(--cds-text-primary);
  }

  .tooltip-content {
    font-size: 0.75rem;
    font-family: 'IBM Plex Sans', sans-serif;
    text-align: center;
  }

  /* Progressive Disclosure Overlay */
  .details-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.4);
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .details-panel {
    background: var(--cds-background);
    border: 1px solid var(--cds-border-subtle);
    border-radius: 8px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    width: 90%;
    max-width: 400px;
    max-height: 80vh;
    overflow-y: auto;
  }

  .details-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem;
    border-bottom: 1px solid var(--cds-border-subtle);
  }

  .details-header h6 {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    color: var(--cds-text-primary);
  }

  .close-button {
    background: none;
    border: none;
    font-size: 1.5rem;
    color: var(--cds-text-secondary);
    cursor: pointer;
    padding: 0;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .close-button:hover {
    color: var(--cds-text-primary);
  }

  .details-content {
    padding: 1rem;
  }

  .detail-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 0.75rem;
    gap: 1rem;
  }

  .label {
    color: var(--cds-text-secondary);
    font-weight: 500;
    font-size: 0.875rem;
    flex-shrink: 0;
  }

  .value {
    color: var(--cds-text-primary);
    font-size: 0.875rem;
    text-align: right;
  }

  .value.mono {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.75rem;
    word-break: break-all;
    text-align: right;
  }

  .technical-details {
    margin-top: 1rem;
    border-top: 1px solid var(--cds-border-subtle);
    padding-top: 1rem;
  }

  .technical-details summary {
    cursor: pointer;
    font-weight: 500;
    color: var(--cds-text-secondary);
    margin-bottom: 0.5rem;
  }

  .technical-details summary:hover {
    color: var(--cds-text-primary);
  }

  .tech-content {
    margin-top: 0.5rem;
  }
</style>

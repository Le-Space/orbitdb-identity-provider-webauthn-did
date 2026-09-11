<script>
  // One badge per todo: what the verifier in shared/lib/verification.js
  // found for the entry behind it. `result` is null while it is still
  // looking.
  import { TooltipDefinition } from 'carbon-components-svelte';
  import { Checkmark, Warning, Time, Information } from 'carbon-icons-svelte';

  export let result = null;

  let showDetails = false;

  const CHECKS = [
    ['signature', 'Entry signature by the writer key'],
    ['binding', 'Identity document carries that key'],
    ['identity', 'Identity document verifies for its DID'],
    ['writeAccess', 'Writer DID is in the write list'],
  ];

  $: status =
    result === null
      ? {
          icon: Time,
          color: 'var(--cds-text-helper)',
          text: 'Verifying…',
          tooltip: 'Checking the entry',
          state: 'pending',
        }
      : result.ok
        ? {
            icon: Checkmark,
            color: 'var(--cds-support-success)',
            text: 'Verified',
            tooltip: `Signed by ${result.writer}`,
            state: 'verified',
          }
        : {
            icon: Warning,
            color: 'var(--cds-support-error)',
            text: 'Rejected',
            tooltip:
              result.error ??
              `failed: ${CHECKS.filter(([k]) => result.checks[k] !== true)
                .map(([k]) => k)
                .join(', ')}`,
            state: 'rejected',
          };
</script>

<div
  class="verification-badge"
  data-testid="verification-badge"
  data-state={status.state}
  data-writer={result?.writer ?? ''}
>
  <TooltipDefinition align="center" direction="top" tabindex={0}>
    <div slot="trigger" class="badge-container">
      <div
        class="badge-pill"
        style="background-color: {status.color}20; border-color: {status.color};"
      >
        <svelte:component
          this={status.icon}
          size={12}
          style="color: {status.color}"
        />
        <span class="badge-text" style="color: {status.color}"
          >{status.text}</span
        >
      </div>
      {#if result}
        <button
          class="info-button"
          on:click|stopPropagation={() => (showDetails = !showDetails)}
          aria-label="Show verification details"
        >
          <Information size={14} />
        </button>
      {/if}
    </div>
    <div class="tooltip-content">{status.tooltip}</div>
  </TooltipDefinition>

  {#if showDetails && result}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <!-- svelte-ignore a11y-no-static-element-interactions -->
    <div
      class="details-overlay"
      on:click={() => (showDetails = false)}
      role="button"
      tabindex="0"
      on:keydown={(e) => e.key === 'Escape' && (showDetails = false)}
    >
      <!-- svelte-ignore a11y-click-events-have-key-events -->
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div
        class="details-panel"
        on:click|stopPropagation
        role="dialog"
        aria-modal="true"
        tabindex="-1"
      >
        <div class="details-header">
          <h6>What was checked</h6>
          <button class="close-button" on:click={() => (showDetails = false)}
            >×</button
          >
        </div>
        <div class="details-content">
          <ul class="checks">
            {#each CHECKS as [key, label]}
              <li data-check={key} data-passed={result.checks[key] === true}>
                <span class="mark"
                  >{result.checks[key] === true
                    ? '✓'
                    : result.checks[key] === false
                      ? '✗'
                      : '·'}</span
                >
                {label}
              </li>
            {/each}
          </ul>
          <div class="detail-row">
            <span class="label">Writer DID</span>
            <span class="value mono">{result.writer ?? '—'}</span>
          </div>
          <div class="detail-row">
            <span class="label">Identity block</span>
            <span class="value mono">{result.identityHash ?? '—'}</span>
          </div>
          <div class="detail-row">
            <span class="label">Entry</span>
            <span class="value mono">{result.entryHash ?? '—'}</span>
          </div>
          {#if result.error}
            <div class="detail-row">
              <span class="label">Error</span>
              <span class="value">{result.error}</span>
            </div>
          {/if}
          <div class="detail-row">
            <span class="label">Checked</span>
            <span class="value">{new Date(result.at).toLocaleString()}</span>
          </div>
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
  }
  .info-button:hover {
    background: var(--cds-layer-selected);
    color: var(--cds-text-primary);
  }
  .tooltip-content {
    font-size: 0.75rem;
    text-align: center;
    word-break: break-all;
  }
  .details-overlay {
    position: fixed;
    inset: 0;
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
    max-width: 440px;
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
    width: 24px;
    height: 24px;
  }
  .details-content {
    padding: 1rem;
  }
  .checks {
    list-style: none;
    margin: 0 0 1rem;
    padding: 0;
    font-size: 0.875rem;
    color: var(--cds-text-primary);
  }
  .checks li {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 0.25rem;
  }
  .checks li[data-passed='true'] .mark {
    color: var(--cds-support-success);
  }
  .checks li[data-passed='false'] .mark {
    color: var(--cds-support-error);
  }
  .detail-row {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.75rem;
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
  }
</style>

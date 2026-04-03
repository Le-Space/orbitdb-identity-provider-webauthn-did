<script>
  import { createEventDispatcher } from 'svelte';

  export let request = null;

  const dispatch = createEventDispatcher();

  function approve() {
    dispatch('decision', 'granted');
  }

  function deny() {
    dispatch('decision', 'rejected');
  }
</script>

<div class="confirm-overlay">
  <div class="confirm-card">
    <h2>New Device Wants to Join</h2>

    {#if request}
      <div class="device-info">
        <p><strong>Device:</strong> {request.identity?.deviceLabel || 'Unknown Device'}</p>
        <p class="did" title={request.identity?.id}>
          <strong>DID:</strong>
          {#if request.identity?.id}
            {request.identity.id.slice(0, 16)}…{request.identity.id.slice(-8)}
          {:else}
            —
          {/if}
        </p>
      </div>
    {/if}

    <p class="prompt">
      Grant this device write access to your shared database?
    </p>

    <div class="actions">
      <button class="btn-approve" on:click={approve}>✅ Approve</button>
      <button class="btn-deny" on:click={deny}>❌ Deny</button>
    </div>
  </div>
</div>

<style>
  .confirm-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .confirm-card {
    background: var(--cds-layer, #fff);
    border-radius: 1rem;
    padding: 2rem;
    max-width: 400px;
    width: 90%;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
  }

  h2 {
    margin: 0 0 1rem;
    font-size: 1.25rem;
  }

  .device-info {
    background: var(--cds-layer-02, #f4f4f4);
    border-radius: 0.5rem;
    padding: 0.75rem 1rem;
    margin-bottom: 1rem;
  }

  .device-info p {
    margin: 0.25rem 0;
    font-size: 0.9rem;
  }

  .did {
    font-family: monospace;
    word-break: break-all;
  }

  .prompt {
    color: var(--cds-text-secondary, #555);
    margin-bottom: 1.5rem;
  }

  .actions {
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
  }

  button {
    padding: 0.6rem 1.25rem;
    border: none;
    border-radius: 0.4rem;
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 600;
    transition: opacity 0.2s;
  }

  button:hover {
    opacity: 0.85;
  }

  .btn-approve {
    background: #27ae60;
    color: white;
  }

  .btn-deny {
    background: #e74c3c;
    color: white;
  }
</style>

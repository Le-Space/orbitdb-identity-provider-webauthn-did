<script>
  export let devices = [];

  function formatDate(ts) {
    if (!ts) return '—';
    return new Date(ts).toLocaleString();
  }

  function shortDid(did) {
    if (!did) return '—';
    return did.length > 24 ? did.slice(0, 12) + '…' + did.slice(-8) : did;
  }
</script>

<div class="device-list">
  <h3>Registered Devices ({devices.length})</h3>

  {#if devices.length === 0}
    <p class="empty">No devices registered yet.</p>
  {:else}
    <ul>
      {#each devices as device}
        <li class="device-item" class:revoked={device.status === 'revoked'}>
          <div class="device-label">
            <span class="icon">{device.status === 'revoked' ? '🚫' : '✅'}</span>
            <strong>{device.device_label || 'Unknown Device'}</strong>
            {#if device.status === 'revoked'}
              <span class="badge revoked">revoked</span>
            {/if}
          </div>
          <div class="device-meta">
            <span title={device.ed25519_did}>DID: {shortDid(device.ed25519_did)}</span>
            <span>Added: {formatDate(device.created_at)}</span>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .device-list {
    margin: 1rem 0;
  }

  h3 {
    margin: 0 0 0.75rem;
    font-size: 1rem;
  }

  .empty {
    color: var(--cds-text-helper, #888);
    font-style: italic;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .device-item {
    padding: 0.75rem 1rem;
    border: 1px solid var(--cds-border-subtle, #ddd);
    border-radius: 0.5rem;
    background: var(--cds-layer, #f9f9f9);
  }

  .device-item.revoked {
    opacity: 0.6;
    text-decoration: line-through;
  }

  .device-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.25rem;
  }

  .badge.revoked {
    font-size: 0.7rem;
    background: #e74c3c;
    color: white;
    padding: 0.1rem 0.4rem;
    border-radius: 0.25rem;
    text-decoration: none;
  }

  .device-meta {
    display: flex;
    gap: 1rem;
    font-size: 0.8rem;
    color: var(--cds-text-helper, #666);
    flex-wrap: wrap;
  }
</style>

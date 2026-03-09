<script>
  export let entries = [];
  export let title = 'Pairing Timeline';

  function formatTime(timestamp) {
    if (!timestamp) return '--:--:--';
    return new Date(timestamp).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  }

  function roleLabel(role) {
    if (role === 'device-a') return 'A';
    if (role === 'device-b') return 'B';
    if (role === 'sync') return 'SYNC';
    return 'APP';
  }
</script>

<section class="timeline-panel">
  <div class="timeline-header">
    <h3>{title}</h3>
    <span>{entries.length} event{entries.length === 1 ? '' : 's'}</span>
  </div>

  {#if entries.length === 0}
    <p class="timeline-empty">No pairing events yet.</p>
  {:else}
    <ol class="timeline-list">
      {#each entries as entry (entry.id)}
        <li class={`timeline-entry ${entry.level || 'info'}`}>
          <div class="entry-meta">
            <span class="role">{roleLabel(entry.role)}</span>
            <span class="time">{formatTime(entry.timestamp)}</span>
            <span class="stage">{entry.stage}</span>
          </div>
          <p class="detail">{entry.detail}</p>
          {#if entry.metaSummary}
            <p class="meta-summary">{entry.metaSummary}</p>
          {/if}
        </li>
      {/each}
    </ol>
  {/if}
</section>

<style>
  .timeline-panel {
    width: 100%;
    padding: 1rem;
    border: 1px solid #d6d3d1;
    border-radius: 0.75rem;
    background:
      linear-gradient(180deg, rgba(251, 247, 240, 0.95), rgba(245, 241, 232, 0.95));
  }

  .timeline-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.75rem;
  }

  .timeline-header h3,
  .timeline-header span,
  .timeline-empty,
  .detail,
  .meta-summary,
  .entry-meta {
    margin: 0;
  }

  .timeline-header h3 {
    font-size: 0.95rem;
  }

  .timeline-header span,
  .timeline-empty,
  .meta-summary,
  .entry-meta {
    color: #57534e;
    font-size: 0.8rem;
  }

  .timeline-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.65rem;
    max-height: 20rem;
    overflow: auto;
  }

  .timeline-entry {
    padding: 0.7rem 0.8rem;
    border-radius: 0.6rem;
    border-left: 4px solid #64748b;
    background: rgba(255, 255, 255, 0.78);
  }

  .timeline-entry.success {
    border-left-color: #15803d;
  }

  .timeline-entry.warning {
    border-left-color: #b45309;
  }

  .timeline-entry.error {
    border-left-color: #b91c1c;
  }

  .entry-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
    align-items: center;
    font-family: monospace;
  }

  .role {
    min-width: 2.8rem;
    padding: 0.1rem 0.35rem;
    border-radius: 999px;
    background: #e7e5e4;
    color: #292524;
    text-align: center;
    font-weight: 700;
  }

  .stage {
    color: #44403c;
  }

  .detail {
    margin-top: 0.35rem;
    color: #1c1917;
    font-size: 0.9rem;
  }

  .meta-summary {
    margin-top: 0.2rem;
    font-family: monospace;
    word-break: break-word;
  }
</style>

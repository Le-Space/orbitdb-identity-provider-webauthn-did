<script>
  export let peers = [];

  function truncate(value, head = 16, tail = 10) {
    if (!value || typeof value !== 'string') return value || 'n/a';
    if (value.length <= head + tail + 1) return value;
    return `${value.slice(0, head)}...${value.slice(-tail)}`;
  }

  function transportLabel(kind) {
    if (kind === 'direct-webrtc') return 'Direct WebRTC';
    if (kind === 'relay-webrtc') return 'Relay + WebRTC';
    if (kind === 'relay-circuit') return 'Relay Circuit';
    if (kind === 'webtransport') return 'WebTransport';
    if (kind === 'websocket') return 'WebSocket';
    return kind || 'Unknown';
  }

  function capabilityLabel(peer) {
    if (peer.connectionUpgraded) return 'Upgraded';
    if (peer.connectionLimited === true) return 'Limited';
    if (peer.connectionLimited === false) return 'Unlimited';
    return 'Unknown';
  }
</script>

<section class="peers-panel">
  <div class="header">
    <h3>Connected libp2p Peers</h3>
    <span>{peers.length}</span>
  </div>

  {#if peers.length === 0}
    <p class="empty">No connected peers yet.</p>
  {:else}
    <ul>
      {#each peers as peer (peer.peerId + (peer.remoteAddr || ''))}
        <li>
          <div class="peer-topline">
            <div class="peer-id" title={peer.peerId}>{truncate(peer.peerId)}</div>
            <div class="badges">
              <span class={`transport ${peer.transportKind || 'unknown'}`}>{transportLabel(peer.transportKind)}</span>
              <span class={`capability ${peer.connectionUpgraded ? 'upgraded' : peer.connectionLimited === false ? 'unlimited' : peer.connectionLimited === true ? 'limited' : 'unknown'}`}>
                {capabilityLabel(peer)}
              </span>
            </div>
          </div>
          {#if peer.remoteAddr}
            <div class="peer-addr" title={peer.remoteAddr}>{truncate(peer.remoteAddr, 22, 14)}</div>
          {/if}
          {#if peer.pathKind && peer.pathKind !== 'unknown'}
            <div class="peer-state">Path: {peer.pathKind}</div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .peers-panel {
    width: 100%;
    padding: 1rem;
    border: 1px solid #cbd5e1;
    border-radius: 0.75rem;
    background: #f8fafc;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.75rem;
  }

  .header h3,
  .header span,
  .empty,
  .peer-id,
  .peer-addr {
    margin: 0;
  }

  .header h3 {
    font-size: 0.95rem;
  }

  .header span,
  .empty {
    color: #475569;
    font-size: 0.85rem;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  li {
    padding: 0.6rem 0.7rem;
    border-radius: 0.5rem;
    background: #ffffff;
    border: 1px solid #e2e8f0;
  }

  .peer-id,
  .peer-addr {
    font-family: monospace;
    word-break: break-word;
    color: #0f172a;
    font-size: 0.8rem;
  }

  .peer-addr {
    margin-top: 0.2rem;
    color: #475569;
  }

  .peer-topline {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
  }

  .badges {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    flex-wrap: wrap;
    justify-content: flex-end;
  }

  .transport {
    flex-shrink: 0;
    font-size: 0.72rem;
    font-weight: 700;
    border-radius: 999px;
    padding: 0.15rem 0.45rem;
    background: #e2e8f0;
    color: #0f172a;
  }

  .transport.direct-webrtc {
    background: #dcfce7;
    color: #166534;
  }

  .transport.relay-webrtc {
    background: #dbeafe;
    color: #1d4ed8;
  }

  .transport.relay-circuit {
    background: #fef3c7;
    color: #92400e;
  }

  .capability,
  .peer-state {
    font-size: 0.72rem;
    color: #475569;
  }

  .capability {
    flex-shrink: 0;
    font-weight: 700;
    border-radius: 999px;
    padding: 0.15rem 0.45rem;
    background: #e2e8f0;
  }

  .capability.limited {
    background: #fef3c7;
    color: #92400e;
  }

  .capability.unlimited,
  .capability.upgraded {
    background: #dcfce7;
    color: #166534;
  }

  .capability.unknown {
    background: #e2e8f0;
    color: #334155;
  }

  .peer-state {
    margin-top: 0.25rem;
  }
</style>

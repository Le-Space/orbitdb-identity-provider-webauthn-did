<script>
  // A green badge proves nothing on its own. This runs the same verifier on
  // two forgeries — an entry whose text was changed after signing, and an
  // identity that claims the owner's DID with a key of its own — and shows
  // that both are refused. Before 0.5.2 the second one was accepted.
  import { Button, Tile } from 'carbon-components-svelte';
  import { impostorRejected, tamperedEntryRejected } from './lib/forgery.js';

  export let database = null;
  export let identities = null;
  export let identity = null;

  let running = false;
  let tampered = null;
  let impostor = null;
  let error = null;

  async function run() {
    running = true;
    error = null;
    try {
      tampered = await tamperedEntryRejected({ database, identities });
      impostor = await impostorRejected({ identities, identity });
    } catch (e) {
      error = e.message;
    } finally {
      running = false;
    }
  }

  const verdict = (r) =>
    r === null
      ? 'no entry to tamper with'
      : r.rejected
        ? 'rejected'
        : 'ACCEPTED';
</script>

<Tile data-testid="forgery-check" style="margin-top: 1rem;">
  <h5 style="margin: 0 0 0.5rem;">Does the verifier refuse a forgery?</h5>
  <p
    style="margin: 0 0 0.75rem; color: var(--cds-text-secondary); font-size: 0.875rem;"
  >
    Same checks as the badges, run on an entry edited after signing and on an
    identity claiming your DID with a key it made up.
  </p>
  <Button
    size="small"
    kind="tertiary"
    on:click={run}
    disabled={running || !database || !identities || !identity}
    data-testid="forgery-run"
  >
    {running ? 'Checking…' : 'Try to forge'}
  </Button>
  {#if tampered !== undefined && (tampered || impostor)}
    <ul
      style="margin: 0.75rem 0 0; padding-left: 1.25rem; font-size: 0.875rem;"
    >
      <li
        data-testid="forgery-tampered"
        data-rejected={tampered?.rejected ?? ''}
      >
        Edited entry: <strong>{verdict(tampered)}</strong>
        {#if tampered}
          — signature check {tampered.result.checks.signature
            ? 'passed'
            : 'failed'}
        {/if}
      </li>
      <li
        data-testid="forgery-impostor"
        data-rejected={impostor?.rejected ?? ''}
      >
        Impostor claiming <code>{impostor?.claimed?.slice(0, 24)}…</code>:
        <strong>{verdict(impostor)}</strong>
      </li>
    </ul>
  {/if}
  {#if error}
    <p style="color: var(--cds-support-error); margin: 0.5rem 0 0;">{error}</p>
  {/if}
</Tile>

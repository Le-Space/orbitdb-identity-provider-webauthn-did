<script>
  export let debug = {
    currentDid: null,
    currentPeerId: null,
    registryDeviceCount: null,
    registryDbName: null,
    registryDbAddress: null,
    registryAccessType: null,
    accessControllerDbName: null,
    accessControllerDbAddress: null,
    accessControllerType: null,
    accessControllerHeadCount: 0,
    accessControllerHeadHashes: [],
    recoveryDbAddress: null,
    recoveryAccessType: null,
    recoveryRootWritePermissions: [],
    recoveryWritePermissions: [],
    recoveryAdminPermissions: [],
    identityReferencesTotal: 0,
    identitiesResolvedCount: 0,
    identitiesVerifiedCount: 0,
    identityReplicationComplete: null,
    identityMissingHashes: [],
    identityInvalidHashes: [],
    identityReplicationDetails: [],
    currentIdentityIsRootWriter: null,
    currentIdentityCanWrite: null,
    currentIdentityIsAdmin: null,
    rootWritePermissions: [],
    writePermissions: [],
    adminPermissions: [],
    workerArchiveRestored: null,
    workerArchivePrincipalId: null,
    workerRecoveryRecordFound: null,
    workerRecoveryRecordSource: null,
    workerRecoveryDbName: null,
    workerMainDbAddress: null,
  };

  function renderBool(value) {
    if (value === true) return 'yes';
    if (value === false) return 'no';
    return 'unknown';
  }

  function renderIdentityReplication(debug) {
    if (!debug.identityReferencesTotal) return 'no replicated identities yet';
    const status = debug.identityReplicationComplete ? 'complete' : 'partial';
    return `${status} (${debug.identitiesVerifiedCount}/${debug.identityReferencesTotal} verified)`;
  }

  function buildIdentityTooltip(debug) {
    const lines = [];
    lines.push(`referenced => ${debug.identityReferencesTotal || 0}`);
    lines.push(`resolved => ${debug.identitiesResolvedCount || 0}`);
    lines.push(`verified => ${debug.identitiesVerifiedCount || 0}`);
    lines.push(`missing => ${debug.identityMissingHashes?.length ? debug.identityMissingHashes.join(', ') : '[]'}`);
    lines.push(`invalid => ${debug.identityInvalidHashes?.length ? debug.identityInvalidHashes.join(', ') : '[]'}`);
    if (Array.isArray(debug.identityReplicationDetails) && debug.identityReplicationDetails.length) {
      lines.push('');
      lines.push(...debug.identityReplicationDetails);
    }
    return lines.join('\n');
  }

  function truncate(value, head = 20, tail = 12) {
    if (!value || typeof value !== 'string') return value || 'n/a';
    if (value.length <= head + tail + 1) return value;
    return `${value.slice(0, head)}...${value.slice(-tail)}`;
  }

  function buildAccessTooltip({ write = [], admin = [] } = {}) {
    const formatList = (label, values) =>
      `${label} => ${
        Array.isArray(values) && values.length
          ? `[${values.join(', ')}]`
          : '[]'
      }`;

    return [
      formatList('write', write),
      formatList('admin', admin),
    ].join('\n');
  }

  function buildHeadTooltip(hashes = []) {
    return Array.isArray(hashes) && hashes.length ? hashes.join('\n') : '';
  }
</script>

<section class="debug-panel">
  <h3>Identity and Access Debug</h3>
  <p class="explanation">
    `ACL write/admin` are the authoritative OrbitDB access-controller capabilities replicated through the
    access-controller database.
  </p>
  <dl>
    <div>
      <dt>Current DID</dt>
      <dd title={debug.currentDid || ''}>{truncate(debug.currentDid)}</dd>
    </div>
    <div>
      <dt>Current PeerId</dt>
      <dd title={debug.currentPeerId || ''}>{truncate(debug.currentPeerId)}</dd>
    </div>
    <div>
      <dt>Registry device count</dt>
      <dd>{debug.registryDeviceCount ?? 'unknown'}</dd>
    </div>
    <div>
      <dt>Registry DB</dt>
      <dd title={debug.registryDbAddress || ''}>
        {debug.registryDbName || 'multi-device-registry'}
        {#if debug.registryAccessType}
          <br />
          <span
            class="access-type"
            title={buildAccessTooltip({
              write: debug.writePermissions,
              admin: debug.adminPermissions,
            })}
          >AC-Type: {debug.registryAccessType}</span>
        {/if}
        {#if debug.registryDbAddress}
          <br />
          {truncate(debug.registryDbAddress)}
        {/if}
      </dd>
    </div>
    <div>
      <dt>Access controller DB</dt>
      <dd
        title={`${debug.accessControllerDbAddress || ''}${
          debug.accessControllerDbAddress ? '\n' : ''
        }${buildAccessTooltip({
          write: debug.writePermissions,
          admin: debug.adminPermissions,
        })}`}
      >
        {debug.accessControllerDbName || 'OrbitDB access controller'}
        {#if debug.accessControllerType}
          <br />
          <span
            class="access-type"
            title={buildAccessTooltip({
              write: debug.writePermissions,
              admin: debug.adminPermissions,
            })}
          >AC-Type: {debug.accessControllerType}</span>
        {/if}
        {#if debug.accessControllerDbAddress}
          <br />
          {truncate(debug.accessControllerDbAddress)}
        {/if}
      </dd>
    </div>
    <div>
      <dt>ACL head count</dt>
      <dd title={buildHeadTooltip(debug.accessControllerHeadHashes)}>
        {typeof debug.accessControllerHeadCount === 'number' ? debug.accessControllerHeadCount : 'unknown'}
      </dd>
    </div>
    <div>
      <dt>ACL head CIDs</dt>
      <dd title={buildHeadTooltip(debug.accessControllerHeadHashes)}>
        {debug.accessControllerHeadHashes?.length
          ? debug.accessControllerHeadHashes.map((hash) => truncate(hash)).join(', ')
          : 'none'}
      </dd>
    </div>
    <div>
      <dt>Worker archive restored</dt>
      <dd>{renderBool(debug.workerArchiveRestored)}</dd>
    </div>
    <div>
      <dt>Archive principal ID</dt>
      <dd title={debug.workerArchivePrincipalId || ''}>{truncate(debug.workerArchivePrincipalId)}</dd>
    </div>
    <div>
      <dt>Recovery record found</dt>
      <dd>{renderBool(debug.workerRecoveryRecordFound)}</dd>
    </div>
    <div>
      <dt>Recovery source</dt>
      <dd>{debug.workerRecoveryRecordSource || 'n/a'}</dd>
    </div>
    <div>
      <dt>Recovery DB</dt>
      <dd title={debug.recoveryDbAddress || ''}>
        {truncate(debug.workerRecoveryDbName)}
        {#if debug.recoveryAccessType}
          <br />
          <span
            class="access-type"
            title={buildAccessTooltip({
              write: debug.recoveryWritePermissions,
              admin: debug.recoveryAdminPermissions,
            })}
          >AC-Type: {debug.recoveryAccessType}</span>
        {/if}
        {#if debug.recoveryDbAddress}
          <br />
          {truncate(debug.recoveryDbAddress)}
        {/if}
      </dd>
    </div>
    <div>
      <dt>Recovered main DB</dt>
      <dd title={debug.workerMainDbAddress || ''}>{truncate(debug.workerMainDbAddress)}</dd>
    </div>
    <div>
      <dt>Replicated identities</dt>
      <dd title={buildIdentityTooltip(debug)}>{renderIdentityReplication(debug)}</dd>
    </div>
    <div>
      <dt>Can append registry entries</dt>
      <dd>{renderBool(debug.currentIdentityCanWrite)}</dd>
    </div>
    <div>
      <dt>Can change access controller</dt>
      <dd>{renderBool(debug.currentIdentityIsAdmin)}</dd>
    </div>
    <div>
      <dt>ACL write IDs</dt>
      <dd title={debug.writePermissions.join('\n')}>
        {debug.writePermissions.length ? debug.writePermissions.map((did) => truncate(did)).join(', ') : 'none'}
      </dd>
    </div>
    <div>
      <dt>ACL admin IDs</dt>
      <dd title={debug.adminPermissions.join('\n')}>
        {debug.adminPermissions.length ? debug.adminPermissions.map((did) => truncate(did)).join(', ') : 'none'}
      </dd>
    </div>
  </dl>
</section>

<style>
  .debug-panel {
    width: 100%;
    padding: 1rem;
    border: 1px solid #cbd5e1;
    border-radius: 0.75rem;
    background: #f8fafc;
  }

  .debug-panel h3 {
    margin: 0 0 0.75rem;
    font-size: 0.95rem;
  }

  .explanation {
    margin: 0 0 0.85rem;
    color: #475569;
    font-size: 0.78rem;
    line-height: 1.4;
  }

  dl {
    margin: 0;
    display: grid;
    grid-template-columns: minmax(8rem, 11rem) 1fr;
    gap: 0.45rem 0.75rem;
    font-size: 0.82rem;
  }

  dl div {
    display: contents;
  }

  dt {
    color: #475569;
    font-weight: 600;
  }

  dd {
    margin: 0;
    color: #0f172a;
    font-family: monospace;
    word-break: break-word;
  }

  .access-type {
    color: #0f766e;
    font-weight: 700;
  }
</style>

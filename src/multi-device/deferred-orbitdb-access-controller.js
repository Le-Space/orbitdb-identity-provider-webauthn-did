import { IPFSAccessController } from '@orbitdb/core'
import { createId } from '@orbitdb/core/src/utils/index.js'

const type = 'orbitdb-deferred'
const DEFAULT_ACL_SYNC_TIMEOUT = 5000
const CUSTOM_PREFIX = '/orbitdb-deferred/'
const ORBITDB_PREFIX = '/orbitdb/'

const toUnderlyingAddress = (address) => {
  if (!address || typeof address !== 'string') return address
  if (!address.startsWith(CUSTOM_PREFIX)) return address
  return `${ORBITDB_PREFIX}${address.slice(CUSTOM_PREFIX.length)}`
}

const toCustomAddress = (address) => {
  if (!address || typeof address !== 'string') return address
  if (!address.startsWith(ORBITDB_PREFIX)) return address
  return `${CUSTOM_PREFIX}${address.slice(ORBITDB_PREFIX.length)}`
}

const DeferredOrbitDBAccessController = ({ write, syncTimeout = DEFAULT_ACL_SYNC_TIMEOUT } = {}) => async ({ orbitdb, identities, address, name }) => {
  const aclAddress = toUnderlyingAddress(address || name || await createId(64))
  write = write || [orbitdb.identity.id]

  // Open the database used for access information.
  const db = await orbitdb.open(aclAddress, {
    type: 'keyvalue',
    AccessController: IPFSAccessController({ write }),
  })

  let aclActivitySeen = false
  let resolveAclActivity
  let aclActivityPromise = new Promise((resolve) => {
    resolveAclActivity = () => {
      aclActivitySeen = true
      resolve()
    }
  })

  const markAclActivity = () => {
    if (aclActivitySeen) return
    resolveAclActivity?.()
  }

  db.events.on('update', markAclActivity)
  db.events.on('join', markAclActivity)

  const capabilities = async () => {
    const _capabilities = []
    for await (const entry of db.iterator()) {
      _capabilities[entry.key] = entry.value
    }

    const toSet = (e) => {
      const key = e[0]
      _capabilities[key] = new Set([...(_capabilities[key] || []), ...e[1]])
    }

    Object.entries({
      ..._capabilities,
      ...{ admin: new Set([...(_capabilities.admin || []), ...db.access.write]) }
    }).forEach(toSet)

    return _capabilities
  }

  const get = async (capability) => {
    const _capabilities = await capabilities()
    return _capabilities[capability] || new Set([])
  }

  const hasCapability = async (capability, key) => {
    const access = new Set(await get(capability))
    return access.has(key) || access.has('*')
  }

  const waitForAclReplication = async () => {
    if (aclActivitySeen) return
    if ((db.peers?.size || 0) === 0) return

    await Promise.race([
      aclActivityPromise,
      new Promise((resolve) => setTimeout(resolve, syncTimeout)),
    ])
  }

  const canAppend = async (entry) => {
    const writerIdentity = await identities.getIdentity(entry.identity)
    if (!writerIdentity) {
      return false
    }

    const { id } = writerIdentity

    let hasWriteAccess =
      await hasCapability('write', id) || await hasCapability('admin', id)

    if (!hasWriteAccess) {
      await waitForAclReplication()
      hasWriteAccess =
        await hasCapability('write', id) || await hasCapability('admin', id)
    }

    if (hasWriteAccess) {
      return await identities.verifyIdentity(writerIdentity)
    }

    return false
  }

  const close = async () => {
    await db.close()
  }

  const drop = async () => {
    await db.drop()
  }

  const grant = async (capability, key) => {
    const nextCapabilities = new Set([...(await db.get(capability) || []), ...[key]])
    await db.put(capability, Array.from(nextCapabilities.values()))
  }

  const revoke = async (capability, key) => {
    const nextCapabilities = new Set(await db.get(capability) || [])
    nextCapabilities.delete(key)
    if (nextCapabilities.size > 0) {
      await db.put(capability, Array.from(nextCapabilities.values()))
    } else {
      await db.del(capability)
    }
  }

  return {
    type,
    address: toCustomAddress(db.address?.toString?.() || db.address),
    write,
    canAppend,
    capabilities,
    get,
    grant,
    revoke,
    close,
    drop,
    events: db.events,
  }
}

DeferredOrbitDBAccessController.type = type

export default DeferredOrbitDBAccessController

/**
 * libp2p Pairing Protocol for Multi-Device Linking
 *
 * Protocol: /orbitdb/link-device/1.0.0
 *
 * Message flow:
 *   Device B → Device A: { type: 'request', identity: { id, credentialId, deviceLabel } }
 *   Device A → Device B: { type: 'granted', orbitdbAddress } | { type: 'rejected', reason }
 */

import { lpStream } from 'it-length-prefixed-stream';
import {
  getDeviceByCredentialId,
  getDeviceByDID,
  grantDeviceWriteAccess,
  registerDevice,
} from './device-registry.js';

export const LINK_DEVICE_PROTOCOL = '/orbitdb/link-device/1.0.0';

function decodeMessage(bytes) {
  const raw = typeof bytes.subarray === 'function' ? bytes.subarray() : bytes;
  return JSON.parse(new TextDecoder().decode(raw));
}

function encodeMessage(msg) {
  return new TextEncoder().encode(JSON.stringify(msg));
}

function emitPairingEvent(onEvent, event) {
  if (!onEvent) return;
  onEvent({
    timestamp: Date.now(),
    scope: 'pairing',
    ...event,
  });
}

function classifyConnectionKind(remoteAddr = '') {
  const lower = remoteAddr.toLowerCase();
  if (!lower) return 'unknown';
  if (lower.includes('/p2p-circuit/') && lower.includes('/webrtc/')) return 'relay-webrtc';
  if (lower.includes('/p2p-circuit/')) return 'relay-circuit';
  if (lower.includes('/webrtc/')) return 'direct-webrtc';
  if (lower.includes('/webtransport/')) return 'webtransport';
  if (lower.includes('/wss/') || lower.includes('/ws/')) return 'websocket';
  return 'other';
}

function describeConnectionState(connection) {
  const remoteAddr = connection?.remoteAddr?.toString?.() || null;
  return {
    remoteAddr,
    transportKind: classifyConnectionKind(remoteAddr || ''),
    connectionLimited: connection?.limits != null,
    connectionUpgraded: connection?.timeline?.upgraded != null,
    pathKind:
      remoteAddr == null
        ? 'unknown'
        : remoteAddr.includes('/p2p-circuit')
          ? connection?.limits != null
            ? 'relay-limited'
            : 'relay-unlimited'
          : remoteAddr.includes('/webrtc')
            ? 'direct'
            : connection?.limits != null
              ? 'limited'
              : 'unlimited',
  };
}

async function getAccessSnapshot(db, identityId = null) {
  let rootWritePermissions = [];
  let writePermissions = [];
  let adminPermissions = [];

  try {
    const raw = db.access?.write;
    if (Array.isArray(raw)) {
      rootWritePermissions = raw;
    }
  } catch {}

  try {
    if (typeof db.access?.get === 'function') {
      writePermissions = Array.from(await db.access.get('write'));
      adminPermissions = Array.from(await db.access.get('admin'));
    }
  } catch {}

  return {
    rootWritePermissions,
    writePermissions,
    adminPermissions,
    currentIdentityIsRootWriter: Boolean(identityId && rootWritePermissions.includes(identityId)),
    currentIdentityCanWrite: Boolean(identityId && (writePermissions.includes(identityId) || writePermissions.includes('*'))),
    currentIdentityIsAdmin: Boolean(identityId && (adminPermissions.includes(identityId) || adminPermissions.includes('*'))),
  };
}

/**
 * Register the link-device handler on Device A (the established device).
 *
 * @param {Object} libp2p - libp2p instance
 * @param {Object} db - The device registry KV database
 * @param {Function} onRequest - async (requestMsg) => 'granted' | 'rejected'
 * @param {Function} [onDeviceLinked] - (deviceEntry) => void
 * @param {Function} [onEvent] - ({ stage, detail, ...meta }) => void
 * @returns {Promise<void>}
 */
export async function registerLinkDeviceHandler(libp2p, db, onRequest, onDeviceLinked, onEvent) {
  console.log('[pairing] Registering handler for protocol:', LINK_DEVICE_PROTOCOL, 'on peer:', libp2p.peerId.toString());
  await libp2p.handle(LINK_DEVICE_PROTOCOL, async ({ stream, connection }) => {
    console.log('[pairing] Received incoming connection from:', connection?.remotePeer?.toString());
    emitPairingEvent(onEvent, {
      role: 'device-a',
      stage: 'incoming-connection',
      level: 'info',
      detail: 'Incoming pairing stream received',
      remotePeerId: connection?.remotePeer?.toString() || null,
      dbAddress: db.address?.toString?.() || db.address,
    });
    const lp = lpStream(stream);
    let result;

    try {
      console.log('[pairing] Waiting for request message...');
      const request = decodeMessage(await lp.read());
      console.log('[pairing] Received request:', request.type);
      emitPairingEvent(onEvent, {
        role: 'device-a',
        stage: 'request-received',
        level: 'info',
        detail: `Received pairing request: ${request.type}`,
      });

      if (request.type !== 'request') {
        emitPairingEvent(onEvent, {
          role: 'device-a',
          stage: 'invalid-request',
          level: 'error',
          detail: `Unexpected pairing message type: ${request.type}`,
        });
        await stream.close();
        return;
      }

      const { identity } = request;
      console.log('[pairing] Request identity DID:', identity.id);
      const isKnown =
        (await getDeviceByCredentialId(db, identity.credentialId)) ||
        (await getDeviceByDID(db, identity.id));

      console.log('[pairing] Is known device:', !!isKnown);
      emitPairingEvent(onEvent, {
        role: 'device-a',
        stage: 'request-inspected',
        level: 'info',
        detail: isKnown ? 'Request came from a known device' : 'Request came from a new device',
        requesterDid: identity.id,
        credentialId: identity.credentialId,
      });
      if (isKnown) {
        console.log('[pairing] Device is known, granting access and triggering callback');
        result = { type: 'granted', orbitdbAddress: db.address };
        emitPairingEvent(onEvent, {
          role: 'device-a',
          stage: 'known-device',
          level: 'success',
          detail: 'Known device detected; returning existing database address',
          requesterDid: identity.id,
          orbitdbAddress: db.address?.toString?.() || db.address,
        });
        // Even if known, trigger the callback so UI updates
        if (isKnown && onDeviceLinked) {
          onDeviceLinked({
            credential_id: identity.credentialId,
            public_key: identity.publicKey || null,
            device_label: identity.deviceLabel || 'Linked Device',
            created_at: isKnown.created_at || Date.now(),
            status: 'active',
            ed25519_did: identity.id,
          });
        }
      } else {
        const decision = await onRequest(request);
        console.log('[pairing] Pairing request decision:', decision);
        emitPairingEvent(onEvent, {
          role: 'device-a',
          stage: 'decision-made',
          level: decision === 'granted' ? 'success' : 'warning',
          detail: decision === 'granted' ? 'User approved pairing request' : 'User rejected pairing request',
          requesterDid: identity.id,
        });
        if (decision === 'granted') {
          const accessBeforeGrant = await getAccessSnapshot(db, db.identity?.id || null);
          emitPairingEvent(onEvent, {
            role: 'device-a',
            stage: 'access-check',
            level: accessBeforeGrant.currentIdentityIsAdmin || accessBeforeGrant.currentIdentityIsRootWriter ? 'info' : 'warning',
            detail: accessBeforeGrant.currentIdentityIsAdmin || accessBeforeGrant.currentIdentityIsRootWriter
              ? 'Current Device A identity appears authorized to mutate access control'
              : 'Current Device A identity does not appear in the access controller admin/root-writer set',
            requesterDid: identity.id,
            rootWritePermissions: accessBeforeGrant.rootWritePermissions,
            writePermissions: accessBeforeGrant.writePermissions,
            adminPermissions: accessBeforeGrant.adminPermissions,
            currentIdentityIsRootWriter: accessBeforeGrant.currentIdentityIsRootWriter,
            currentIdentityCanWrite: accessBeforeGrant.currentIdentityCanWrite,
            currentIdentityIsAdmin: accessBeforeGrant.currentIdentityIsAdmin,
          });
          console.log('[pairing] Granting write access for DID:', identity.id);
          emitPairingEvent(onEvent, {
            role: 'device-a',
            stage: 'grant-start',
            level: 'info',
            detail: 'Granting write access in OrbitDB access controller',
            requesterDid: identity.id,
          });
          await grantDeviceWriteAccess(db, identity.id);
          console.log('[pairing] Write access granted, registering device...');
          const accessAfterGrant = await getAccessSnapshot(db, db.identity?.id || null);
          emitPairingEvent(onEvent, {
            role: 'device-a',
            stage: 'grant-complete',
            level: 'success',
            detail: 'Write access grant completed',
            requesterDid: identity.id,
            rootWritePermissions: accessAfterGrant.rootWritePermissions,
            writePermissions: accessAfterGrant.writePermissions,
            adminPermissions: accessAfterGrant.adminPermissions,
            currentIdentityIsRootWriter: accessAfterGrant.currentIdentityIsRootWriter,
            currentIdentityCanWrite: accessAfterGrant.currentIdentityCanWrite,
            currentIdentityIsAdmin: accessAfterGrant.currentIdentityIsAdmin,
          });
          const deviceEntry = {
            credential_id: identity.credentialId,
            public_key: identity.publicKey || null,
            device_label: identity.deviceLabel || 'Unknown Device',
            created_at: Date.now(),
            status: 'active',
            ed25519_did: identity.id,
          };
          try {
            emitPairingEvent(onEvent, {
              role: 'device-a',
              stage: 'registry-write-start',
              level: 'info',
              detail: 'Registering new device in shared registry',
              requesterDid: identity.id,
            });
            await registerDevice(db, deviceEntry);
            console.log('[pairing] Device registered successfully');
            const devices = await db.all();
            emitPairingEvent(onEvent, {
              role: 'device-a',
              stage: 'registry-write-complete',
              level: 'success',
              detail: 'New device registered in shared registry',
              requesterDid: identity.id,
              deviceCount: devices.length,
            });
            if (db?.log?.heads) {
              const heads = await db.log.heads();
              emitPairingEvent(onEvent, {
                role: 'device-a',
                stage: 'registry-heads-local',
                level: 'info',
                detail: 'Local registry heads after registering the new device',
                requesterDid: identity.id,
                registryHeadCount: heads.length,
                registryHeadHashes: heads.map((entry) => entry.hash),
              });
            }
            result = { type: 'granted', orbitdbAddress: db.address };
            onDeviceLinked?.(deviceEntry);
          } catch (registerErr) {
            console.error('[pairing] Failed to register device:', registerErr.message);
            emitPairingEvent(onEvent, {
              role: 'device-a',
              stage: 'registry-write-retry',
              level: 'warning',
              detail: `Registry write failed; retrying once: ${registerErr.message}`,
              requesterDid: identity.id,
              error: registerErr.message,
            });
            // Retry once after a short delay
            console.log('[pairing] Retrying device registration...');
            await new Promise(resolve => setTimeout(resolve, 500));
            await registerDevice(db, deviceEntry);
            console.log('[pairing] Device registered successfully on retry');
            const devices = await db.all();
            emitPairingEvent(onEvent, {
              role: 'device-a',
              stage: 'registry-write-complete',
              level: 'success',
              detail: 'New device registered in shared registry after retry',
              requesterDid: identity.id,
              deviceCount: devices.length,
            });
            if (db?.log?.heads) {
              const heads = await db.log.heads();
              emitPairingEvent(onEvent, {
                role: 'device-a',
                stage: 'registry-heads-local',
                level: 'info',
                detail: 'Local registry heads after registering the new device on retry',
                requesterDid: identity.id,
                registryHeadCount: heads.length,
                registryHeadHashes: heads.map((entry) => entry.hash),
              });
            }
            result = { type: 'granted', orbitdbAddress: db.address };
            onDeviceLinked?.(deviceEntry);
          }
        } else {
          result = { type: 'rejected', reason: 'User cancelled' };
        }
      }
    } catch (err) {
      console.error('[pairing-protocol] handler error:', err);
      emitPairingEvent(onEvent, {
        role: 'device-a',
        stage: 'handler-error',
        level: 'error',
        detail: `Pairing handler failed: ${err.message}`,
        error: err.message,
      });
      result = { type: 'rejected', reason: err.message };
    }

    try {
      if (result?.type === 'granted') {
        const accessBeforeResponse = await getAccessSnapshot(db, db.identity?.id || null);
        const devicesBeforeResponse = await db.all();
        emitPairingEvent(onEvent, {
          role: 'device-a',
          stage: 'response-ready',
          level: 'info',
          detail: 'Device A is about to send the granted response after local ACL/registry checks',
          orbitdbAddress: result.orbitdbAddress || null,
          deviceCount: devicesBeforeResponse.length,
          rootWritePermissions: accessBeforeResponse.rootWritePermissions,
          writePermissions: accessBeforeResponse.writePermissions,
          adminPermissions: accessBeforeResponse.adminPermissions,
          currentIdentityIsRootWriter: accessBeforeResponse.currentIdentityIsRootWriter,
          currentIdentityCanWrite: accessBeforeResponse.currentIdentityCanWrite,
          currentIdentityIsAdmin: accessBeforeResponse.currentIdentityIsAdmin,
        });
      }
      await lp.write(encodeMessage(result));
      emitPairingEvent(onEvent, {
        role: 'device-a',
        stage: 'response-sent',
        level: result.type === 'granted' ? 'success' : 'warning',
        detail: result.type === 'granted' ? 'Granted response sent to requesting device' : 'Rejected response sent to requesting device',
        orbitdbAddress: result.orbitdbAddress || null,
        reason: result.reason || null,
      });
      await stream.close();
    } catch (writeErr) {
      console.warn('[pairing-protocol] error writing response:', writeErr);
      emitPairingEvent(onEvent, {
        role: 'device-a',
        stage: 'response-write-error',
        level: 'error',
        detail: `Failed to send pairing response: ${writeErr.message}`,
        error: writeErr.message,
      });
    }
  });
}

/**
 * Unregister the link-device handler from libp2p.
 * @param {Object} libp2p - libp2p instance
 * @returns {Promise<void>}
 */
export async function unregisterLinkDeviceHandler(libp2p) {
  await libp2p.unhandle(LINK_DEVICE_PROTOCOL);
}

/**
 * Detect a human-readable device label from the browser user-agent.
 * @returns {string}
 */
export function detectDeviceLabel() {
  if (typeof navigator === 'undefined') return 'Unknown Device';
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return 'Android';
  if (/Mac/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows PC';
  if (/Linux/.test(ua)) return 'Linux';
  return 'Unknown Device';
}

/**
 * Device B side: dial Device A and send a pairing request.
 *
 * @param {Object} libp2p - libp2p instance (Device B)
 * @param {string|Object} deviceAPeerId - peerId string or PeerId object of Device A
 * @param {Object} identity - { id, credentialId, publicKey?, deviceLabel? }
 * @param {string[]} [hintMultiaddrs] - Known multiaddrs for Device A (from QR payload)
 * @param {Function} [onEvent] - ({ stage, detail, ...meta }) => void
 * @returns {Promise<{type: 'granted', orbitdbAddress: string}|{type: 'rejected', reason: string}>}
 */
export async function sendPairingRequest(libp2p, deviceAPeerId, identity, hintMultiaddrs = [], onEvent) {
  let stream;

  let targetPeerId;
  if (typeof deviceAPeerId === 'string') {
    targetPeerId = deviceAPeerId;
  } else if (typeof deviceAPeerId?.toString === 'function') {
    targetPeerId = deviceAPeerId.toString();
  } else if (deviceAPeerId?.id) {
    targetPeerId = deviceAPeerId.id;
  } else {
    throw new Error(`Invalid deviceAPeerId: ${JSON.stringify(deviceAPeerId)}`);
  }

  if (hintMultiaddrs.length > 0) {
    try {
      console.log('[pairing] Attempting to dial with hint multiaddrs:', hintMultiaddrs);
      emitPairingEvent(onEvent, {
        role: 'device-b',
        stage: 'dial-start',
        level: 'info',
        detail: `Dialing Device A with ${hintMultiaddrs.length} hinted multiaddr(s)`,
        targetPeerId,
      });
      const { multiaddr } = await import('@multiformats/multiaddr');
      const parsedMultiaddrs = hintMultiaddrs
        .map((a) => {
          try {
            return multiaddr(a);
          } catch (e) {
            console.warn('[pairing] failed to parse multiaddr:', a, e.message);
            return null;
          }
        })
        .filter(Boolean);

      if (parsedMultiaddrs.length === 0) {
        throw new Error(`No valid multiaddrs for deviceAPeerId: ${deviceAPeerId}`);
      }

      console.log('[pairing] Dialing parsed multiaddrs:', parsedMultiaddrs.map((m) => m.toString()));
      const connection = await libp2p.dial(parsedMultiaddrs);
      const connectionState = describeConnectionState(connection);
      console.log('[pairing] Dial successful, connection:', connection.remotePeer.toString());
      emitPairingEvent(onEvent, {
        role: 'device-b',
        stage: 'dial-connected',
        level: 'success',
        detail: 'Connected to Device A over libp2p',
        targetPeerId: connection.remotePeer.toString(),
        remoteAddr: connectionState.remoteAddr,
        transportKind: connectionState.transportKind,
        connectionLimited: connectionState.connectionLimited,
        connectionUpgraded: connectionState.connectionUpgraded,
        pathKind: connectionState.pathKind,
      });
      stream = await connection.newStream(LINK_DEVICE_PROTOCOL);
      console.log('[pairing] Stream created');
      emitPairingEvent(onEvent, {
        role: 'device-b',
        stage: 'stream-open',
        level: 'success',
        detail: 'Pairing stream opened',
        targetPeerId: connection.remotePeer.toString(),
        remoteAddr: connectionState.remoteAddr,
        transportKind: connectionState.transportKind,
        connectionLimited: connectionState.connectionLimited,
        connectionUpgraded: connectionState.connectionUpgraded,
        pathKind: connectionState.pathKind,
      });
    } catch (e) {
      console.error('[pairing] Dial failed:', e.message);
      emitPairingEvent(onEvent, {
        role: 'device-b',
        stage: 'dial-error',
        level: 'error',
        detail: `Failed to connect to Device A: ${e.message}`,
        error: e.message,
        targetPeerId,
        });
      throw new Error(`Failed to connect to Device A: ${e.message}`);
    }
  } else {
    const { multiaddr } = await import('@multiformats/multiaddr');
    const peerOnlyMultiaddr = multiaddr(`/p2p/${targetPeerId}`);
    emitPairingEvent(onEvent, {
      role: 'device-b',
      stage: 'dial-start',
      level: 'info',
      detail: 'Dialing Device A by peer ID via discovery/bootstrap',
      targetPeerId,
    });
    const connection = await libp2p.dial(peerOnlyMultiaddr);
    const connectionState = describeConnectionState(connection);
    emitPairingEvent(onEvent, {
      role: 'device-b',
      stage: 'dial-connected',
      level: 'success',
      detail: 'Connected to Device A over libp2p',
      targetPeerId: connection.remotePeer.toString(),
      remoteAddr: connectionState.remoteAddr,
      transportKind: connectionState.transportKind,
      connectionLimited: connectionState.connectionLimited,
      connectionUpgraded: connectionState.connectionUpgraded,
      pathKind: connectionState.pathKind,
    });
    stream = await connection.newStream(LINK_DEVICE_PROTOCOL);
    emitPairingEvent(onEvent, {
      role: 'device-b',
      stage: 'stream-open',
      level: 'success',
      detail: 'Pairing stream opened',
      targetPeerId: connection.remotePeer.toString(),
      remoteAddr: connectionState.remoteAddr,
      transportKind: connectionState.transportKind,
      connectionLimited: connectionState.connectionLimited,
      connectionUpgraded: connectionState.connectionUpgraded,
      pathKind: connectionState.pathKind,
    });
  }

  const lp = lpStream(stream);
  emitPairingEvent(onEvent, {
    role: 'device-b',
    stage: 'request-sent',
    level: 'info',
    detail: 'Pairing request sent to Device A',
    requesterDid: identity.id,
    credentialId: identity.credentialId,
    targetPeerId,
  });
  await lp.write(encodeMessage({
    type: 'request',
    identity: {
      id: identity.id,
      credentialId: identity.credentialId,
      publicKey: identity.publicKey || null,
      deviceLabel: identity.deviceLabel || detectDeviceLabel(),
    },
  }));

  const result = decodeMessage(await lp.read());
  emitPairingEvent(onEvent, {
    role: 'device-b',
    stage: 'response-received',
    level: result.type === 'granted' ? 'success' : 'warning',
    detail: result.type === 'granted' ? 'Received granted response from Device A' : `Received rejected response from Device A: ${result.reason || 'Unknown reason'}`,
    orbitdbAddress: result.orbitdbAddress || null,
    reason: result.reason || null,
  });
  await stream.close();
  return result;
}

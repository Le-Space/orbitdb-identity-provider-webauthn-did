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
import { peerIdFromString } from '@libp2p/peer-id';

export const LINK_DEVICE_PROTOCOL = '/orbitdb/link-device/1.0.0';

function decodeMessage(bytes) {
  const raw = typeof bytes.subarray === 'function' ? bytes.subarray() : bytes;
  return JSON.parse(new TextDecoder().decode(raw));
}

function encodeMessage(msg) {
  return new TextEncoder().encode(JSON.stringify(msg));
}

/**
 * Register the link-device handler on Device A (the established device).
 *
 * @param {Object} libp2p - libp2p instance
 * @param {Object} db - The device registry KV database
 * @param {Function} onRequest - async (requestMsg) => 'granted' | 'rejected'
 * @param {Function} [onDeviceLinked] - (deviceEntry) => void
 * @returns {Promise<void>}
 */
export async function registerLinkDeviceHandler(libp2p, db, onRequest, onDeviceLinked) {
  console.log('[pairing] Registering handler for protocol:', LINK_DEVICE_PROTOCOL, 'on peer:', libp2p.peerId.toString());
  await libp2p.handle(LINK_DEVICE_PROTOCOL, async ({ stream, connection }) => {
    console.log('[pairing] Received incoming connection from:', connection?.remotePeer?.toString());
    const lp = lpStream(stream);
    let result;

    try {
      console.log('[pairing] Waiting for request message...');
      const request = decodeMessage(await lp.read());
      console.log('[pairing] Received request:', request.type);

      if (request.type !== 'request') {
        await stream.close();
        return;
      }

      const { identity } = request;
      console.log('[pairing] Request identity DID:', identity.id);
      const isKnown =
        (await getDeviceByCredentialId(db, identity.credentialId)) ||
        (await getDeviceByDID(db, identity.id));

      console.log('[pairing] Is known device:', !!isKnown);
      if (isKnown) {
        console.log('[pairing] Device is known, granting access and triggering callback');
        result = { type: 'granted', orbitdbAddress: db.address };
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
        if (decision === 'granted') {
          console.log('[pairing] Granting write access for DID:', identity.id);
          await grantDeviceWriteAccess(db, identity.id);
          console.log('[pairing] Write access granted, registering device...');
          const deviceEntry = {
            credential_id: identity.credentialId,
            public_key: identity.publicKey || null,
            device_label: identity.deviceLabel || 'Unknown Device',
            created_at: Date.now(),
            status: 'active',
            ed25519_did: identity.id,
          };
          try {
            await registerDevice(db, deviceEntry);
            console.log('[pairing] Device registered successfully');
            result = { type: 'granted', orbitdbAddress: db.address };
            onDeviceLinked?.(deviceEntry);
          } catch (registerErr) {
            console.error('[pairing] Failed to register device:', registerErr.message);
            // Retry once after a short delay
            console.log('[pairing] Retrying device registration...');
            await new Promise(resolve => setTimeout(resolve, 500));
            await registerDevice(db, deviceEntry);
            console.log('[pairing] Device registered successfully on retry');
            result = { type: 'granted', orbitdbAddress: db.address };
            onDeviceLinked?.(deviceEntry);
          }
        } else {
          result = { type: 'rejected', reason: 'User cancelled' };
        }
      }
    } catch (err) {
      console.error('[pairing-protocol] handler error:', err);
      result = { type: 'rejected', reason: err.message };
    }

    try {
      await lp.write(encodeMessage(result));
      await stream.close();
    } catch (writeErr) {
      console.warn('[pairing-protocol] error writing response:', writeErr);
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
 * @returns {Promise<{type: 'granted', orbitdbAddress: string}|{type: 'rejected', reason: string}>}
 */
export async function sendPairingRequest(libp2p, deviceAPeerId, identity, hintMultiaddrs = []) {
  let stream;

  let peerId;
  if (typeof deviceAPeerId === 'string') {
    peerId = peerIdFromString(deviceAPeerId);
  } else if (deviceAPeerId?.toMultihash) {
    peerId = deviceAPeerId;
  } else if (deviceAPeerId?.id) {
    peerId = peerIdFromString(deviceAPeerId.id);
  } else {
    throw new Error(`Invalid deviceAPeerId: ${JSON.stringify(deviceAPeerId)}`);
  }

  if (hintMultiaddrs.length > 0) {
    try {
      console.log('[pairing] Attempting to dial with hint multiaddrs:', hintMultiaddrs);
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

      console.log('[pairing] Dialing parsed multiaddrs:', parsedMultiaddrs.map(m => m.toString()));
      const connection = await libp2p.dial(parsedMultiaddrs);
      console.log('[pairing] Dial successful, connection:', connection.remotePeer.toString());
      stream = await connection.newStream(LINK_DEVICE_PROTOCOL);
      console.log('[pairing] Stream created');
    } catch (e) {
      console.error('[pairing] Dial failed:', e.message);
      throw new Error(`Failed to connect to Device A: ${e.message}`);
    }
  } else {
    stream = await libp2p.dialProtocol(peerId, LINK_DEVICE_PROTOCOL);
  }

  const lp = lpStream(stream);
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
  await stream.close();
  return result;
}

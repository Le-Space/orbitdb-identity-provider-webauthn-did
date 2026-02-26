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
import { toString, fromString } from 'uint8arrays/to-string';
import {
  getDeviceByCredentialId,
  getDeviceByDID,
  grantDeviceWriteAccess,
  registerDevice,
} from './device-registry.js';
import { peerIdFromString } from '@libp2p/peer-id';
export const LINK_DEVICE_PROTOCOL = '/orbitdb/link-device/1.0.0';

/**
 * Decode bytes from an lp.read() result into a parsed JSON object.
 * Handles both Uint8Array and Uint8ArrayList (from it-length-prefixed-stream).
 * @param {Uint8Array|Object} bytes
 * @returns {Object}
 */
function decodeMessage(bytes) {
  const raw = typeof bytes.subarray === 'function' ? bytes.subarray() : bytes;
  return JSON.parse(new TextDecoder().decode(raw));
}

/**
 * Encode a JS object to UTF-8 bytes for lp.write().
 * @param {Object} msg
 * @returns {Uint8Array}
 */
function encodeMessage(msg) {
  return new TextEncoder().encode(JSON.stringify(msg));
}

/**
 * Register the link-device handler on Device A (the established device).
 *
 * @param {Object} libp2p - libp2p instance
 * @param {Object} db - The device registry KV database
 * @param {Function} onRequest - async (requestMsg) => 'granted' | 'rejected'
 *   Called for unknown devices; bridges protocol to UI confirmation dialog.
 * @returns {Promise<void>}
 */
export async function registerLinkDeviceHandler(libp2p, db, onRequest) {
  await libp2p.handle(LINK_DEVICE_PROTOCOL, async ({ stream }) => {
    const lp = lpStream(stream);
    let result;

    try {
      const bytes = await lp.read();
      const request = decodeMessage(bytes);

      if (request.type !== 'request') {
        await stream.close();
        return;
      }

      const isKnownDevice = await getDeviceByCredentialId(
        db,
        request.identity.credentialId
      );

      const existingDeviceWithDID = await getDeviceByDID(db, request.identity.id);

      if (existingDeviceWithDID) {
        result = { type: 'rejected', reason: 'This identity is already registered on another device' };
      } else if (isKnownDevice) {
        // Recovery: same credential → same Ed25519 DID → already has write access
        result = { type: 'granted', orbitdbAddress: db.address };
      } else {
        // New device: ask user via UI callback
        const decision = await onRequest(request);

        if (decision === 'granted') {
          await grantDeviceWriteAccess(db, request.identity.id);
          await registerDevice(db, {
            credential_id: request.identity.credentialId,
            public_key: request.identity.publicKey || null,
            device_label: request.identity.deviceLabel || 'Unknown Device',
            created_at: Date.now(),
            status: 'active',
            ed25519_did: request.identity.id,
          });
          result = { type: 'granted', orbitdbAddress: db.address };
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
 * @param {Object} identity - OrbitDB identity from Device B
 *   { id: string, credentialId: string, publicKey?: JWK, deviceLabel?: string }
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
      const { multiaddr } = await import('@multiformats/multiaddr');
      console.log('deviceAPeerId:', deviceAPeerId);
      console.log('type:', typeof deviceAPeerId);
      console.log('has toMultihash:', deviceAPeerId?.toMultihash);


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
      console.log('parsedMultiaddrs:', parsedMultiaddrs);
      if (parsedMultiaddrs.length > 0) {
        const connection = await libp2p.dial(parsedMultiaddrs);
        console.log('connection:', connection);
        stream = await connection.newStream(LINK_DEVICE_PROTOCOL);
        console.log('stream:', stream);
      } else {
        throw new Error(`No parsedMultiaddrs for deviceAPeerId: ${deviceAPeerId}`);
      }
    } catch (e) {
      throw new Error(`Failed to connect to Device A: ${e.message} for deviceAPeerId: ${deviceAPeerId}`);
    }
  } else {
    stream = await libp2p.dialProtocol(peerId, LINK_DEVICE_PROTOCOL);
    console.log('stream:', stream);
  }
  console.log('stream:', stream);
  const lp = lpStream(stream);

  const request = {
    type: 'request',
    identity: {
      id: identity.id,
      credentialId: identity.credentialId,
      publicKey: identity.publicKey || null,
      deviceLabel: identity.deviceLabel || detectDeviceLabel(),
    },
  };

  await lp.write(encodeMessage(request));
  const bytes = await lp.read();
  const result = decodeMessage(bytes);
  await stream.close();
  return result;
}

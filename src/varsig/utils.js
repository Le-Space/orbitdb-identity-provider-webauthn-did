import { concat } from 'iso-webauthn-varsig';

const encoder = new TextEncoder();

function toArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function toBytes(data) {
  return typeof data === 'string' ? encoder.encode(data) : data;
}

async function buildChallengeBytes(domainLabel, payloadBytes) {
  const domain = encoder.encode(domainLabel);
  const hash = await crypto.subtle.digest('SHA-256', concat([domain, payloadBytes]));
  return new Uint8Array(hash);
}

export {
  encoder,
  toArrayBuffer,
  toBytes,
  buildChallengeBytes
};

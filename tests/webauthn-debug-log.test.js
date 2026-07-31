/**
 * Guards the redaction in the WebAuthn debug logger.
 *
 * The helper this replaced wrote the whole credential to console on every
 * call — including getClientExtensionResults(), which since 0.4.1 can carry
 * the PRF output, the material both keystore encryption and the OrbitDB
 * signing key derive from. See issue #22.
 */
import { test, expect } from '@playwright/test';

import {
  describeWebAuthnResponse,
  logWebAuthnResponse,
} from '../src/webauthn/debug-log.js';

const PRF_SECRET = new Uint8Array(32).fill(0xab);
const SIGNATURE = new Uint8Array(64).fill(0xcd);
const RAW_ID = new Uint8Array(32).fill(0xef);

function assertionWithPrf() {
  return {
    id: 'credential-id',
    rawId: RAW_ID.buffer,
    type: 'public-key',
    response: {
      authenticatorData: new Uint8Array(37).buffer,
      clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}')
        .buffer,
      signature: SIGNATURE.buffer,
      userHandle: null,
    },
    getClientExtensionResults: () => ({
      prf: { results: { first: PRF_SECRET.buffer } },
    }),
  };
}

test.describe('WebAuthn debug logging', () => {
  test('describes an assertion by shape only', () => {
    const described = describeWebAuthnResponse(assertionWithPrf());

    expect(described).toEqual({
      type: 'public-key',
      rawIdBytes: 32,
      clientDataJSONBytes: 23,
      attestationObjectBytes: null,
      hasGetPublicKey: false,
      authenticatorDataBytes: 37,
      signatureBytes: 64,
      hasUserHandle: false,
      extensions: ['prf'],
    });
  });

  test('reports that PRF engaged without revealing its output', () => {
    const described = describeWebAuthnResponse(assertionWithPrf());
    const serialised = JSON.stringify(described);

    // The name is the diagnostic; the value is key material.
    expect(described.extensions).toContain('prf');
    expect(serialised).not.toContain('results');
    expect(serialised).not.toContain('ab');
  });

  test('carries no credential bytes at all', () => {
    const serialised = JSON.stringify(
      describeWebAuthnResponse(assertionWithPrf())
    );

    for (const [name, bytes] of [
      ['PRF output', PRF_SECRET],
      ['signature', SIGNATURE],
      ['rawId', RAW_ID],
    ]) {
      const hex = Buffer.from(bytes).toString('hex');
      const base64 = Buffer.from(bytes).toString('base64');
      expect(serialised, `${name} must not appear as hex`).not.toContain(hex);
      expect(serialised, `${name} must not appear as base64`).not.toContain(
        base64
      );
    }
  });

  test('handles a registration response', () => {
    const described = describeWebAuthnResponse({
      type: 'public-key',
      rawId: RAW_ID.buffer,
      response: {
        attestationObject: new Uint8Array(194).buffer,
        clientDataJSON: new Uint8Array(133).buffer,
        getPublicKey: () => new Uint8Array(91).buffer,
      },
      getClientExtensionResults: () => ({}),
    });

    expect(described.attestationObjectBytes).toBe(194);
    expect(described.hasGetPublicKey).toBe(true);
    expect(described.authenticatorDataBytes).toBeNull();
    expect(described.extensions).toEqual([]);
  });

  test('survives a malformed or empty response', () => {
    expect(() => describeWebAuthnResponse(undefined)).not.toThrow();
    expect(() => describeWebAuthnResponse({})).not.toThrow();

    const described = describeWebAuthnResponse({
      getClientExtensionResults: () => {
        throw new Error('not available');
      },
    });
    expect(described.extensions).toBeNull();
  });

  test('writes nothing to console when the debug logger is off', () => {
    const seen = [];
    const originals = {};
    for (const level of ['log', 'group', 'groupEnd', 'info', 'debug']) {
      originals[level] = console[level];
      console[level] = (...args) => seen.push([level, args]);
    }

    try {
      logWebAuthnResponse('navigator.credentials.get()', assertionWithPrf());
    } finally {
      for (const [level, fn] of Object.entries(originals)) {
        console[level] = fn;
      }
    }

    expect(seen).toEqual([]);
  });
});

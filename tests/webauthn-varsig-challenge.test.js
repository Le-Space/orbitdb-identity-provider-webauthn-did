/**
 * The varsig challenge carries the payload hash, and the context that the
 * payload was signed for lives inside the signed bytes.
 *
 * Both properties are load-bearing and neither is obvious from the code:
 *
 * - The challenge must be a multihash of exactly the bytes that were signed,
 *   or a verifier following the varsig WebAuthn draft cannot reproduce it
 *   (step 5 of its verification procedure).
 * - The same credential signs identities, public keys and oplog entries. A
 *   signature over one must not be reusable as a signature over another, and
 *   since the WebAuthn signature only covers
 *   `authenticatorData ‖ SHA-256(clientDataJSON)`, that separation has to be
 *   inside the hashed bytes rather than beside them.
 */
import { test, expect } from '@playwright/test';

import { bindContext, buildChallengeBytes } from '../src/varsig/utils.js';
import { DEFAULT_DOMAIN_LABELS } from '../src/varsig/domain.js';

const payload = new TextEncoder().encode('oplog entry #42');

const MULTIHASH_SHA256 = 0x12;
const MULTIHASH_SHA256_LENGTH = 0x20;

test.describe('varsig challenge', () => {
  test('is a SHA-256 multihash of the signed bytes', async () => {
    const signed = bindContext(DEFAULT_DOMAIN_LABELS.entry, payload);
    const challenge = await buildChallengeBytes(signed);

    expect(challenge).toHaveLength(34);
    expect(challenge[0]).toBe(MULTIHASH_SHA256);
    expect(challenge[1]).toBe(MULTIHASH_SHA256_LENGTH);
  });

  test('lets a verifier re-hash the payload and get the same digest', async () => {
    // This is step 5 of the varsig WebAuthn verification procedure. Mixing the
    // context into the challenge preimage instead — which is what this
    // replaced — made it impossible to reproduce.
    const signed = bindContext(DEFAULT_DOMAIN_LABELS.entry, payload);
    const challenge = await buildChallengeBytes(signed);

    const rehashed = new Uint8Array(
      await crypto.subtle.digest('SHA-256', signed)
    );

    expect([...challenge.slice(2)]).toEqual([...rehashed]);
  });

  test('separates the three signing contexts', async () => {
    const challenges = await Promise.all(
      Object.values(DEFAULT_DOMAIN_LABELS).map(async (label) =>
        (await buildChallengeBytes(bindContext(label, payload))).join(',')
      )
    );

    expect(new Set(challenges).size).toBe(challenges.length);
  });

  test('frames the context unambiguously', () => {
    // Without a length prefix, context 'a' + payload 'bc' and context 'ab' +
    // payload 'c' would produce identical bytes, and the separation above
    // could be sidestepped by choosing a payload that absorbs the label.
    const encode = (s) => new TextEncoder().encode(s);

    expect([...bindContext('a', encode('bc'))]).not.toEqual([
      ...bindContext('ab', encode('c')),
    ]);
  });

  test('keeps the payload recoverable from the signed bytes', () => {
    const signed = bindContext(DEFAULT_DOMAIN_LABELS.entry, payload);
    const contextLength = new TextEncoder().encode(
      DEFAULT_DOMAIN_LABELS.entry
    ).length;

    // 1 varint byte for the length, then the context, then the payload.
    expect([...signed.slice(1 + contextLength)]).toEqual([...payload]);
  });
});

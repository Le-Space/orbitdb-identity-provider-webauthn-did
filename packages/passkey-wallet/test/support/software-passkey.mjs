/**
 * A P-256 key in memory that answers like a passkey: for a challenge it
 * returns the parts of a WebAuthn assertion — authenticatorData,
 * clientDataJSON with the challenge in base64url, the offsets of its "type"
 * and "challenge", and a low-s signature over sha256(authenticatorData ‖
 * sha256(clientDataJSON)) — in the shape `signP256Challenge` returns. For
 * tests that cannot reach an authenticator. The key is random per call and
 * holds nothing.
 */
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';

const encoder = new TextEncoder();

export function createSoftwarePasskey({ rpId = 'wallet.test' } = {}) {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(privateKey, false);
  const x = publicKey.slice(1, 33);
  const y = publicKey.slice(33, 65);
  let signCount = 0;

  /** @param {Uint8Array} challenge */
  async function sign(challenge) {
    signCount += 1;
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(sha256(encoder.encode(rpId)), 0);
    authenticatorData[32] = 0x05; // user present, user verified
    new DataView(authenticatorData.buffer).setUint32(33, signCount);
    const clientDataJSON = JSON.stringify({
      type: 'webauthn.get',
      challenge: Buffer.from(challenge).toString('base64url'),
      origin: `https://${rpId}`,
      crossOrigin: false,
    });
    const clientDataHash = sha256(encoder.encode(clientDataJSON));
    const message = new Uint8Array(authenticatorData.length + 32);
    message.set(authenticatorData, 0);
    message.set(clientDataHash, authenticatorData.length);
    const signature = p256.sign(sha256(message), privateKey, { lowS: true });
    return {
      authenticatorData,
      clientDataJSON,
      challengeIndex: clientDataJSON.indexOf('"challenge":"'),
      typeIndex: clientDataJSON.indexOf('"type":"'),
      r: signature.r,
      s: signature.s,
    };
  }

  return {
    sign,
    descriptor: {
      credentialId: 'AQ',
      rawCredentialId: new Uint8Array([1]),
      rpId,
      x,
      y,
      userVerification: 'required',
    },
  };
}

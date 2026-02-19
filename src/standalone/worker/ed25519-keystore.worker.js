/**
 * Ed25519 keystore web worker.
 *
 * Responsibilities:
 * - Derive and hold AES-GCM key from PRF seed
 * - Generate and hold Ed25519 keypair
 * - Load keypair archive back into worker memory
 * - Encrypt/decrypt bytes
 * - Sign/verify bytes
 */

const WORKER_KDF_INFO = new TextEncoder().encode('orbitdb/standalone-ed25519-keystore');

let ed25519KeyPair = null;
let aesKey = null;

function asUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new Uint8Array(value || []);
}

function toDetachedBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

async function deriveAesKeyFromPrfSeed(prfSeedBuffer) {
  const seedBytes = asUint8Array(prfSeedBuffer);
  if (seedBytes.length === 0) {
    throw new Error('PRF seed must not be empty');
  }

  const saltHash = await crypto.subtle.digest('SHA-256', seedBytes);
  const salt = new Uint8Array(saltHash).slice(0, 16);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    seedBytes,
    'HKDF',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: WORKER_KDF_INFO
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
}

async function generateEd25519KeypairArchive() {
  ed25519KeyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
  );

  const publicKeySpki = new Uint8Array(await crypto.subtle.exportKey('spki', ed25519KeyPair.publicKey));
  const privateKeyPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', ed25519KeyPair.privateKey));

  const publicKey = publicKeySpki.slice(-32);

  return {
    publicKey,
    archive: {
      version: 1,
      algorithm: 'Ed25519',
      format: 'pkcs8-spki',
      publicKeySpki: Array.from(publicKeySpki),
      privateKeyPkcs8: Array.from(privateKeyPkcs8)
    }
  };
}

async function loadKeypairFromArchive(archive) {
  if (!archive || archive.algorithm !== 'Ed25519') {
    throw new Error('Unsupported archive: expected Ed25519 archive');
  }

  const privateKeyBytes = asUint8Array(archive.privateKeyPkcs8);
  const publicKeyBytes = asUint8Array(archive.publicKeySpki);

  if (privateKeyBytes.length === 0 || publicKeyBytes.length === 0) {
    throw new Error('Invalid archive: missing key material');
  }

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    toDetachedBuffer(privateKeyBytes),
    { name: 'Ed25519' },
    true,
    ['sign']
  );

  const publicKey = await crypto.subtle.importKey(
    'spki',
    toDetachedBuffer(publicKeyBytes),
    { name: 'Ed25519' },
    true,
    ['verify']
  );

  ed25519KeyPair = { privateKey, publicKey };
}

async function encrypt(plaintextBuffer) {
  if (!aesKey) {
    throw new Error('Keystore not initialized');
  }

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    plaintextBuffer
  );

  return {
    ciphertext: new Uint8Array(ciphertext),
    iv
  };
}

async function decrypt(ciphertextBuffer, ivBuffer) {
  if (!aesKey) {
    throw new Error('Keystore not initialized');
  }

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuffer },
    aesKey,
    ciphertextBuffer
  );

  return {
    plaintext: new Uint8Array(plaintext)
  };
}

async function sign(dataBuffer) {
  if (!ed25519KeyPair) {
    throw new Error('Ed25519 keypair not generated');
  }

  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    ed25519KeyPair.privateKey,
    dataBuffer
  );

  return {
    signature: new Uint8Array(signature)
  };
}

async function verify(dataBuffer, signatureBuffer) {
  if (!ed25519KeyPair) {
    throw new Error('Ed25519 keypair not generated');
  }

  const valid = await crypto.subtle.verify(
    { name: 'Ed25519' },
    ed25519KeyPair.publicKey,
    signatureBuffer,
    dataBuffer
  );

  return { valid };
}

function postSuccess(id, result, transferables = []) {
  self.postMessage({ id, ok: true, result }, transferables);
}

function postError(id, error) {
  self.postMessage({
    id,
    ok: false,
    error: error instanceof Error ? error.message : String(error)
  });
}

self.onmessage = async (event) => {
  const msg = event.data;
  const id = msg.id;

  try {
    switch (msg.type) {
    case 'init': {
      aesKey = await deriveAesKeyFromPrfSeed(msg.prfSeed);
      postSuccess(id, { initialized: true });
      break;
    }
    case 'generateKeypair': {
      const { publicKey, archive } = await generateEd25519KeypairArchive();
      const publicKeyBuffer = toDetachedBuffer(publicKey);
      postSuccess(id, { publicKey: publicKeyBuffer, archive }, [publicKeyBuffer]);
      break;
    }
    case 'loadKeypair': {
      await loadKeypairFromArchive(msg.archive);
      postSuccess(id, { loaded: true });
      break;
    }
    case 'encrypt': {
      const result = await encrypt(msg.plaintext);
      const ciphertextBuffer = toDetachedBuffer(result.ciphertext);
      const ivBuffer = toDetachedBuffer(result.iv);
      postSuccess(
        id,
        { ciphertext: ciphertextBuffer, iv: ivBuffer },
        [ciphertextBuffer, ivBuffer]
      );
      break;
    }
    case 'decrypt': {
      const result = await decrypt(msg.ciphertext, msg.iv);
      const plaintextBuffer = toDetachedBuffer(result.plaintext);
      postSuccess(id, { plaintext: plaintextBuffer }, [plaintextBuffer]);
      break;
    }
    case 'sign': {
      const result = await sign(msg.data);
      const signatureBuffer = toDetachedBuffer(result.signature);
      postSuccess(id, { signature: signatureBuffer }, [signatureBuffer]);
      break;
    }
    case 'verify': {
      const result = await verify(msg.data, msg.signature);
      postSuccess(id, result);
      break;
    }
    default: {
      throw new Error(`Unknown message type: ${msg.type}`);
    }
    }
  } catch (error) {
    postError(id, error);
  }
};


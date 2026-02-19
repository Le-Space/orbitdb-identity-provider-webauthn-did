import { varint } from 'multiformats';
import { base58btc } from 'multiformats/bases/base58';

/**
 * Convert a Uint8Array into a detached ArrayBuffer slice.
 * @param {Uint8Array} bytes
 * @returns {ArrayBuffer}
 */
function toDetachedBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function normalizeArchiveForSerialization(archive) {
  if (!archive || typeof archive !== 'object') {
    return archive;
  }
  if (archive.id && archive.keys && typeof archive.keys === 'object') {
    return {
      ...archive,
      keys: Object.fromEntries(
        Object.entries(archive.keys).map(([did, keyBytes]) => [
          did,
          Array.from(
            keyBytes instanceof Uint8Array
              ? keyBytes
              : new Uint8Array(keyBytes || [])
          )
        ])
      )
    };
  }
  return archive;
}

function normalizeArchiveAfterDeserialization(archive) {
  if (!archive || typeof archive !== 'object') {
    return archive;
  }
  if (archive.id && archive.keys && typeof archive.keys === 'object') {
    return {
      ...archive,
      keys: Object.fromEntries(
        Object.entries(archive.keys).map(([did, keyBytes]) => [
          did,
          keyBytes instanceof Uint8Array
            ? keyBytes
            : new Uint8Array(Array.isArray(keyBytes) ? keyBytes : Object.values(keyBytes || {}))
        ])
      )
    };
  }
  return archive;
}

/**
 * Build a did:key identifier from raw Ed25519 public key bytes.
 * @param {Uint8Array} publicKeyBytes
 * @returns {string}
 */
export function createEd25519DidFromPublicKey(publicKeyBytes) {
  if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: ${publicKeyBytes?.length || 0}`);
  }

  const ED25519_MULTICODEC = 0xed;
  const codecLength = varint.encodingLength(ED25519_MULTICODEC);
  const codecBytes = new Uint8Array(codecLength);
  varint.encodeTo(ED25519_MULTICODEC, codecBytes, 0);

  const multikey = new Uint8Array(codecBytes.length + publicKeyBytes.length);
  multikey.set(codecBytes, 0);
  multikey.set(publicKeyBytes, codecBytes.length);

  return `did:key:${base58btc.encode(multikey)}`;
}

/**
 * @returns {boolean}
 */
export function isWorkerKeystoreAvailable() {
  return typeof Worker !== 'undefined';
}

class WorkerKeystoreClient {
  constructor(workerFactory) {
    this.worker = workerFactory();
    this.nextId = 1;
    this.pending = new Map();

    this.worker.onmessage = (event) => {
      const response = event.data;
      const pending = this.pending.get(response.id);
      if (!pending) return;
      this.pending.delete(response.id);
      if (response.ok) {
        pending.resolve(response.result);
      } else {
        pending.reject(new Error(response.error || 'Worker request failed'));
      }
    };

    this.worker.onerror = (event) => {
      const message = event?.message || 'Worker runtime error';
      for (const [, pending] of this.pending) {
        pending.reject(new Error(message));
      }
      this.pending.clear();
    };
  }

  request(type, payload = {}, transferables = []) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, type, ...payload }, transferables);
    });
  }

  /**
   * Initialize worker keystore from a PRF seed.
   * @param {Uint8Array} prfSeed
   */
  async initWithPrfSeed(prfSeed) {
    if (!(prfSeed instanceof Uint8Array) || prfSeed.length === 0) {
      throw new Error('initWithPrfSeed requires a non-empty Uint8Array seed');
    }
    const prfSeedBuffer = toDetachedBuffer(prfSeed);
    await this.request('init', { prfSeed: prfSeedBuffer }, [prfSeedBuffer]);
  }

  /**
   * Generate an Ed25519 keypair in the worker and return DID + archive.
   * @returns {Promise<{did: string, publicKey: Uint8Array, archive: Object}>}
   */
  async generateEd25519Identity() {
    const result = await this.request('generateKeypair');
    const publicKey = new Uint8Array(result.publicKey);
    const did = createEd25519DidFromPublicKey(publicKey);
    return { did, publicKey, archive: result.archive };
  }

  /**
   * Load a previously exported archive back into the worker.
   * @param {Object} archive
   */
  async loadArchive(archive) {
    if (!archive || typeof archive !== 'object') {
      throw new Error('loadArchive requires an archive object');
    }
    await this.request('loadKeypair', { archive });
  }

  /**
   * Encrypt bytes with worker-held AES key.
   * @param {Uint8Array} plaintext
   * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array}>}
   */
  async encrypt(plaintext) {
    if (!(plaintext instanceof Uint8Array)) {
      throw new Error('encrypt requires Uint8Array plaintext');
    }
    const plaintextBuffer = toDetachedBuffer(plaintext);
    const result = await this.request('encrypt', { plaintext: plaintextBuffer }, [plaintextBuffer]);
    return {
      ciphertext: new Uint8Array(result.ciphertext),
      iv: new Uint8Array(result.iv)
    };
  }

  /**
   * Decrypt bytes with worker-held AES key.
   * @param {Uint8Array} ciphertext
   * @param {Uint8Array} iv
   * @returns {Promise<Uint8Array>}
   */
  async decrypt(ciphertext, iv) {
    if (!(ciphertext instanceof Uint8Array) || !(iv instanceof Uint8Array)) {
      throw new Error('decrypt requires Uint8Array ciphertext and iv');
    }
    const ciphertextBuffer = toDetachedBuffer(ciphertext);
    const ivBuffer = toDetachedBuffer(iv);
    const result = await this.request(
      'decrypt',
      { ciphertext: ciphertextBuffer, iv: ivBuffer },
      [ciphertextBuffer, ivBuffer]
    );
    return new Uint8Array(result.plaintext);
  }

  /**
   * Sign bytes using worker-held Ed25519 keypair.
   * @param {Uint8Array} data
   * @returns {Promise<Uint8Array>}
   */
  async sign(data) {
    if (!(data instanceof Uint8Array)) {
      throw new Error('sign requires Uint8Array data');
    }
    const dataBuffer = toDetachedBuffer(data);
    const result = await this.request('sign', { data: dataBuffer }, [dataBuffer]);
    return new Uint8Array(result.signature);
  }

  /**
   * Verify Ed25519 signature using worker-held keypair.
   * @param {Uint8Array} data
   * @param {Uint8Array} signature
   * @returns {Promise<boolean>}
   */
  async verify(data, signature) {
    if (!(data instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
      throw new Error('verify requires Uint8Array data and signature');
    }
    const dataBuffer = toDetachedBuffer(data);
    const signatureBuffer = toDetachedBuffer(signature);
    const result = await this.request(
      'verify',
      { data: dataBuffer, signature: signatureBuffer },
      [dataBuffer, signatureBuffer]
    );
    return Boolean(result.valid);
  }

  /**
   * Serialize and encrypt an archive object.
   * @param {Object} archive
   * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array}>}
   */
  async encryptArchive(archive) {
    const payload = new TextEncoder().encode(
      JSON.stringify(normalizeArchiveForSerialization(archive))
    );
    return this.encrypt(payload);
  }

  /**
   * Decrypt and deserialize an archive object.
   * @param {Uint8Array} ciphertext
   * @param {Uint8Array} iv
   * @returns {Promise<Object>}
   */
  async decryptArchive(ciphertext, iv) {
    const plaintext = await this.decrypt(ciphertext, iv);
    const json = new TextDecoder().decode(plaintext);
    return normalizeArchiveAfterDeserialization(JSON.parse(json));
  }

  /**
   * Terminate worker and reject pending requests.
   */
  destroy() {
    this.worker.terminate();
    for (const [, pending] of this.pending) {
      pending.reject(new Error('Worker client destroyed'));
    }
    this.pending.clear();
  }
}

let defaultClient = null;

/**
 * Create a worker keystore client instance.
 * @param {{workerFactory?: () => Worker}} [options]
 * @returns {WorkerKeystoreClient}
 */
export function createWorkerKeystoreClient(options = {}) {
  if (!isWorkerKeystoreAvailable()) {
    throw new Error('Web Workers are not available in this environment');
  }
  const workerFactory = options.workerFactory || (() =>
    new Worker(new URL('./ed25519-keystore.worker.js', import.meta.url), { type: 'module' }));
  return new WorkerKeystoreClient(workerFactory);
}

/**
 * Get a singleton worker keystore client.
 * @param {{workerFactory?: () => Worker}} [options]
 * @returns {WorkerKeystoreClient}
 */
export function getDefaultWorkerKeystoreClient(options = {}) {
  if (!defaultClient) {
    defaultClient = createWorkerKeystoreClient(options);
  }
  return defaultClient;
}

/**
 * Destroy and clear the singleton worker keystore client.
 */
export function resetDefaultWorkerKeystoreClient() {
  if (defaultClient) {
    defaultClient.destroy();
    defaultClient = null;
  }
}

/**
 * Compatibility wrapper: initialize singleton worker keystore with PRF seed.
 * @param {Uint8Array} prfSeed
 * @param {{workerFactory?: () => Worker}} [options]
 */
export async function initEd25519KeystoreWithPrfSeed(prfSeed, options = {}) {
  const client = getDefaultWorkerKeystoreClient(options);
  await client.initWithPrfSeed(prfSeed);
}

/**
 * Compatibility wrapper: generate DID + public key + archive.
 * @param {{workerFactory?: () => Worker}} [options]
 * @returns {Promise<{did: string, publicKey: Uint8Array, archive: Object}>}
 */
export async function generateWorkerEd25519DID(options = {}) {
  return getDefaultWorkerKeystoreClient(options).generateEd25519Identity();
}

/**
 * Compatibility wrapper: load archive into singleton worker keystore.
 * @param {Object} archive
 * @param {{workerFactory?: () => Worker}} [options]
 */
export async function loadWorkerEd25519Archive(archive, options = {}) {
  await getDefaultWorkerKeystoreClient(options).loadArchive(archive);
}

/**
 * Compatibility wrapper: encrypt data with singleton worker keystore.
 * @param {Uint8Array} plaintext
 * @param {{workerFactory?: () => Worker}} [options]
 * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array}>}
 */
export async function keystoreEncrypt(plaintext, options = {}) {
  return getDefaultWorkerKeystoreClient(options).encrypt(plaintext);
}

/**
 * Compatibility wrapper: decrypt data with singleton worker keystore.
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} iv
 * @param {{workerFactory?: () => Worker}} [options]
 * @returns {Promise<Uint8Array>}
 */
export async function keystoreDecrypt(ciphertext, iv, options = {}) {
  return getDefaultWorkerKeystoreClient(options).decrypt(ciphertext, iv);
}

/**
 * Compatibility wrapper: sign data with singleton worker keystore.
 * @param {Uint8Array} data
 * @param {{workerFactory?: () => Worker}} [options]
 * @returns {Promise<Uint8Array>}
 */
export async function keystoreSign(data, options = {}) {
  return getDefaultWorkerKeystoreClient(options).sign(data);
}

/**
 * Compatibility wrapper: verify signature with singleton worker keystore.
 * @param {Uint8Array} data
 * @param {Uint8Array} signature
 * @param {{workerFactory?: () => Worker}} [options]
 * @returns {Promise<boolean>}
 */
export async function keystoreVerify(data, signature, options = {}) {
  return getDefaultWorkerKeystoreClient(options).verify(data, signature);
}

/**
 * Compatibility wrapper: encrypt archive with singleton worker keystore.
 * @param {Object} archive
 * @param {{workerFactory?: () => Worker}} [options]
 * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array}>}
 */
export async function encryptArchive(archive, options = {}) {
  return getDefaultWorkerKeystoreClient(options).encryptArchive(archive);
}

/**
 * Compatibility wrapper: decrypt archive with singleton worker keystore.
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} iv
 * @param {{workerFactory?: () => Worker}} [options]
 * @returns {Promise<Object>}
 */
export async function decryptArchive(ciphertext, iv, options = {}) {
  return getDefaultWorkerKeystoreClient(options).decryptArchive(ciphertext, iv);
}

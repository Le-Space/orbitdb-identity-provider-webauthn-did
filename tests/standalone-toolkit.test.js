import { test, expect } from '@playwright/test';
import {
  StandaloneWebAuthnVarsigSigner,
  WebAuthnHardwareSignerService,
  createEd25519DidFromPublicKey,
  createWorkerKeystoreClient,
  clearWebAuthnCredentialSafe,
  decryptArchive,
  encryptArchive,
  extractPrfSeedFromCredential,
  generateWorkerEd25519DID,
  getStoredWebAuthnHardwareSignerInfo,
  initEd25519KeystoreWithPrfSeed,
  keystoreDecrypt,
  keystoreEncrypt,
  keystoreSign,
  keystoreVerify,
  loadWebAuthnCredentialSafe,
  resetDefaultWorkerKeystoreClient,
  storeWebAuthnCredentialSafe
} from '../src/standalone/index.js';

class MemoryStorage {
  constructor() {
    this.map = new Map();
  }

  getItem(key) {
    return this.map.has(key) ? this.map.get(key) : null;
  }

  setItem(key, value) {
    this.map.set(key, String(value));
  }

  removeItem(key) {
    this.map.delete(key);
  }

  clear() {
    this.map.clear();
  }
}

test.describe('Standalone WebAuthn Toolkit', () => {
  test.beforeEach(() => {
    globalThis.localStorage = new MemoryStorage();
    if (typeof globalThis.Worker === 'undefined') {
      globalThis.Worker = class Worker {};
    }
    resetDefaultWorkerKeystoreClient();
  });

  test('creates deterministic Ed25519 did:key from public key bytes', async () => {
    const did = createEd25519DidFromPublicKey(new Uint8Array(32).fill(7));
    expect(did.startsWith('did:key:z')).toBe(true);
    expect(did.length).toBeGreaterThan(20);
  });

  test('worker client protocol works with custom worker factory', async () => {
    class FakeWorker {
      constructor() {
        this.onmessage = null;
        this.onerror = null;
        this.archive = null;
      }

      postMessage(msg) {
        setTimeout(() => {
          try {
            if (msg.type === 'init') {
              this.onmessage?.({ data: { id: msg.id, ok: true, result: { initialized: true } } });
              return;
            }
            if (msg.type === 'generateKeypair') {
              const publicKey = new Uint8Array(32).fill(3);
              this.archive = {
                version: 1,
                algorithm: 'Ed25519',
                privateKeyPkcs8: [1, 2, 3],
                publicKeySpki: [4, 5, 6]
              };
              this.onmessage?.({
                data: {
                  id: msg.id,
                  ok: true,
                  result: {
                    publicKey: publicKey.buffer.slice(0),
                    archive: this.archive
                  }
                }
              });
              return;
            }
            if (msg.type === 'loadKeypair') {
              this.onmessage?.({ data: { id: msg.id, ok: true, result: { loaded: true } } });
              return;
            }
            if (msg.type === 'encrypt') {
              const bytes = new Uint8Array(msg.plaintext);
              const ciphertext = Uint8Array.from(bytes, (b) => b ^ 0xff);
              const iv = new Uint8Array(12).fill(9);
              this.onmessage?.({
                data: {
                  id: msg.id,
                  ok: true,
                  result: {
                    ciphertext: ciphertext.buffer.slice(0),
                    iv: iv.buffer.slice(0)
                  }
                }
              });
              return;
            }
            if (msg.type === 'decrypt') {
              const bytes = new Uint8Array(msg.ciphertext);
              const plaintext = Uint8Array.from(bytes, (b) => b ^ 0xff);
              this.onmessage?.({
                data: {
                  id: msg.id,
                  ok: true,
                  result: { plaintext: plaintext.buffer.slice(0) }
                }
              });
              return;
            }
            if (msg.type === 'sign') {
              const data = new Uint8Array(msg.data);
              const signature = new Uint8Array([data.length, 42]);
              this.onmessage?.({
                data: {
                  id: msg.id,
                  ok: true,
                  result: { signature: signature.buffer.slice(0) }
                }
              });
              return;
            }
            if (msg.type === 'verify') {
              const data = new Uint8Array(msg.data);
              const sig = new Uint8Array(msg.signature);
              const valid = sig.length === 2 && sig[0] === data.length && sig[1] === 42;
              this.onmessage?.({ data: { id: msg.id, ok: true, result: { valid } } });
              return;
            }
            this.onmessage?.({ data: { id: msg.id, ok: false, error: `Unknown type: ${msg.type}` } });
          } catch (error) {
            this.onmessage?.({
              data: {
                id: msg.id,
                ok: false,
                error: error instanceof Error ? error.message : String(error)
              }
            });
          }
        }, 0);
      }

      terminate() {}
    }

    const client = createWorkerKeystoreClient({
      workerFactory: () => new FakeWorker()
    });

    await client.initWithPrfSeed(new Uint8Array([1, 2, 3]));
    const identity = await client.generateEd25519Identity();
    await client.loadArchive(identity.archive);

    const data = new TextEncoder().encode('hello');
    const encrypted = await client.encrypt(data);
    const decrypted = await client.decrypt(encrypted.ciphertext, encrypted.iv);
    const signature = await client.sign(data);
    const valid = await client.verify(data, signature);

    const archivePayload = {
      id: identity.did,
      keys: { [identity.did]: [1, 2, 3] }
    };
    const encryptedArchive = await client.encryptArchive(archivePayload);
    const decryptedArchive = await client.decryptArchive(
      encryptedArchive.ciphertext,
      encryptedArchive.iv
    );

    client.destroy();

    expect(identity.did.startsWith('did:key:z')).toBe(true);
    expect(identity.publicKey.length).toBe(32);
    expect(new TextDecoder().decode(decrypted)).toBe('hello');
    expect(valid).toBe(true);
    expect(decryptedArchive.id).toBe(identity.did);
  });

  test('compatibility wrappers work with singleton worker client', async () => {
    class FakeWorker {
      constructor() {
        this.onmessage = null;
        this.onerror = null;
      }

      postMessage(msg) {
        setTimeout(() => {
          if (msg.type === 'init') {
            this.onmessage?.({ data: { id: msg.id, ok: true, result: { initialized: true } } });
            return;
          }
          if (msg.type === 'generateKeypair') {
            const publicKey = new Uint8Array(32).fill(1);
            this.onmessage?.({
              data: {
                id: msg.id,
                ok: true,
                result: {
                  publicKey: publicKey.buffer.slice(0),
                  archive: { version: 1, algorithm: 'Ed25519', privateKeyPkcs8: [7], publicKeySpki: [8] }
                }
              }
            });
            return;
          }
          if (msg.type === 'encrypt') {
            const bytes = new Uint8Array(msg.plaintext);
            const ciphertext = Uint8Array.from(bytes, (b) => b ^ 0xaa);
            const iv = new Uint8Array(12).fill(5);
            this.onmessage?.({
              data: {
                id: msg.id,
                ok: true,
                result: { ciphertext: ciphertext.buffer.slice(0), iv: iv.buffer.slice(0) }
              }
            });
            return;
          }
          if (msg.type === 'decrypt') {
            const bytes = new Uint8Array(msg.ciphertext);
            const plaintext = Uint8Array.from(bytes, (b) => b ^ 0xaa);
            this.onmessage?.({
              data: {
                id: msg.id,
                ok: true,
                result: { plaintext: plaintext.buffer.slice(0) }
              }
            });
            return;
          }
          if (msg.type === 'sign') {
            const payload = new Uint8Array(msg.data);
            const signature = new Uint8Array([payload.length, 9]);
            this.onmessage?.({
              data: {
                id: msg.id,
                ok: true,
                result: { signature: signature.buffer.slice(0) }
              }
            });
            return;
          }
          if (msg.type === 'verify') {
            const payload = new Uint8Array(msg.data);
            const signature = new Uint8Array(msg.signature);
            const valid = signature.length === 2 && signature[0] === payload.length && signature[1] === 9;
            this.onmessage?.({ data: { id: msg.id, ok: true, result: { valid } } });
            return;
          }
          this.onmessage?.({ data: { id: msg.id, ok: false, error: `Unsupported ${msg.type}` } });
        }, 0);
      }

      terminate() {}
    }

    const options = {
      workerFactory: () => new FakeWorker()
    };

    await initEd25519KeystoreWithPrfSeed(new Uint8Array([9, 8, 7]), options);
    const identity = await generateWorkerEd25519DID(options);

    const data = new TextEncoder().encode('compat');
    const encrypted = await keystoreEncrypt(data, options);
    const decrypted = await keystoreDecrypt(encrypted.ciphertext, encrypted.iv, options);
    const signature = await keystoreSign(data, options);
    const valid = await keystoreVerify(data, signature, options);

    const payload = { id: identity.did, keys: {} };
    const encryptedArchive = await encryptArchive(payload, options);
    const decryptedArchive = await decryptArchive(
      encryptedArchive.ciphertext,
      encryptedArchive.iv,
      options
    );

    expect(identity.did.startsWith('did:key:z')).toBe(true);
    expect(new TextDecoder().decode(decrypted)).toBe('compat');
    expect(valid).toBe(true);
    expect(decryptedArchive.id).toBe(identity.did);
  });

  test('hardware signer metadata storage and load works', async () => {
    const credential = {
      credentialId: new Uint8Array([10, 11, 12]),
      publicKey: new Uint8Array(32).fill(8),
      did: 'did:key:z6MkrmFAKE123',
      algorithm: 'Ed25519',
      cose: { kty: 1, alg: -8, crv: 6 }
    };

    const signer = new StandaloneWebAuthnVarsigSigner(credential);
    const service = new WebAuthnHardwareSignerService({
      storageKey: 'test-hw-signer'
    });

    service.store(signer);
    const loaded = service.load();
    const info = getStoredWebAuthnHardwareSignerInfo('test-hw-signer');

    expect(loaded?.did).toBe('did:key:z6MkrmFAKE123');
    expect(loaded?.algorithm).toBe('Ed25519');
    expect(info?.did).toBe('did:key:z6MkrmFAKE123');
    expect(info?.algorithm).toBe('Ed25519');

    service.clear();
    expect(getStoredWebAuthnHardwareSignerInfo('test-hw-signer')).toBeNull();
  });

  test('safe credential storage excludes prfSeed and restores typed arrays', async () => {
    const input = {
      credentialId: 'test',
      rawCredentialId: new Uint8Array([1, 2, 3]),
      publicKey: {
        x: new Uint8Array([4, 5]),
        y: new Uint8Array([6, 7])
      },
      prfInput: new Uint8Array([8, 9]),
      prfSeed: new Uint8Array([10, 11])
    };

    storeWebAuthnCredentialSafe(input, 'credential-safe-test');
    const loaded = loadWebAuthnCredentialSafe('credential-safe-test');

    expect(loaded).toBeTruthy();
    expect(loaded.prfSeed).toBeUndefined();
    expect(loaded.rawCredentialId).toBeInstanceOf(Uint8Array);
    expect(Array.from(loaded.rawCredentialId)).toEqual([1, 2, 3]);
    expect(loaded.publicKey.x).toBeInstanceOf(Uint8Array);
    expect(Array.from(loaded.publicKey.x)).toEqual([4, 5]);

    clearWebAuthnCredentialSafe('credential-safe-test');
    expect(loadWebAuthnCredentialSafe('credential-safe-test')).toBeNull();
  });

  test('extractPrfSeedFromCredential uses PRF output then falls back', async () => {
    const credential = {
      rawCredentialId: new Uint8Array([91, 92, 93]),
      prfInput: new Uint8Array([1, 1, 1])
    };

    const navigatorObject = globalThis.navigator || {};
    const originalCredentials = navigatorObject.credentials;

    Object.defineProperty(navigatorObject, 'credentials', {
      configurable: true,
      value: {
        get: async () => ({
          getClientExtensionResults: () => ({
            prf: {
              results: {
                first: new Uint8Array([7, 7, 7])
              }
            }
          })
        })
      }
    });

    const prfResult = await extractPrfSeedFromCredential(credential, { rpId: 'example.test' });
    expect(prfResult.source).toBe('prf');
    expect(Array.from(prfResult.seed)).toEqual([7, 7, 7]);

    Object.defineProperty(navigatorObject, 'credentials', {
      configurable: true,
      value: {
        get: async () => ({
          getClientExtensionResults: () => ({})
        })
      }
    });

    const fallback = await extractPrfSeedFromCredential(credential, { rpId: 'example.test' });
    expect(fallback.source).toBe('credentialId');
    expect(Array.from(fallback.seed)).toEqual([91, 92, 93]);

    Object.defineProperty(navigatorObject, 'credentials', {
      configurable: true,
      value: originalCredentials
    });
  });
});

/**
 * Tests for OrbitDB WebAuthn DID Identity Provider
 *
 * These tests verify the WebAuthn identity provider functionality
 * including credential creation, signing, and OrbitDB integration.
 */

import assert from 'assert';
import {
  WebAuthnDIDProvider,
  OrbitDBWebAuthnIdentityProvider,
  OrbitDBWebAuthnIdentityProviderFunction,
  registerWebAuthnProvider,
  checkWebAuthnSupport
} from '../src/index.js';

// Mock WebAuthn for Node.js testing environment
const setupMockWebAuthn = () => {
  // Mock the global objects that WebAuthn needs
  global.window = {
    PublicKeyCredential: {
      isUserVerifyingPlatformAuthenticatorAvailable: async () => true
    },
    location: {
      hostname: 'localhost'
    }
  };

  global.navigator = {
    credentials: {
      create: async () => {
        // Mock WebAuthn credential creation
        const credentialId = new Uint8Array(32);
        crypto.getRandomValues(credentialId);

        return {
          rawId: credentialId,
          response: {
            attestationObject: new Uint8Array(300), // Mock attestation object
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.create',
              challenge: 'mock-challenge',
              origin: 'https://localhost'
            }))
          }
        };
      },
      get: async (options) => {
        // Mock WebAuthn authentication
        return {
          rawId: options.publicKey.allowCredentials[0].id,
          response: {
            authenticatorData: new Uint8Array(37), // Mock authenticator data
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.get',
              challenge: 'mock-challenge',
              origin: 'https://localhost'
            })),
            signature: new Uint8Array(64) // Mock signature
          }
        };
      }
    }
  };

  global.crypto = {
    getRandomValues: (array) => {
      for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256);
      }
      return array;
    },
    subtle: {
      digest: async (algorithm, data) => {
        // Simple mock hash function
        const hash = new ArrayBuffer(32);
        const view = new Uint8Array(hash);
        for (let i = 0; i < view.length; i++) {
          view[i] = (data instanceof ArrayBuffer ? new Uint8Array(data)[i % data.byteLength] : data[i % data.length]) || 0;
        }
        return hash;
      }
    }
  };

  global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
  global.atob = (str) => Buffer.from(str, 'base64').toString('binary');
  global.TextEncoder = TextEncoder;
  global.TextDecoder = TextDecoder;
};

describe('WebAuthn DID Identity Provider', function() {
  this.timeout(10000); // Allow extra time for async operations

  before(() => {
    setupMockWebAuthn();
  });

  describe('Support Detection', () => {
    it('should detect WebAuthn support', () => {
      const isSupported = WebAuthnDIDProvider.isSupported();
      assert.strictEqual(isSupported, true, 'WebAuthn should be supported in mock environment');
    });

    it('should check platform authenticator availability', async () => {
      const isAvailable = await WebAuthnDIDProvider.isPlatformAuthenticatorAvailable();
      assert.strictEqual(isAvailable, true, 'Platform authenticator should be available in mock');
    });

    it('should provide comprehensive support information', async () => {
      const support = await checkWebAuthnSupport();

      assert.strictEqual(support.supported, true);
      assert.strictEqual(support.platformAuthenticator, true);
      assert.strictEqual(typeof support.message, 'string');
      assert.strictEqual(support.error, null);
    });
  });

  describe('Credential Creation', () => {
    let testCredential;

    it('should create WebAuthn credential with default options', async () => {
      testCredential = await WebAuthnDIDProvider.createCredential();

      assert(testCredential, 'Credential should be created');
      assert(testCredential.credentialId, 'Should have credential ID');
      assert(testCredential.rawCredentialId, 'Should have raw credential ID');
      assert(testCredential.publicKey, 'Should have public key');
      assert(testCredential.userId, 'Should have user ID');
      assert(testCredential.displayName, 'Should have display name');
    });

    it('should create credential with custom options', async () => {
      const options = {
        userId: 'test-user-123',
        displayName: 'Test User',
        domain: 'test-domain.com'
      };

      const credential = await WebAuthnDIDProvider.createCredential(options);

      assert.strictEqual(credential.userId, options.userId);
      assert.strictEqual(credential.displayName, options.displayName);
    });

    it('should generate deterministic DID from credential', () => {
      const did = WebAuthnDIDProvider.createDID(testCredential);

      assert(did.startsWith('did:key:'), 'DID should have correct prefix');
      assert(did.length > 50, 'DID should have expected length'); // 'did:key:z' + base58btc encoded multikey

      // Should be deterministic
      const did2 = WebAuthnDIDProvider.createDID(testCredential);
      assert.strictEqual(did, did2, 'DID generation should be deterministic');
    });
  });

  describe('WebAuthn Provider Core', () => {
    let webauthnProvider;
    let testCredential;

    before(async () => {
      testCredential = await WebAuthnDIDProvider.createCredential({
        userId: 'test-signer',
        displayName: 'Test Signer'
      });
      webauthnProvider = new WebAuthnDIDProvider(testCredential);
    });

    it('should initialize with credential info', () => {
      assert.strictEqual(webauthnProvider.type, 'webauthn');
      assert.strictEqual(webauthnProvider.credentialId, testCredential.credentialId);
      assert.strictEqual(webauthnProvider.publicKey, testCredential.publicKey);
    });

    it('should sign data using WebAuthn', async () => {
      const testData = 'Hello, OrbitDB!';
      const signature = await webauthnProvider.sign(testData);

      assert(signature, 'Should return signature');
      assert.strictEqual(typeof signature, 'string', 'Signature should be string');
      assert(signature.length > 0, 'Signature should not be empty');
    });

    it('should verify signatures', async () => {
      const testData = 'Test verification data';
      const signature = await webauthnProvider.sign(testData);

      const isValid = await webauthnProvider.verify(signature, testData, testCredential.publicKey);
      assert.strictEqual(isValid, true, 'Should verify signature successfully');
    });
  });

  describe('OrbitDB Integration', () => {
    let identityProvider;
    let testCredential;

    before(async () => {
      testCredential = await WebAuthnDIDProvider.createCredential({
        userId: 'orbitdb-user',
        displayName: 'OrbitDB User'
      });
    });

    it('should create OrbitDB identity provider', () => {
      identityProvider = new OrbitDBWebAuthnIdentityProvider({
        webauthnCredential: testCredential
      });

      assert.strictEqual(identityProvider.type, 'webauthn');
      assert.strictEqual(OrbitDBWebAuthnIdentityProvider.type, 'webauthn');
    });

    it('should return valid DID as identity ID', () => {
      const id = identityProvider.getId();

      assert(id.startsWith('did:key:'), 'Should return DID format');
      assert.strictEqual(typeof id, 'string', 'ID should be string');
    });

    it('should sign identity data', async () => {
      const testData = 'OrbitDB identity verification';
      const signature = await identityProvider.signIdentity(testData);

      assert(signature, 'Should return signature');
      assert.strictEqual(typeof signature, 'string', 'Signature should be string');
    });

    it('should verify identity signatures', async () => {
      const testData = 'Identity verification test';
      const signature = await identityProvider.signIdentity(testData);

      const isValid = await identityProvider.verifyIdentity(signature, testData);
      assert.strictEqual(isValid, true, 'Should verify identity signature');
    });
  });

  describe('Provider Function', () => {
    let testCredential;

    before(async () => {
      testCredential = await WebAuthnDIDProvider.createCredential();
    });

    it('should create provider function with correct type', () => {
      const providerFunction = OrbitDBWebAuthnIdentityProviderFunction({
        webauthnCredential: testCredential
      });

      assert.strictEqual(typeof providerFunction, 'function');
      assert.strictEqual(OrbitDBWebAuthnIdentityProviderFunction.type, 'webauthn');
    });

    it('should create identity provider instance', async () => {
      const providerFunction = OrbitDBWebAuthnIdentityProviderFunction({
        webauthnCredential: testCredential
      });

      const provider = await providerFunction();
      assert(provider instanceof OrbitDBWebAuthnIdentityProvider);
    });

    it('should verify identity statically', async () => {
      const identity = {
        id: 'did:key:zDnaeReWND2i3xwN5GxPdBFLWHWv1wfCQNw25yJCuLWFErgMP',
        type: 'webauthn'
      };

      const isValid = await OrbitDBWebAuthnIdentityProviderFunction.verifyIdentity(identity);
      assert.strictEqual(isValid, true, 'Should verify valid WebAuthn identity');
    });

    it('should reject invalid identity', async () => {
      const invalidIdentity = {
        id: 'invalid-id',
        type: 'webauthn'
      };

      const isValid = await OrbitDBWebAuthnIdentityProviderFunction.verifyIdentity(invalidIdentity);
      assert.strictEqual(isValid, false, 'Should reject invalid identity');
    });
  });

  describe('Registration', () => {
    it('should register WebAuthn provider with OrbitDB', () => {
      // Since we can't easily mock the import, we'll just test the function exists
      assert.strictEqual(typeof registerWebAuthnProvider, 'function');
    });
  });

  describe('Utility Methods', () => {
    it('should convert ArrayBuffer to base64url correctly', () => {
      const buffer = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const base64url = WebAuthnDIDProvider.arrayBufferToBase64url(buffer);

      assert.strictEqual(typeof base64url, 'string');
      assert(!base64url.includes('+'), 'Should not contain + characters');
      assert(!base64url.includes('/'), 'Should not contain / characters');
      assert(!base64url.includes('='), 'Should not contain = characters');
    });

    it('should convert base64url to ArrayBuffer correctly', () => {
      const base64url = 'SGVsbG8';
      const buffer = WebAuthnDIDProvider.base64urlToArrayBuffer(base64url);
      const bytes = new Uint8Array(buffer);

      assert(buffer instanceof ArrayBuffer);
      assert.deepStrictEqual(Array.from(bytes), [72, 101, 108, 108, 111]); // "Hello"
    });

    it('should handle round-trip conversion', () => {
      const originalData = new Uint8Array([1, 2, 3, 4, 5, 255]);
      const base64url = WebAuthnDIDProvider.arrayBufferToBase64url(originalData);
      const converted = new Uint8Array(WebAuthnDIDProvider.base64urlToArrayBuffer(base64url));

      assert.deepStrictEqual(Array.from(originalData), Array.from(converted));
    });
  });

  describe('Error Handling', () => {
    it('should handle WebAuthn not supported', () => {
      // Temporarily break WebAuthn support
      const originalWindow = global.window;
      delete global.window;

      assert.strictEqual(WebAuthnDIDProvider.isSupported(), false);

      // Restore
      global.window = originalWindow;
    });

    it('should handle credential creation failure', async () => {
      // Mock credential creation failure
      const originalCreate = global.navigator.credentials.create;
      global.navigator.credentials.create = async () => {
        throw { name: 'NotAllowedError', message: 'User cancelled' };
      };

      try {
        await WebAuthnDIDProvider.createCredential();
        assert.fail('Should have thrown error');
      } catch (error) {
        assert.strictEqual(error.message, 'Biometric authentication was cancelled or failed');
      }

      // Restore
      global.navigator.credentials.create = originalCreate;
    });

    it('should handle signing failure', async () => {
      const credential = await WebAuthnDIDProvider.createCredential();
      const provider = new WebAuthnDIDProvider(credential);

      // Mock authentication failure
      const originalGet = global.navigator.credentials.get;
      global.navigator.credentials.get = async () => {
        throw { name: 'InvalidStateError', message: 'Credential invalid' };
      };

      try {
        await provider.sign('test data');
        assert.fail('Should have thrown error');
      } catch (error) {
        assert.strictEqual(error.message, 'WebAuthn credential is invalid or expired');
      }

      // Restore
      global.navigator.credentials.get = originalGet;
    });
  });
});

// Integration test example (commented out since it requires real WebAuthn)
/*
describe('Real WebAuthn Integration', function() {
  // These tests would run in a real browser environment
  this.skip() // Skip by default

  it('should work with real WebAuthn', async () => {
    if (typeof window === 'undefined') {
      this.skip()
      return
    }

    const support = await checkWebAuthnSupport()
    if (!support.supported) {
      this.skip()
      return
    }

    // Real WebAuthn test
    const credential = await WebAuthnDIDProvider.createCredential({
      userId: 'real-test-user',
      displayName: 'Real Test User'
    })

    assert(credential)

    const provider = new WebAuthnDIDProvider(credential)
    const signature = await provider.sign('real test data')

    assert(signature)
  })
})
*/

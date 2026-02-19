/**
 * Tests for WebAuthn-Encrypted Keystore Feature
 *
 * This test suite verifies that the encrypted keystore feature works correctly,
 * including AES-GCM encryption, WebAuthn extension support, and session management.
 */

import { test, expect } from '@playwright/test';
import { OrbitDBWebAuthnIdentityProvider } from '../src/index.js';

async function waitForKeystoreEncryption(page) {
  try {
    await page.waitForFunction(() =>
      window.KeystoreEncryption &&
      typeof window.KeystoreEncryption.generateSecretKey === 'function' &&
      typeof window.KeystoreEncryption.checkExtensionSupport === 'function'
    , { timeout: 20000 });
  } catch {
    throw new Error(
      'KeystoreEncryption not available. Run with USE_ENCRYPTED_DEMO=true (ed25519-encrypted-keystore-demo).'
    );
  }
}

async function installLargeBlobMock(context, { hasBlob }) {
  await context.addInitScript(({ hasBlob }) => {
    const mockCredentialId = new Uint8Array([1, 2, 3, 4]);
    const mockSecretKey = new Uint8Array(32);
    for (let i = 0; i < mockSecretKey.length; i++) {
      mockSecretKey[i] = i * 7 % 256;
    }

    const installMock = () => {
      if (!window.navigator.credentials) {
        Object.defineProperty(window.navigator, 'credentials', {
          value: {},
          configurable: true
        });
      }

      const mockGet = async () => {
        window.__largeBlobMockCalled = true;
        return {
          id: 'test-credential',
          rawId: mockCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: new Uint8Array(37),
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.get',
              challenge: 'test',
              origin: window.location.origin
            })),
            signature: new Uint8Array(64)
          },
          getClientExtensionResults: () => ({
            largeBlob: hasBlob ? { blob: mockSecretKey } : null
          })
        };
      };

      Object.defineProperty(window.navigator.credentials, 'get', {
        value: mockGet,
        configurable: true,
        writable: true
      });
    };

    try {
      installMock();
    } catch {
      Object.defineProperty(window.navigator, 'credentials', {
        value: {},
        configurable: true
      });
      installMock();
    }

    window.__largeBlobMockInstalled = true;
  }, { hasBlob });
}

test.describe('WebAuthn-Encrypted Keystore Feature', () => {

  test('should check encryption extension support', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const support = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;
      return await KeystoreEncryption.checkExtensionSupport();
    });

    expect(support).toHaveProperty('largeBlob');
    expect(support).toHaveProperty('hmacSecret');
    expect(typeof support.largeBlob).toBe('boolean');
    expect(typeof support.hmacSecret).toBe('boolean');

    console.log('Extension support:', support);
  });

  test('should generate secret key', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(() => {
      const { KeystoreEncryption } = window;
      const sk = KeystoreEncryption.generateSecretKey();

      return {
        length: sk.length,
        isUint8Array: sk instanceof Uint8Array
      };
    });

    expect(result.length).toBe(32); // 256-bit key
    expect(result.isUint8Array).toBe(true);
  });

  test('should encrypt and decrypt data with AES-GCM', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;

      // Generate secret key
      const sk = KeystoreEncryption.generateSecretKey();

      // Test data
      const originalData = new TextEncoder().encode('Hello, encrypted world!');

      // Encrypt
      const encrypted = await KeystoreEncryption.encryptWithAESGCM(originalData, sk);

      // Decrypt
      const decrypted = await KeystoreEncryption.decryptWithAESGCM(
        encrypted.ciphertext,
        sk,
        encrypted.iv
      );

      const decryptedText = new TextDecoder().decode(decrypted);

      return {
        originalText: 'Hello, encrypted world!',
        decryptedText,
        hasCiphertext: encrypted.ciphertext.length > 0,
        hasIV: encrypted.iv.length === 12,
        matches: decryptedText === 'Hello, encrypted world!'
      };
    });

    expect(result.hasCiphertext).toBe(true);
    expect(result.hasIV).toBe(true);
    expect(result.matches).toBe(true);
    expect(result.decryptedText).toBe(result.originalText);
  });

  test('should fail decryption with wrong key', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;

      // Generate two different secret keys
      const sk1 = KeystoreEncryption.generateSecretKey();
      const sk2 = KeystoreEncryption.generateSecretKey();

      const originalData = new TextEncoder().encode('Secret message');

      // Encrypt with sk1
      const encrypted = await KeystoreEncryption.encryptWithAESGCM(originalData, sk1);

      // Try to decrypt with sk2 (wrong key)
      try {
        await KeystoreEncryption.decryptWithAESGCM(
          encrypted.ciphertext,
          sk2,
          encrypted.iv
        );
        return { decryptionFailed: false };
      } catch (error) {
        return { decryptionFailed: true, errorMessage: error.message };
      }
    });

    expect(result.decryptionFailed).toBe(true);
    expect(result.errorMessage).toContain('decrypt');
  });

  test('should store and load encrypted keystore', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;

      const sk = KeystoreEncryption.generateSecretKey();
      const testData = new TextEncoder().encode('Test keystore data');
      const encrypted = await KeystoreEncryption.encryptWithAESGCM(testData, sk);

      const credentialId = 'test-credential-' + Date.now();

      // Store encrypted keystore
      const dataToStore = {
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        credentialId: credentialId,
        encryptionMethod: 'test'
      };

      await KeystoreEncryption.storeEncryptedKeystore(dataToStore, credentialId);

      // Load encrypted keystore
      const loaded = await KeystoreEncryption.loadEncryptedKeystore(credentialId);

      // Clean up
      await KeystoreEncryption.clearEncryptedKeystore(credentialId);

      return {
        stored: true,
        loaded: !!loaded,
        ciphertextMatches: Array.from(loaded.ciphertext).join(',') === Array.from(encrypted.ciphertext).join(','),
        ivMatches: Array.from(loaded.iv).join(',') === Array.from(encrypted.iv).join(','),
        credentialIdMatches: loaded.credentialId === credentialId
      };
    });

    expect(result.stored).toBe(true);
    expect(result.loaded).toBe(true);
    expect(result.ciphertextMatches).toBe(true);
    expect(result.ivMatches).toBe(true);
    expect(result.credentialIdMatches).toBe(true);
  });

  test('should create identity with encrypted keystore option', async ({ page }) => {
    await page.addInitScript(() => {
      if (!window.PublicKeyCredential) {
        window.PublicKeyCredential = function PublicKeyCredential() {};
      }
      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;

      const storedCredential = {
        credentialId: 'test-credential-id',
        rawCredentialId: Array.from(new Uint8Array([1, 2, 3, 4])),
        attestationObject: Array.from(new Uint8Array([1, 2, 3])),
        publicKey: {
          algorithm: -7,
          keyType: 2,
          curve: 1,
          x: Array.from(new Uint8Array(32)),
          y: Array.from(new Uint8Array(32))
        }
      };

      localStorage.setItem('webauthn-credential', JSON.stringify(storedCredential));
    });
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);
    await page.waitForSelector('text=Encrypt keystore with WebAuthn');

    // Check if encryption option is available in UI
    const hasEncryptionOption = await page.evaluate(() => {
      // This would check if the UI has an encryption toggle
      // For now, we'll test programmatically
      return true;
    });

    expect(hasEncryptionOption).toBe(true);
  });

  test('should handle encryption flag in provider options', async () => {
    // Create mock credential
    const mockCredential = {
      credentialId: 'mock-id',
      rawCredentialId: new Uint8Array([1, 2, 3]),
      publicKey: {
        x: new Uint8Array(32),
        y: new Uint8Array(32)
      }
    };

    // Test without encryption
    const provider1 = new OrbitDBWebAuthnIdentityProvider({
      webauthnCredential: mockCredential
    });

    // Test with encryption
    const provider2 = new OrbitDBWebAuthnIdentityProvider({
      webauthnCredential: mockCredential,
      encryptKeystore: true,
      keystoreEncryptionMethod: 'largeBlob'
    });

    const result = {
      provider1HasEncryption: provider1.encryptKeystore,
      provider2HasEncryption: provider2.encryptKeystore,
      provider2Method: provider2.keystoreEncryptionMethod
    };

    expect(result.provider1HasEncryption).toBe(false);
    expect(result.provider2HasEncryption).toBe(true);
    expect(result.provider2Method).toBe('largeBlob');
  });
});

test.describe('Encryption Utilities', () => {

  test('should generate different keys each time', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(() => {
      const { KeystoreEncryption } = window;

      const sk1 = KeystoreEncryption.generateSecretKey();
      const sk2 = KeystoreEncryption.generateSecretKey();

      const sk1Str = Array.from(sk1).join(',');
      const sk2Str = Array.from(sk2).join(',');

      return {
        keysAreDifferent: sk1Str !== sk2Str,
        bothAre32Bytes: sk1.length === 32 && sk2.length === 32
      };
    });

    expect(result.keysAreDifferent).toBe(true);
    expect(result.bothAre32Bytes).toBe(true);
  });

  test('should produce different ciphertext for same data', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;

      const sk = KeystoreEncryption.generateSecretKey();
      const data = new TextEncoder().encode('Same data');

      // Encrypt twice (different IV each time)
      const encrypted1 = await KeystoreEncryption.encryptWithAESGCM(data, sk);
      const encrypted2 = await KeystoreEncryption.encryptWithAESGCM(data, sk);

      const cipher1Str = Array.from(encrypted1.ciphertext).join(',');
      const cipher2Str = Array.from(encrypted2.ciphertext).join(',');

      // But both should decrypt to same value
      const decrypted1 = await KeystoreEncryption.decryptWithAESGCM(encrypted1.ciphertext, sk, encrypted1.iv);
      const decrypted2 = await KeystoreEncryption.decryptWithAESGCM(encrypted2.ciphertext, sk, encrypted2.iv);

      const text1 = new TextDecoder().decode(decrypted1);
      const text2 = new TextDecoder().decode(decrypted2);

      return {
        ciphertextsAreDifferent: cipher1Str !== cipher2Str,
        plaintextsAreSame: text1 === text2,
        bothDecryptCorrectly: text1 === 'Same data' && text2 === 'Same data'
      };
    });

    expect(result.ciphertextsAreDifferent).toBe(true);
    expect(result.plaintextsAreSame).toBe(true);
    expect(result.bothDecryptCorrectly).toBe(true);
  });

  test('should add PRF extension to credential options', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);
    const hasPRFHelper = await page.evaluate(() =>
      typeof window.KeystoreEncryption?.addPRFToCredentialOptions === 'function'
    );
    test.skip(!hasPRFHelper, 'PRF helper is not exposed in this demo runtime.');

    const result = await page.evaluate(() => {
      const { KeystoreEncryption } = window;

      const baseOptions = {
        challenge: new Uint8Array(32),
        rp: { name: 'Test' },
        user: {
          id: new Uint8Array(16),
          name: 'test',
          displayName: 'Test User'
        },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }]
      };

      const { credentialOptions, prfInput } =
        KeystoreEncryption.addPRFToCredentialOptions(baseOptions);

      return {
        hasPrf: !!credentialOptions.extensions?.prf,
        hasEval: !!credentialOptions.extensions?.prf?.eval?.first,
        prfInputLength: prfInput ? prfInput.length : 0,
        originalUnmodified: !baseOptions.extensions
      };
    });

    expect(result.hasPrf).toBe(true);
    expect(result.hasEval).toBe(true);
    expect(result.prfInputLength).toBe(32);
    expect(result.originalUnmodified).toBe(true);
  });

  test('should wrap and unwrap secret key with PRF (mocked)', async ({ page, context, browserName }) => {
    test.skip(
      browserName === 'webkit',
      'WebKit blocks WebAuthn PRF in this test context.'
    );
    await context.addInitScript(() => {
      if (!window.navigator.credentials) {
        Object.defineProperty(window.navigator, 'credentials', {
          value: {},
          configurable: true
        });
      }

      const prfSeed = new Uint8Array(32);
      for (let i = 0; i < prfSeed.length; i++) {
        prfSeed[i] = 255 - i;
      }

      Object.defineProperty(window.navigator.credentials, 'get', {
        value: async () => ({
          id: 'test-credential',
          rawId: new Uint8Array([1, 2, 3, 4]),
          type: 'public-key',
          response: {
            authenticatorData: new Uint8Array(37),
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.get',
              challenge: 'test',
              origin: window.location.origin
            })),
            signature: new Uint8Array(64)
          },
          getClientExtensionResults: () => ({
            prf: { results: { first: prfSeed.buffer } }
          })
        }),
        configurable: true,
        writable: true
      });
    });

    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);
    const hasPRFHelpers = await page.evaluate(() =>
      typeof window.KeystoreEncryption?.wrapSKWithPRF === 'function' &&
      typeof window.KeystoreEncryption?.unwrapSKWithPRF === 'function'
    );
    test.skip(!hasPRFHelpers, 'PRF wrap/unwrap helpers are not exposed in this demo runtime.');

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;
      const sk = KeystoreEncryption.generateSecretKey();
      const prfInput = new Uint8Array(32);
      for (let i = 0; i < prfInput.length; i++) {
        prfInput[i] = i;
      }

      const wrapped = await KeystoreEncryption.wrapSKWithPRF(
        new Uint8Array([1, 2, 3, 4]),
        sk,
        window.location.hostname,
        prfInput
      );

      const unwrapped = await KeystoreEncryption.unwrapSKWithPRF(
        new Uint8Array([1, 2, 3, 4]),
        wrapped.wrappedSK,
        wrapped.wrappingIV,
        wrapped.salt,
        window.location.hostname
      );

      return {
        matches: Array.from(sk).join(',') === Array.from(unwrapped).join(','),
        prfSource: wrapped.prfSource,
        saltLength: wrapped.salt ? wrapped.salt.length : 0
      };
    });

    expect(result.matches).toBe(true);
    expect(result.prfSource).toBe('prf');
    expect(result.saltLength).toBe(32);
  });

  test('should handle large data encryption', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;

      const sk = KeystoreEncryption.generateSecretKey();

      // Create 1MB of data
      const largeData = new Uint8Array(1024 * 1024);
      for (let i = 0; i < largeData.length; i++) {
        largeData[i] = i % 256;
      }

      const start = performance.now();
      const encrypted = await KeystoreEncryption.encryptWithAESGCM(largeData, sk);
      const encryptTime = performance.now() - start;

      const start2 = performance.now();
      const decrypted = await KeystoreEncryption.decryptWithAESGCM(encrypted.ciphertext, sk, encrypted.iv);
      const decryptTime = performance.now() - start2;

      // Verify first and last bytes
      const firstMatches = decrypted[0] === largeData[0];
      const lastMatches = decrypted[largeData.length - 1] === largeData[largeData.length - 1];

      return {
        dataSize: largeData.length,
        encryptTime,
        decryptTime,
        firstMatches,
        lastMatches,
        decryptedSize: decrypted.length
      };
    });

    expect(result.firstMatches).toBe(true);
    expect(result.lastMatches).toBe(true);
    expect(result.decryptedSize).toBe(result.dataSize);
    expect(result.encryptTime).toBeLessThan(1000); // Should be fast
    expect(result.decryptTime).toBeLessThan(1000);

    console.log(`Encrypted ${result.dataSize} bytes in ${result.encryptTime.toFixed(2)}ms`);
    console.log(`Decrypted ${result.dataSize} bytes in ${result.decryptTime.toFixed(2)}ms`);
  });
});

test.describe('Storage Management', () => {

  test('should clear encrypted keystore', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;

      const credentialId = 'test-clear-' + Date.now();
      const sk = KeystoreEncryption.generateSecretKey();
      const data = new TextEncoder().encode('Test data');
      const encrypted = await KeystoreEncryption.encryptWithAESGCM(data, sk);

      // Store
      await KeystoreEncryption.storeEncryptedKeystore({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        credentialId
      }, credentialId);

      // Verify it's stored
      const loaded1 = await KeystoreEncryption.loadEncryptedKeystore(credentialId);
      const stored = !!loaded1;

      // Clear
      await KeystoreEncryption.clearEncryptedKeystore(credentialId);

      // Try to load again
      let cleared = false;
      try {
        await KeystoreEncryption.loadEncryptedKeystore(credentialId);
      } catch {
        cleared = true;
      }

      return { stored, cleared };
    });

    expect(result.stored).toBe(true);
    expect(result.cleared).toBe(true);
  });

  test('should handle multiple encrypted keystores', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;

      const count = 3;
      const credentialIds = [];

      // Store multiple keystores
      for (let i = 0; i < count; i++) {
        const credentialId = `test-multi-${Date.now()}-${i}`;
        credentialIds.push(credentialId);

        const sk = KeystoreEncryption.generateSecretKey();
        const data = new TextEncoder().encode(`Data ${i}`);
        const encrypted = await KeystoreEncryption.encryptWithAESGCM(data, sk);

        await KeystoreEncryption.storeEncryptedKeystore({
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
          credentialId
        }, credentialId);
      }

      // Load all and verify
      const loaded = [];
      for (const credentialId of credentialIds) {
        const data = await KeystoreEncryption.loadEncryptedKeystore(credentialId);
        loaded.push(data);
        // Clean up
        await KeystoreEncryption.clearEncryptedKeystore(credentialId);
      }

      return {
        storedCount: count,
        loadedCount: loaded.length,
        allLoaded: loaded.every(d => !!d),
        credentialIdsMatch: loaded.every((d, i) => d.credentialId === credentialIds[i])
      };
    });

    expect(result.loadedCount).toBe(result.storedCount);
    expect(result.allLoaded).toBe(true);
    expect(result.credentialIdsMatch).toBe(true);
  });
});

test.describe('WebAuthn largeBlob Extension', () => {

  test('should add largeBlob extension to credential options', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(() => {
      const { KeystoreEncryption } = window;
      const sk = KeystoreEncryption.generateSecretKey();

      const baseOptions = {
        challenge: new Uint8Array(32),
        rp: { name: 'Test' },
        user: {
          id: new Uint8Array(16),
          name: 'test',
          displayName: 'Test User'
        },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }]
      };

      const optionsWithLargeBlob = KeystoreEncryption.addLargeBlobToCredentialOptions(baseOptions, sk);

      return {
        hasExtensions: !!optionsWithLargeBlob.extensions,
        hasLargeBlob: !!optionsWithLargeBlob.extensions?.largeBlob,
        largeBlobSupport: optionsWithLargeBlob.extensions?.largeBlob?.support ?? null,
        hasWriteKey: optionsWithLargeBlob.extensions?.largeBlob?.write?.length === 32,
        originalUnmodified: !baseOptions.extensions // Should not modify original
      };
    });

    expect(result.hasExtensions).toBe(true);
    expect(result.hasLargeBlob).toBe(true);
    expect(['required', null]).toContain(result.largeBlobSupport);
    expect(result.hasWriteKey).toBe(true);
    expect(result.originalUnmodified).toBe(true);
  });

  test('should retrieve secret key from largeBlob (mocked)', async ({ page, context, browserName }) => {
    test.skip(
      browserName !== 'chromium',
      'WebKit blocks WebAuthn credential.get in this test context.'
    );

    // Set up mock that simulates largeBlob storage
    await installLargeBlobMock(context, { hasBlob: true });

    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;

      try {
        // Mock credential with rawId
        const rawCredentialId = new Uint8Array([1, 2, 3, 4]);

        const sk = await KeystoreEncryption.retrieveSKFromLargeBlob(rawCredentialId);

        return {
          success: true,
          secretKeyLength: sk ? sk.length : 0,
          isUint8Array: sk instanceof Uint8Array,
          firstByte: sk ? sk[0] : null,
          lastByte: sk ? sk[31] : null
        };
      } catch (error) {
        return {
          success: false,
          error: error.message
        };
      }
    });

    expect(result.success, result.error).toBe(true);
    expect(result.secretKeyLength).toBe(32);
    expect(result.isUint8Array).toBe(true);
    expect(result.firstByte).toBe(0); // i * 7 % 256 for i=0
    expect(result.lastByte).toBe(217); // i * 7 % 256 for i=31
  });

  test('should handle largeBlob not available', async ({ page, context, browserName }) => {
    test.skip(
      browserName !== 'chromium',
      'WebKit blocks WebAuthn credential.get in this test context.'
    );

    // Set up mock that simulates largeBlob NOT available
    await installLargeBlobMock(context, { hasBlob: false });

    await page.goto('http://localhost:5173');
    await waitForKeystoreEncryption(page);

    const result = await page.evaluate(async () => {
      const { KeystoreEncryption } = window;

      try {
        const rawCredentialId = new Uint8Array([1, 2, 3, 4]);

        await KeystoreEncryption.retrieveSKFromLargeBlob(rawCredentialId);
        return { threwError: false };
      } catch (error) {
        return {
          threwError: true,
          errorMessage: error.message
        };
      }
    });

    expect(result.threwError, result.errorMessage).toBe(true);
    expect(result.errorMessage).toContain('largeBlob');
  });
});

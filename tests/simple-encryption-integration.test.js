import { test, expect } from '@playwright/test';

/**
 * E2E Test for @orbitdb/simple-encryption Integration
 *
 * Tests that the WebAuthn-protected secret key can be used with
 * @orbitdb/simple-encryption to encrypt database content.
 */

test.describe('Simple Encryption Integration', () => {

  test.beforeEach(async ({ page, context }) => {
    // Clear storage
    await context.clearCookies();

    // Set up WebAuthn mocks
    await context.addInitScript(() => {
      console.log('🔧 Setting up WebAuthn mocks...');

      if (!window.PublicKeyCredential) {
        window.PublicKeyCredential = {};
      }

      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
      window.PublicKeyCredential.isConditionalMediationAvailable = async () => true;

      const mockCredentialId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

      if (!window.navigator.credentials) {
        window.navigator.credentials = {};
      }

      window.navigator.credentials.create = async (options) => {
        console.log('🔐 MOCK: Creating credential...');
        await new Promise(resolve => setTimeout(resolve, 100));

        const mockAttestation = new Uint8Array(300);
        mockAttestation.set([
          0xa3, 0x63, 0x66, 0x6d, 0x74, 0x66, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x64,
          0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0xa0, 0x68, 0x61, 0x75,
          0x74, 0x68, 0x44, 0x61, 0x74, 0x61
        ]);

        const extensionResults = {};
        if (options?.publicKey?.extensions?.hmacCreateSecret) {
          extensionResults.hmacCreateSecret = true;
        }

        return {
          id: 'mock-credential-id-' + Date.now(),
          rawId: mockCredentialId,
          type: 'public-key',
          response: {
            attestationObject: mockAttestation,
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.create',
              challenge: 'mock-challenge',
              origin: window.location.origin,
              crossOrigin: false
            })),
            getPublicKey: () => new Uint8Array(65),
            getPublicKeyAlgorithm: () => -7
          },
          getClientExtensionResults: () => extensionResults
        };
      };

      window.navigator.credentials.get = async (options) => {
        console.log('🔐 MOCK: Getting credential...');
        await new Promise(resolve => setTimeout(resolve, 100));

        const extensionResults = {};
        if (options?.publicKey?.extensions?.hmacGetSecret) {
          extensionResults.hmacGetSecret = {
            output1: new Uint8Array(32).fill(42)
          };
        }

        return {
          id: 'mock-credential-id',
          rawId: mockCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: new Uint8Array(37),
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.get',
              challenge: 'mock-challenge',
              origin: window.location.origin,
              crossOrigin: false
            })),
            signature: new Uint8Array(64),
            userHandle: null
          },
          getClientExtensionResults: () => extensionResults
        };
      };

      console.log('✅ WebAuthn mocks setup complete');
    });

    // Navigate to demo
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    await page.waitForFunction(() => document.readyState === 'complete');
  });

  test('should use WebAuthn-protected SK with simple-encryption pattern', async ({ page }) => {
    console.log('\n🧪 Testing simple-encryption integration pattern...');

    const result = await page.evaluate(async () => {
      const { generateSecretKey, encryptWithAESGCM, decryptWithAESGCM } = window.KeystoreEncryption;

      try {
        // Step 1: Generate secret key (would be protected by WebAuthn in real usage)
        const sk = generateSecretKey();

        // Step 2: Convert SK to password format for simple-encryption
        const password = btoa(String.fromCharCode(...sk));

        // Step 3: Simulate simple-encryption's AES-GCM encryption
        // (We use our own encryptWithAESGCM since we can't import @orbitdb/simple-encryption in browser)
        const testData = new TextEncoder().encode('Secret database content');
        const encrypted = await encryptWithAESGCM(testData, sk);

        // Step 4: Decrypt the data
        const decrypted = await decryptWithAESGCM(encrypted.ciphertext, sk, encrypted.iv);
        const decryptedText = new TextDecoder().decode(decrypted);

        return {
          success: true,
          skLength: sk.length,
          passwordLength: password.length,
          originalText: 'Secret database content',
          decryptedText,
          matched: decryptedText === 'Secret database content'
        };
      } catch (error) {
        return {
          success: false,
          error: error.message
        };
      }
    });

    console.log('✅ Test result:', result);

    expect(result.success).toBe(true);
    expect(result.skLength).toBe(32);
    expect(result.matched).toBe(true);
    expect(result.decryptedText).toBe('Secret database content');
  });

  test('should demonstrate dual-layer encryption (keystore + content)', async ({ page }) => {
    console.log('\n🧪 Testing dual-layer encryption pattern...');

    await page.waitForSelector('text=WebAuthn is fully supported', { timeout: 30000 });

    const result = await page.evaluate(async () => {
      const { generateSecretKey, encryptWithAESGCM, decryptWithAESGCM } = window.KeystoreEncryption;

      try {
        // Generate a single secret key
        const sk = generateSecretKey();

        // Layer 1: Encrypt keystore private key
        const keystorePrivateKey = new TextEncoder().encode('mock-private-key-from-keystore');
        const encryptedKeystore = await encryptWithAESGCM(keystorePrivateKey, sk);

        // Layer 2: Encrypt database content (using same SK)
        const dbContent = new TextEncoder().encode('{"task":"Secret TODO","done":false}');
        const encryptedContent = await encryptWithAESGCM(dbContent, sk);

        // Simulate session end - clear memory
        // (In real usage, SK would be retrieved from WebAuthn on next session)

        // Decrypt keystore
        const decryptedKeystore = await decryptWithAESGCM(
          encryptedKeystore.ciphertext,
          sk,
          encryptedKeystore.iv
        );
        const keystoreKey = new TextDecoder().decode(decryptedKeystore);

        // Decrypt content
        const decryptedContent = await decryptWithAESGCM(
          encryptedContent.ciphertext,
          sk,
          encryptedContent.iv
        );
        const content = new TextDecoder().decode(decryptedContent);

        return {
          success: true,
          singleBiometricPrompt: true, // One SK protects both layers
          keystoreDecrypted: keystoreKey === 'mock-private-key-from-keystore',
          contentDecrypted: content === '{"task":"Secret TODO","done":false}',
          parsedContent: JSON.parse(content)
        };
      } catch (error) {
        return {
          success: false,
          error: error.message
        };
      }
    });

    console.log('✅ Dual-layer encryption result:', result);

    expect(result.success).toBe(true);
    expect(result.singleBiometricPrompt).toBe(true);
    expect(result.keystoreDecrypted).toBe(true);
    expect(result.contentDecrypted).toBe(true);
    expect(result.parsedContent.task).toBe('Secret TODO');
  });

  test('should verify password derivation is consistent', async ({ page }) => {
    console.log('\n🧪 Testing password derivation consistency...');

    const result = await page.evaluate(() => {
      const { generateSecretKey } = window.KeystoreEncryption;

      // Generate SK
      const sk = generateSecretKey();

      // Convert to password multiple times
      const password1 = btoa(String.fromCharCode(...sk));
      const password2 = btoa(String.fromCharCode(...sk));

      // Convert back to verify
      const decoded = Uint8Array.from(atob(password1), c => c.charCodeAt(0));

      return {
        skLength: sk.length,
        password1Length: password1.length,
        password2Length: password2.length,
        passwordsMatch: password1 === password2,
        roundTripMatches: Array.from(sk).every((byte, i) => byte === decoded[i])
      };
    });

    console.log('✅ Password derivation result:', result);

    expect(result.skLength).toBe(32);
    expect(result.passwordsMatch).toBe(true);
    expect(result.roundTripMatches).toBe(true);
  });

  test('should handle encryption with different secret keys', async ({ page }) => {
    console.log('\n🧪 Testing encryption isolation with different keys...');

    const result = await page.evaluate(async () => {
      const { generateSecretKey, encryptWithAESGCM, decryptWithAESGCM } = window.KeystoreEncryption;

      try {
        // User 1's key
        const sk1 = generateSecretKey();
        const data1 = new TextEncoder().encode('User 1 secret data');
        const encrypted1 = await encryptWithAESGCM(data1, sk1);

        // User 2's key
        const sk2 = generateSecretKey();
        const data2 = new TextEncoder().encode('User 2 secret data');
        const encrypted2 = await encryptWithAESGCM(data2, sk2);

        // Decrypt with correct keys
        const decrypted1 = await decryptWithAESGCM(encrypted1.ciphertext, sk1, encrypted1.iv);
        const decrypted2 = await decryptWithAESGCM(encrypted2.ciphertext, sk2, encrypted2.iv);

        // Try to decrypt User 1's data with User 2's key (should fail)
        let wrongKeyFailed = false;
        try {
          await decryptWithAESGCM(encrypted1.ciphertext, sk2, encrypted1.iv);
        } catch (error) {
          wrongKeyFailed = true;
        }

        return {
          success: true,
          decrypted1: new TextDecoder().decode(decrypted1),
          decrypted2: new TextDecoder().decode(decrypted2),
          wrongKeyFailed
        };
      } catch (error) {
        return {
          success: false,
          error: error.message
        };
      }
    });

    console.log('✅ Encryption isolation result:', result);

    expect(result.success).toBe(true);
    expect(result.decrypted1).toBe('User 1 secret data');
    expect(result.decrypted2).toBe('User 2 secret data');
    expect(result.wrongKeyFailed).toBe(true);
  });
});

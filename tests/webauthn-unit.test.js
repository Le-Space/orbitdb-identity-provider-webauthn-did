import { test, expect } from '@playwright/test';

test.describe('WebAuthn DID Provider Unit Tests', () => {
  test.beforeEach(async ({ page, context }) => {
    // Mock WebAuthn API
    await context.addInitScript(() => {
      window.PublicKeyCredential = class PublicKeyCredentialMock {
        static async isUserVerifyingPlatformAuthenticatorAvailable() {
          return true;
        }
      };

      const mockCredentialId = crypto.getRandomValues(new Uint8Array(16));
      const mockPublicKey = {
        x: crypto.getRandomValues(new Uint8Array(32)),
        y: crypto.getRandomValues(new Uint8Array(32))
      };

      const mockCredentials = {
        create: async (options) => ({
          rawId: mockCredentialId,
          response: {
            attestationObject: crypto.getRandomValues(new Uint8Array(300)),
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.create',
              challenge: Array.from(new Uint8Array(options.publicKey.challenge)).map(b => String.fromCharCode(b)).join(''),
              origin: window.location.origin
            }))
          }
        }),

        get: async (options) => ({
          rawId: options.publicKey.allowCredentials[0].id,
          response: {
            authenticatorData: crypto.getRandomValues(new Uint8Array(37)),
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.get',
              challenge: Array.from(new Uint8Array(options.publicKey.challenge)).map(b => String.fromCharCode(b)).join(''),
              origin: window.location.origin
            })),
            signature: crypto.getRandomValues(new Uint8Array(64))
          }
        })
      };

      if (window.navigator.credentials) {
        window.navigator.credentials.create = mockCredentials.create;
        window.navigator.credentials.get = mockCredentials.get;
      } else {
        try {
          Object.defineProperty(window.navigator, 'credentials', {
            configurable: true,
            value: mockCredentials
          });
        } catch {
          Object.defineProperty(Navigator.prototype, 'credentials', {
            configurable: true,
            get() {
              return mockCredentials;
            }
          });
        }
      }

      // Mock CBOR decode function
      window.mockCBORDecode = () => {
        // Simple mock that returns a structure similar to what CBOR would decode
        return {
          authData: new Uint8Array([
            ...crypto.getRandomValues(new Uint8Array(32)), // rpIdHash
            0x01, // flags
            ...new Uint8Array(4), // signCount
            ...crypto.getRandomValues(new Uint8Array(16)), // AAGUID
            0x00, 0x10, // credentialIdLength
            ...mockCredentialId, // credentialId
            // Mock COSE key format
            0xa5, // map(5)
            0x01, 0x02, // kty: 2 (EC2)
            0x03, 0x26, // alg: -7 (ES256)
            0x20, 0x01, // crv: 1 (P-256)
            0x21, 0x58, 0x20, ...mockPublicKey.x, // x coordinate
            0x22, 0x58, 0x20, ...mockPublicKey.y  // y coordinate
          ])
        };
      };
    });

    await page.goto('/');
    const moduleUrl = `/@fs${process.cwd().replace(/\\/g, '/')}/src/index.js`;
    await page.evaluate(async (url) => {
      try {
        const module = await import(url);
        window.WebAuthnModule = module;
        window.moduleLoaded = true;
      } catch (error) {
        window.moduleLoadError = String(error?.stack || error);
        window.moduleLoaded = false;
      }
    }, moduleUrl);
    await page.waitForFunction(() => window.moduleLoaded === true || !!window.moduleLoadError);
    const moduleLoadError = await page.evaluate(() => window.moduleLoadError || null);
    expect(moduleLoadError).toBeNull();
  });

  test('should detect WebAuthn support correctly', async ({ page }) => {
    const isSupported = await page.evaluate(() => {
      return window.WebAuthnModule.WebAuthnDIDProvider.isSupported();
    });

    expect(isSupported).toBe(true);
  });

  test('should check platform authenticator availability', async ({ page }) => {
    const isAvailable = await page.evaluate(async () => {
      return await window.WebAuthnModule.WebAuthnDIDProvider.isPlatformAuthenticatorAvailable();
    });

    expect(isAvailable).toBe(true);
  });

  test('should provide comprehensive WebAuthn support information', async ({ page }) => {
    const support = await page.evaluate(async () => {
      return await window.WebAuthnModule.checkWebAuthnSupport();
    });

    expect(support.supported).toBe(true);
    expect(support.platformAuthenticator).toBe(true);
    expect(typeof support.message).toBe('string');
    expect(support.message).toContain('WebAuthn is fully supported');
  });

  test('should create WebAuthn credential with default options', async ({ page }) => {
    const credential = await page.evaluate(async () => {
      try {
        return await window.WebAuthnModule.WebAuthnDIDProvider.createCredential();
      } catch (error) {
        return { error: error.message };
      }
    });

    expect(credential.error).toBeUndefined();
    expect(credential.credentialId).toBeTruthy();
    expect(credential.rawCredentialId).toBeTruthy();
    expect(credential.publicKey).toBeTruthy();
    expect(credential.userId).toBeTruthy();
    expect(credential.displayName).toBeTruthy();
  });

  test('should create credential with custom options', async ({ page }) => {
    const customOptions = {
      userId: 'test-user-123',
      displayName: 'Test User Custom',
      domain: 'test-domain.com'
    };

    const credential = await page.evaluate(async (options) => {
      try {
        return await window.WebAuthnModule.WebAuthnDIDProvider.createCredential(options);
      } catch (error) {
        return { error: error.message };
      }
    }, customOptions);

    expect(credential.error).toBeUndefined();
    expect(credential.userId).toBe(customOptions.userId);
    expect(credential.displayName).toBe(customOptions.displayName);
  });

  test('should generate deterministic DID from credential', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const credential = await window.WebAuthnModule.WebAuthnDIDProvider.createCredential();

        const did1 = await window.WebAuthnModule.WebAuthnDIDProvider.createDID(credential);
        const did2 = await window.WebAuthnModule.WebAuthnDIDProvider.createDID(credential);

        return {
          did1,
          did2,
          credential: {
            credentialId: credential.credentialId,
            publicKey: {
              x: Array.from(credential.publicKey.x),
              y: Array.from(credential.publicKey.y)
            }
          }
        };
      } catch (error) {
        return { error: error.message };
      }
    });

    expect(result.error).toBeUndefined();
    expect(result.did1).toBeTruthy();
    expect(result.did2).toBeTruthy();
    expect(result.did1).toBe(result.did2); // Should be deterministic
    expect(result.did1).toMatch(/^did:key:z[A-Za-z0-9]+$/);
    expect(result.did1.length).toBeGreaterThan(50); // 'did:key:z' + base58btc encoded multikey
  });

  test('should create WebAuthn provider instance', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const credential = await window.WebAuthnModule.WebAuthnDIDProvider.createCredential({
          userId: 'test-provider',
          displayName: 'Test Provider'
        });

        const provider = new window.WebAuthnModule.WebAuthnDIDProvider(credential);

        return {
          type: provider.type,
          credentialId: provider.credentialId,
          hasPublicKey: !!provider.publicKey,
          hasRawCredentialId: !!provider.rawCredentialId
        };
      } catch (error) {
        return { error: error.message };
      }
    });

    expect(result.error).toBeUndefined();
    expect(result.type).toBe('webauthn');
    expect(result.credentialId).toBeTruthy();
    expect(result.hasPublicKey).toBe(true);
    expect(result.hasRawCredentialId).toBe(true);
  });

  test('should create OrbitDB identity provider', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const credential = await window.WebAuthnModule.WebAuthnDIDProvider.createCredential({
          userId: 'orbitdb-test',
          displayName: 'OrbitDB Test'
        });

        const provider = new window.WebAuthnModule.OrbitDBWebAuthnIdentityProvider({
          webauthnCredential: credential
        });

        const did = await provider.getId();

        return {
          type: provider.type,
          staticType: window.WebAuthnModule.OrbitDBWebAuthnIdentityProvider.type,
          did,
          hasCredential: !!provider.credential,
          hasWebAuthnProvider: !!provider.webauthnProvider
        };
      } catch (error) {
        return { error: error.message };
      }
    });

    expect(result.error).toBeUndefined();
    expect(result.type).toBe('webauthn');
    expect(result.staticType).toBe('webauthn');
    expect(result.did).toMatch(/^did:key:z[A-Za-z0-9]+$/);
    expect(result.hasCredential).toBe(true);
    expect(result.hasWebAuthnProvider).toBe(true);
  });

  test('should sign and verify data', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const credential = await window.WebAuthnModule.WebAuthnDIDProvider.createCredential();
        const provider = new window.WebAuthnModule.WebAuthnDIDProvider(credential);

        const testData = 'Hello, WebAuthn DID!';
        const signature = await provider.sign(testData);

        const isValid = await provider.verify(signature, testData, credential.publicKey);

        return {
          testData,
          signature: signature ? signature.substring(0, 50) + '...' : null, // Truncate for display
          signatureLength: signature ? signature.length : 0,
          isValid,
          hasSignature: !!signature
        };
      } catch (error) {
        return { error: error.message };
      }
    });

    expect(result.error).toBeUndefined();
    expect(result.hasSignature).toBe(true);
    expect(result.signatureLength).toBeGreaterThan(0);
    expect(result.isValid).toBe(true);
  });

  test('should handle array buffer utility functions', async ({ page }) => {
    const result = await page.evaluate(() => {
      try {
        const testData = new Uint8Array([1, 2, 3, 4, 5]);
        const base64url = window.WebAuthnModule.WebAuthnDIDProvider.arrayBufferToBase64url(testData);
        const recovered = new Uint8Array(window.WebAuthnModule.WebAuthnDIDProvider.base64urlToArrayBuffer(base64url));

        return {
          original: Array.from(testData),
          base64url,
          recovered: Array.from(recovered),
          isRoundTrip: testData.every((val, i) => val === recovered[i])
        };
      } catch (error) {
        return { error: error.message };
      }
    });

    expect(result.error).toBeUndefined();
    expect(result.base64url).toBeTruthy();
    expect(result.base64url).not.toContain('+');  // base64url shouldn't have +
    expect(result.base64url).not.toContain('/');  // base64url shouldn't have /
    expect(result.base64url).not.toContain('=');  // base64url shouldn't have =
    expect(result.isRoundTrip).toBe(true);
  });
});

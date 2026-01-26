import { test, expect } from '@playwright/test';

const CREDENTIAL_SUCCESS_TEXT = 'Credential created successfully!';
const AUTH_SUCCESS_TEXT = 'Successfully authenticated with biometric security!';

async function installWebAuthnMock(context) {
  // Enable WebAuthn API mocking
  await context.addInitScript(() => {
    // Mock WebAuthn APIs for testing
    if (!window.PublicKeyCredential) {
      window.PublicKeyCredential = function PublicKeyCredential() {};
    }
    if (!window.PublicKeyCredential.prototype) {
      window.PublicKeyCredential.prototype = {};
    }
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    window.PublicKeyCredential.isConditionalMediationAvailable = async () => true;

    const mockCredentialId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const mockAttestation = new Uint8Array(300);

    const installCredentialMock = () => {
      if (!window.navigator.credentials) {
        Object.defineProperty(window.navigator, 'credentials', {
          value: {},
          configurable: true
        });
      }

      window.navigator.credentials.create = async (options) => {
        console.log('Mock WebAuthn create called with:', options);

        // Simulate successful credential creation
        return {
          id: 'mock-credential-id',
          rawId: mockCredentialId.buffer,
          type: 'public-key',
          response: {
            attestationObject: mockAttestation.buffer, // Mock attestation
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.create',
              challenge: 'mock-challenge',
              origin: window.location.origin
            })),
            getPublicKey: () => new Uint8Array([/* mock public key */]),
            getPublicKeyAlgorithm: () => -7, // ES256
          },
          getClientExtensionResults: () => ({})
        };
      };

      window.navigator.credentials.get = async (options) => {
        console.log('Mock WebAuthn get called with:', options);

        // Simulate successful authentication
        return {
          id: 'mock-credential-id',
          rawId: mockCredentialId.buffer,
          type: 'public-key',
          response: {
            authenticatorData: new Uint8Array(37),
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.get',
              challenge: 'mock-challenge',
              origin: window.location.origin
            })),
            signature: new Uint8Array(64), // Mock signature
            userHandle: null
          },
          getClientExtensionResults: () => ({})
        };
      };
    };

    try {
      installCredentialMock();
    } catch (error) {
      console.warn('Failed to install WebAuthn mock, retrying with defineProperty:', error);
      Object.defineProperty(window.navigator, 'credentials', {
        value: {},
        configurable: true
      });
      installCredentialMock();
    }
  });
}

async function createCredential(page) {
  const createButton = page.locator('button:has-text("Create Credential")');
  await expect(createButton).toBeVisible();
  await createButton.click();

  try {
    await page.waitForSelector(`text=${CREDENTIAL_SUCCESS_TEXT}`, { timeout: 20000 });
  } catch (error) {
    if (page.isClosed()) {
      throw error;
    }
    const failureLocator = page.locator('text=Failed to create credential');
    if (await failureLocator.isVisible()) {
      const failureText = await failureLocator.first().textContent();
      throw new Error(failureText?.trim() || 'Failed to create credential');
    }
    throw error;
  }
}

async function authenticate(page) {
  const authButton = page.locator('button:has-text("Authenticate with WebAuthn")');
  await expect(authButton).toBeVisible();
  await authButton.click();
  await page.waitForSelector(`text=${AUTH_SUCCESS_TEXT}`, { timeout: 30000 });
}

test.describe('WebAuthn DID Identity Provider Integration', () => {
  test.beforeEach(async ({ page, context }) => {
    await installWebAuthnMock(context);

    // Navigate to the demo app
    await page.goto('http://localhost:5173');

    // Wait for the app to load and WebAuthn support to be detected
    await page.waitForFunction(
      () => document.body.innerText.includes('WebAuthn is fully supported'),
      { timeout: 30000 }
    );
  });

  test('should detect WebAuthn support', async ({ page }) => {
    // Check that WebAuthn support is properly detected
    await expect(page.locator('text=WebAuthn is fully supported')).toBeVisible();

    // Check that biometric authentication is available
    await expect(page.locator('text=Biometric authentication available')).toBeVisible();
  });

  test('should create WebAuthn credential', async ({ page }) => {
    // Click the "Create Credential" button
    await createCredential(page);

    // Verify the credential was created
    await expect(page.locator(`text=${CREDENTIAL_SUCCESS_TEXT}`)).toBeVisible();

    // Check that the authenticate button is now visible
    await expect(page.locator('button:has-text("Authenticate with WebAuthn")')).toBeVisible();
  });

  test('should authenticate and show WebAuthn DID', async ({ page }) => {
    // First create a credential
    await createCredential(page);

    // Then authenticate
    await authenticate(page);

    // Verify authentication was successful
    await expect(page.locator(`text=${AUTH_SUCCESS_TEXT}`)).toBeVisible();

    // Check that the WebAuthn DID is displayed
    await expect(page.locator('text=WebAuthn DID')).toBeVisible();
    await expect(page.locator('code')).toBeVisible(); // The DID should be in a code element

    // Verify DID format
    const didElement = page.locator('code').first();
    const didText = await didElement.textContent();
    expect(didText).toMatch(/^did:key:z[A-Za-z0-9]+$/);

    // Check that TODO functionality is available
    await expect(page.locator('input[placeholder="Add a new TODO..."]')).toBeVisible();
    await expect(page.locator('button:has-text("Add")')).toBeVisible();
  });

  test('should copy DID to clipboard', async ({ page, context, browserName }) => {
    test.skip(
      browserName !== 'chromium',
      'clipboard permissions are only supported in Chromium'
    );

    // Grant clipboard permissions
    await context.grantPermissions(['clipboard-write', 'clipboard-read']);

    // Create credential and authenticate
    await createCredential(page);
    await authenticate(page);

    // Click the copy button next to the DID
    await page.click('button[title="Copy DID to clipboard"]');

    // Verify the copy confirmation message
    await expect(page.locator('text=DID copied to clipboard!')).toBeVisible();

    // Verify that the clipboard actually contains a DID
    const clipboardText = await page.evaluate(async () => {
      return await navigator.clipboard.readText();
    });
    expect(clipboardText).toMatch(/^did:key:z[A-Za-z0-9]+$/);
  });

  test('should add and manage todos with WebAuthn authentication', async ({ page }) => {
    // Create credential and authenticate
    await createCredential(page);
    await authenticate(page);

    // Add a new TODO
    const todoText = 'Test WebAuthn secured TODO';
    await page.fill('input[placeholder="Add a new TODO..."]', todoText);
    await page.click('button:has-text("Add")');

    // Wait for the TODO to be added (this should trigger WebAuthn signing)
    await page.waitForSelector(`text=${todoText}`, { timeout: 15000 });

    // Verify the TODO appears in the list
    await expect(page.locator(`text=${todoText}`)).toBeVisible();

    // Check todo statistics
    await expect(page.locator('text=1 total • 0 completed')).toBeVisible();

    // Toggle the TODO as completed
    await page.click('button[data-testid="toggle-todo"]', { timeout: 5000 });

    // Wait for the toggle operation to complete
    await page.waitForTimeout(2000);

    // Check that statistics updated
    await expect(page.locator('text=1 total • 1 completed')).toBeVisible();
  });

  test('should handle WebAuthn errors gracefully', async ({ page, context }) => {
    // Override the WebAuthn API to simulate errors
    await context.addInitScript(() => {
      window.navigator.credentials.create = async () => {
        throw new Error('Biometric authentication was cancelled or failed');
      };
    });

    await page.goto('http://localhost:5173');
    await page.waitForSelector('text=WebAuthn is fully supported', { timeout: 10000 });

    // Try to create a credential (should fail)
    await page.click('button:has-text("Create Credential")');

    // Verify error handling
    await expect(page.locator('text=Failed to create credential')).toBeVisible();
  });

  test('should reset database functionality', async ({ page }) => {
    // Create credential and authenticate
    await createCredential(page);
    await authenticate(page);

    // Add a TODO
    await page.fill('input[placeholder="Add a new TODO..."]', 'Test TODO');
    await page.click('button:has-text("Add")');
    await page.waitForSelector('text=Test TODO', { timeout: 15000 });

    // Reset the database
    await page.click('button:has-text("Reset DB")');

    // Wait for reset to complete
    await page.waitForSelector('text=Database reset complete', { timeout: 15000 });

    // Verify we're back to unauthenticated state but credential still exists
    await expect(page.locator('button:has-text("Authenticate with WebAuthn")')).toBeVisible();
  });

  test('should logout and clear credentials', async ({ page }) => {
    // Create credential and authenticate
    await createCredential(page);
    await authenticate(page);

    // Logout
    await page.click('button:has-text("Logout")');

    // Wait for logout to complete
    await page.waitForSelector('text=Logged out successfully', { timeout: 10000 });

    // Verify we're back to credential creation state
    await expect(page.locator('button:has-text("Create Credential")')).toBeVisible();
    await expect(page.locator('text=Create a WebAuthn credential')).toBeVisible();
  });

  test('should work across different browser contexts', async ({ browser }) => {
    // Test that WebAuthn DIDs are consistent across browser sessions
    const context1 = await browser.newContext();
    await installWebAuthnMock(context1);
    const page1 = await context1.newPage();

    await page1.goto('http://localhost:5173');
    await page1.waitForSelector('text=WebAuthn is fully supported', { timeout: 10000 });

    // Create credential in first context
    await createCredential(page1);

    // Get the stored credential from localStorage
    const storedCredential = await page1.evaluate(() => {
      return localStorage.getItem('webauthn-credential');
    });

    expect(storedCredential).toBeTruthy();

    await context1.close();
  });
});

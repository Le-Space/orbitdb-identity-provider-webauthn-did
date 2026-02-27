import { test, expect } from '@playwright/test';

test.describe('WebAuthn Credential Creation Test', () => {
  test.beforeEach(async ({ page, context }) => {
    // Enhanced WebAuthn mocking
    await context.addInitScript(() => {
      console.log('🔧 Setting up WebAuthn mocks...');

      // Ensure PublicKeyCredential exists
      if (!window.PublicKeyCredential) {
        window.PublicKeyCredential = {};
      }

      // Mock the support detection methods
      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable =
        async () => {
          console.log('🔍 Mock: Platform authenticator available');
          return true;
        };

      window.PublicKeyCredential.isConditionalMediationAvailable = async () => {
        console.log('🔍 Mock: Conditional mediation available');
        return true;
      };

      // Create a consistent mock credential ID
      const mockCredentialId = new Uint8Array([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      ]);

      // Mock navigator.credentials
      if (!window.navigator.credentials) {
        window.navigator.credentials = {};
      }

      window.navigator.credentials.create = async (options) => {
        console.log(
          '🔐 Mock: Creating WebAuthn credential with options:',
          options
        );

        // Simulate slight delay like real WebAuthn
        await new Promise((resolve) => setTimeout(resolve, 100));

        // Create a realistic mock attestation object (300 bytes)
        const mockAttestation = new Uint8Array(300);
        // Fill with some realistic-looking data
        mockAttestation.set([
          // CBOR map indicator and some mock data
          0xa3, 0x63, 0x66, 0x6d, 0x74, 0x66, 0x70, 0x61, 0x63, 0x6b, 0x65,
          0x64, 0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0xa0, 0x68,
          0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61,
        ]);

        const mockCredential = {
          id: 'mock-credential-id-' + Date.now(),
          rawId: mockCredentialId,
          type: 'public-key',
          response: {
            attestationObject: mockAttestation,
            clientDataJSON: new TextEncoder().encode(
              JSON.stringify({
                type: 'webauthn.create',
                challenge: 'mock-challenge',
                origin: window.location.origin,
                crossOrigin: false,
              })
            ),
            getPublicKey: () => {
              console.log('🔑 Mock: Getting public key');
              return new Uint8Array(65); // Mock P-256 public key
            },
            getPublicKeyAlgorithm: () => -7, // ES256
          },
          getClientExtensionResults: () => ({}),
        };

        console.log('✅ Mock: WebAuthn credential created successfully');
        return mockCredential;
      };

      window.navigator.credentials.get = async (options) => {
        console.log(
          '🔐 Mock: Getting WebAuthn credential with options:',
          options
        );

        // Simulate slight delay
        await new Promise((resolve) => setTimeout(resolve, 100));

        const mockAssertion = {
          id: 'mock-credential-id',
          rawId: mockCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: new Uint8Array(37), // Standard length
            clientDataJSON: new TextEncoder().encode(
              JSON.stringify({
                type: 'webauthn.get',
                challenge: 'mock-challenge',
                origin: window.location.origin,
                crossOrigin: false,
              })
            ),
            signature: new Uint8Array(64), // Mock signature
            userHandle: null,
          },
          getClientExtensionResults: () => ({}),
        };

        console.log('✅ Mock: WebAuthn assertion created successfully');
        return mockAssertion;
      };

      // Also ensure other required globals exist
      if (!window.TextEncoder) {
        window.TextEncoder = TextEncoder;
      }
      if (!window.TextDecoder) {
        window.TextDecoder = TextDecoder;
      }

      console.log('✅ WebAuthn mocks setup complete');
    });

    // Navigate to the demo
    console.log('🌐 Navigating to demo app...');
    await page.goto('http://localhost:5173');

    // Wait for basic page load
    await page.waitForLoadState('networkidle');

    // Wait for the WebAuthn support check to complete
    await page.waitForFunction(() => {
      return document.readyState === 'complete';
    });

    console.log('✅ Demo app loaded');
  });

  test('should create WebAuthn credential', async ({ page }) => {
    console.log('🧪 Starting credential creation test...');

    // Wait for the app to detect WebAuthn support
    console.log('⏳ Waiting for WebAuthn support detection...');
    await page.waitForSelector('text=WebAuthn is fully supported', {
      timeout: 30000,
    });
    console.log('✅ WebAuthn support detected');

    // Take a screenshot for debugging
    await page.screenshot({ path: 'test-before-click.png', fullPage: true });

    // Check if the "Create Credential" button is visible
    const createButton = page.locator('button:has-text("Create Credential")');
    await expect(createButton).toBeVisible();
    console.log('✅ Create Credential button is visible');

    // Add some console monitoring
    page.on('console', (msg) => {
      if (msg.type() === 'log' || msg.type() === 'error') {
        console.log(`🌐 Browser console [${msg.type()}]:`, msg.text());
      }
    });

    // Click the "Create Credential" button
    console.log('👆 Clicking Create Credential button...');
    await createButton.click();

    // Take another screenshot after clicking
    await page.screenshot({ path: 'test-after-click.png', fullPage: true });

    // Wait for the loading state first
    console.log('⏳ Waiting for credential creation process...');

    // Look for either success or error message
    try {
      // Try to wait for success message
      await page.waitForSelector('text=Credential created successfully!', {
        timeout: 30000,
      });
      console.log('✅ Credential creation successful!');

      // Verify the credential was created
      await expect(
        page.locator('text=Credential created successfully!')
      ).toBeVisible();

      // Check that the authenticate button appears
      await expect(
        page.locator('button:has-text("Authenticate with WebAuthn")')
      ).toBeVisible();
      console.log('✅ Authenticate button appeared');
    } catch (error) {
      console.log(
        '❌ Waiting for success message failed, checking for error messages...'
      );

      // Take a screenshot on error
      await page.screenshot({ path: 'test-error.png', fullPage: true });

      // Check for any error messages
      const errorSelectors = [
        'text=Failed to create credential',
        'text=WebAuthn error',
        'text=Error:',
        'text=Biometric authentication was cancelled',
        'text=WebAuthn is not supported',
      ];

      for (const selector of errorSelectors) {
        if (await page.locator(selector).isVisible()) {
          console.log(`❌ Found error message: ${selector}`);
          const errorText = await page.locator(selector).textContent();
          console.log(`❌ Error text: ${errorText}`);
        }
      }

      // Get the current page content for debugging
      const currentUrl = page.url();
      const pageTitle = await page.title();
      console.log(`📍 Current URL: ${currentUrl}`);
      console.log(`📄 Page title: ${pageTitle}`);

      // Get any visible text in the status area
      const statusElements = await page
        .locator(
          '[class*="status"], [class*="notification"], [class*="message"]'
        )
        .all();
      for (const element of statusElements) {
        const text = await element.textContent();
        if (text && text.trim()) {
          console.log(`📊 Status element: ${text.trim()}`);
        }
      }

      throw error;
    }

    console.log('🎉 Test completed successfully!');
  });

  test('should show WebAuthn support detection', async ({ page }) => {
    console.log('🧪 Testing WebAuthn support detection...');

    // This should be visible after the mocks are set up
    await expect(page.locator('text=WebAuthn is fully supported')).toBeVisible({
      timeout: 30000,
    });
    await expect(
      page.locator('text=Biometric authentication available')
    ).toBeVisible();

    console.log('✅ WebAuthn support detection working correctly');
  });

  test('should create credential and authenticate', async ({ page }) => {
    console.log(
      '🧪 Starting full credential creation + authentication test...'
    );

    // Wait for WebAuthn support detection
    await page.waitForSelector('text=WebAuthn is fully supported', {
      timeout: 30000,
    });
    console.log('✅ WebAuthn support detected');

    // Create credential first
    const createButton = page.locator('button:has-text("Create Credential")');
    await expect(createButton).toBeVisible();
    await createButton.click();
    console.log('👆 Clicked Create Credential button');

    // Wait for credential creation to complete
    await page.waitForSelector('text=Credential created successfully!', {
      timeout: 30000,
    });
    console.log('✅ Credential created successfully');

    // Now test authentication
    const authButton = page.locator(
      'button:has-text("Authenticate with WebAuthn")'
    );
    await expect(authButton).toBeVisible();
    console.log('✅ Authenticate button is visible');

    // Add console monitoring for authentication
    page.on('console', (msg) => {
      if (msg.type() === 'log' || msg.type() === 'error') {
        console.log(`🌐 Browser console [${msg.type()}]:`, msg.text());
      }
    });

    // Click the authenticate button
    console.log('🔐 Clicking Authenticate with WebAuthn button...');
    await authButton.click();

    // Wait for authentication to complete - look for the TODO app to appear
    try {
      // Wait for the header of the TODO application to appear
      await page.waitForSelector('text=OrbitDB WebAuthn Demo DID', {
        timeout: 15000,
      });
      console.log('✅ Authentication successful - TODO app loaded!');

      // Check for the DID being displayed
      const didElement = page.locator('code:has-text("did:key:")');
      await expect(didElement).toBeVisible();
      const didText = await didElement.textContent();
      console.log(`🆔 DID created: ${didText}`);

      // Check for the TODO input field
      await expect(
        page.locator('input[placeholder="Add a new TODO..."]')
      ).toBeVisible();
      console.log('✅ TODO input field is visible');

      // Check for Add TODO button
      await expect(page.locator('button:has-text("Add")')).toBeVisible();
      console.log('✅ Add TODO button is visible');
    } catch (error) {
      console.log('❌ Authentication failed or timed out');

      // Check for error messages
      const errorSelectors = [
        'text=Authentication failed',
        'text=WebAuthn authentication error',
        'text=Error:',
      ];

      for (const selector of errorSelectors) {
        if (await page.locator(selector).isVisible()) {
          const errorText = await page.locator(selector).textContent();
          console.log(`❌ Error: ${errorText}`);
        }
      }

      throw error;
    }

    console.log('🎉 Full authentication flow completed successfully!');
  });

  test('should persist credential across browser reload and maintain TODO data', async ({
    page,
  }) => {
    console.log('🧪 Starting persistence and TODO operations test...');

    // === PHASE 1: Initial setup and first TODO ===
    console.log('📋 Phase 1: Initial authentication and first TODO');

    // Wait for WebAuthn support detection
    await page.waitForSelector('text=WebAuthn is fully supported', {
      timeout: 30000,
    });
    console.log('✅ WebAuthn support detected');

    // Create credential
    const createButton = page.locator('button:has-text("Create Credential")');
    await expect(createButton).toBeVisible();
    await createButton.click();
    console.log('👆 Clicked Create Credential button');

    // Wait for credential creation
    await page.waitForSelector('text=Credential created successfully!', {
      timeout: 30000,
    });
    console.log('✅ Credential created successfully');

    // Authenticate
    const authButton = page.locator(
      'button:has-text("Authenticate with WebAuthn")'
    );
    await expect(authButton).toBeVisible();
    await authButton.click();
    console.log('🔐 Clicked Authenticate with WebAuthn button');

    // Wait for TODO app to load
    await page.waitForSelector('text=OrbitDB WebAuthn Demo DID', {
      timeout: 15000,
    });
    console.log('✅ Authentication successful - TODO app loaded');

    // Get and store the DID for comparison later
    const didElement = page.locator('code:has-text("did:key:")');
    await expect(didElement).toBeVisible();
    const originalDID = await didElement.textContent();
    console.log(`🆔 Original DID: ${originalDID}`);

    // Add first TODO item
    const todoInput = page.locator('input[placeholder="Add a new TODO..."]');
    const addButton = page.locator('button:has-text("Add")');

    await expect(todoInput).toBeVisible();
    await expect(addButton).toBeVisible();

    const firstTodo = 'Test TODO #1 - Before Reload';
    await todoInput.fill(firstTodo);
    console.log(`📝 Entered first TODO: "${firstTodo}"`);

    // Add console monitoring for TODO operations
    page.on('console', (msg) => {
      if (
        msg.type() === 'log' &&
        (msg.text().includes('TODO') || msg.text().includes('Database'))
      ) {
        console.log(`🌐 Browser console [${msg.type()}]:`, msg.text());
      }
    });

    await addButton.click();
    console.log('👆 Clicked Add TODO button');

    // Wait for the TODO to appear in the list
    await page.waitForSelector(`text=${firstTodo}`, { timeout: 10000 });
    console.log('✅ First TODO added and visible in list');

    // Verify TODO count
    await expect(page.locator('text=1 total • 0 completed')).toBeVisible();
    console.log('✅ TODO statistics show 1 total, 0 completed');

    // === PHASE 2: Browser reload and persistence test ===
    console.log('🔄 Phase 2: Browser reload and persistence test');

    // Reload the page
    console.log('🔄 Reloading the browser page...');
    await page.reload({ waitUntil: 'networkidle' });

    // Wait for page to fully load after reload
    await page.waitForFunction(() => document.readyState === 'complete');
    console.log('✅ Page reloaded successfully');

    // Should see the credential exists (not showing create credential button)
    await page.waitForSelector(
      'text=Use your biometric authentication to access your secure TODO list.',
      { timeout: 15000 }
    );
    console.log(
      '✅ Credential persistence detected - no create credential button shown'
    );

    // Authenticate again with the persisted credential
    const authButtonReload = page.locator(
      'button:has-text("Authenticate with WebAuthn")'
    );
    await expect(authButtonReload).toBeVisible();
    await authButtonReload.click();
    console.log('🔐 Clicked Authenticate button after reload');

    // Wait for TODO app to load again
    await page.waitForSelector('text=OrbitDB WebAuthn Demo DID', {
      timeout: 15000,
    });
    console.log('✅ Re-authentication successful - TODO app loaded again');

    // Verify same DID is used
    const reloadDidElement = page.locator('code:has-text("did:key:")');
    await expect(reloadDidElement).toBeVisible();
    const reloadDID = await reloadDidElement.textContent();
    console.log(`🆔 Reloaded DID: ${reloadDID}`);

    if (originalDID === reloadDID) {
      console.log('✅ DID persistence confirmed - same identity used');
    } else {
      console.log('❌ DID mismatch - different identity after reload');
      throw new Error(
        `DID mismatch: original=${originalDID}, reload=${reloadDID}`
      );
    }

    // === PHASE 3: Data persistence verification ===
    console.log('📊 Phase 3: Data persistence verification');

    // Wait for database to load
    await page.waitForTimeout(2000); // Give OrbitDB time to sync

    // Check if the first TODO is still there
    await expect(page.locator(`text=${firstTodo}`)).toBeVisible();
    console.log('✅ First TODO persisted across reload');

    // Verify TODO count is still correct
    await expect(page.locator('text=1 total • 0 completed')).toBeVisible();
    console.log('✅ TODO statistics persisted correctly');

    // === PHASE 4: Add second TODO to confirm functionality ===
    console.log('➕ Phase 4: Adding second TODO to confirm functionality');

    const todoInputReload = page.locator(
      'input[placeholder="Add a new TODO..."]'
    );
    const addButtonReload = page.locator('button:has-text("Add")');

    const secondTodo = 'Test TODO #2 - After Reload';
    await todoInputReload.fill(secondTodo);
    console.log(`📝 Entered second TODO: "${secondTodo}"`);

    await addButtonReload.click();
    console.log('👆 Clicked Add TODO button for second item');

    // Wait for the second TODO to appear
    await page.waitForSelector(`text=${secondTodo}`, { timeout: 10000 });
    console.log('✅ Second TODO added and visible');

    // Verify both TODOs are visible
    await expect(page.locator(`text=${firstTodo}`)).toBeVisible();
    await expect(page.locator(`text=${secondTodo}`)).toBeVisible();
    console.log('✅ Both TODOs are visible');

    // Verify updated TODO count
    await expect(page.locator('text=2 total • 0 completed')).toBeVisible();
    console.log('✅ TODO statistics updated to 2 total, 0 completed');

    // === PHASE 5: Complete a TODO to test biometric-secured operations ===
    console.log('✅ Phase 5: Testing TODO completion with biometric security');

    // Click the checkbox for the first TODO to complete it
    const firstTodoCheckbox = page
      .locator(`text=${firstTodo}`)
      .locator('..')
      .locator('button')
      .first();
    await firstTodoCheckbox.click();
    console.log('👆 Clicked checkbox to complete first TODO');

    // Wait a moment for the completion to process
    await page.waitForTimeout(1000);

    // Verify the TODO shows as completed (should have strikethrough)
    await expect(page.locator(`text=${firstTodo}`)).toBeVisible();
    console.log('✅ First TODO marked as completed');

    // Verify updated statistics
    await expect(page.locator('text=2 total • 1 completed')).toBeVisible();
    console.log('✅ TODO statistics updated to 2 total, 1 completed');

    console.log('🎉 Complete persistence and TODO operations test passed!');
    console.log('\n📋 Test Summary:');
    console.log('  ✅ WebAuthn credential creation');
    console.log('  ✅ Initial authentication and TODO app access');
    console.log('  ✅ TODO creation and database operations');
    console.log('  ✅ Browser reload with credential persistence');
    console.log('  ✅ Re-authentication with same DID');
    console.log('  ✅ Data persistence across reload');
    console.log('  ✅ Continued TODO operations after reload');
    console.log('  ✅ Biometric-secured TODO completion');
    console.log('  🆔 DID used:', originalDID);
  });
});

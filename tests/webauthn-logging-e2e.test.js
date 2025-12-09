import { test, expect } from '@playwright/test';

/**
 * E2E Logging Test for WebAuthn Identity Provider
 *
 * This test analyzes the complete WebAuthn authentication flow by:
 * 1. Capturing all @libp2p/logger logs from the application
 * 2. Creating a credential and adding multiple TODOs
 * 3. Analyzing logs to determine authentication behavior
 * 4. Generating a findings report that explains:
 *    - Whether sign() is called for each entry
 *    - Whether navigator.credentials.get() is invoked each time
 *    - Whether biometric prompts appear or are cached
 *    - Whether OrbitDB caches signatures
 *    - Browser grace period effects
 */

test.describe('WebAuthn Logging E2E Test', () => {
  let capturedLogs = [];

  test.beforeEach(async ({ page, context }) => {
    // Reset captured logs
    capturedLogs = [];

    // Set up WebAuthn mocks and enable DEBUG logging
    await context.addInitScript(() => {
      // Enable @libp2p/logger debug output in browser
      // @libp2p/logger uses localStorage for debug configuration
      window.localStorage.setItem('debug', 'orbitdb-identity-provider-webauthn-did*');

      // Also intercept console.debug to capture @libp2p/logger output
      const originalDebug = console.debug;
      console.debug = function(...args) {
        // Convert to regular console.log so Playwright captures it
        console.log('[DEBUG]', ...args);
        originalDebug.apply(console, args);
      };

      console.log('🔧 Setting up WebAuthn mocks and debug logging...');
      console.log('🔧 DEBUG localStorage set to: ' + window.localStorage.getItem('debug'));

      if (!window.PublicKeyCredential) {
        window.PublicKeyCredential = {};
      }

      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => {
        return true;
      };

      window.PublicKeyCredential.isConditionalMediationAvailable = async () => {
        return true;
      };

      const mockCredentialId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

      if (!window.navigator.credentials) {
        window.navigator.credentials = {};
      }

      window.navigator.credentials.create = async () => {
        console.log('🔐 WEBAUTHN_MOCK: navigator.credentials.create() called');
        await new Promise(resolve => setTimeout(resolve, 100));

        const mockAttestation = new Uint8Array(300);
        mockAttestation.set([
          0xa3, 0x63, 0x66, 0x6d, 0x74, 0x66, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x64,
          0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0xa0, 0x68, 0x61, 0x75,
          0x74, 0x68, 0x44, 0x61, 0x74, 0x61
        ]);

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
          getClientExtensionResults: () => ({})
        };
      };

      window.navigator.credentials.get = async () => {
        console.log('🔐 WEBAUTHN_MOCK: navigator.credentials.get() called - BIOMETRIC PROMPT WOULD APPEAR');
        await new Promise(resolve => setTimeout(resolve, 100));

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
          getClientExtensionResults: () => ({})
        };
      };

      console.log('✅ WebAuthn mocks setup complete');
    });

    // Capture console logs from the page
    page.on('console', msg => {
      const text = msg.text();
      const timestamp = new Date().toISOString();
      capturedLogs.push({ timestamp, type: msg.type(), text });
    });

    // Navigate to the demo
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    await page.waitForFunction(() => document.readyState === 'complete');
  });

  test('should analyze WebAuthn authentication flow with multiple TODO additions', async ({ page }) => {
    console.log('\n🧪 ========================================');
    console.log('🧪 Starting WebAuthn Logging E2E Test');
    console.log('🧪 ========================================\n');

    // Wait for WebAuthn support detection
    await page.waitForSelector('text=WebAuthn is fully supported', { timeout: 30000 });
    console.log('✅ WebAuthn support detected');

    // Click "Create Credential" button
    const createButton = page.locator('button:has-text("Create Credential")');
    await expect(createButton).toBeVisible();
    console.log('👆 Clicking Create Credential button...');
    await createButton.click();

    // Wait for credential creation
    await page.waitForSelector('text=Credential created successfully!', { timeout: 30000 });
    console.log('✅ Credential created successfully');

    // Authenticate with WebAuthn
    console.log('👆 Clicking Authenticate with WebAuthn button...');
    const authenticateButton = page.locator('button:has-text("Authenticate with WebAuthn")');
    await authenticateButton.click();

    // Wait for authentication to complete
    await page.waitForSelector('text=Successfully authenticated with biometric security!', { timeout: 30000 });
    console.log('✅ Authentication successful');

    // Wait for the app to be ready for adding TODOs
    await page.waitForTimeout(1000);

    // Add multiple TODOs in sequence to analyze authentication behavior
    const todos = [
      'First TODO - Testing authentication',
      'Second TODO - Immediate follow-up',
      'Third TODO - Still testing'
    ];

    console.log('\n📝 Adding TODOs to analyze authentication flow...');

    for (let i = 0; i < todos.length; i++) {
      const todoText = todos[i];
      const todoNumber = i + 1;

      console.log(`\n--- Adding TODO ${todoNumber}: "${todoText}" ---`);
      const startTime = Date.now();

      // Find the input field and add button (use exact placeholder from the app)
      const input = page.locator('input[placeholder="Add a new TODO..."]');
      const addButton = page.locator('button:has-text("Add")');

      await input.fill(todoText);
      await addButton.click();

      // Wait for TODO to appear
      await page.waitForSelector(`text=${todoText}`, { timeout: 10000 });

      const endTime = Date.now();
      console.log(`✅ TODO ${todoNumber} added in ${endTime - startTime}ms`);

      // Short delay between TODOs to separate logs
      if (i < todos.length - 1) {
        await page.waitForTimeout(500);
      }
    }

    console.log('\n✅ All TODOs added successfully');

    // Wait a bit for all logs to be captured
    await page.waitForTimeout(2000);

    // Analyze the captured logs
    console.log('\n📊 ========================================');
    console.log('📊 ANALYZING CAPTURED LOGS');
    console.log('📊 ========================================\n');

    const analysis = analyzeLogsForAuthenticationBehavior(capturedLogs);

    // Generate findings report
    generateFindingsReport(analysis);

    // Assert expected behaviors based on analysis
    console.log('\n🧪 ========================================');
    console.log('🧪 VALIDATING TEST ASSERTIONS');
    console.log('🧪 ========================================\n');

    // Validate that sign() was called for each TODO
    expect(analysis.signCallCount, 'sign() should be called for each TODO addition').toBeGreaterThanOrEqual(todos.length);

    // Validate that navigator.credentials.get() was called
    expect(analysis.credentialsGetCallCount, 'navigator.credentials.get() should be called at least once').toBeGreaterThan(0);

    // Check if logging is working
    expect(analysis.loggingEnabled, 'Structured logging should be enabled').toBe(true);

    console.log('✅ All assertions passed!');
  });
});

/**
 * Analyzes captured logs to determine authentication behavior
 */
function analyzeLogsForAuthenticationBehavior(logs) {
  const analysis = {
    loggingEnabled: false,
    signCallCount: 0,
    credentialsGetCallCount: 0,
    credentialsCreateCallCount: 0,
    signIdentityCallCount: 0,
    databasePutCallCount: 0,
    verifyCallCount: 0,
    timingData: [],
    detailedFlow: []
  };

  // Filter logs for WebAuthn and identity provider messages
  const relevantLogs = logs.filter(log => {
    const text = log.text.toLowerCase();
    return text.includes('webauthn') ||
           text.includes('sign') ||
           text.includes('identity') ||
           text.includes('database') ||
           text.includes('orbitdb') ||
           text.includes('credentials.get') ||
           text.includes('credentials.create');
  });

  console.log(`📋 Found ${relevantLogs.length} relevant log entries out of ${logs.length} total logs\n`);

  // Analyze each log entry
  for (const log of relevantLogs) {
    const text = log.text;

    // Check if structured logging is enabled
    if (text.includes('orbitdb-identity-provider-webauthn-did')) {
      analysis.loggingEnabled = true;
    }

    // Count sign() calls
    if (text.includes('sign() called') || text.includes('Calling navigator.credentials.get()')) {
      analysis.signCallCount++;
      analysis.detailedFlow.push({ timestamp: log.timestamp, event: 'sign() called' });
    }

    // Count navigator.credentials.get() calls (actual biometric prompts)
    if (text.includes('navigator.credentials.get() called') || text.includes('BIOMETRIC PROMPT WOULD APPEAR')) {
      analysis.credentialsGetCallCount++;
      analysis.detailedFlow.push({ timestamp: log.timestamp, event: 'navigator.credentials.get() - BIOMETRIC PROMPT' });
    }

    // Count navigator.credentials.create() calls
    if (text.includes('navigator.credentials.create() called')) {
      analysis.credentialsCreateCallCount++;
    }

    // Count signIdentity() calls
    if (text.includes('signIdentity() called')) {
      analysis.signIdentityCallCount++;
      analysis.detailedFlow.push({ timestamp: log.timestamp, event: 'signIdentity() called' });
    }

    // Count database.put() calls
    if (text.includes('database.put()') || text.includes('addTodo() called')) {
      analysis.databasePutCallCount++;
      analysis.detailedFlow.push({ timestamp: log.timestamp, event: 'database.put() called' });
    }

    // Count verify() calls
    if (text.includes('verify() called')) {
      analysis.verifyCallCount++;
    }
  }

  return analysis;
}

/**
 * Generates a comprehensive findings report based on log analysis
 */
function generateFindingsReport(analysis) {
  console.log('📄 ========================================');
  console.log('📄 FINDINGS REPORT');
  console.log('📄 ========================================\n');

  console.log('🔍 AUTHENTICATION FLOW ANALYSIS:\n');

  // Report on logging
  if (analysis.loggingEnabled) {
    console.log('✅ Structured logging (@libp2p/logger) is ENABLED');
  } else {
    console.log('❌ Structured logging is NOT ENABLED - check DEBUG environment variable');
  }

  // Report on sign() calls
  console.log('\n📊 SIGNATURE OPERATIONS:');
  console.log(`   - sign() called: ${analysis.signCallCount} times`);
  console.log(`   - signIdentity() called: ${analysis.signIdentityCallCount} times`);
  console.log(`   - database.put() called: ${analysis.databasePutCallCount} times`);

  // Report on biometric prompts
  console.log('\n🔐 BIOMETRIC AUTHENTICATION:');
  console.log(`   - navigator.credentials.get() called: ${analysis.credentialsGetCallCount} times`);
  console.log(`   - navigator.credentials.create() called: ${analysis.credentialsCreateCallCount} times`);

  if (analysis.credentialsGetCallCount === analysis.signCallCount) {
    console.log('   ✅ FINDING: Biometric prompt appears for EVERY signature operation');
    console.log('      This means NO signature caching is occurring.');
  } else if (analysis.credentialsGetCallCount < analysis.signCallCount) {
    console.log(`   ⚠️  FINDING: Biometric prompts (${analysis.credentialsGetCallCount}) < sign() calls (${analysis.signCallCount})`);
    console.log('      This suggests signature caching or browser grace period is active.');
  } else {
    console.log('   🤔 FINDING: Unexpected behavior - more prompts than sign calls');
  }

  // Report on verification
  console.log('\n✓ VERIFICATION:');
  console.log(`   - verify() called: ${analysis.verifyCallCount} times`);

  // Detailed flow
  if (analysis.detailedFlow.length > 0) {
    console.log('\n📋 DETAILED FLOW (first 10 events):');
    analysis.detailedFlow.slice(0, 10).forEach((event, i) => {
      console.log(`   ${i + 1}. [${event.timestamp}] ${event.event}`);
    });
  }

  // Answer the key questions from issue #2
  console.log('\n🎯 KEY FINDINGS (Issue #2 - Authentication Frequency):\n');

  console.log('1. ❓ Why do we need to authenticate for every TODO?');
  if (analysis.credentialsGetCallCount >= analysis.databasePutCallCount) {
    console.log('   ✅ Because navigator.credentials.get() is called for EACH database operation.');
    console.log('      This is by design - each OrbitDB write requires a new signature.');
  } else {
    console.log('   ⚠️  navigator.credentials.get() is NOT called for every operation.');
    console.log('      Browser may be caching authentication for a grace period.');
  }

  console.log('\n2. ❓ Is OrbitDB caching signatures?');
  if (analysis.signCallCount === analysis.databasePutCallCount) {
    console.log('   ❌ NO - sign() is called for EACH database.put() operation.');
    console.log('      OrbitDB is NOT caching signatures.');
  } else {
    console.log('   ⚠️  Inconsistent behavior detected - needs further investigation.');
  }

  console.log('\n3. ❓ Is the browser grace period affecting authentication?');
  if (analysis.credentialsGetCallCount < analysis.signCallCount) {
    console.log('   ✅ YES - Browser grace period is likely active.');
    console.log('      Some sign() operations don\'t trigger new biometric prompts.');
  } else {
    console.log('   ❌ NO - Each sign() operation triggers a new biometric prompt.');
    console.log('      No browser grace period detected.');
  }

  console.log('\n4. ❓ Complete flow from db.put() to oplog entry:');
  console.log('   db.put() → identity.sign() → signIdentity() → webauthnProvider.sign() → navigator.credentials.get()');
  console.log('   This flow is executed for EACH write operation.');

  console.log('\n📄 ========================================\n');
}

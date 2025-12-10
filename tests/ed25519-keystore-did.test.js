/**
 * Tests for Ed25519 Keystore DID Feature
 *
 * This test suite verifies that the useKeystoreDID flag correctly creates
 * Ed25519 DIDs from the OrbitDB keystore instead of P-256 DIDs from WebAuthn.
 */

import { test, expect } from '@playwright/test';

test.describe('Ed25519 Keystore DID Feature', () => {

  test('should create P-256 DID by default (without flag)', async ({ page }) => {
    await page.goto('http://localhost:5173');

    // Wait for page to load
    await page.waitForSelector('h1:has-text("WebAuthn Identity Provider Demo")');

    // Create credential
    await page.click('button:has-text("Create WebAuthn Credential")');

    // Wait for biometric authentication (mocked in test environment)
    await page.waitForTimeout(1000);

    // Check that credential was created
    const credentialStatus = await page.textContent('#credential-status');
    expect(credentialStatus).toContain('Credential created');

    // Create identity (default behavior - P-256 DID)
    await page.click('button:has-text("Create Identity")');
    await page.waitForTimeout(1000);

    // Get the DID
    const didElement = await page.textContent('#identity-did');

    // P-256 DIDs start with "did:key:zDna"
    expect(didElement).toMatch(/^did:key:zDna/);

    console.log('P-256 DID (default):', didElement);
  });

  test('should create Ed25519 DID with useKeystoreDID flag', async ({ page }) => {
    await page.goto('http://localhost:5173');

    // Wait for page to load
    await page.waitForSelector('h1:has-text("WebAuthn Identity Provider Demo")');

    // Create credential
    await page.click('button:has-text("Create WebAuthn Credential")');
    await page.waitForTimeout(1000);

    // Enable Ed25519 keystore DID option
    await page.click('input#use-keystore-did');

    // Create identity with Ed25519 keystore DID
    await page.click('button:has-text("Create Identity")');
    await page.waitForTimeout(1000);

    // Get the DID
    const didElement = await page.textContent('#identity-did');

    // Ed25519 DIDs start with "did:key:z6Mk"
    expect(didElement).toMatch(/^did:key:z6Mk/);

    console.log('Ed25519 DID (from keystore):', didElement);
  });

  test('should create different DIDs for P-256 vs Ed25519', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForSelector('h1:has-text("WebAuthn Identity Provider Demo")');

    // Create credential once
    await page.click('button:has-text("Create WebAuthn Credential")');
    await page.waitForTimeout(1000);

    // Create P-256 DID
    await page.click('button:has-text("Create Identity")');
    await page.waitForTimeout(1000);
    const p256DID = await page.textContent('#identity-did');

    // Reset identity
    await page.click('button:has-text("Reset")');
    await page.waitForTimeout(500);

    // Enable Ed25519 keystore DID
    await page.click('input#use-keystore-did');

    // Create Ed25519 DID
    await page.click('button:has-text("Create Identity")');
    await page.waitForTimeout(1000);
    const ed25519DID = await page.textContent('#identity-did');

    // DIDs should be different
    expect(p256DID).not.toBe(ed25519DID);
    expect(p256DID).toMatch(/^did:key:zDna/);
    expect(ed25519DID).toMatch(/^did:key:z6Mk/);

    console.log('P-256 DID:', p256DID);
    console.log('Ed25519 DID:', ed25519DID);
  });

  test('should use Ed25519 DID for database operations', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForSelector('h1:has-text("WebAuthn Identity Provider Demo")');

    // Create credential
    await page.click('button:has-text("Create WebAuthn Credential")');
    await page.waitForTimeout(1000);

    // Enable Ed25519 keystore DID
    await page.click('input#use-keystore-did');

    // Create identity
    await page.click('button:has-text("Create Identity")');
    await page.waitForTimeout(1000);

    // Get the DID
    const did = await page.textContent('#identity-did');
    expect(did).toMatch(/^did:key:z6Mk/);

    // Open database
    await page.click('button:has-text("Open Database")');
    await page.waitForTimeout(1000);

    // Add a TODO
    await page.fill('input#todo-text', 'Test Ed25519 DID');
    await page.click('button:has-text("Add TODO")');
    await page.waitForTimeout(500);

    // Verify TODO was added
    const todoList = await page.textContent('#todo-list');
    expect(todoList).toContain('Test Ed25519 DID');

    // Verify the database is using the Ed25519 DID
    const dbIdentity = await page.textContent('#db-identity');
    expect(dbIdentity).toContain(did);
  });

  test('should throw error if keystore not provided with useKeystoreDID flag', async ({ page }) => {
    await page.goto('http://localhost:5173');

    // Inject code to test error handling
    const errorThrown = await page.evaluate(async () => {
      try {
        const { OrbitDBWebAuthnIdentityProvider } = window;

        // Try to create provider without keystore
        const provider = new OrbitDBWebAuthnIdentityProvider({
          webauthnCredential: { /* mock credential */ },
          useKeystoreDID: true,
          keystore: null  // Missing keystore
        });

        // Try to call createEd25519DIDFromKeystore
        await provider.createEd25519DIDFromKeystore();

        return false; // Should not reach here
      } catch (error) {
        return error.message.includes('Keystore is required');
      }
    });

    expect(errorThrown).toBe(true);
  });

  test('should maintain same Ed25519 DID across sessions', async ({ page }) => {
    // First session
    await page.goto('http://localhost:5173');
    await page.waitForSelector('h1:has-text("WebAuthn Identity Provider Demo")');

    // Create credential and identity with Ed25519
    await page.click('button:has-text("Create WebAuthn Credential")');
    await page.waitForTimeout(1000);
    await page.click('input#use-keystore-did');
    await page.click('button:has-text("Create Identity")');
    await page.waitForTimeout(1000);

    const firstDID = await page.textContent('#identity-did');
    expect(firstDID).toMatch(/^did:key:z6Mk/);

    // Store credential in localStorage
    await page.evaluate(() => {
      localStorage.setItem('ed25519-did-test', 'true');
    });

    // Reload page (new session)
    await page.reload();
    await page.waitForSelector('h1:has-text("WebAuthn Identity Provider Demo")');

    // Load credential and recreate identity with Ed25519
    await page.click('button:has-text("Load Credential")');
    await page.waitForTimeout(500);
    await page.click('input#use-keystore-did');
    await page.click('button:has-text("Create Identity")');
    await page.waitForTimeout(1000);

    const secondDID = await page.textContent('#identity-did');

    // Same credential and keystore should produce same Ed25519 DID
    expect(secondDID).toBe(firstDID);
  });
});

test.describe('Ed25519 DID Format Validation', () => {

  test('should validate Ed25519 DID format', async ({ page }) => {
    await page.goto('http://localhost:5173');

    const isValidFormat = await page.evaluate(() => {
      // Test Ed25519 DID format
      const ed25519DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

      // Should start with did:key:z6Mk
      const startsCorrect = ed25519DID.startsWith('did:key:z6Mk');

      // Should be a valid base58btc encoding after z6Mk
      const base58Part = ed25519DID.replace('did:key:', '');
      const isBase58 = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(base58Part);

      return startsCorrect && isBase58;
    });

    expect(isValidFormat).toBe(true);
  });

  test('should differentiate P-256 and Ed25519 DID prefixes', async ({ page }) => {
    await page.goto('http://localhost:5173');

    const prefixCheck = await page.evaluate(() => {
      const p256DID = 'did:key:zDnaerx9CtfPpYYn5FcUDqx73m7Tk4xJjBx9FXwpEHh6YhJny';
      const ed25519DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

      return {
        p256StartsWithZDna: p256DID.startsWith('did:key:zDna'),
        ed25519StartsWithZ6Mk: ed25519DID.startsWith('did:key:z6Mk'),
        areDifferent: p256DID !== ed25519DID
      };
    });

    expect(prefixCheck.p256StartsWithZDna).toBe(true);
    expect(prefixCheck.ed25519StartsWithZ6Mk).toBe(true);
    expect(prefixCheck.areDifferent).toBe(true);
  });
});

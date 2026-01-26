import { test, expect } from '@playwright/test';

const CREDENTIAL_SUCCESS_TEXT = 'Credential created successfully!';
const AUTH_SUCCESS_TEXT = 'Successfully authenticated with biometric security!';

async function installWebAuthnMock(context) {
  await context.addInitScript(() => {
    window.__PLAYWRIGHT__ = true;

    if (!window.PublicKeyCredential) {
      window.PublicKeyCredential = function PublicKeyCredential() {};
    }
    if (!window.PublicKeyCredential.prototype) {
      window.PublicKeyCredential.prototype = {};
    }
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    window.PublicKeyCredential.isConditionalMediationAvailable = async () => true;

  });
}

test.describe('WebAuthn Varsig Demo E2E', () => {
  test('should create credential, authenticate, and manage todos', async ({ page, context }) => {
    test.setTimeout(120000);
    await installWebAuthnMock(context);

    await page.goto('http://localhost:5173');
    await page.waitForSelector('button:has-text("Create Credential")', { timeout: 30000 });

    await page.click('button:has-text("Create Credential")');
    await expect(page.locator(`text=${CREDENTIAL_SUCCESS_TEXT}`)).toBeVisible({
      timeout: 30000
    });

    await page.click('button:has-text("Authenticate with Passkey")');
    await page.waitForSelector('input[placeholder="Add a new TODO..."]', {
      timeout: 90000
    });

    await expect(page.locator('text=WebAuthn Varsig DID')).toBeVisible();
    await expect(page.locator('code')).toBeVisible();

    const todoText = 'Test Varsig TODO';
    await page.fill('input[placeholder="Add a new TODO..."]', todoText);
    await page.click('button:has-text("Add")');
    await page.waitForSelector(`text=${todoText}`, { timeout: 15000 });
    await expect(page.locator(`text=${todoText}`)).toBeVisible();

    await page.click('button[data-testid="toggle-todo"]', { timeout: 5000 });

    await page.click('button:has-text("Logout")');
    await page.waitForSelector('text=Logged out successfully', { timeout: 15000 });
    await expect(page.locator('button:has-text("Create Credential")')).toBeVisible();
  });
});

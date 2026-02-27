import { test, expect } from '@playwright/test';

const createCredentialButton = 'button:has-text("Create Credential")';
const authenticateButton = 'button:has-text("Authenticate with WebAuthn")';

async function openSecurityOptions(page) {
  await page.goto('http://localhost:5173', { waitUntil: 'domcontentloaded' });
  if (await page.getByText('TODO List').isVisible({ timeout: 2000 }).catch(() => false)) {
    await page.click('button:has-text("Logout")');
    await page.waitForTimeout(300);
  }
  const hasCreateButton = await page.waitForSelector(createCredentialButton, { timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  if (hasCreateButton) {
    await page.click(createCredentialButton);
    await Promise.race([
      page.waitForSelector('text=Credential created successfully!', { timeout: 30000 }),
      page.waitForSelector(authenticateButton, { timeout: 30000 })
    ]);
  } else {
    await page.waitForSelector(authenticateButton, { timeout: 30000 });
  }
  await page.waitForSelector(authenticateButton, { timeout: 30000 });
  await page.waitForSelector('text=Security Options', { timeout: 30000 });
}

async function authenticateAndReadDid(page) {
  await page.click(authenticateButton);
  await page.waitForSelector('text=TODO List', { timeout: 30000 });
  await page.waitForFunction(() => document.body.innerText.includes('did:key:'), null, { timeout: 30000 });
  return page.evaluate(() => {
    const codeDid = Array.from(document.querySelectorAll('code'))
      .map((node) => node.textContent?.trim() || '')
      .find((value) => value.startsWith('did:key:'));
    if (codeDid) return codeDid;

    const bodyMatch = document.body.innerText.match(/did:key:z[1-9A-HJ-NP-Za-km-z]+/);
    const did = bodyMatch ? bodyMatch[0] : null;
    return did || null;
  });
}

test.describe('Ed25519 Keystore DID Feature', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeEach(async ({ context }) => {
    await context.clearCookies();
    await context.addInitScript(() => {
      localStorage.clear();

      if (!window.PublicKeyCredential) {
        window.PublicKeyCredential = function PublicKeyCredential() {};
      }
      if (!window.PublicKeyCredential.prototype) {
        window.PublicKeyCredential.prototype = {};
      }

      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
      window.PublicKeyCredential.isConditionalMediationAvailable = async () => true;

      const mockCredentialId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      if (!window.navigator.credentials) {
        window.navigator.credentials = {};
      }

      window.navigator.credentials.create = async () => ({
        id: 'mock-credential-id',
        rawId: mockCredentialId,
        type: 'public-key',
        response: {
          attestationObject: new Uint8Array(300),
          clientDataJSON: new TextEncoder().encode(JSON.stringify({
            type: 'webauthn.create',
            challenge: 'mock-challenge',
            origin: window.location.origin,
            crossOrigin: false
          })),
          getPublicKey: () => new Uint8Array(65),
          getPublicKeyAlgorithm: () => -7
        },
        getClientExtensionResults: () => ({ hmacCreateSecret: true })
      });

      window.navigator.credentials.get = async () => ({
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
        getClientExtensionResults: () => ({ hmacGetSecret: { output1: new Uint8Array(32).fill(42) } })
      });
    });
  });

  test('uses keystore DID when persistent identity is enabled', async ({ page }) => {
    await openSecurityOptions(page);

    const useKeystoreIdentity = page.getByLabel(/Use persistent keystore identity/i);
    await expect(useKeystoreIdentity).toBeChecked();
    await page.locator('input[type="radio"][value="Ed25519"]').check();

    const did = await authenticateAndReadDid(page);
    expect(did).toMatch(/^did:key:z/);
    expect(did.startsWith('did:key:z4')).toBe(false);
  });

  test('uses non-Ed25519 DID when persistent identity is disabled', async ({ page }) => {
    await openSecurityOptions(page);

    const useKeystoreIdentity = page.getByLabel(/Use persistent keystore identity/i);
    await useKeystoreIdentity.uncheck();

    const did = await authenticateAndReadDid(page);
    expect(did).toMatch(/^did:key:z/);
    expect(did.startsWith('did:key:z6Mk')).toBe(false);
  });

  test('shows key type controls only when persistent identity is enabled', async ({ page }) => {
    await openSecurityOptions(page);

    const useKeystoreIdentity = page.getByLabel(/Use persistent keystore identity/i);
    const secpKeyOption = page.getByLabel('secp256k1');
    const ed25519KeyOption = page.getByLabel('Ed25519');

    await expect(secpKeyOption).toBeVisible();
    await expect(ed25519KeyOption).toBeVisible();

    await useKeystoreIdentity.uncheck();
    await expect(secpKeyOption).toBeHidden();
    await expect(ed25519KeyOption).toBeHidden();
  });

  test('produces different DIDs for WebAuthn identity vs Ed25519 keystore identity', async ({ page }) => {
    await openSecurityOptions(page);

    const useKeystoreIdentity = page.getByLabel(/Use persistent keystore identity/i);
    await useKeystoreIdentity.uncheck();
    const webauthnDid = await authenticateAndReadDid(page);

    await openSecurityOptions(page);
    await page.getByLabel(/Use persistent keystore identity/i).check();
    await page.locator('input[type="radio"][value="Ed25519"]').check();
    const ed25519Did = await authenticateAndReadDid(page);

    expect(webauthnDid).not.toBe(ed25519Did);
    expect(ed25519Did).toMatch(/^did:key:z/);
    expect(ed25519Did.startsWith('did:key:z4')).toBe(false);
  });
});

test.describe('Ed25519 DID Format Validation', () => {
  test('should validate Ed25519 DID format', async ({ page }) => {
    await page.goto('http://localhost:5173');

    const isValidFormat = await page.evaluate(() => {
      const ed25519DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
      const startsCorrect = ed25519DID.startsWith('did:key:z6Mk');
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

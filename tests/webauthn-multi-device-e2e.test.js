import { test, expect } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

/**
 * E2E Tests for WebAuthn Multi-Device Linking & Recovery
 *
 * Strategy: Two separate browser contexts on the same page (localhost:5173).
 * libp2p transport is bypassed via window.__multiDevice test API.
 * WebAuthn is mocked with deterministic credentials per context.
 *
 * Scenarios:
 * A — First device setup: DB address format, device count, device entry shape, QR payload
 * B — Device linking:     2 devices in registry after pairing, Device B DID present
 * C — Recovery:           Same DB address returned for known credential without confirm dialog
 */

// ── WebAuthn mock factory ─────────────────────────────────────────────────────

/**
 * The browser-side mock installer. Receives { seed } as the arg object.
 * addInitScript supports (fn, arg) where arg is JSON-serializable.
 */
function webAuthnMockScript({ seed, forceP256Hardware = false }) {
  window.__testMode = true;
  window.__PLAYWRIGHT__ = true;
  window.__FORCE_P256_HARDWARE__ = forceP256Hardware;
  window.__WEBAUTHN_VARSIG_SEED__ = seed;

  const mockCredentialId = new Uint8Array(seed);

  if (!window.PublicKeyCredential) {
    window.PublicKeyCredential = function PublicKeyCredential() {};
  }
  window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
  window.PublicKeyCredential.isConditionalMediationAvailable = async () => true;

  if (!window.navigator.credentials) {
    window.navigator.credentials = {};
  }

  window.navigator.credentials.create = async (options) => {
    console.log('[webauthn-mock] credentials.create() called');
    await new Promise((r) => setTimeout(r, 50));

    const mockAttestation = new Uint8Array(300);
    mockAttestation.set([
      0xa3, 0x63, 0x66, 0x6d, 0x74, 0x66, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x64,
      0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0xa0, 0x68, 0x61, 0x75,
      0x74, 0x68, 0x44, 0x61, 0x74, 0x61,
    ]);

    const extensionResults = {};
    if (options?.publicKey?.extensions?.prf) {
      extensionResults.prf = { enabled: true };
    }
    if (options?.publicKey?.extensions?.hmacCreateSecret) {
      extensionResults.hmacCreateSecret = true;
    }

    return {
      id: 'mock-cred-' + Date.now(),
      rawId: mockCredentialId,
      type: 'public-key',
      response: {
        attestationObject: mockAttestation,
        clientDataJSON: new TextEncoder().encode(JSON.stringify({
          type: 'webauthn.create',
          challenge: 'mock-challenge',
          origin: window.location.origin,
          crossOrigin: false,
        })),
        getPublicKey: () => new Uint8Array(65),
        getPublicKeyAlgorithm: () => -7,
      },
      getClientExtensionResults: () => extensionResults,
    };
  };

  window.navigator.credentials.get = async (options) => {
    console.log('[webauthn-mock] credentials.get() called');
    await new Promise((r) => setTimeout(r, 50));

    const extensionResults = {};
    if (options?.publicKey?.extensions?.prf) {
      const prfOutput = new Uint8Array(32);
      for (let i = 0; i < 32; i++) prfOutput[i] = (mockCredentialId[i % 16] + i) % 256;
      extensionResults.prf = { results: { first: prfOutput } };
    }
    if (options?.publicKey?.extensions?.hmacGetSecret) {
      extensionResults.hmacGetSecret = { output1: new Uint8Array(32).fill(42) };
    }

    return {
      id: 'mock-cred',
      rawId: mockCredentialId,
      type: 'public-key',
      response: {
        authenticatorData: new Uint8Array(37),
        clientDataJSON: new TextEncoder().encode(JSON.stringify({
          type: 'webauthn.get',
          challenge: 'mock-challenge',
          origin: window.location.origin,
          crossOrigin: false,
        })),
        signature: new Uint8Array(64),
        userHandle: null,
      },
      getClientExtensionResults: () => extensionResults,
    };
  };

  console.log('[webauthn-mock] Setup complete, __testMode =', window.__testMode);
}

const SEED_A = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const SEED_B = [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
const SEED_C = [33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48];

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Wait for the window.__multiDevice test API to be exposed by the component. */
async function waitForMultiDeviceApi(page, timeout = 60000) {
  await page.waitForFunction(
    () => typeof window.__multiDevice !== 'undefined',
    { timeout }
  );
}

async function setIdentityMode(page, mode) {
  await page.evaluate((value) => window.__multiDevice.setIdentityMode(value), mode);
  await page.waitForFunction(
    (expectedMode) => window.__multiDevice?.getState?.()?.identityMode === expectedMode,
    mode
  );
}

/**
 * Trigger first-device setup via the Start button + test API.
 * Clicks "🚀 Start" → handleStart() detects mock credential, creates OrbitDB manager
 * → calls setupAsDeviceA() which creates the device registry → waits for DB address.
 */
async function doFirstDeviceSetup(page, mode = 'keystore-ed25519') {
  await setIdentityMode(page, mode);
  await page.click('button:has-text("Start")');
  await page.waitForTimeout(1000); // handleStart completes (credential + OrbitDB setup)
  await page.waitForLoadState('domcontentloaded');
  await waitForMultiDeviceApi(page);
  await page.evaluate(() => window.__multiDevice.setupAsDeviceA());
  await page.waitForSelector('[data-testid="db-address"]', { timeout: 120000 });
}

/**
 * Trigger credential setup on Device B via the Start button.
 * Clicks "🚀 Start" → handleStart() detects mock credential, creates OrbitDB identity
 * → waits for identity to be available in state.
 */
async function doDeviceBCredentialSetup(page, mode = 'keystore-ed25519') {
  await setIdentityMode(page, mode);
  await page.click('button:has-text("Start")');
  await page.waitForTimeout(1000);
  await page.waitForLoadState('domcontentloaded');
  await waitForMultiDeviceApi(page);

  const hasIdentity = await page.evaluate(
    () => window.__multiDevice?.getState()?.identity !== null
  );

  if (!hasIdentity) {
    const linkButton = page.locator('button:has-text("Link to Existing Device")');
    if (await linkButton.count()) {
      await linkButton.click();
    }
  }

  await page.waitForFunction(() => {
    const state = window.__multiDevice?.getState?.();
    return state?.identity !== null;
  }, { timeout: 120000 });
}

// ── Scenario A ────────────────────────────────────────────────────────────────

test.describe('Scenario A — First device setup', () => {
  test.beforeEach(async ({ context }) => {
    await context.addInitScript(webAuthnMockScript, { seed: SEED_A });
  });

  test('DB address has /orbitdb/ prefix and device count is 1', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    await waitForMultiDeviceApi(page);

    await doFirstDeviceSetup(page);
    await page.waitForTimeout(2000); // let refreshDevices() complete

    const state = await page.evaluate(() => window.__multiDevice.getState());
    expect(state.devicesDbAddress).toMatch(/^\/orbitdb\//);
    expect(state.deviceCount).toBe(1);
    expect(state.identity?.id).toBeTruthy();

    console.log('✅ Scenario A: DB address:', state.devicesDbAddress.substring(0, 30) + '…');
    console.log('✅ Scenario A: Device count:', state.deviceCount);
  });

  test('registered device entry has correct shape', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    await waitForMultiDeviceApi(page);

    await doFirstDeviceSetup(page);
    await page.waitForTimeout(2000);

    const devices = await page.evaluate(() => window.__multiDevice.listDevices());
    expect(devices).toHaveLength(1);

    const device = devices[0];
    expect(device.credential_id).toBeTruthy();
    expect(device.device_label).toBeTruthy();
    expect(device.created_at).toBeGreaterThan(0);
    expect(device.status).toBe('active');
    // Ed25519 did:key identifiers start with did:key:z6Mk
    expect(device.ed25519_did).toMatch(/^did:key:z6Mk/);

    console.log('✅ Scenario A: Device entry:', {
      credential_id: device.credential_id.substring(0, 16),
      ed25519_did: device.ed25519_did.substring(0, 20) + '…',
      status: device.status,
    });
  });

  test('QR canvas has data-payload with peerId and multiaddrs', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    await waitForMultiDeviceApi(page);

    await doFirstDeviceSetup(page);

    // The QRCode component renders a <canvas data-testid="qr-payload" data-payload="...">
    const qrCanvas = page.locator('[data-testid="qr-payload"]');
    await expect(qrCanvas).toBeVisible({ timeout: 15000 });

    const payloadStr = await qrCanvas.getAttribute('data-payload');
    expect(payloadStr).toBeTruthy();

    const qrPayload = JSON.parse(payloadStr);
    expect(qrPayload).toHaveProperty('peerId');
    expect(qrPayload).toHaveProperty('multiaddrs');
    expect(typeof qrPayload.peerId).toBe('string');
    expect(qrPayload.peerId.length).toBeGreaterThan(0);
    expect(Array.isArray(qrPayload.multiaddrs)).toBe(true);

    // Verify consistency with API
    const apiPayload = await page.evaluate(() => window.__multiDevice.getQRPayload());
    expect(apiPayload?.peerId).toBe(qrPayload.peerId);

    console.log('✅ Scenario A: QR payload peerId:', qrPayload.peerId.substring(0, 16) + '…');
    console.log('✅ Scenario A: multiaddrs count:', qrPayload.multiaddrs.length);
  });
});

// ── Scenario B ────────────────────────────────────────────────────────────────

test.describe('Scenario B — Device linking (transport bypassed)', () => {
  test('Device A registry has 2 entries after pairing; Device B DID present', async ({ browser }) => {
    // Create two independent browser contexts
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();

    await contextA.addInitScript(webAuthnMockScript, { seed: SEED_A });
    await contextB.addInitScript(webAuthnMockScript, { seed: SEED_B });

    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();

    try {
      // Navigate both pages
      await Promise.all([
        pageA.goto('http://localhost:5173').then(() => pageA.waitForLoadState('networkidle')),
        pageB.goto('http://localhost:5173').then(() => pageB.waitForLoadState('networkidle')),
      ]);

      await Promise.all([
        waitForMultiDeviceApi(pageA),
        waitForMultiDeviceApi(pageB),
      ]);

      // ── Device A: first-device setup ──────────────────────────────────────
      await doFirstDeviceSetup(pageA);
      await pageA.waitForTimeout(2000);

      const stateA = await pageA.evaluate(() => window.__multiDevice.getState());
      expect(stateA.devicesDbAddress).toMatch(/^\/orbitdb\//);
      expect(stateA.deviceCount).toBe(1);

      // ── Device B: create credential and OrbitDB identity ──────────────────
      await doDeviceBCredentialSetup(pageB);

      const stateB = await pageB.evaluate(() => window.__multiDevice.getState());
      const deviceBDid = stateB.identity.id;
      // Ed25519 did:key identifiers start with did:key:z6Mk
      expect(deviceBDid).toMatch(/^did:key:z6Mk/);

      // ── Simulate pairing: inject Device B's request into Device A via test API ──
      const grantResult = await pageA.evaluate(
        ({ did }) => {
          return window.__multiDevice.simulateIncomingRequest({
            type: 'request',
            identity: {
              id: did,
              credentialId: 'mock-seed-b-credential-id',
              deviceLabel: 'Device B (Test)',
              publicKey: null,
            },
          });
        },
        { did: deviceBDid }
      );

      expect(grantResult.type).toBe('granted');
      expect(grantResult.orbitdbAddress).toMatch(/^\/orbitdb\//);

      await pageA.waitForTimeout(1000);

      // ── Verify Device A has 2 devices ──────────────────────────────────────
      const devicesA = await pageA.evaluate(() => window.__multiDevice.listDevices());
      expect(devicesA).toHaveLength(2);

      // Device B's DID must be in the registry
      const deviceBEntry = devicesA.find((d) => d.ed25519_did === deviceBDid);
      expect(deviceBEntry).toBeTruthy();
      expect(deviceBEntry.status).toBe('active');
      // Ed25519 did:key identifiers start with did:key:z6Mk
      expect(deviceBEntry.ed25519_did).toMatch(/^did:key:z6Mk/);

      console.log('✅ Scenario B: Device A has', devicesA.length, 'devices after pairing');
      console.log('✅ Scenario B: Device B DID in registry:', deviceBDid.substring(0, 20) + '…');
      console.log('✅ Scenario B: Granted address:', grantResult.orbitdbAddress.substring(0, 30) + '…');

      // ── Verify granted address matches Device A's DB address ──────────────
      expect(grantResult.orbitdbAddress).toBe(stateA.devicesDbAddress);

    } finally {
      await contextA.close();
      await contextB.close();
    }
  });
});

// ── Scenario C ────────────────────────────────────────────────────────────────

test.describe('Scenario C — Recovery (known credential auto-granted)', () => {
  test.beforeEach(async ({ context }) => {
    await context.addInitScript(webAuthnMockScript, { seed: SEED_A });
  });

  test('returns same DB address immediately without confirmation dialog', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    await waitForMultiDeviceApi(page);

    await doFirstDeviceSetup(page);
    await page.waitForTimeout(2000);

    // Get original state
    const initialState = await page.evaluate(() => window.__multiDevice.getState());
    const originalAddress = initialState.devicesDbAddress;
    expect(originalAddress).toMatch(/^\/orbitdb\//);

    // Get the registered device's credential_id and DID
    const devices = await page.evaluate(() => window.__multiDevice.listDevices());
    expect(devices).toHaveLength(1);
    const selfDevice = devices[0];

    // Simulate a recovery request using the SAME credential_id (known device)
    const recoveryResult = await page.evaluate(
      ({ credentialId, did }) => {
        return window.__multiDevice.simulateIncomingRequest({
          type: 'request',
          identity: {
            id: did,
            credentialId: credentialId,
            deviceLabel: 'Recovery Attempt',
            publicKey: null,
          },
        });
      },
      { credentialId: selfDevice.credential_id, did: selfDevice.ed25519_did }
    );

    // Known device → immediately granted with same address
    expect(recoveryResult.type).toBe('granted');
    expect(recoveryResult.orbitdbAddress).toBe(originalAddress);

    // Device count must NOT have increased (same credential = same device)
    const devicesAfter = await page.evaluate(() => window.__multiDevice.listDevices());
    expect(devicesAfter).toHaveLength(1);

    // No confirmation dialog should have appeared
    const confirmDialog = page.locator('text=New Device Wants to Join');
    await expect(confirmDialog).toHaveCount(0);

    console.log('✅ Scenario C: Recovery returned original address:', originalAddress.substring(0, 30) + '…');
    console.log('✅ Scenario C: Device count unchanged:', devicesAfter.length);
    console.log('✅ Scenario C: No confirmation dialog shown');
  });
});

// ── Scenario D: MultiDeviceManager Class API ───────────────────────────────────

test.describe('Scenario D — MultiDeviceManager class API', () => {
  test.beforeEach(async ({ context }) => {
    await context.addInitScript(webAuthnMockScript, { seed: SEED_A });
  });

  test('manager is exposed via test API after setup', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    await waitForMultiDeviceApi(page);

    await doFirstDeviceSetup(page);
    await page.waitForTimeout(2000);

    const manager = await page.evaluate(() => window.__multiDevice.getManager());
    expect(manager).toBeTruthy();

    console.log('✅ Scenario D: Manager is exposed:', typeof manager);
    console.log('✅ Scenario D: Manager has createNew:', typeof manager?.createNew);
    console.log('✅ Scenario D: Manager has listDevices:', typeof manager?.listDevices);
  });
});

// ── Scenario E ────────────────────────────────────────────────────────────────

test.describe('Scenario E — Rejected pairing request', () => {
  test('rejected request returns type=rejected and does not add device', async ({ browser }) => {
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    await contextA.addInitScript(webAuthnMockScript, { seed: SEED_A });
    await contextB.addInitScript(webAuthnMockScript, { seed: SEED_B });
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();

    try {
      await Promise.all([
        pageA.goto('http://localhost:5173').then(() => pageA.waitForLoadState('networkidle')),
        pageB.goto('http://localhost:5173').then(() => pageB.waitForLoadState('networkidle')),
      ]);
      await Promise.all([waitForMultiDeviceApi(pageA), waitForMultiDeviceApi(pageB)]);

      await doFirstDeviceSetup(pageA);
      await pageA.waitForTimeout(2000);

      await doDeviceBCredentialSetup(pageB);
      const stateB = await pageB.evaluate(() => window.__multiDevice.getState());
      const deviceBDid = stateB.identity.id;

      // Simulate incoming request with approve: false
      const rejectResult = await pageA.evaluate(
        ({ did }) =>
          window.__multiDevice.simulateIncomingRequest(
            { type: 'request', identity: { id: did, credentialId: 'mock-seed-b-cred', deviceLabel: 'Device B', publicKey: null } },
            { approve: false }
          ),
        { did: deviceBDid }
      );

      expect(rejectResult.type).toBe('rejected');

      // Device count on A must remain 1
      const devicesA = await pageA.evaluate(() => window.__multiDevice.listDevices());
      expect(devicesA).toHaveLength(1);

      // Device B's DID must NOT be in the registry
      const deviceBEntry = devicesA.find((d) => d.ed25519_did === deviceBDid);
      expect(deviceBEntry).toBeUndefined();

      console.log('✅ Scenario E: Rejection result:', rejectResult.type);
      console.log('✅ Scenario E: Device count unchanged:', devicesA.length);
    } finally {
      await contextA.close();
      await contextB.close();
    }
  });
});

// ── Scenario F ────────────────────────────────────────────────────────────────

test.describe('Scenario F — Device revocation', () => {
  test('revokeDevice sets status to revoked and active count drops', async ({ browser }) => {
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    await contextA.addInitScript(webAuthnMockScript, { seed: SEED_A });
    await contextB.addInitScript(webAuthnMockScript, { seed: SEED_B });
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();

    try {
      await Promise.all([
        pageA.goto('http://localhost:5173').then(() => pageA.waitForLoadState('networkidle')),
        pageB.goto('http://localhost:5173').then(() => pageB.waitForLoadState('networkidle')),
      ]);
      await Promise.all([waitForMultiDeviceApi(pageA), waitForMultiDeviceApi(pageB)]);

      await doFirstDeviceSetup(pageA);
      await pageA.waitForTimeout(2000);

      await doDeviceBCredentialSetup(pageB);
      const stateB = await pageB.evaluate(() => window.__multiDevice.getState());
      const deviceBDid = stateB.identity.id;

      // Pair Device B
      await pageA.evaluate(
        ({ did }) =>
          window.__multiDevice.simulateIncomingRequest({
            type: 'request', identity: { id: did, credentialId: 'mock-seed-b-cred', deviceLabel: 'Device B', publicKey: null },
          }),
        { did: deviceBDid }
      );
      await pageA.waitForTimeout(500);

      // Verify 2 devices before revocation
      const devicesBefore = await pageA.evaluate(() => window.__multiDevice.listDevices());
      expect(devicesBefore).toHaveLength(2);

      // Revoke Device B directly via manager
      await pageA.evaluate(
        ({ did }) => window.__multiDevice.getManager().revokeDevice(did),
        { did: deviceBDid }
      );
      await pageA.waitForTimeout(500);

      const devicesAfter = await pageA.evaluate(() => window.__multiDevice.listDevices());
      expect(devicesAfter).toHaveLength(2); // entry still present

      const revokedEntry = devicesAfter.find((d) => d.ed25519_did === deviceBDid);
      expect(revokedEntry).toBeTruthy();
      expect(revokedEntry.status).toBe('revoked');

      const activeDevices = devicesAfter.filter((d) => d.status === 'active');
      expect(activeDevices).toHaveLength(1);

      console.log('✅ Scenario F: Revoked Device B — status:', revokedEntry.status);
      console.log('✅ Scenario F: Active devices remaining:', activeDevices.length);
    } finally {
      await contextA.close();
      await contextB.close();
    }
  });
});

// ── Scenario H ────────────────────────────────────────────────────────────────

test.describe('Scenario H — Three-device registry', () => {
  test('Device A registry has 3 entries after pairing two separate devices', async ({ browser }) => {
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    const contextC = await browser.newContext();
    await contextA.addInitScript(webAuthnMockScript, { seed: SEED_A });
    await contextB.addInitScript(webAuthnMockScript, { seed: SEED_B });
    await contextC.addInitScript(webAuthnMockScript, { seed: SEED_C });
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();
    const pageC = await contextC.newPage();

    try {
      await Promise.all([
        pageA.goto('http://localhost:5173').then(() => pageA.waitForLoadState('networkidle')),
        pageB.goto('http://localhost:5173').then(() => pageB.waitForLoadState('networkidle')),
        pageC.goto('http://localhost:5173').then(() => pageC.waitForLoadState('networkidle')),
      ]);
      await Promise.all([
        waitForMultiDeviceApi(pageA),
        waitForMultiDeviceApi(pageB),
        waitForMultiDeviceApi(pageC),
      ]);

      await doFirstDeviceSetup(pageA);
      await pageA.waitForTimeout(2000);

      // Device B and C get credentials in parallel
      await Promise.all([doDeviceBCredentialSetup(pageB), doDeviceBCredentialSetup(pageC)]);

      const [stateB, stateC] = await Promise.all([
        pageB.evaluate(() => window.__multiDevice.getState()),
        pageC.evaluate(() => window.__multiDevice.getState()),
      ]);
      const deviceBDid = stateB.identity.id;
      const deviceCDid = stateC.identity.id;
      expect(deviceBDid).not.toBe(deviceCDid);

      // Pair Device B
      await pageA.evaluate(
        ({ did }) =>
          window.__multiDevice.simulateIncomingRequest({
            type: 'request', identity: { id: did, credentialId: 'mock-seed-b-cred', deviceLabel: 'Device B', publicKey: null },
          }),
        { did: deviceBDid }
      );

      // Pair Device C
      await pageA.evaluate(
        ({ did }) =>
          window.__multiDevice.simulateIncomingRequest({
            type: 'request', identity: { id: did, credentialId: 'mock-seed-c-cred', deviceLabel: 'Device C', publicKey: null },
          }),
        { did: deviceCDid }
      );

      await pageA.waitForTimeout(1000);

      const devicesA = await pageA.evaluate(() => window.__multiDevice.listDevices());
      expect(devicesA).toHaveLength(3);

      const dids = devicesA.map((d) => d.ed25519_did);
      expect(dids).toContain(deviceBDid);
      expect(dids).toContain(deviceCDid);

      const allActive = devicesA.every((d) => d.status === 'active');
      expect(allActive).toBe(true);

      console.log('✅ Scenario H: Device A has', devicesA.length, 'registered devices');
      console.log('✅ Scenario H: All devices active:', allActive);
    } finally {
      await contextA.close();
      await contextB.close();
      await contextC.close();
    }
  });
});

// ── Scenario I ────────────────────────────────────────────────────────────────

const MODE_CASES = [
  {
    mode: 'worker-ed25519',
    expectedBackend: 'worker-keystore',
    expectedType: 'worker-ed25519',
    expectedAlgorithm: 'Ed25519',
    didPattern: /^did:key:z6Mk/,
  },
  {
    mode: 'varsig-ed25519',
    expectedBackend: 'webauthn-varsig',
    expectedType: 'webauthn-varsig',
    expectedAlgorithm: 'Ed25519',
    didPattern: /^did:key:/,
  },
  {
    mode: 'varsig-p256',
    expectedBackend: 'webauthn-varsig',
    expectedType: 'webauthn-varsig',
    expectedAlgorithm: 'P-256',
    didPattern: /^did:key:/,
  },
];

test.describe('Scenario I — Alternate identity modes', () => {
  for (const modeCase of MODE_CASES) {
    test(`${modeCase.mode} exposes expected backend metadata on first-device setup`, async ({
      browser,
    }) => {
      const context = await browser.newContext();
      await context.addInitScript(webAuthnMockScript, {
        seed: SEED_A,
        forceP256Hardware: modeCase.mode === 'varsig-p256',
      });
      const page = await context.newPage();

      try {
        await page.goto('http://localhost:5173');
        await page.waitForLoadState('networkidle');
        await waitForMultiDeviceApi(page);

        await doFirstDeviceSetup(page, modeCase.mode);
        await page.waitForTimeout(2000);

        const state = await page.evaluate(() => window.__multiDevice.getState());
        expect(state.identityMode).toBe(modeCase.mode);
        expect(state.signingBackend).toBe(modeCase.expectedBackend);
        expect(state.identityType).toBe(modeCase.expectedType);
        expect(state.didAlgorithm).toBe(modeCase.expectedAlgorithm);
        expect(state.identity.id).toMatch(modeCase.didPattern);

        if (modeCase.mode === 'worker-ed25519') {
          expect(state.worker?.did).toBe(state.identity.id);
          expect(['prf', 'credentialId']).toContain(state.worker?.seedSource);
        }
      } finally {
        await context.close();
      }
    });

    test(`${modeCase.mode} links a second device and preserves mode metadata`, async ({
      browser,
    }) => {
      const contextA = await browser.newContext();
      const contextB = await browser.newContext();
      const forceP256 = modeCase.mode === 'varsig-p256';

      await contextA.addInitScript(webAuthnMockScript, {
        seed: SEED_A,
        forceP256Hardware: forceP256,
      });
      await contextB.addInitScript(webAuthnMockScript, {
        seed: SEED_B,
        forceP256Hardware: forceP256,
      });

      const pageA = await contextA.newPage();
      const pageB = await contextB.newPage();

      try {
        await Promise.all([
          pageA.goto('http://localhost:5173').then(() => pageA.waitForLoadState('networkidle')),
          pageB.goto('http://localhost:5173').then(() => pageB.waitForLoadState('networkidle')),
        ]);

        await Promise.all([
          waitForMultiDeviceApi(pageA),
          waitForMultiDeviceApi(pageB),
        ]);

        await doFirstDeviceSetup(pageA, modeCase.mode);
        await doDeviceBCredentialSetup(pageB, modeCase.mode);
        await pageA.waitForTimeout(1500);

        const stateB = await pageB.evaluate(() => window.__multiDevice.getState());
        expect(stateB.identityMode).toBe(modeCase.mode);
        expect(stateB.signingBackend).toBe(modeCase.expectedBackend);
        expect(stateB.didAlgorithm).toBe(modeCase.expectedAlgorithm);
        expect(stateB.identity.id).toMatch(modeCase.didPattern);

        await pageA.evaluate(
          ({ did }) =>
            window.__multiDevice.simulateIncomingRequest({
              type: 'request',
              identity: {
                id: did,
                credentialId: 'alt-mode-device-b',
                deviceLabel: 'Device B',
                publicKey: null,
              },
            }),
          { did: stateB.identity.id }
        );

        await pageA.waitForTimeout(1000);
        const devicesA = await pageA.evaluate(() => window.__multiDevice.listDevices());
        expect(devicesA).toHaveLength(2);
        expect(devicesA.some((device) => device.ed25519_did === stateB.identity.id)).toBe(true);
      } finally {
        await contextA.close();
        await contextB.close();
      }
    });
  }
});

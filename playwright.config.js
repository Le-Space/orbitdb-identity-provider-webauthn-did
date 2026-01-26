import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  /* Only run Playwright tests, ignore mocha tests */
  testIgnore: '**/webauthn-provider-old.test.js',
  /* Run tests in files in parallel */
  fullyParallel: true,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,
  /* Opt out of parallel tests on CI. */
  workers: process.env.CI ? 1 : undefined,
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: 'html',
  /* Shared settings for all the tests. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: 'http://localhost:5173',

    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on-first-retry',

    /* Screenshots */
    screenshot: 'only-on-failure',

    /* Video */
    video: 'retain-on-failure',
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },

    /* Test against mobile viewports. */
    {
      name: 'Mobile Chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 12'] },
    },
  ],

  /* Run your local dev server before starting the tests */
  webServer: {
    command: (() => {
      // Determine which demo to run based on test file or environment variable
      const testFile = process.env.PLAYWRIGHT_TEST_FILE || '';
      const cliArgs = process.argv.join(' ');
      const useEncryptedDemo = testFile.includes('encrypted-keystore') ||
        testFile.includes('simple-encryption') ||
        cliArgs.includes('ed25519-encrypted-keystore') ||
        cliArgs.includes('encrypted-keystore') ||
        cliArgs.includes('simple-encryption') ||
        process.env.USE_ENCRYPTED_DEMO === 'true';

      const useVarsigDemo = testFile.includes('varsig') ||
        cliArgs.includes('varsig') ||
        process.env.USE_VARSIG_DEMO === 'true';
      
      const demoDir = useEncryptedDemo
        ? 'examples/ed25519-encrypted-keystore-demo'
        : useVarsigDemo
          ? 'examples/webauthn-varsig-demo'
          : 'examples/webauthn-todo-demo';
      
      return process.env.CI 
        ? `cd ${demoDir} && npm run preview -- --port 5173 --host`
        : `cd ${demoDir} && npm run dev`;
    })(),
    url: 'http://localhost:5173',
    reuseExistingServer: process.env.PLAYWRIGHT_REUSE_SERVER === 'true',
    timeout: 120 * 1000,
  },
});

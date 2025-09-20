# CI/CD Pipeline Documentation

## Overview

This project uses GitHub Actions for comprehensive testing and automated npm publishing. The pipeline ensures that all WebAuthn functionality, OrbitDB integration, and data persistence work correctly before any release.

## Workflows

### 1. Test Workflow (`.github/workflows/test.yml`)

Runs on every push and pull request to `main` and `develop` branches.

**Jobs:**
- **Quick Tests**: Runs the comprehensive WebAuthn test suite
- **Code Quality**: Linting and formatting checks

**What it tests:**
- ✅ WebAuthn credential creation and authentication
- ✅ Browser reload persistence
- ✅ TODO operations with biometric security
- ✅ OrbitDB integration
- ✅ Data persistence across sessions

### 2. CI/CD Workflow (`.github/workflows/ci-cd.yml`)

Comprehensive workflow that runs on releases and publishes to npm.

**Jobs:**

#### Test Job
- Tests on Node.js 22.x (latest LTS)
- Installs Playwright and Chromium
- Builds and serves the demo application
- Runs the complete WebAuthn test suite
- Uploads test artifacts on failure

#### Security Audit Job
- Runs `npm audit` for known vulnerabilities
- Uses `better-npm-audit` for enhanced security checking
- Fails the build if moderate or higher severity issues found

#### Package Validation Job
- Validates package.json structure
- Tests package installation in isolation
- Verifies package exports work correctly
- Runs dry-run packaging to check file inclusion

#### Publish Job (Release Only)
- Runs final comprehensive tests
- Publishes to npm with public access
- Updates GitHub release notes with test results
- Only runs when a GitHub release is created

#### Notification Job
- Sends success/failure notifications
- Provides release information

## Test Coverage

The CI/CD pipeline runs these specific test scenarios:

### Phase 1: Initial Authentication
```javascript
✅ WebAuthn support detection
✅ Credential creation with biometric security
✅ OrbitDB database initialization
✅ DID generation (e.g., did:webauthn:5dfbabeedf318bf33c0927c43d7630f5)
✅ TODO creation and storage
```

### Phase 2: Browser Persistence
```javascript
✅ Browser reload simulation
✅ Credential persistence from localStorage
✅ Re-authentication with same identity
✅ Data recovery from OrbitDB
```

### Phase 3: Operations
```javascript
✅ Additional TODO creation
✅ TODO completion with biometric confirmation
✅ Database synchronization
✅ Statistics updates
```

## npm Publishing

### Automatic Publishing
When you create a GitHub release, the workflow will:

1. Run all tests on Node.js 22.x (latest LTS)
2. Perform security audits
3. Validate package structure
4. Run final integration tests
5. Publish to npm automatically
6. Update release notes with test results

### Manual Publishing
You can also publish manually:

```bash
# Run tests first
npm run test:ci

# Version bump and publish (triggers preversion tests)
npm version patch  # or minor, major
npm publish
```

## Environment Variables

### Required GitHub Secrets

Add these secrets to your GitHub repository:

- `NPM_TOKEN`: Your npm authentication token for publishing

To get an npm token:
1. Login to npmjs.com
2. Go to "Access Tokens" in your account settings
3. Generate a new token with "Automation" type
4. Add it to GitHub repository secrets

## Running Tests Locally

```bash
# Install dependencies
npm install
cd examples/webauthn-todo-demo && npm install && cd ../..

# Run focused WebAuthn tests
npm run test:focused

# Run tests with browser visible (for debugging)
npm run test:headed

# Run all tests including cross-browser
npm run test:all

# Run full flow with demo setup
npm run test:full-flow
```

## Test Artifacts

When tests fail, the workflow uploads:
- Screenshots at failure points
- Video recordings of test execution
- Detailed error logs
- Playwright reports

These can be downloaded from the GitHub Actions run page.

## Development Workflow

### For Contributors

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes and test locally**
   ```bash
   npm run test:focused
   ```

3. **Create a pull request**
   - Tests will run automatically
   - Code quality checks will be performed
   - Review and merge when ready

### For Releases

1. **Ensure all tests pass on main branch**

2. **Create a GitHub release**
   - Tag version (e.g., `v1.0.0`)
   - Add release notes
   - Publish the release

3. **Automatic pipeline will:**
   - Run comprehensive tests
   - Perform security audits
   - Publish to npm
   - Update release notes

## Debugging Failed Tests

If tests fail in CI:

1. **Download test artifacts** from the GitHub Actions page
2. **Check the video recordings** to see what happened
3. **Review screenshots** at failure points
4. **Run tests locally** with the same conditions:
   ```bash
   npm run demo:setup
   npm run demo:preview &
   npm run test:focused
   ```

## Security Considerations

The pipeline includes several security measures:

- **Dependency scanning** with npm audit
- **Vulnerability detection** with better-npm-audit
- **Package validation** to ensure only intended files are published
- **Test isolation** to prevent test interference
- **Secret management** for npm tokens

## Performance

Typical pipeline execution times:
- **Test job**: ~5-8 minutes
- **Security audit**: ~1-2 minutes  
- **Package validation**: ~2-3 minutes
- **Full CI/CD pipeline**: ~10-15 minutes

The tests are optimized to run only on Chromium in CI to balance coverage with speed, while still providing comprehensive WebAuthn and OrbitDB validation.
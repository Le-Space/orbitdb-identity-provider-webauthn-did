# Contributing to OrbitDB WebAuthn Identity Provider

Thank you for your interest in contributing to the OrbitDB WebAuthn Identity Provider! This project provides biometric authentication for decentralized applications using WebAuthn and OrbitDB.

## 🚀 Quick Start

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/orbitdb-identity-provider-webauthn-did.git
   cd orbitdb-identity-provider-webauthn-did
   ```

2. **Install dependencies**
   ```bash
   npm install
   cd examples/webauthn-todo-demo && npm install && cd ../..
   ```

3. **Run the tests**
   ```bash
   npm run test:focused
   ```

4. **Start the demo application**
   ```bash
   npm run demo
   ```

## 🧪 Testing

### Test Suite Overview

Our comprehensive test suite validates the entire WebAuthn + OrbitDB integration:

- **WebAuthn Support Detection**: Verifies biometric authentication availability
- **Credential Creation**: Tests WebAuthn credential generation and public key extraction
- **Authentication Flow**: Validates complete login process with OrbitDB integration
- **Persistence Testing**: Ensures credentials and data survive browser reloads
- **TODO Operations**: Tests biometric-secured database operations

### Running Tests

```bash
# Run focused WebAuthn tests (recommended for development)
npm run test:focused

# Run tests with visible browser (for debugging)
npm run test:headed

# Run all tests including cross-browser
npm run test:all

# Run CI-style tests (GitHub Actions format)
npm run test:ci

# Run full flow with demo setup
npm run test:full-flow
```

### Test Structure

Tests are organized in phases:

**Phase 1 - Initial Setup**
- WebAuthn credential creation
- Authentication and OrbitDB initialization
- First TODO creation

**Phase 2 - Browser Persistence**
- Browser reload simulation  
- Credential persistence validation
- Re-authentication with same identity

**Phase 3 - Data Validation**
- TODO data persistence across reload
- Database integrity checks

**Phase 4 - Continued Operations**
- Additional TODO operations after reload
- Biometric-secured database updates

## 🔄 CI/CD Workflow

### Automated Testing

Every push and pull request triggers automated tests:

- ✅ **Cross-platform testing** (Node.js 18.x, 20.x, 22.x)
- ✅ **Security auditing** with npm audit
- ✅ **Package validation** and export verification
- ✅ **Complete WebAuthn flow testing**
- ✅ **OrbitDB integration validation**

### Release Process

When you create a GitHub release, the automated pipeline:

1. **Runs comprehensive tests** across all Node.js versions
2. **Performs security audits** for vulnerabilities
3. **Validates package structure** and exports
4. **Publishes to npm** with public access
5. **Updates release notes** with test results

### GitHub Secrets Required

For automated npm publishing, add these repository secrets:

- `NPM_TOKEN`: Your npm automation token

## 📝 Development Guidelines

### Code Style

- Use ESM modules (type: "module")
- Follow existing code formatting
- Add JSDoc comments for public APIs
- Use descriptive variable and function names

### WebAuthn Integration

When working with WebAuthn functionality:

- Always handle errors gracefully
- Support both platform and cross-platform authenticators  
- Include proper timeout handling
- Test with mocked WebAuthn for CI compatibility

### OrbitDB Integration

For database operations:

- Ensure proper access control setup
- Handle async operations correctly
- Validate data integrity after operations
- Test persistence across sessions

## 🔒 Security Considerations

### WebAuthn Security

- Never store private keys or sensitive credential data
- Use proper challenge generation
- Validate attestations and assertions
- Handle user verification requirements

### Package Security

- Run `npm audit` before submitting changes
- Keep dependencies updated
- Follow secure coding practices
- Validate all inputs

## 🐛 Debugging

### Test Failures

If tests fail:

1. **Run locally first**: `npm run test:headed`
2. **Check console logs** for detailed error information
3. **Use Playwright UI**: `npm run test:ui`
4. **Review test artifacts** in CI (screenshots, videos)

### Demo Application Issues

For demo app problems:

1. **Ensure dependencies are installed**: `npm run demo:setup`
2. **Check browser console** for errors
3. **Verify WebAuthn support** in your browser
4. **Clear localStorage** if authentication state seems corrupted

## 📋 Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following project conventions
   - Add tests for new functionality
   - Update documentation if needed

3. **Test your changes**
   ```bash
   npm run test:focused
   ```

4. **Submit pull request**
   - Describe your changes clearly
   - Reference any related issues
   - Ensure all CI checks pass

### PR Requirements

- ✅ All tests must pass
- ✅ Code should follow existing patterns
- ✅ New features should include tests
- ✅ Security audit must pass
- ✅ Documentation should be updated for significant changes

## 🚀 Release Process

### For Maintainers

1. **Ensure main branch is stable**
   ```bash
   npm run test:ci
   ```

2. **Update version and changelog**
   ```bash
   npm version patch  # or minor/major
   ```

3. **Create GitHub release**
   - Use the git tag as the release version
   - Add meaningful release notes
   - Highlight breaking changes if any

4. **Automated pipeline handles the rest**
   - Tests run across all supported Node.js versions
   - Security audits are performed
   - Package is published to npm
   - Release notes are enhanced with test results

## 🤝 Community

### Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and community support
- **Demo Application**: Try the live example to understand functionality

### Code of Conduct

Please be respectful and inclusive. We welcome contributions from developers of all experience levels.

## 📊 Project Stats

### Test Coverage

- 4 comprehensive test scenarios
- WebAuthn credential lifecycle testing
- OrbitDB persistence validation
- Browser reload simulation
- Biometric operation testing

### Performance

- Tests complete in ~10-15 seconds locally
- CI pipeline runs in ~10-15 minutes
- Package size: ~10kB compressed

### Compatibility

- Node.js: ≥18.0.0
- Browsers: Modern browsers with WebAuthn support
- OrbitDB: ^3.0.0

---

Thank you for contributing to the future of decentralized, biometric-secured applications! 🎉
# Brave Extension Scanner Tests

This directory contains comprehensive tests for the Brave Extension Scanner's analyzers and utilities.

## Test Structure

- `analyzers/` - Tests for the analyzer modules
  - `manifest-analyzer.test.js` - Tests for manifest.json analysis
  - `network-analyzer.test.js` - Tests for network endpoint detection
  - `obfuscation-detector.test.js` - Tests for code obfuscation detection
  - `static-analyzer.test.js` - Tests for static code analysis
  - `threat-classifier.test.js` - Tests for threat classification

## Running Tests

To run all tests:

```bash
npm test
```

To run tests with watch mode (automatically re-run tests when files change):

```bash
npm run test:watch
```

To run tests with coverage report:

```bash
npm run test:coverage
```

## Test Coverage

The test suite aims to achieve at least 80% code coverage across all analyzer modules. Coverage reports can be viewed after running the coverage command.

## Writing Tests

When writing new tests, follow these guidelines:

1. **Test Structure**: Use describe/test blocks to organize tests logically
2. **Isolation**: Each test should be independent and not rely on state from other tests
3. **Mocking**: Use Jest's mocking capabilities for external dependencies
4. **Edge Cases**: Include tests for edge cases and error handling
5. **Coverage**: Ensure all code paths are covered, including error handling

## Continuous Integration

Tests are automatically run as part of the CI/CD pipeline to ensure code quality and prevent regressions.
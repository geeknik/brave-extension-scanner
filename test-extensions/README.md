# Test Extensions for Brave Extension Scanner

This directory contains test extensions designed to validate the accuracy and effectiveness of the Brave Extension Scanner.

## Test Extension Categories

### 1. **test-eval-usage** - Dynamic Code Execution Patterns
- **Purpose**: Test detection of eval(), Function constructor, setTimeout/setInterval with strings
- **Expected Result**: HIGH risk - should detect multiple eval usage patterns
- **Key Patterns**:
  - Direct eval() calls
  - new Function() constructor
  - setTimeout/setInterval with string arguments
  - document.write() usage
  - Dynamic script element creation

### 2. **test-excessive-permissions** - Permission Analysis
- **Purpose**: Test detection of excessive and dangerous permissions
- **Expected Result**: HIGH risk - should flag excessive permissions
- **Key Patterns**:
  - Dangerous permissions: history, bookmarks, cookies, management, debugger
  - Host permissions: `<all_urls>`
  - Critical permissions: webRequest, desktopCapture
  - Browser fingerprinting through content script

### 3. **test-obfuscated-code** - Code Obfuscation Detection
- **Purpose**: Test detection of various obfuscation techniques
- **Expected Result**: MEDIUM-HIGH risk - should detect obfuscation patterns
- **Key Patterns**:
  - Hex-encoded strings
  - Unicode escape sequences
  - Base64 encoding
  - Minified variable names
  - String concatenation obfuscation
  - Array access obfuscation

### 4. **test-network-exfiltration** - Data Exfiltration Patterns
- **Purpose**: Test detection of data exfiltration and suspicious network activity
- **Expected Result**: CRITICAL risk - should detect data theft patterns
- **Key Patterns**:
  - History/bookmark exfiltration
  - Cookie theft
  - Form data monitoring
  - Suspicious domain communications
  - Multiple transmission methods (fetch, XHR, image beacons)

### 5. **test-keylogging** - Keylogging Detection
- **Purpose**: Test detection of keylogging and input monitoring
- **Expected Result**: CRITICAL risk - should detect keylogging patterns
- **Key Patterns**:
  - addEventListener for keyboard events
  - Direct onkeydown/onkeyup assignments
  - Form input monitoring
  - Password field targeting
  - Dynamic handler injection

### 6. **test-clean-extension** - Safe Extension (Control)
- **Purpose**: Verify scanner doesn't flag legitimate, safe extensions
- **Expected Result**: SAFE - should pass all security checks
- **Key Patterns**:
  - Minimal permissions (activeTab only)
  - No suspicious API usage
  - Safe DOM manipulation
  - Proper error handling
  - No external data transmission

## Testing Instructions

1. **Build the main scanner extension**:
   ```bash
   npm run build
   ```

2. **Load the scanner extension in browser**:
   - Open `brave://extensions` or `chrome://extensions`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the `dist/` directory

3. **Test each test extension**:
   - Load each test extension from the `test-extensions/` subdirectories
   - The scanner should automatically detect and analyze each extension
   - Check the scan results in the scanner's popup

4. **Verify Expected Results**:
   - **test-eval-usage**: Should detect eval usage patterns
   - **test-excessive-permissions**: Should flag dangerous permissions
   - **test-obfuscated-code**: Should detect obfuscation techniques
   - **test-network-exfiltration**: Should detect data exfiltration patterns
   - **test-keylogging**: Should detect keylogging patterns
   - **test-clean-extension**: Should be classified as SAFE

## Expected Scanner Performance

| Test Extension | Expected Threat Level | Key Detection Points |
|---|---|---|
| test-eval-usage | HIGH | 9+ eval patterns detected |
| test-excessive-permissions | HIGH | 15+ dangerous permissions |
| test-obfuscated-code | MEDIUM-HIGH | Obfuscation detected |
| test-network-exfiltration | CRITICAL | Data theft + suspicious domains |
| test-keylogging | CRITICAL | Keylogging patterns detected |
| test-clean-extension | SAFE | No suspicious patterns |

## Debugging Scanner Issues

If the scanner doesn't detect expected patterns:

1. **Check Static Analyzer**: Look for patterns in `src/analyzers/static-analyzer.js`
2. **Check Manifest Analyzer**: Verify permission detection in `src/analyzers/manifest-analyzer.js`
3. **Check Obfuscation Detector**: Verify entropy analysis in `src/analyzers/obfuscation-detector.js`
4. **Check Network Analyzer**: Verify domain detection in `src/analyzers/network-analyzer.js`
5. **Check Threat Classifier**: Verify scoring logic in `src/analyzers/threat-classifier.js`

## Adding New Test Cases

To add new test patterns:

1. Create a new directory under `test-extensions/`
2. Add `manifest.json` with appropriate permissions
3. Add JavaScript files with the patterns to test
4. Document expected results in this README
5. Test against the scanner and adjust detection logic if needed

## Security Note

These test extensions contain simulated malicious patterns for testing purposes only. They should:
- Never be published to extension stores
- Only be used in isolated testing environments
- Be clearly marked as test/development extensions
- Not contain actual malicious functionality that could cause harm
# Brave Extension Scanner - Immediate Action Plan

## 🎯 PRIORITY 0: Critical Fixes (Complete These First)

### 1. Reduce Permission Scope (30 minutes)

**Current permissions are excessive and violate least privilege principle.**

#### Step 1.1: Update manifest.json

```json
{
  "permissions": [
    "management",       // Required: Monitor extension installations
    "storage",          // Required: Store scan results and settings
    "notifications"     // Required: Alert users to threats
    // REMOVED: "webRequest" - Not actually used
    // REMOVED: "downloads" - Not needed
  ],
  "host_permissions": [
    // CHANGED from "<all_urls>" to specific domain
    "https://clients2.google.com/*"  // Only for CRX downloads
  ]
}
```

#### Step 1.2: Test Functionality

```bash
# Rebuild
npm run build

# Load extension in Brave
# Test:
# - Extension scanning still works
# - Notifications still work
# - Settings save/load works
# - CRX download attempts (may fail due to CORS - that's expected)
```

#### Step 1.3: Verify No Functionality Lost

If tests fail:
- Check console for permission errors
- Identify which permission is actually needed
- Add back ONLY what's necessary

---

### 2. Initialize Git Repository (10 minutes)

**All source code is currently untracked!**

#### Step 2.1: Review .gitignore

```bash
cat .gitignore
```

Should contain:
```
node_modules/
dist/
build/
coverage/
*.log
.DS_Store
.env
.env.*
```

#### Step 2.2: Initial Commit

```bash
cd /Users/geeknik/brave_Ext/brave-extension-scanner

# Stage all source files
git add .gitignore
git add package.json package-lock.json
git add babel.config.js jest.config.js webpack.config.js
git add manifest.json background.js popup.js popup.html styles.css
git add src/
git add tests/
git add test-extensions/
git add icons/
git add README.md LICENSE DESIGN.md CHANGES.md
git add AUDIT_REPORT.md ACTION_PLAN.md

# Commit
git commit -m "chore: initial commit - Brave Extension Scanner v0.1.0

- Core analyzers: static, manifest, obfuscation, network, threat
- 87% test coverage with comprehensive test suite
- Post-installation scanning working
- UI with dashboard, scan options, history

Known issues:
- Using mock acorn/jszip libraries
- Cannot block pre-installation (MV3 limitation)
- CRX download from Web Store unreliable"

# Push to remote (if exists)
git push origin main
```

---

### 3. Replace Mock Libraries with Real Implementations (2-3 hours)

**Currently using simplified mocks instead of real acorn and jszip.**

#### Step 3.1: Verify Current Dependencies

```bash
# Check what's installed
npm list acorn jszip acorn-walk

# Should show:
# acorn@8.10.0
# acorn-walk@8.2.0  
# jszip@3.10.1
```

#### Step 3.2: Remove Mock Libraries

```bash
# Delete the mock files
rm -rf src/lib/acorn.js
rm -rf src/lib/acorn-walk.js
```

#### Step 3.3: Update Import Statements

**File: src/analyzers/static-analyzer.js**

Change:
```javascript
// OLD
import * as acorn from '../lib/acorn.js';
import * as walk from '../lib/acorn-walk.js';
```

To:
```javascript
// NEW
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
```

**File: src/utils/extension-files.js**

Change:
```javascript
// OLD
async function extractZipFromArrayBuffer(zipData) {
  if (typeof JSZip === 'undefined') {
    throw new Error('JSZip not available');
  }
  const zip = await JSZip.loadAsync(zipData);
  return zip;
}
```

To:
```javascript
// NEW
import JSZip from 'jszip';

async function extractZipFromArrayBuffer(zipData) {
  const zip = await JSZip.loadAsync(zipData);
  return zip;
}
```

Remove the `simulateZipExtraction()` mock function entirely.

#### Step 3.4: Update Webpack Configuration

**File: webpack.config.js**

The current config should already handle this, but verify:

```javascript
module.exports = {
  resolve: {
    fallback: {
      "stream": require.resolve("stream-browserify"),
      "buffer": require.resolve("buffer/"),
      "path": require.resolve("path-browserify"),
      "util": require.resolve("util/")
    }
  },
  // ... rest of config
};
```

#### Step 3.5: Test Build

```bash
npm run build

# Check for errors
# If successful, dist/ should contain bundled code with real libraries
```

#### Step 3.6: Test Functionality

```bash
# Load the rebuilt extension in Brave
# Test:
# 1. Scan a test extension
# 2. Check console for AST parsing errors
# 3. Verify obfuscation detection still works
# 4. Run test suite: npm test
```

#### Step 3.7: Update Tests

**File: tests/analyzers/static-analyzer.test.js**

Remove the mock setup:
```javascript
// DELETE THIS ENTIRE SECTION:
jest.mock('../../src/lib/acorn.js', () => ({
  parse: jest.fn((code) => {
    return {
      type: 'Program',
      body: []
    };
  })
}));

jest.mock('../../src/lib/acorn-walk.js', () => ({
  simple: jest.fn((ast, visitors) => {
    // Mock implementation
  })
}));
```

Instead, test against the real library:
```javascript
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

describe('StaticAnalyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new StaticAnalyzer();
  });

  test('should parse valid JavaScript with real acorn', () => {
    const code = 'const x = 42;';
    const result = analyzer.analyzeCode(code);
    expect(result).toBeDefined();
    expect(result.riskScore).toBeDefined();
  });
  
  // ... rest of tests
});
```

Run tests:
```bash
npm test
```

---

### 4. Update README with MV3 Limitations (30 minutes)

**Users need to understand what the extension can and cannot do.**

#### Step 4.1: Add Limitations Section

**File: README.md**

Add after the "Features" section:

```markdown
## Important Limitations

### ⚠️ Chrome Manifest V3 Restrictions

Due to Chrome's Manifest V3 architecture, this extension **cannot**:

❌ **Block extensions before installation completes**  
- Extensions are scanned **after** they're already installed
- We can disable/alert but cannot prevent initial installation

❌ **Access files from Chrome Web Store extensions**  
- Can only read metadata and manifest information
- Cannot analyze actual JavaScript code for Web Store extensions
- Full code analysis only works for unpacked/sideloaded extensions

❌ **Monitor all network requests**  
- Can only use declarativeNetRequest (limited functionality)
- Cannot intercept/modify extension network traffic

### ✅ What This Extension CAN Do

✅ **Scan extensions immediately after installation**  
✅ **Analyze unpacked/developer extensions completely**  
✅ **Detect dangerous permissions and suspicious patterns**  
✅ **Alert you to potential threats**  
✅ **Disable malicious extensions automatically**  
✅ **Track scan history and provide detailed reports**

### How It Works

1. **Installation Detection**: When you install an extension, we detect it immediately
2. **Post-Install Scanning**: We scan the extension's manifest and available code
3. **Threat Assessment**: Our analyzers check for malicious patterns
4. **User Alert**: If threats are found, you receive an alert with recommended actions
5. **Auto-Protection**: High-risk extensions can be disabled automatically

**Think of this as antivirus for browser extensions** - it scans what you install and protects you from threats, but it cannot prevent the initial installation like a firewall would.
```

#### Step 4.2: Add Setup Instructions

```markdown
## Installation & Setup

### For Users

1. Download the extension from the Chrome Web Store (coming soon)
2. Or build from source (see Developer Installation below)
3. Grant the requested permissions when prompted
4. Configure your security settings in the extension popup

### For Developers

#### Prerequisites
- Node.js 14+ and npm
- Git
- Brave or Chrome browser

#### Build from Source

\`\`\`bash
# Clone the repository
git clone https://github.com/yourusername/brave-extension-scanner.git
cd brave-extension-scanner

# Install dependencies
npm install

# Run tests
npm test

# Build for production
npm run build

# Build for development (with source maps)
npm run build:dev

# Watch mode (auto-rebuild on changes)
npm run watch
\`\`\`

#### Load in Brave/Chrome

1. Open `brave://extensions` (or `chrome://extensions`)
2. Enable "Developer mode" (toggle in top-right)
3. Click "Load unpacked"
4. Select the `dist/` directory from your build

#### Testing

We have test extensions in `test-extensions/` for validation:

\`\`\`bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
\`\`\`
```

---

### 5. Strengthen Content Security Policy (15 minutes)

**Current CSP is basic. Make it more restrictive.**

#### Step 5.1: Update manifest.json

```json
{
  "content_security_policy": {
    "extension_pages": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests;"
  }
}
```

#### Step 5.2: Test All Functionality

```bash
npm run build

# Load extension in Brave
# Test:
# - Popup opens correctly
# - Scans work
# - Reports display
# - No CSP violations in console
```

If you see CSP errors, you may need to relax specific directives.

---

## ✅ Verification Checklist

After completing Priority 0 tasks:

- [ ] `manifest.json` permissions reduced to minimum required
- [ ] Git repository initialized with all source files committed
- [ ] Real acorn and jszip libraries integrated (no more mocks)
- [ ] All tests pass: `npm test`
- [ ] Build succeeds: `npm run build`
- [ ] README updated with MV3 limitations clearly documented
- [ ] CSP strengthened and tested
- [ ] Extension loads without errors in Brave
- [ ] Can scan a test extension successfully
- [ ] Threat detection still works correctly

---

## 🔄 Next Steps (After Priority 0)

Once the critical fixes above are complete:

### Priority 1: Security Hardening (Week 2)

1. **Add Input Validation**
   - Validate all function inputs
   - Add size limits for code analysis
   - Prevent DoS attacks

2. **Sanitize Error Messages**
   - Remove sensitive data from logs
   - Implement proper error reporting

3. **Add Rate Limiting**
   - Prevent rapid scan abuse
   - Protect system resources

### Priority 2: Testing & Documentation (Week 3-4)

1. **Integration Tests**
   - End-to-end scan workflows
   - Real extension testing
   - Error condition testing

2. **Documentation**
   - API documentation
   - Architecture diagrams
   - Security policy

### Priority 3: Advanced Features (Month 2+)

1. **Pattern Database System**
2. **Performance Optimization** 
3. **CI/CD Pipeline**
4. **Firefox Support**

---

## 🆘 Troubleshooting

### Issue: Build fails after removing mock libraries

**Solution:**
```bash
# Clean rebuild
rm -rf node_modules dist
npm install
npm run build
```

### Issue: Tests fail with "Cannot find module 'acorn'"

**Solution:**
```bash
# Ensure dependencies are installed
npm install acorn acorn-walk jszip

# Clear jest cache
npx jest --clearCache

# Run tests again
npm test
```

### Issue: Extension throws error "JSZip is not defined"

**Solution:**
- Check webpack bundled JSZip correctly
- Verify import statement is correct
- Check dist/background.js contains JSZip code

### Issue: Scan results show "AST parsing failed"

**Possible causes:**
- Invalid JavaScript code (expected)
- Acorn not bundled correctly (check webpack output)
- Missing browser polyfills (check webpack config)

---

## 📊 Success Metrics

After completing Priority 0, you should have:

1. **Security Score:** 🟢 LOW risk (down from 🟡 MEDIUM-HIGH)
2. **Code Quality:** A- grade (all real libraries, no mocks)
3. **Git History:** Clean commit history started
4. **Documentation:** Clear user expectations set
5. **Permissions:** Minimal required permissions only

**Time Estimate:** 4-6 hours for complete Priority 0 implementation

---

**Last Updated:** September 29, 2025  
**Status:** READY TO EXECUTE

#!/usr/bin/env node

/**
 * Test Extension Validator
 * Validates that test extensions contain expected patterns for scanner testing
 */

const fs = require('fs');
const path = require('path');

const testExtensions = [
  {
    name: 'test-eval-usage',
    expectedPatterns: [
      'eval\\(',
      'new Function',
      'setTimeout.*"',
      'setInterval.*"',
      'document\\.write'
    ],
    expectedThreatLevel: 'HIGH',
    description: 'Dynamic code execution patterns'
  },
  {
    name: 'test-excessive-permissions',
    expectedPatterns: [
      'chrome\\.history',
      'chrome\\.bookmarks',
      'chrome\\.cookies',
      'chrome\\.management',
      'chrome\\.debugger'
    ],
    expectedThreatLevel: 'HIGH',
    description: 'Excessive permissions'
  },
  {
    name: 'test-obfuscated-code',
    expectedPatterns: [
      '\\\\x[0-9a-fA-F]{2}',
      '\\\\u[0-9a-fA-F]{4}',
      '_0x[0-9a-fA-F]+',
      'atob\\(',
      'fromCharCode'
    ],
    expectedThreatLevel: 'MEDIUM-HIGH',
    description: 'Code obfuscation patterns'
  },
  {
    name: 'test-network-exfiltration',
    expectedPatterns: [
      'suspicious-domain\\.com',
      'data-collector\\.evil',
      'chrome\\.history',
      'chrome\\.bookmarks',
      'chrome\\.cookies',
      'fetch\\('
    ],
    expectedThreatLevel: 'CRITICAL',
    description: 'Data exfiltration patterns'
  },
  {
    name: 'test-keylogging',
    expectedPatterns: [
      'addEventListener.*keydown',
      'addEventListener.*keyup',
      'addEventListener.*keypress',
      'onkeydown',
      'onkeyup',
      'password'
    ],
    expectedThreatLevel: 'CRITICAL',
    description: 'Keylogging patterns'
  },
  {
    name: 'test-clean-extension',
    avoidPatterns: [
      'eval\\(',
      'chrome\\.history',
      'chrome\\.cookies',
      'keydown'
    ],
    expectedThreatLevel: 'SAFE',
    description: 'Clean extension (control)'
  }
];

function validateTestExtension(testConfig) {
  const extensionPath = path.join(__dirname, testConfig.name);
  
  console.log(`\n🔍 Validating ${testConfig.name}`);
  console.log(`   Description: ${testConfig.description}`);
  console.log(`   Expected threat level: ${testConfig.expectedThreatLevel}`);
  
  if (!fs.existsSync(extensionPath)) {
    console.log(`   ❌ Extension directory not found: ${extensionPath}`);
    return false;
  }
  
  // Check manifest.json exists
  const manifestPath = path.join(extensionPath, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    console.log(`   ❌ manifest.json not found`);
    return false;
  }
  
  // Read all JavaScript files
  const jsFiles = [];
  const files = fs.readdirSync(extensionPath);
  
  files.forEach(file => {
    if (file.endsWith('.js')) {
      const filePath = path.join(extensionPath, file);
      const content = fs.readFileSync(filePath, 'utf8');
      jsFiles.push({ name: file, content });
    }
  });
  
  if (jsFiles.length === 0) {
    console.log(`   ❌ No JavaScript files found`);
    return false;
  }
  
  console.log(`   📁 Found ${jsFiles.length} JS files: ${jsFiles.map(f => f.name).join(', ')}`);
  
  // Combine all JS content for pattern matching
  const allJsContent = jsFiles.map(f => f.content).join('\n');
  
  // Check expected patterns
  if (testConfig.expectedPatterns) {
    const foundPatterns = [];
    const missingPatterns = [];
    
    testConfig.expectedPatterns.forEach(pattern => {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(allJsContent)) {
        foundPatterns.push(pattern);
      } else {
        missingPatterns.push(pattern);
      }
    });
    
    console.log(`   ✅ Found patterns (${foundPatterns.length}/${testConfig.expectedPatterns.length}): ${foundPatterns.join(', ')}`);
    
    if (missingPatterns.length > 0) {
      console.log(`   ⚠️  Missing patterns: ${missingPatterns.join(', ')}`);
    }
    
    // Should find at least 70% of expected patterns
    const successRate = foundPatterns.length / testConfig.expectedPatterns.length;
    if (successRate < 0.7) {
      console.log(`   ❌ Insufficient pattern coverage: ${Math.round(successRate * 100)}%`);
      return false;
    }
  }
  
  // Check avoid patterns (for clean extension)
  if (testConfig.avoidPatterns) {
    const foundBadPatterns = [];
    
    testConfig.avoidPatterns.forEach(pattern => {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(allJsContent)) {
        foundBadPatterns.push(pattern);
      }
    });
    
    if (foundBadPatterns.length > 0) {
      console.log(`   ❌ Found suspicious patterns in clean extension: ${foundBadPatterns.join(', ')}`);
      return false;
    } else {
      console.log(`   ✅ No suspicious patterns found (as expected)`);
    }
  }
  
  // Check manifest for permissions
  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const permissions = manifest.permissions || [];
    const hostPermissions = manifest.host_permissions || [];
    
    console.log(`   📋 Permissions: ${permissions.join(', ')}`);
    if (hostPermissions.length > 0) {
      console.log(`   🌐 Host permissions: ${hostPermissions.join(', ')}`);
    }
    
    // Validate permission expectations
    if (testConfig.name === 'test-excessive-permissions') {
      const dangerousPerms = ['history', 'bookmarks', 'cookies', 'management', 'debugger'];
      const foundDangerous = permissions.filter(p => dangerousPerms.includes(p));
      
      if (foundDangerous.length < 3) {
        console.log(`   ⚠️  Expected more dangerous permissions, found: ${foundDangerous.join(', ')}`);
      }
    }
    
    if (testConfig.name === 'test-clean-extension') {
      const dangerousPerms = ['history', 'bookmarks', 'cookies', 'management', 'debugger', 'webRequest'];
      const foundDangerous = permissions.filter(p => dangerousPerms.includes(p));
      
      if (foundDangerous.length > 0) {
        console.log(`   ❌ Clean extension has dangerous permissions: ${foundDangerous.join(', ')}`);
        return false;
      }
    }
    
  } catch (e) {
    console.log(`   ❌ Error reading manifest: ${e.message}`);
    return false;
  }
  
  console.log(`   ✅ Validation passed`);
  return true;
}

function main() {
  console.log('🧪 Brave Extension Scanner - Test Extension Validator');
  console.log('=' .repeat(60));
  
  let allPassed = true;
  const results = [];
  
  testExtensions.forEach(testConfig => {
    const passed = validateTestExtension(testConfig);
    results.push({ name: testConfig.name, passed, expectedLevel: testConfig.expectedThreatLevel });
    
    if (!passed) {
      allPassed = false;
    }
  });
  
  console.log('\n📊 Validation Summary');
  console.log('=' .repeat(60));
  
  results.forEach(result => {
    const status = result.passed ? '✅ PASS' : '❌ FAIL';
    console.log(`${status} ${result.name.padEnd(25)} (Expected: ${result.expectedLevel})`);
  });
  
  console.log('\n' + '=' .repeat(60));
  
  if (allPassed) {
    console.log('🎉 All test extensions validated successfully!');
    console.log('\n📋 Next Steps:');
    console.log('1. Build the scanner: npm run build');
    console.log('2. Load scanner extension in browser');
    console.log('3. Load and test each test extension');
    console.log('4. Verify scanner detects expected threat levels');
  } else {
    console.log('❌ Some test extensions failed validation');
    console.log('   Fix the issues above before testing the scanner');
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { validateTestExtension, testExtensions };
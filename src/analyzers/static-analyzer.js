/**
 * Static Analyzer Module
 * Performs static analysis on extension code to detect malicious patterns
 * Uses AST-based analysis for more accurate detection
 */

// Import real acorn and acorn-walk libraries (bundled by webpack)
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

class StaticAnalyzer {
  constructor() {
    // Define patterns for regex-based analysis (as fallback)
    this.patterns = {
      // Eval and dynamic code execution
      evalPatterns: [
        /eval\s*\(/g,
        /new\s+Function\s*\(/g,
        /setTimeout\s*\(\s*['"`]/g,
        /setInterval\s*\(\s*['"`]/g,
        /document\.write\s*\(/g,
        /String\.fromCharCode/g,
        /atob\s*\(/g,
        /btoa\s*\(/g,
        /\.apply\s*\(\s*null\s*,/g,
        /\['.*'\]\s*\+\s*\['.*'\]/g  // Computed property concatenation
      ],
      
      // Remote code loading
      remoteCodePatterns: [
        /\.appendChild\s*\(\s*document\.createElement\s*\(\s*['"`]script['"`]\s*\)\s*\)/g,
        /document\.createElement\s*\(\s*['"`]script['"`]\s*\)[\s\S]{0,50}\.src\s*=/g,
        /\.innerHTML\s*=\s*['"`]<script/g
      ],
      
      // Cookie theft
      cookieTheftPatterns: [
        /document\.cookie/g,
        /chrome\.cookies\.get/g,
        /chrome\.cookies\.getAll/g
      ],
      
      // History/bookmark exfiltration
      dataExfiltrationPatterns: [
        /chrome\.history\./g,
        /chrome\.bookmarks\./g,
        /chrome\.tabs\.query/g
      ],
      
      // DOM-based keyloggers
      keyloggerPatterns: [
        /addEventListener\s*\(\s*['"`]keydown['"`]/g,
        /addEventListener\s*\(\s*['"`]keyup['"`]/g,
        /addEventListener\s*\(\s*['"`]keypress['"`]/g,
        /onkeydown/g,
        /onkeyup/g,
        /onkeypress/g
      ],
      
      // Browser fingerprinting
      fingerprintingPatterns: [
        /navigator\.userAgent/g,
        /navigator\.platform/g,
        /navigator\.language/g,
        /navigator\.languages/g,
        /screen\.width/g,
        /screen\.height/g,
        /screen\.colorDepth/g,
        /navigator\.plugins/g,
        /navigator\.mimeTypes/g
      ],
      
      // Advanced malware patterns
      malwarePatterns: [
        // Cryptocurrency mining
        /crypto\s*\.\s*getRandomValues/g,
        /WebAssembly/g,
        /worker\s*\.\s*postMessage/g,
        /setInterval\s*\(\s*function\s*\(\s*\)\s*\{[\s\S]*?crypto/g,
        
        // Form hijacking
        /addEventListener\s*\(\s*['"`]submit['"`]/g,
        /form\s*\.\s*addEventListener/g,
        /input\s*\[.*type.*password.*\]/g,
        
        // Clickjacking
        /pointer-events\s*:\s*none/g,
        /opacity\s*:\s*0/g,
        /visibility\s*:\s*hidden/g,
        
        // Social engineering
        /alert\s*\(/g,
        /confirm\s*\(/g,
        /prompt\s*\(/g,
        /window\s*\.\s*open/g,
        
        // Data exfiltration
        /XMLHttpRequest/g,
        /fetch\s*\(/g,
        /WebSocket/g,
        /EventSource/g,
        
        // Steganography/encoding
        /fromCharCode\s*\(/g,
        /charCodeAt\s*\(/g,
        /btoa\s*\(/g,
        /atob\s*\(/g,
        
        // Anti-debugging
        /debugger\s*;/g,
        /console\s*\.\s*clear/g,
        /setInterval\s*\(\s*function\s*\(\s*\)\s*\{[\s\S]*?debugger/g,
        
        // Persistence mechanisms
        /localStorage/g,
        /sessionStorage/g,
        /indexedDB/g,
        /chrome\s*\.\s*storage/g,
        
        // Network evasion
        /Math\s*\.\s*random/g,
        /Date\s*\.\s*now/g,
        /setTimeout\s*\(\s*Math\s*\.\s*random/g,
        
        // Code injection
        /innerHTML\s*=/g,
        /outerHTML\s*=/g,
        /insertAdjacentHTML/g,
        /document\s*\.\s*write/g
      ],
      
      // Behavioral analysis patterns
      behavioralPatterns: [
        // Suspicious timing patterns
        /setTimeout\s*\(\s*[^,]*,\s*[0-9]{4,}/g, // Long delays
        /setInterval\s*\(\s*[^,]*,\s*[0-9]{4,}/g, // Long intervals
        
        // Stealth patterns
        /try\s*\{[\s\S]*?\}\s*catch/g,
        /typeof\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*===?\s*['"`]undefined['"`]/g,
        
        // Environment detection
        /window\s*\.\s*chrome/g,
        /navigator\s*\.\s*webdriver/g,
        /window\s*\.\s*phantom/g,
        
        // Communication patterns
        /postMessage\s*\(/g,
        /addEventListener\s*\(\s*['"`]message['"`]/g,
        /chrome\s*\.\s*runtime\s*\.\s*sendMessage/g,
        /chrome\s*\.\s*runtime\s*\.\s*onMessage/g
      ]
    };
    
    // Define AST patterns for more accurate detection
    this.astPatterns = {
      // Dynamic code execution patterns
      evalPatterns: {
        // Direct eval calls
        evalCall: (node) => 
          node.type === 'CallExpression' && 
          node.callee.type === 'Identifier' && 
          node.callee.name === 'eval',
        
        // new Function() constructor
        functionConstructor: (node) => 
          node.type === 'NewExpression' && 
          node.callee.type === 'Identifier' && 
          node.callee.name === 'Function',
        
        // setTimeout/setInterval with string argument
        timerWithString: (node) => 
          node.type === 'CallExpression' && 
          node.callee.type === 'Identifier' && 
          (node.callee.name === 'setTimeout' || node.callee.name === 'setInterval') &&
          node.arguments.length > 0 &&
          node.arguments[0].type === 'Literal' &&
          typeof node.arguments[0].value === 'string',
        
        // document.write
        documentWrite: (node) => 
          node.type === 'CallExpression' && 
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'document' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'write',
        
        // String.fromCharCode obfuscation
        stringFromCharCode: (node) =>
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'String' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'fromCharCode',
        
        // atob/btoa base64 functions
        base64Functions: (node) =>
          node.type === 'CallExpression' &&
          node.callee.type === 'Identifier' &&
          (node.callee.name === 'atob' || node.callee.name === 'btoa'),
        
        // Function.apply with null context (common obfuscation)
        functionApply: (node) =>
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'apply' &&
          node.arguments.length >= 1 &&
          node.arguments[0].type === 'Literal' &&
          node.arguments[0].value === null
      },
      
      // Remote code loading patterns
      remoteCodePatterns: {
        // script element creation
        scriptCreation: (node, parent, ancestors) => {
          if (node.type === 'CallExpression' && 
              node.callee.type === 'MemberExpression' &&
              node.callee.object.type === 'Identifier' &&
              node.callee.object.name === 'document' &&
              node.callee.property.type === 'Identifier' &&
              node.callee.property.name === 'createElement' &&
              node.arguments.length > 0 &&
              node.arguments[0].type === 'Literal' &&
              node.arguments[0].value === 'script') {
            
            // Look for script.src assignment in parent nodes (with null check)
            if (ancestors && ancestors.length > 0) {
              for (let i = ancestors.length - 1; i >= 0; i--) {
                const ancestor = ancestors[i];
                if (ancestor && ancestor.type === 'AssignmentExpression' &&
                    ancestor.left && ancestor.left.type === 'MemberExpression' &&
                    ancestor.left.property && ancestor.left.property.type === 'Identifier' &&
                    ancestor.left.property.name === 'src') {
                  return true;
                }
              }
            }
            // Return true for any script creation, even without src assignment
            return true;
          }
          return false;
        },
        
        // innerHTML with script tag
        innerHTMLScript: (node) => 
          node.type === 'AssignmentExpression' &&
          node.left.type === 'MemberExpression' &&
          node.left.property.type === 'Identifier' &&
          node.left.property.name === 'innerHTML' &&
          node.right.type === 'Literal' &&
          typeof node.right.value === 'string' &&
          node.right.value.includes('<script')
      },
      
      // Cookie access patterns
      cookiePatterns: {
        // document.cookie access
        documentCookie: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'Identifier' &&
          node.object.name === 'document' &&
          node.property.type === 'Identifier' &&
          node.property.name === 'cookie',
        
        // chrome.cookies API
        chromeCookies: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'MemberExpression' &&
          node.object.object.type === 'Identifier' &&
          node.object.object.name === 'chrome' &&
          node.object.property.type === 'Identifier' &&
          node.object.property.name === 'cookies'
      },
      
      // Data exfiltration patterns
      dataExfiltrationPatterns: {
        // chrome.history API
        chromeHistory: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'MemberExpression' &&
          node.object.object.type === 'Identifier' &&
          node.object.object.name === 'chrome' &&
          node.object.property.type === 'Identifier' &&
          node.object.property.name === 'history',
        
        // chrome.bookmarks API
        chromeBookmarks: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'MemberExpression' &&
          node.object.object.type === 'Identifier' &&
          node.object.object.name === 'chrome' &&
          node.object.property.type === 'Identifier' &&
          node.object.property.name === 'bookmarks',
        
        // chrome.tabs.query
        chromeTabsQuery: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'MemberExpression' &&
          node.callee.object.object.type === 'Identifier' &&
          node.callee.object.object.name === 'chrome' &&
          node.callee.object.property.type === 'Identifier' &&
          node.callee.object.property.name === 'tabs' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'query'
      },
      
      // Keylogging patterns
      keyloggingPatterns: {
        // addEventListener for keyboard events
        keyboardEventListener: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'addEventListener' &&
          node.arguments.length >= 1 &&
          node.arguments[0].type === 'Literal' &&
          typeof node.arguments[0].value === 'string' &&
          ['keydown', 'keyup', 'keypress'].includes(node.arguments[0].value),
        
        // onkeydown, onkeyup, onkeypress properties
        keyboardEventProperty: (node) => 
          node.type === 'AssignmentExpression' &&
          node.left.type === 'MemberExpression' &&
          node.left.property.type === 'Identifier' &&
          ['onkeydown', 'onkeyup', 'onkeypress'].includes(node.left.property.name)
      },
      
      // Browser fingerprinting patterns
      fingerprintingPatterns: {
        // navigator properties
        navigatorProperties: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'Identifier' &&
          node.object.name === 'navigator' &&
          node.property.type === 'Identifier' &&
          ['userAgent', 'platform', 'language', 'languages', 'plugins', 'mimeTypes'].includes(node.property.name),
        
        // screen properties
        screenProperties: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'Identifier' &&
          node.object.name === 'screen' &&
          node.property.type === 'Identifier' &&
          ['width', 'height', 'colorDepth', 'pixelDepth', 'availWidth', 'availHeight'].includes(node.property.name)
      },
      
      // Advanced malware patterns
      malwarePatterns: {
        // Cryptocurrency mining
        cryptoMining: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'Identifier' &&
          node.object.name === 'crypto' &&
          node.property.type === 'Identifier' &&
          node.property.name === 'getRandomValues',
        
        webAssembly: (node) => 
          node.type === 'Identifier' &&
          node.name === 'WebAssembly',
        
        // Form hijacking
        formSubmitListener: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'addEventListener' &&
          node.arguments.length >= 1 &&
          node.arguments[0].type === 'Literal' &&
          node.arguments[0].value === 'submit',
        
        // Social engineering
        alertCall: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'Identifier' &&
          ['alert', 'confirm', 'prompt'].includes(node.callee.name),
        
        windowOpen: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'window' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'open',
        
        // Data exfiltration
        networkRequest: (node) => 
          node.type === 'NewExpression' &&
          node.callee.type === 'Identifier' &&
          ['XMLHttpRequest', 'WebSocket', 'EventSource'].includes(node.callee.name),
        
        fetchCall: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'Identifier' &&
          node.callee.name === 'fetch',
        
        // Anti-debugging
        debuggerStatement: (node) => 
          node.type === 'DebuggerStatement',
        
        consoleClear: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'console' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'clear',
        
        // Persistence mechanisms
        storageAccess: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'Identifier' &&
          ['localStorage', 'sessionStorage'].includes(node.object.name),
        
        chromeStorage: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'MemberExpression' &&
          node.object.object.type === 'Identifier' &&
          node.object.object.name === 'chrome' &&
          node.object.property.type === 'Identifier' &&
          node.object.property.name === 'storage'
      },
      
      // Behavioral analysis patterns
      behavioralPatterns: {
        // Suspicious timing
        longTimeout: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'Identifier' &&
          (node.callee.name === 'setTimeout' || node.callee.name === 'setInterval') &&
          node.arguments.length >= 2 &&
          node.arguments[1].type === 'Literal' &&
          typeof node.arguments[1].value === 'number' &&
          node.arguments[1].value > 10000, // 10+ seconds
        
        // Environment detection
        chromeDetection: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'Identifier' &&
          node.object.name === 'window' &&
          node.property.type === 'Identifier' &&
          node.property.name === 'chrome',
        
        webdriverDetection: (node) => 
          node.type === 'MemberExpression' &&
          node.object.type === 'MemberExpression' &&
          node.object.object.type === 'Identifier' &&
          node.object.object.name === 'navigator' &&
          node.object.property.type === 'Identifier' &&
          node.object.property.name === 'webdriver',
        
        // Communication patterns
        postMessage: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === 'postMessage',
        
        chromeRuntimeMessage: (node) => 
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'MemberExpression' &&
          node.callee.object.object.type === 'MemberExpression' &&
          node.callee.object.object.object.type === 'Identifier' &&
          node.callee.object.object.object.name === 'chrome' &&
          node.callee.object.object.property.type === 'Identifier' &&
          node.callee.object.object.property.name === 'runtime' &&
          node.callee.object.property.type === 'Identifier' &&
          node.callee.object.property.name === 'sendMessage'
      }
    };
  }
  
  /**
   * Analyze JavaScript code for suspicious patterns
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Analysis results
   */
  analyzeCode(code) {
    // Input validation
    if (typeof code !== 'string') {
      throw new TypeError('Code must be a string');
    }
    
    if (code.length === 0) {
      return {
        evalUsage: [],
        remoteCodeLoading: [],
        cookieAccess: [],
        dataExfiltration: [],
        keylogging: [],
        fingerprinting: [],
        riskScore: 0,
        suspiciousPatterns: []
      };
    }
    
    // Size limit: 10MB to prevent DoS
    const MAX_CODE_SIZE = 10 * 1024 * 1024; // 10MB
    if (code.length > MAX_CODE_SIZE) {
      console.warn(`Code size ${code.length} exceeds maximum ${MAX_CODE_SIZE} bytes`);
      throw new Error(`Code exceeds maximum size of ${MAX_CODE_SIZE} bytes`);
    }
    
    // Initialize results
    const results = {
      evalUsage: [],
      remoteCodeLoading: [],
      cookieAccess: [],
      dataExfiltration: [],
      keylogging: [],
      fingerprinting: [],
      malware: [],
      behavioral: []
    };
    
    // Attempt to parse the code into an AST
    let ast;
    try {
      ast = acorn.parse(code, { ecmaVersion: 'latest', locations: true, errorRecovery: true });
    } catch (e) {
      // If parsing fails, fall back to regex-based analysis
      results.error = `AST parsing failed: ${e.message}`;
      results.evalUsage = this.detectPatterns(code, this.patterns.evalPatterns);
      results.remoteCodeLoading = this.detectPatterns(code, this.patterns.remoteCodePatterns);
      results.cookieAccess = this.detectPatterns(code, this.patterns.cookieTheftPatterns);
      results.dataExfiltration = this.detectPatterns(code, this.patterns.dataExfiltrationPatterns);
      results.keylogging = this.detectPatterns(code, this.patterns.keyloggerPatterns);
      results.fingerprinting = this.detectPatterns(code, this.patterns.fingerprintingPatterns);
      results.malware = this.detectPatterns(code, this.patterns.malwarePatterns);
      results.behavioral = this.detectPatterns(code, this.patterns.behavioralPatterns);
      results.riskScore = this.calculateRiskScore(results);
      return results;
    }
    
    // Perform AST-based analysis
    if (ast && ast.body) {
      this.analyzeAST(ast, code, results);
    } else {
      console.warn('AST parsing returned invalid result, falling back to regex analysis');
      results.evalUsage = this.detectPatterns(code, this.patterns.evalPatterns);
      results.remoteCodeLoading = this.detectPatterns(code, this.patterns.remoteCodePatterns);
      results.cookieAccess = this.detectPatterns(code, this.patterns.cookieTheftPatterns);
      results.dataExfiltration = this.detectPatterns(code, this.patterns.dataExfiltrationPatterns);
      results.keylogging = this.detectPatterns(code, this.patterns.keyloggerPatterns);
      results.fingerprinting = this.detectPatterns(code, this.patterns.fingerprintingPatterns);
      results.malware = this.detectPatterns(code, this.patterns.malwarePatterns);
      results.behavioral = this.detectPatterns(code, this.patterns.behavioralPatterns);
    }
    
    results.riskScore = this.calculateRiskScore(results);
    
    return results;
  }
  
  /**
   * Traverse the AST and check for malicious patterns
   * @param {Object} ast - The AST object from Acorn
   * @param {string} code - Original code for context
   * @param {Object} results - The results object to populate
   */
  analyzeAST(ast, code, results) {
    const getNodeContext = (node) => {
      const { start, end } = node.loc;
      const snippet = code.substring(node.start, node.end);
      return {
        line: start.line,
        column: start.column,
        snippet: snippet.length > 100 ? snippet.substring(0, 97) + '...' : snippet
      };
    };
    
    const addMatch = (category, patternName, node, description) => {
      results[category].push({
        type: patternName,
        ...getNodeContext(node),
        description
      });
    };
    
    // Use acorn's simple walk with proper context
    const self = this;
    walk.simple(ast, {
      CallExpression(node, _, ancestors) {
        // eval
        if (self.astPatterns.evalPatterns.evalCall(node)) {
          addMatch('evalUsage', 'evalCall', node, 'Direct call to eval()');
        }
        
        // setTimeout/setInterval with string
        if (self.astPatterns.evalPatterns.timerWithString(node)) {
          addMatch('evalUsage', 'timerWithString', node, 'setTimeout/setInterval with string argument');
        }
        
        // script creation
        if (self.astPatterns.remoteCodePatterns.scriptCreation(node, _, ancestors)) {
          addMatch('remoteCodeLoading', 'scriptCreation', node, 'Dynamic script element creation and src assignment');
        }
        
        // chrome.tabs.query
        if (self.astPatterns.dataExfiltrationPatterns.chromeTabsQuery(node)) {
          addMatch('dataExfiltration', 'chromeTabsQuery', node, 'Access to chrome.tabs.query');
        }
        
        // addEventListener
        if (self.astPatterns.keyloggingPatterns.keyboardEventListener(node)) {
          addMatch('keylogging', 'keyboardEventListener', node, 'Keyboard event listener attached');
        }
        
        // String.fromCharCode obfuscation
        if (self.astPatterns.evalPatterns.stringFromCharCode(node)) {
          addMatch('evalUsage', 'stringFromCharCode', node, 'String.fromCharCode obfuscation detected');
        }
        
        // Base64 functions
        if (self.astPatterns.evalPatterns.base64Functions(node)) {
          addMatch('evalUsage', 'base64Functions', node, 'Base64 encoding/decoding function');
        }
        
        // Function.apply obfuscation
        if (self.astPatterns.evalPatterns.functionApply(node)) {
          addMatch('evalUsage', 'functionApply', node, 'Function.apply with null context');
        }
      },
      
      NewExpression(node) {
        // new Function()
        if (self.astPatterns.evalPatterns.functionConstructor(node)) {
          addMatch('evalUsage', 'functionConstructor', node, 'new Function() constructor');
        }
      },
      
      AssignmentExpression(node) {
        // innerHTML
        if (self.astPatterns.remoteCodePatterns.innerHTMLScript(node)) {
          addMatch('remoteCodeLoading', 'innerHTMLScript', node, 'innerHTML assignment with script tag');
        }
        
        // keyboard event properties
        if (self.astPatterns.keyloggingPatterns.keyboardEventProperty(node)) {
          addMatch('keylogging', 'keyboardEventProperty', node, 'Assignment to onkeydown/onkeyup/onkeypress');
        }
      },
      
      MemberExpression(node) {
        // document.cookie
        if (self.astPatterns.cookiePatterns.documentCookie(node)) {
          addMatch('cookieAccess', 'documentCookie', node, 'Access to document.cookie');
        }
        
        // chrome.cookies
        if (self.astPatterns.cookiePatterns.chromeCookies(node)) {
          addMatch('cookieAccess', 'chromeCookies', node, 'Access to chrome.cookies API');
        }
        
        // chrome.history
        if (self.astPatterns.dataExfiltrationPatterns.chromeHistory(node)) {
          addMatch('dataExfiltration', 'chromeHistory', node, 'Access to chrome.history API');
        }
        
        // chrome.bookmarks
        if (self.astPatterns.dataExfiltrationPatterns.chromeBookmarks(node)) {
          addMatch('dataExfiltration', 'chromeBookmarks', node, 'Access to chrome.bookmarks API');
        }
        
        // Fingerprinting
        if (self.astPatterns.fingerprintingPatterns.navigatorProperties(node)) {
          addMatch('fingerprinting', 'navigatorProperties', node, `Navigator property accessed: ${node.property.name}`);
        }
        
        if (self.astPatterns.fingerprintingPatterns.screenProperties(node)) {
          addMatch('fingerprinting', 'screenProperties', node, `Screen property accessed: ${node.property.name}`);
        }
        
        // Advanced malware patterns
        if (self.astPatterns.malwarePatterns.cryptoMining(node)) {
          addMatch('malware', 'cryptoMining', node, 'Cryptocurrency mining detected');
        }
        
        if (self.astPatterns.malwarePatterns.webAssembly(node)) {
          addMatch('malware', 'webAssembly', node, 'WebAssembly usage detected');
        }
        
        if (self.astPatterns.malwarePatterns.storageAccess(node)) {
          addMatch('malware', 'storageAccess', node, `Storage access: ${node.object.name}`);
        }
        
        if (self.astPatterns.malwarePatterns.chromeStorage(node)) {
          addMatch('malware', 'chromeStorage', node, 'Chrome storage API access');
        }
        
        // Behavioral patterns
        if (self.astPatterns.behavioralPatterns.chromeDetection(node)) {
          addMatch('behavioral', 'chromeDetection', node, 'Chrome environment detection');
        }
        
        if (self.astPatterns.behavioralPatterns.webdriverDetection(node)) {
          addMatch('behavioral', 'webdriverDetection', node, 'WebDriver detection (anti-automation)');
        }
      },
      
      CallExpression(node, _, ancestors) {
        // Existing patterns...
        if (self.astPatterns.evalPatterns.evalCall(node)) {
          addMatch('evalUsage', 'evalCall', node, 'Direct call to eval()');
        }
        
        if (self.astPatterns.evalPatterns.timerWithString(node)) {
          addMatch('evalUsage', 'timerWithString', node, 'setTimeout/setInterval with string argument');
        }
        
        if (self.astPatterns.remoteCodePatterns.scriptCreation(node, _, ancestors)) {
          addMatch('remoteCodeLoading', 'scriptCreation', node, 'Dynamic script element creation and src assignment');
        }
        
        if (self.astPatterns.dataExfiltrationPatterns.chromeTabsQuery(node)) {
          addMatch('dataExfiltration', 'chromeTabsQuery', node, 'Access to chrome.tabs.query');
        }
        
        if (self.astPatterns.keyloggingPatterns.keyboardEventListener(node)) {
          addMatch('keylogging', 'keyboardEventListener', node, 'Keyboard event listener attached');
        }
        
        if (self.astPatterns.evalPatterns.stringFromCharCode(node)) {
          addMatch('evalUsage', 'stringFromCharCode', node, 'String.fromCharCode obfuscation detected');
        }
        
        if (self.astPatterns.evalPatterns.base64Functions(node)) {
          addMatch('evalUsage', 'base64Functions', node, 'Base64 encoding/decoding function');
        }
        
        if (self.astPatterns.evalPatterns.functionApply(node)) {
          addMatch('evalUsage', 'functionApply', node, 'Function.apply with null context');
        }
        
        // New malware patterns
        if (self.astPatterns.malwarePatterns.formSubmitListener(node)) {
          addMatch('malware', 'formSubmitListener', node, 'Form submission hijacking detected');
        }
        
        if (self.astPatterns.malwarePatterns.alertCall(node)) {
          addMatch('malware', 'alertCall', node, `Social engineering: ${node.callee.name}() call`);
        }
        
        if (self.astPatterns.malwarePatterns.windowOpen(node)) {
          addMatch('malware', 'windowOpen', node, 'Window.open() call - potential popup abuse');
        }
        
        if (self.astPatterns.malwarePatterns.fetchCall(node)) {
          addMatch('malware', 'fetchCall', node, 'Fetch API call - potential data exfiltration');
        }
        
        if (self.astPatterns.malwarePatterns.consoleClear(node)) {
          addMatch('malware', 'consoleClear', node, 'Console.clear() - anti-debugging technique');
        }
        
        // New behavioral patterns
        if (self.astPatterns.behavioralPatterns.longTimeout(node)) {
          addMatch('behavioral', 'longTimeout', node, `Suspicious long delay: ${node.arguments[1].value}ms`);
        }
        
        if (self.astPatterns.behavioralPatterns.postMessage(node)) {
          addMatch('behavioral', 'postMessage', node, 'PostMessage communication');
        }
        
        if (self.astPatterns.behavioralPatterns.chromeRuntimeMessage(node)) {
          addMatch('behavioral', 'chromeRuntimeMessage', node, 'Chrome runtime message passing');
        }
      },
      
      NewExpression(node) {
        if (self.astPatterns.evalPatterns.functionConstructor(node)) {
          addMatch('evalUsage', 'functionConstructor', node, 'new Function() constructor');
        }
        
        if (self.astPatterns.malwarePatterns.networkRequest(node)) {
          addMatch('malware', 'networkRequest', node, `Network request: ${node.callee.name}`);
        }
      },
      
      DebuggerStatement(node) {
        if (self.astPatterns.malwarePatterns.debuggerStatement(node)) {
          addMatch('malware', 'debuggerStatement', node, 'Debugger statement - anti-debugging technique');
        }
      }
    });
  }
  
  /**
   * Fallback for detecting patterns using regex
   * @param {string} code - The code to analyze
   * @param {Array<RegExp>} patterns - Array of regex patterns
   * @returns {Array<Object>} Found matches
   */
  detectPatterns(code, patterns) {
    const found = [];
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        found.push({
          type: 'regex',
          match: match[0],
          // Basic line number calculation
          line: (code.substring(0, match.index).match(/\n/g) || []).length + 1
        });
      }
    }
    return found;
  }
  
  /**
   * Calculate risk score based on static analysis findings
   * @param {Object} results - Analysis results
   * @returns {number} Risk score (0-100)
   */
  calculateRiskScore(results) {
    let score = 0;
    
    const weights = {
      evalUsage: 25,
      remoteCodeLoading: 25,
      cookieAccess: 10,
      dataExfiltration: 15,
      keylogging: 20,
      fingerprinting: 5,
      malware: 30,        // High weight for advanced malware patterns
      behavioral: 15      // Medium weight for behavioral analysis
    };
    
    for (const key in weights) {
      if (results[key] && results[key].length > 0) {
        score += weights[key] * results[key].length;
      }
    }
    
    return Math.min(100, score);
  }
  
  /**
   * Summarize static analysis findings
   * @param {Object} results - Analysis results
   * @returns {Object} Summarized findings
   */
  summarizeFindings(results) {
    const summary = [];
    const categories = {
      evalUsage: 'Dynamic Code Execution',
      remoteCodeLoading: 'Remote Code Loading',
      cookieAccess: 'Cookie Access',
      dataExfiltration: 'Data Exfiltration',
      keylogging: 'Keylogging',
      fingerprinting: 'Browser Fingerprinting',
      malware: 'Advanced Malware',
      behavioral: 'Behavioral Analysis'
    };

    for (const key in categories) {
      if (results[key] && results[key].length > 0) {
        summary.push({
          category: categories[key],
          count: results[key].length,
          snippets: results[key].slice(0, 3).map(r => r.match || r.snippet || '')
        });
      }
    }
    return summary;
  }
}

export default StaticAnalyzer;
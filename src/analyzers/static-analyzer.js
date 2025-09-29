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
      fingerprinting: []
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
      fingerprinting: 'Browser Fingerprinting'
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
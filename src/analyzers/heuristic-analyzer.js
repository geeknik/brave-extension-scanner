/**
 * Heuristic Analyzer Module
 * Uses machine learning-inspired heuristics to detect sophisticated threats
 * that may not be caught by traditional pattern matching
 */

class HeuristicAnalyzer {
  constructor() {
    // Heuristic weights for different threat indicators
    this.heuristicWeights = {
      // Manifest-based indicators
      dangerousPermissions: 20,
      broadHostPermissions: 15,
      suspiciousContentScripts: 25,
      suspiciousFileNames: 10,
      
      // Static analysis indicators
      dynamicCodeExecution: 35,
      remoteCodeLoading: 30,
      keylogging: 40,
      dataExfiltration: 30,
      fingerprinting: 10,
      antiDebugging: 25,
      persistenceMechanisms: 15,
      environmentDetection: 10,
      longDelays: 5,
      
      // Obfuscation indicators
      highObfuscation: 30,
      
      // Network indicators
      suspiciousNetworkEndpoints: 20,
      bulkRequests: 20,
      stealthRequests: 15,
      c2Communication: 35,
      evasionTechniques: 20,
      
      // Special cases
      unreadableFiles: 15,
      
      // Legacy indicators (for backward compatibility)
      highComplexity: 15,
      unusualPatterns: 20,
      suspiciousNaming: 25,
      stealthBehavior: 30,
      
      // Statistical indicators
      entropyAnomalies: 35,
      frequencyAnomalies: 20,
      distributionAnomalies: 15,
      
      // Contextual indicators
      permissionMismatch: 40,
      functionalityMismatch: 35,
      timingAnomalies: 25
    };
    
    // Thresholds for heuristic scoring
    this.thresholds = {
      suspicious: 30,
      malicious: 60,
      critical: 80
    };
    
    // Known legitimate patterns (to reduce false positives)
    this.legitimatePatterns = [
      // Common library patterns
      /jquery/i,
      /lodash/i,
      /moment/i,
      /axios/i,
      /bootstrap/i,
      
      // Common extension patterns
      /chrome\.runtime/i,
      /chrome\.tabs/i,
      /chrome\.storage/i,
      
      // Common web APIs
      /addEventListener/i,
      /querySelector/i,
      /getElementById/i,
      /innerHTML/i,
      /textContent/i
    ];
  }
  
  /**
   * Analyze combined results from other analyzers to derive a heuristic score
   * @param {Object} analysisResults - Combined results from Manifest, Static, Obfuscation, and Network Analyzers
   * @returns {Object} Heuristic analysis results
   */
  analyze(analysisResults) {
    let heuristicScore = 0;
    const detectedHeuristics = [];

    // 1. Manifest-based heuristics
    const manifest = analysisResults.manifestAnalysis;
    if (manifest) {
      if (manifest.permissions?.dangerous?.count > 0) {
        heuristicScore += this.heuristicWeights.dangerousPermissions * manifest.permissions.dangerous.count;
        detectedHeuristics.push({ type: 'dangerousPermissions', count: manifest.permissions.dangerous.count, description: `Dangerous permissions requested: ${manifest.permissions.dangerous.permissions.join(', ')}` });
      }
      if (manifest.hostPermissions?.broad?.count > 0) {
        heuristicScore += this.heuristicWeights.broadHostPermissions * manifest.hostPermissions.broad.count;
        detectedHeuristics.push({ type: 'broadHostPermissions', count: manifest.hostPermissions.broad.count, description: `Broad host permissions: ${manifest.hostPermissions.broad.permissions.join(', ')}` });
      }
      if (manifest.contentScripts?.suspicious?.count > 0) {
        heuristicScore += this.heuristicWeights.suspiciousContentScripts * manifest.contentScripts.suspicious.count;
        detectedHeuristics.push({ type: 'suspiciousContentScripts', count: manifest.contentScripts.suspicious.count, description: `Suspicious content script patterns detected.` });
      }
      if (manifest.suspiciousFileNames?.length > 0) {
        heuristicScore += this.heuristicWeights.suspiciousFileNames * manifest.suspiciousFileNames.length;
        detectedHeuristics.push({ type: 'suspiciousFileNames', count: manifest.suspiciousFileNames.length, description: `Suspicious filenames in manifest: ${manifest.suspiciousFileNames.join(', ')}` });
      }
    }

    // 2. Static analysis-based heuristics
    const staticAnalysis = analysisResults.staticAnalysis?.results;
    if (staticAnalysis) {
      if (staticAnalysis.evalUsage?.length > 0) {
        heuristicScore += this.heuristicWeights.dynamicCodeExecution * staticAnalysis.evalUsage.length;
        detectedHeuristics.push({ type: 'dynamicCodeExecution', count: staticAnalysis.evalUsage.length, description: 'Dynamic code execution (eval, new Function) detected.' });
      }
      if (staticAnalysis.remoteCodeLoading?.length > 0) {
        heuristicScore += this.heuristicWeights.remoteCodeLoading * staticAnalysis.remoteCodeLoading.length;
        detectedHeuristics.push({ type: 'remoteCodeLoading', count: staticAnalysis.remoteCodeLoading.length, description: 'Remote code loading detected.' });
      }
      if (staticAnalysis.keylogging?.length > 0) {
        heuristicScore += this.heuristicWeights.keylogging * staticAnalysis.keylogging.length;
        detectedHeuristics.push({ type: 'keylogging', count: staticAnalysis.keylogging.length, description: 'Keylogging patterns detected.' });
      }
      if (staticAnalysis.dataExfiltration?.length > 0) {
        heuristicScore += this.heuristicWeights.dataExfiltration * staticAnalysis.dataExfiltration.length;
        detectedHeuristics.push({ type: 'dataExfiltration', count: staticAnalysis.dataExfiltration.length, description: 'Data exfiltration patterns detected.' });
      }
      if (staticAnalysis.fingerprinting?.length > 0) {
        heuristicScore += this.heuristicWeights.fingerprinting * staticAnalysis.fingerprinting.length;
        detectedHeuristics.push({ type: 'fingerprinting', count: staticAnalysis.fingerprinting.length, description: 'Browser fingerprinting detected.' });
      }
      if (staticAnalysis.malware?.some(m => m.type === 'debuggerStatement' || m.type === 'consoleClear')) {
        heuristicScore += this.heuristicWeights.antiDebugging;
        detectedHeuristics.push({ type: 'antiDebugging', count: 1, description: 'Anti-debugging techniques detected.' });
      }
      if (staticAnalysis.malware?.some(m => m.type === 'storageAccess' || m.type === 'chromeStorage')) {
        heuristicScore += this.heuristicWeights.persistenceMechanisms;
        detectedHeuristics.push({ type: 'persistenceMechanisms', count: 1, description: 'Persistence mechanisms (storage access) detected.' });
      }
      if (staticAnalysis.behavioral?.some(b => b.type === 'chromeDetection' || b.type === 'webdriverDetection')) {
        heuristicScore += this.heuristicWeights.environmentDetection;
        detectedHeuristics.push({ type: 'environmentDetection', count: 1, description: 'Environment detection (anti-analysis) detected.' });
      }
      if (staticAnalysis.behavioral?.some(b => b.type === 'longTimeout')) {
        heuristicScore += this.heuristicWeights.longDelays;
        detectedHeuristics.push({ type: 'longDelays', count: 1, description: 'Suspiciously long delays detected.' });
      }
    }

    // 3. Obfuscation-based heuristics
    const obfuscation = analysisResults.obfuscationAnalysis;
    if (obfuscation && obfuscation.obfuscationDetected && obfuscation.obfuscationScore > 50) {
      heuristicScore += this.heuristicWeights.highObfuscation;
      detectedHeuristics.push({ type: 'highObfuscation', count: 1, description: `High level of code obfuscation detected (Score: ${obfuscation.obfuscationScore}).` });
    }

    // 4. Network-based heuristics
    const network = analysisResults.networkAnalysis;
    if (network) {
      if (network.endpoints?.suspicious?.length > 0) {
        heuristicScore += this.heuristicWeights.suspiciousNetworkEndpoints * network.endpoints.suspicious.length;
        detectedHeuristics.push({ type: 'suspiciousNetworkEndpoints', count: network.endpoints.suspicious.length, description: `Suspicious network endpoints detected.` });
      }
      const behavior = network.behaviorAnalysis;
      if (behavior) {
        if (behavior.bulkRequests?.length > 0) {
          heuristicScore += this.heuristicWeights.bulkRequests * behavior.bulkRequests.length;
          detectedHeuristics.push({ type: 'bulkRequests', count: behavior.bulkRequests.length, description: 'Bulk network requests detected.' });
        }
        if (behavior.stealthRequests?.length > 0) {
          heuristicScore += this.heuristicWeights.stealthRequests * behavior.stealthRequests.length;
          detectedHeuristics.push({ type: 'stealthRequests', count: behavior.stealthRequests.length, description: 'Stealthy network requests detected.' });
        }
        if (behavior.dataExfiltration?.length > 0) {
          heuristicScore += this.heuristicWeights.dataExfiltration * behavior.dataExfiltration.length;
          detectedHeuristics.push({ type: 'dataExfiltration', count: behavior.dataExfiltration.length, description: 'Network-based data exfiltration detected.' });
        }
        if (behavior.c2Communication?.length > 0) {
          heuristicScore += this.heuristicWeights.c2Communication * behavior.c2Communication.length;
          detectedHeuristics.push({ type: 'c2Communication', count: behavior.c2Communication.length, description: 'Command and Control (C2) communication patterns detected.' });
        }
        if (behavior.evasionTechniques?.length > 0) {
          heuristicScore += this.heuristicWeights.evasionTechniques * behavior.evasionTechniques.length;
          detectedHeuristics.push({ type: 'evasionTechniques', count: behavior.evasionTechniques.length, description: 'Network evasion techniques detected.' });
        }
      }
    }

    // Special case: If JS files could not be read, it's a strong heuristic indicator
    if (analysisResults.staticAnalysis?.suspiciousPatterns?.some(p => p.category === 'Unpacked Extension Analysis' && p.description.includes('Cannot read JavaScript files'))) {
      heuristicScore += this.heuristicWeights.unreadableFiles;
      detectedHeuristics.push({ type: 'unreadableFiles', count: 1, description: 'JavaScript files could not be read, relying on manifest analysis.' });
    }

    return {
      heuristicScore: Math.min(100, Math.max(0, Math.round(heuristicScore))),
      detectedHeuristics
    };
  }
  
  /**
   * Perform comprehensive heuristic analysis
   * @param {string} code - JavaScript code to analyze
   * @param {Object} manifest - Extension manifest data
   * @param {Object} context - Additional context (permissions, etc.)
   * @returns {Object} Heuristic analysis results
   */
  analyzeCode(code, manifest = {}, context = {}) {
    // Input validation
    if (typeof code !== 'string') {
      throw new TypeError('Code must be a string');
    }
    
    if (code.length === 0) {
      return {
        heuristicScore: 0,
        threatLevel: 'safe',
        indicators: [],
        anomalies: [],
        recommendations: []
      };
    }
    
    // Perform various heuristic analyses
    const complexityAnalysis = this.analyzeComplexity(code);
    const behavioralAnalysis = this.analyzeBehavior(code);
    const statisticalAnalysis = this.analyzeStatistics(code);
    const contextualAnalysis = this.analyzeContext(code, manifest, context);
    
    // Combine all analyses
    const combinedScore = this.combineScores([
      complexityAnalysis,
      behavioralAnalysis,
      statisticalAnalysis,
      contextualAnalysis
    ]);
    
    // Generate threat level and recommendations
    const threatLevel = this.determineThreatLevel(combinedScore);
    const recommendations = this.generateRecommendations(combinedScore, {
      complexity: complexityAnalysis,
      behavioral: behavioralAnalysis,
      statistical: statisticalAnalysis,
      contextual: contextualAnalysis
    });
    
    return {
      heuristicScore: combinedScore,
      threatLevel,
      indicators: this.extractIndicators(combinedScore),
      anomalies: this.extractAnomalies([
        complexityAnalysis,
        behavioralAnalysis,
        statisticalAnalysis,
        contextualAnalysis
      ]),
      recommendations,
      detailedAnalysis: {
        complexity: complexityAnalysis,
        behavioral: behavioralAnalysis,
        statistical: statisticalAnalysis,
        contextual: contextualAnalysis
      }
    };
  }
  
  /**
   * Analyze code complexity for suspicious patterns
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Complexity analysis results
   */
  analyzeComplexity(code) {
    const analysis = {
      score: 0,
      indicators: [],
      metrics: {}
    };
    
    // Calculate various complexity metrics
    analysis.metrics = {
      linesOfCode: code.split('\n').length,
      cyclomaticComplexity: this.calculateCyclomaticComplexity(code),
      nestingDepth: this.calculateNestingDepth(code),
      functionCount: this.countFunctions(code),
      variableCount: this.countVariables(code),
      stringLiterals: this.countStringLiterals(code),
      numericLiterals: this.countNumericLiterals(code)
    };
    
    // Analyze complexity indicators
    if (analysis.metrics.cyclomaticComplexity > 20) {
      analysis.score += this.heuristicWeights.highComplexity;
      analysis.indicators.push({
        type: 'high_complexity',
        severity: 'medium',
        description: `High cyclomatic complexity (${analysis.metrics.cyclomaticComplexity})`,
        value: analysis.metrics.cyclomaticComplexity
      });
    }
    
    if (analysis.metrics.nestingDepth > 8) {
      analysis.score += this.heuristicWeights.highComplexity;
      analysis.indicators.push({
        type: 'deep_nesting',
        severity: 'medium',
        description: `Deep code nesting (${analysis.metrics.nestingDepth} levels)`,
        value: analysis.metrics.nestingDepth
      });
    }
    
    // Analyze unusual patterns
    const unusualPatterns = this.detectUnusualPatterns(code);
    if (unusualPatterns.length > 0) {
      analysis.score += this.heuristicWeights.unusualPatterns * unusualPatterns.length;
      analysis.indicators.push(...unusualPatterns);
    }
    
    // Analyze suspicious naming
    const suspiciousNames = this.detectSuspiciousNaming(code);
    if (suspiciousNames.length > 0) {
      analysis.score += this.heuristicWeights.suspiciousNaming * suspiciousNames.length;
      analysis.indicators.push(...suspiciousNames);
    }
    
    return analysis;
  }
  
  /**
   * Analyze behavioral patterns
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Behavioral analysis results
   */
  analyzeBehavior(code) {
    const analysis = {
      score: 0,
      indicators: [],
      behaviors: {}
    };
    
    // Detect stealth behaviors
    const stealthBehaviors = this.detectStealthBehaviors(code);
    if (stealthBehaviors.length > 0) {
      analysis.score += this.heuristicWeights.stealthBehavior * stealthBehaviors.length;
      analysis.indicators.push(...stealthBehaviors);
    }
    analysis.behaviors.stealth = stealthBehaviors;
    
    // Detect evasion techniques
    const evasionTechniques = this.detectEvasionTechniques(code);
    if (evasionTechniques.length > 0) {
      analysis.score += this.heuristicWeights.evasionTechniques * evasionTechniques.length;
      analysis.indicators.push(...evasionTechniques);
    }
    analysis.behaviors.evasion = evasionTechniques;
    
    // Detect persistence mechanisms
    const persistenceMechanisms = this.detectPersistenceMechanisms(code);
    if (persistenceMechanisms.length > 0) {
      analysis.score += this.heuristicWeights.persistenceMechanisms * persistenceMechanisms.length;
      analysis.indicators.push(...persistenceMechanisms);
    }
    analysis.behaviors.persistence = persistenceMechanisms;
    
    return analysis;
  }
  
  /**
   * Analyze statistical patterns
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Statistical analysis results
   */
  analyzeStatistics(code) {
    const analysis = {
      score: 0,
      indicators: [],
      statistics: {}
    };
    
    // Calculate entropy
    const entropy = this.calculateEntropy(code);
    analysis.statistics.entropy = entropy;
    
    // Detect entropy anomalies
    if (entropy > 7.5) {
      analysis.score += this.heuristicWeights.entropyAnomalies;
      analysis.indicators.push({
        type: 'high_entropy',
        severity: 'high',
        description: `High entropy detected (${entropy.toFixed(2)}) - possible obfuscation`,
        value: entropy
      });
    }
    
    // Analyze character frequency
    const frequencyAnalysis = this.analyzeCharacterFrequency(code);
    analysis.statistics.frequency = frequencyAnalysis;
    
    // Detect frequency anomalies
    if (frequencyAnalysis.anomalyScore > 0.7) {
      analysis.score += this.heuristicWeights.frequencyAnomalies;
      analysis.indicators.push({
        type: 'frequency_anomaly',
        severity: 'medium',
        description: 'Unusual character frequency distribution detected',
        value: frequencyAnalysis.anomalyScore
      });
    }
    
    // Analyze code distribution
    const distributionAnalysis = this.analyzeCodeDistribution(code);
    analysis.statistics.distribution = distributionAnalysis;
    
    if (distributionAnalysis.anomalyScore > 0.6) {
      analysis.score += this.heuristicWeights.distributionAnomalies;
      analysis.indicators.push({
        type: 'distribution_anomaly',
        severity: 'medium',
        description: 'Unusual code structure distribution detected',
        value: distributionAnalysis.anomalyScore
      });
    }
    
    return analysis;
  }
  
  /**
   * Analyze contextual patterns
   * @param {string} code - JavaScript code to analyze
   * @param {Object} manifest - Extension manifest
   * @param {Object} context - Additional context
   * @returns {Object} Contextual analysis results
   */
  analyzeContext(code, manifest, context) {
    const analysis = {
      score: 0,
      indicators: [],
      context: {}
    };
    
    // Analyze permission mismatches
    const permissionMismatches = this.detectPermissionMismatches(code, manifest);
    if (permissionMismatches.length > 0) {
      analysis.score += this.heuristicWeights.permissionMismatch * permissionMismatches.length;
      analysis.indicators.push(...permissionMismatches);
    }
    analysis.context.permissionMismatches = permissionMismatches;
    
    // Analyze functionality mismatches
    const functionalityMismatches = this.detectFunctionalityMismatches(code, manifest);
    if (functionalityMismatches.length > 0) {
      analysis.score += this.heuristicWeights.functionalityMismatch * functionalityMismatches.length;
      analysis.indicators.push(...functionalityMismatches);
    }
    analysis.context.functionalityMismatches = functionalityMismatches;
    
    // Analyze timing anomalies
    const timingAnomalies = this.detectTimingAnomalies(code);
    if (timingAnomalies.length > 0) {
      analysis.score += this.heuristicWeights.timingAnomalies * timingAnomalies.length;
      analysis.indicators.push(...timingAnomalies);
    }
    analysis.context.timingAnomalies = timingAnomalies;
    
    return analysis;
  }
  
  /**
   * Calculate cyclomatic complexity
   * @param {string} code - JavaScript code
   * @returns {number} Cyclomatic complexity score
   */
  calculateCyclomaticComplexity(code) {
    const complexityKeywords = [
      'if', 'else', 'while', 'for', 'switch', 'case', 'catch'
    ];
    
    const specialOperators = [
      '&&', '||', '?'
    ];
    
    let complexity = 1; // Base complexity
    
    // Handle regular keywords
    complexityKeywords.forEach(keyword => {
      const regex = new RegExp(`\\b${keyword}\\b`, 'g');
      const matches = code.match(regex);
      if (matches) {
        complexity += matches.length;
      }
    });
    
    // Handle special operators (escape them for regex)
    specialOperators.forEach(operator => {
      const escapedOperator = operator.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escapedOperator, 'g');
      const matches = code.match(regex);
      if (matches) {
        complexity += matches.length;
      }
    });
    
    return complexity;
  }
  
  /**
   * Calculate maximum nesting depth
   * @param {string} code - JavaScript code
   * @returns {number} Maximum nesting depth
   */
  calculateNestingDepth(code) {
    let maxDepth = 0;
    let currentDepth = 0;
    
    for (let i = 0; i < code.length; i++) {
      if (code[i] === '{') {
        currentDepth++;
        maxDepth = Math.max(maxDepth, currentDepth);
      } else if (code[i] === '}') {
        currentDepth--;
      }
    }
    
    return maxDepth;
  }
  
  /**
   * Count functions in code
   * @param {string} code - JavaScript code
   * @returns {number} Function count
   */
  countFunctions(code) {
    const functionPatterns = [
      /function\s+\w+\s*\(/g,
      /const\s+\w+\s*=\s*function/g,
      /let\s+\w+\s*=\s*function/g,
      /var\s+\w+\s*=\s*function/g,
      /=>\s*{/g,
      /=>\s*[^{]/g
    ];
    
    let count = 0;
    functionPatterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        count += matches.length;
      }
    });
    
    return count;
  }
  
  /**
   * Count variables in code
   * @param {string} code - JavaScript code
   * @returns {number} Variable count
   */
  countVariables(code) {
    const variablePatterns = [
      /var\s+\w+/g,
      /let\s+\w+/g,
      /const\s+\w+/g
    ];
    
    let count = 0;
    variablePatterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        count += matches.length;
      }
    });
    
    return count;
  }
  
  /**
   * Count string literals
   * @param {string} code - JavaScript code
   * @returns {number} String literal count
   */
  countStringLiterals(code) {
    const stringPatterns = [
      /"[^"]*"/g,
      /'[^']*'/g,
      /`[^`]*`/g
    ];
    
    let count = 0;
    stringPatterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        count += matches.length;
      }
    });
    
    return count;
  }
  
  /**
   * Count numeric literals
   * @param {string} code - JavaScript code
   * @returns {number} Numeric literal count
   */
  countNumericLiterals(code) {
    const numericPattern = /\b\d+(\.\d+)?\b/g;
    const matches = code.match(numericPattern);
    return matches ? matches.length : 0;
  }
  
  /**
   * Detect unusual patterns in code
   * @param {string} code - JavaScript code
   * @returns {Object[]} Unusual patterns found
   */
  detectUnusualPatterns(code) {
    const patterns = [];
    
    // Excessive use of eval-like functions
    const evalPatterns = [
      /eval\s*\(/g,
      /new\s+Function\s*\(/g,
      /setTimeout\s*\(\s*['"`]/g,
      /setInterval\s*\(\s*['"`]/g
    ];
    
    let evalCount = 0;
    evalPatterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        evalCount += matches.length;
      }
    });
    
    if (evalCount > 3) {
      patterns.push({
        type: 'excessive_eval',
        severity: 'high',
        description: `Excessive use of dynamic code execution (${evalCount} instances)`,
        value: evalCount
      });
    }
    
    // Unusual string manipulation
    const stringManipulation = [
      /String\.fromCharCode/g,
      /\.charCodeAt/g,
      /atob\s*\(/g,
      /btoa\s*\(/g
    ];
    
    let stringManipCount = 0;
    stringManipulation.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        stringManipCount += matches.length;
      }
    });
    
    if (stringManipCount > 5) {
      patterns.push({
        type: 'excessive_string_manipulation',
        severity: 'medium',
        description: `Excessive string manipulation (${stringManipCount} instances)`,
        value: stringManipCount
      });
    }
    
    // Unusual object property access
    const propertyAccess = [
      /\[['"`][^'"`]+['"`]\]/g,
      /\.\w+\s*\[/g
    ];
    
    let propertyAccessCount = 0;
    propertyAccess.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        propertyAccessCount += matches.length;
      }
    });
    
    if (propertyAccessCount > 10) {
      patterns.push({
        type: 'excessive_property_access',
        severity: 'low',
        description: `Excessive dynamic property access (${propertyAccessCount} instances)`,
        value: propertyAccessCount
      });
    }
    
    return patterns;
  }
  
  /**
   * Detect suspicious naming patterns
   * @param {string} code - JavaScript code
   * @returns {Object[]} Suspicious naming patterns found
   */
  detectSuspiciousNaming(code) {
    const patterns = [];
    
    // Suspicious function/variable names
    const suspiciousNames = [
      'steal', 'hack', 'exploit', 'backdoor', 'trojan', 'malware',
      'keylog', 'spy', 'track', 'monitor', 'harvest', 'collect',
      'exfiltrate', 'inject', 'payload', 'botnet', 'c2', 'command',
      'control', 'bypass', 'evade', 'hide', 'obfuscate', 'encode',
      'decode', 'crypt', 'mine', 'coin', 'bitcoin', 'monero'
    ];
    
    suspiciousNames.forEach(name => {
      const regex = new RegExp(`\\b${name}\\w*\\b`, 'gi');
      const matches = code.match(regex);
      if (matches) {
        patterns.push({
          type: 'suspicious_naming',
          severity: 'high',
          description: `Suspicious naming pattern detected: ${matches.join(', ')}`,
          value: matches
        });
      }
    });
    
    // Obfuscated naming patterns
    const obfuscatedPatterns = [
      /[a-z]\d+/g, // Single letter followed by numbers
      /[a-z]{1,2}[0-9]{3,}/g, // Short letters with many numbers
      /_[a-z0-9]{8,}/g // Underscore with long alphanumeric
    ];
    
    obfuscatedPatterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches && matches.length > 5) {
        patterns.push({
          type: 'obfuscated_naming',
          severity: 'medium',
          description: `Obfuscated naming pattern detected (${matches.length} instances)`,
          value: matches.slice(0, 5) // Show first 5 examples
        });
      }
    });
    
    return patterns;
  }
  
  /**
   * Detect stealth behaviors
   * @param {string} code - JavaScript code
   * @returns {Object[]} Stealth behaviors found
   */
  detectStealthBehaviors(code) {
    const behaviors = [];
    
    // Console clearing
    if (/console\.clear\s*\(/g.test(code)) {
      behaviors.push({
        type: 'console_clearing',
        severity: 'medium',
        description: 'Console clearing detected - potential anti-debugging technique'
      });
    }
    
    // Debugger statements
    if (/debugger\s*;/g.test(code)) {
      behaviors.push({
        type: 'debugger_statements',
        severity: 'high',
        description: 'Debugger statements detected - anti-debugging technique'
      });
    }
    
    // Environment detection
    const envDetection = [
      /navigator\.webdriver/g,
      /window\.chrome/g,
      /typeof\s+\w+\s*===?\s*['"`]undefined['"`]/g
    ];
    
    let envDetectionCount = 0;
    envDetection.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        envDetectionCount += matches.length;
      }
    });
    
    if (envDetectionCount > 2) {
      behaviors.push({
        type: 'environment_detection',
        severity: 'high',
        description: `Environment detection detected (${envDetectionCount} instances)`,
        value: envDetectionCount
      });
    }
    
    // Stealth timing
    if (/Math\.random\s*\(\s*\)/g.test(code) && /setTimeout|setInterval/g.test(code)) {
      behaviors.push({
        type: 'stealth_timing',
        severity: 'medium',
        description: 'Random timing patterns detected - potential stealth behavior'
      });
    }
    
    return behaviors;
  }
  
  /**
   * Detect evasion techniques
   * @param {string} code - JavaScript code
   * @returns {Object[]} Evasion techniques found
   */
  detectEvasionTechniques(code) {
    const techniques = [];
    
    // Try-catch blocks (potential error hiding)
    const tryCatchCount = (code.match(/try\s*\{/g) || []).length;
    if (tryCatchCount > 5) {
      techniques.push({
        type: 'excessive_try_catch',
        severity: 'medium',
        description: `Excessive try-catch blocks (${tryCatchCount}) - potential error hiding`,
        value: tryCatchCount
      });
    }
    
    // Dynamic property access
    const dynamicAccess = [
      /\[['"`][^'"`]+['"`]\]/g,
      /\.\w+\s*\[/g
    ];
    
    let dynamicAccessCount = 0;
    dynamicAccess.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        dynamicAccessCount += matches.length;
      }
    });
    
    if (dynamicAccessCount > 8) {
      techniques.push({
        type: 'dynamic_property_access',
        severity: 'medium',
        description: `Excessive dynamic property access (${dynamicAccessCount}) - potential evasion`,
        value: dynamicAccessCount
      });
    }
    
    // Function redefinition
    if (/function\s+\w+\s*\([^)]*\)\s*\{[^}]*\w+\s*=\s*function/g.test(code)) {
      techniques.push({
        type: 'function_redefinition',
        severity: 'high',
        description: 'Function redefinition detected - potential API hooking'
      });
    }
    
    return techniques;
  }
  
  /**
   * Detect persistence mechanisms
   * @param {string} code - JavaScript code
   * @returns {Object[]} Persistence mechanisms found
   */
  detectPersistenceMechanisms(code) {
    const mechanisms = [];
    
    // Storage usage
    const storagePatterns = [
      /localStorage/g,
      /sessionStorage/g,
      /chrome\.storage/g,
      /indexedDB/g
    ];
    
    let storageCount = 0;
    storagePatterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        storageCount += matches.length;
      }
    });
    
    if (storageCount > 3) {
      mechanisms.push({
        type: 'excessive_storage_usage',
        severity: 'medium',
        description: `Excessive storage usage (${storageCount} instances) - potential persistence`,
        value: storageCount
      });
    }
    
    // Event listeners for persistence
    const eventListeners = [
      /addEventListener\s*\(\s*['"`]beforeunload['"`]/g,
      /addEventListener\s*\(\s*['"`]unload['"`]/g,
      /addEventListener\s*\(\s*['"`]pagehide['"`]/g
    ];
    
    let eventListenerCount = 0;
    eventListeners.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        eventListenerCount += matches.length;
      }
    });
    
    if (eventListenerCount > 0) {
      mechanisms.push({
        type: 'persistence_event_listeners',
        severity: 'medium',
        description: `Persistence event listeners detected (${eventListenerCount})`,
        value: eventListenerCount
      });
    }
    
    return mechanisms;
  }
  
  /**
   * Calculate Shannon entropy
   * @param {string} text - Text to analyze
   * @returns {number} Entropy value
   */
  calculateEntropy(text) {
    const frequencies = {};
    const length = text.length;
    
    // Count character frequencies
    for (let i = 0; i < length; i++) {
      const char = text[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    // Calculate entropy
    let entropy = 0;
    for (const char in frequencies) {
      const probability = frequencies[char] / length;
      entropy -= probability * Math.log2(probability);
    }
    
    return entropy;
  }
  
  /**
   * Analyze character frequency distribution
   * @param {string} code - JavaScript code
   * @returns {Object} Frequency analysis results
   */
  analyzeCharacterFrequency(code) {
    const frequencies = {};
    const length = code.length;
    
    // Count character frequencies
    for (let i = 0; i < length; i++) {
      const char = code[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    // Calculate expected frequencies for normal JavaScript
    const expectedFrequencies = {
      ' ': 0.15, // Space
      '\n': 0.05, // Newline
      '\t': 0.02, // Tab
      '(': 0.03, ')': 0.03,
      '{': 0.02, '}': 0.02,
      '[': 0.01, ']': 0.01,
      ';': 0.02, ':': 0.01,
      ',': 0.01, '.': 0.01,
      '=': 0.01, '+': 0.005, '-': 0.005,
      '*': 0.002, '/': 0.002,
      '!': 0.001, '?': 0.001,
      '&': 0.001, '|': 0.001
    };
    
    // Calculate anomaly score
    let anomalyScore = 0;
    for (const char in expectedFrequencies) {
      const expected = expectedFrequencies[char];
      const actual = (frequencies[char] || 0) / length;
      const difference = Math.abs(expected - actual);
      anomalyScore += difference;
    }
    
    return {
      frequencies,
      anomalyScore: Math.min(1, anomalyScore)
    };
  }
  
  /**
   * Analyze code structure distribution
   * @param {string} code - JavaScript code
   * @returns {Object} Distribution analysis results
   */
  analyzeCodeDistribution(code) {
    const distribution = {
      functions: (code.match(/function\s+\w+\s*\(/g) || []).length,
      variables: (code.match(/var\s+\w+|let\s+\w+|const\s+\w+/g) || []).length,
      strings: (code.match(/['"`][^'"`]*['"`]/g) || []).length,
      numbers: (code.match(/\b\d+(\.\d+)?\b/g) || []).length,
      operators: (code.match(/[+\-*/=<>!&|]/g) || []).length,
      brackets: (code.match(/[{}()[\]]/g) || []).length
    };
    
    const total = Object.values(distribution).reduce((sum, count) => sum + count, 0);
    
    // Calculate normalized distribution
    const normalizedDistribution = {};
    for (const key in distribution) {
      normalizedDistribution[key] = total > 0 ? distribution[key] / total : 0;
    }
    
    // Expected distribution for normal JavaScript
    const expectedDistribution = {
      functions: 0.1,
      variables: 0.15,
      strings: 0.25,
      numbers: 0.1,
      operators: 0.2,
      brackets: 0.2
    };
    
    // Calculate anomaly score
    let anomalyScore = 0;
    for (const key in expectedDistribution) {
      const expected = expectedDistribution[key];
      const actual = normalizedDistribution[key] || 0;
      const difference = Math.abs(expected - actual);
      anomalyScore += difference;
    }
    
    return {
      distribution: normalizedDistribution,
      anomalyScore: Math.min(1, anomalyScore)
    };
  }
  
  /**
   * Detect permission mismatches
   * @param {string} code - JavaScript code
   * @param {Object} manifest - Extension manifest
   * @returns {Object[]} Permission mismatches found
   */
  detectPermissionMismatches(code, manifest) {
    const mismatches = [];
    
    if (!manifest.permissions) {
      return mismatches;
    }
    
    // Check for API usage without corresponding permissions
    const apiPermissions = {
      'chrome.tabs': ['tabs'],
      'chrome.history': ['history'],
      'chrome.bookmarks': ['bookmarks'],
      'chrome.cookies': ['cookies'],
      'chrome.downloads': ['downloads'],
      'chrome.notifications': ['notifications'],
      'chrome.storage': ['storage'],
      'chrome.management': ['management']
    };
    
    for (const api in apiPermissions) {
      const requiredPermissions = apiPermissions[api];
      const hasApiUsage = new RegExp(api.replace('.', '\\.'), 'g').test(code);
      
      if (hasApiUsage) {
        const hasPermission = requiredPermissions.some(perm => 
          manifest.permissions.includes(perm)
        );
        
        if (!hasPermission) {
          mismatches.push({
            type: 'permission_mismatch',
            severity: 'high',
            description: `API ${api} used without required permissions`,
            value: { api, requiredPermissions }
          });
        }
      }
    }
    
    return mismatches;
  }
  
  /**
   * Detect functionality mismatches
   * @param {string} code - JavaScript code
   * @param {Object} manifest - Extension manifest
   * @returns {Object[]} Functionality mismatches found
   */
  detectFunctionalityMismatches(code, manifest) {
    const mismatches = [];
    
    // Check if code functionality matches manifest description
    const suspiciousPatterns = [
      { pattern: /keylog|steal|harvest|collect/g, description: 'data theft' },
      { pattern: /mining|coin|crypto|bitcoin/g, description: 'cryptocurrency mining' },
      { pattern: /backdoor|trojan|malware/g, description: 'malicious behavior' },
      { pattern: /spy|track|monitor/g, description: 'surveillance' }
    ];
    
    suspiciousPatterns.forEach(({ pattern, description }) => {
      if (pattern.test(code)) {
        mismatches.push({
          type: 'functionality_mismatch',
          severity: 'critical',
          description: `Code contains ${description} patterns but manifest doesn't indicate this functionality`,
          value: { description, pattern: pattern.toString() }
        });
      }
    });
    
    return mismatches;
  }
  
  /**
   * Detect timing anomalies
   * @param {string} code - JavaScript code
   * @returns {Object[]} Timing anomalies found
   */
  detectTimingAnomalies(code) {
    const anomalies = [];
    
    // Detect suspicious timing patterns
    const timingPatterns = [
      { pattern: /setTimeout\s*\([^,]*,\s*\d{5,}/g, description: 'very long delays' },
      { pattern: /setInterval\s*\([^,]*,\s*\d{4,}/g, description: 'long intervals' },
      { pattern: /setTimeout\s*\([^,]*,\s*Math\.random/g, description: 'random delays' }
    ];
    
    timingPatterns.forEach(({ pattern, description }) => {
      const matches = code.match(pattern);
      if (matches) {
        anomalies.push({
          type: 'timing_anomaly',
          severity: 'medium',
          description: `Suspicious timing pattern detected: ${description}`,
          value: matches.length
        });
      }
    });
    
    return anomalies;
  }
  
  /**
   * Combine scores from different analyses
   * @param {Object[]} analyses - Array of analysis results
   * @returns {number} Combined score
   */
  combineScores(analyses) {
    let totalScore = 0;
    
    analyses.forEach(analysis => {
      if (analysis && typeof analysis.score === 'number') {
        totalScore += analysis.score;
      }
    });
    
    return Math.min(100, totalScore);
  }
  
  /**
   * Determine threat level based on score
   * @param {number} score - Combined heuristic score
   * @returns {string} Threat level
   */
  determineThreatLevel(score) {
    if (score >= this.thresholds.critical) return 'critical';
    if (score >= this.thresholds.malicious) return 'malicious';
    if (score >= this.thresholds.suspicious) return 'suspicious';
    return 'safe';
  }
  
  /**
   * Extract key indicators from analysis
   * @param {number} score - Combined score
   * @returns {string[]} Key indicators
   */
  extractIndicators(score) {
    const indicators = [];
    
    if (score >= this.thresholds.critical) {
      indicators.push('Critical threat indicators detected');
    } else if (score >= this.thresholds.malicious) {
      indicators.push('Malicious behavior patterns detected');
    } else if (score >= this.thresholds.suspicious) {
      indicators.push('Suspicious patterns detected');
    }
    
    return indicators;
  }
  
  /**
   * Extract anomalies from analyses
   * @param {Object[]} analyses - Array of analysis results
   * @returns {Object[]} Anomalies found
   */
  extractAnomalies(analyses) {
    const anomalies = [];
    
    analyses.forEach(analysis => {
      if (analysis && analysis.indicators) {
        anomalies.push(...analysis.indicators);
      }
    });
    
    return anomalies;
  }
  
  /**
   * Generate recommendations based on analysis
   * @param {number} score - Combined score
   * @param {Object} analyses - Detailed analyses
   * @returns {string[]} Recommendations
   */
  generateRecommendations(score, analyses) {
    const recommendations = [];
    
    if (score >= this.thresholds.critical) {
      recommendations.push('CRITICAL: Immediate removal recommended');
      recommendations.push('This extension exhibits multiple critical threat indicators');
    } else if (score >= this.thresholds.malicious) {
      recommendations.push('HIGH RISK: Strongly consider removal');
      recommendations.push('Multiple malicious behavior patterns detected');
    } else if (score >= this.thresholds.suspicious) {
      recommendations.push('SUSPICIOUS: Review extension carefully');
      recommendations.push('Several suspicious patterns detected');
    }
    
    // Add specific recommendations based on analysis
    if (analyses.complexity && analyses.complexity.score > 20) {
      recommendations.push('High code complexity detected - review for obfuscation');
    }
    
    if (analyses.behavioral && analyses.behavioral.score > 15) {
      recommendations.push('Suspicious behavioral patterns detected');
    }
    
    if (analyses.statistical && analyses.statistical.score > 10) {
      recommendations.push('Statistical anomalies suggest possible obfuscation');
    }
    
    if (analyses.contextual && analyses.contextual.score > 20) {
      recommendations.push('Contextual mismatches detected - verify extension legitimacy');
    }
    
    return recommendations;
  }
}

export default HeuristicAnalyzer;

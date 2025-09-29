/**
 * Threat Classifier Module
 * Combines results from different analyzers to classify overall threat level
 */

class ThreatClassifier {
  constructor() {
    // Threat categories and their descriptions
    this.threatCategories = {
      dataTheft: {
        name: 'Data Theft',
        description: 'The extension may attempt to steal sensitive user data such as cookies, browsing history, or form inputs.'
      },
      privacyInvasion: {
        name: 'Privacy Invasion',
        description: 'The extension may track user behavior, collect browsing history, or fingerprint the browser.'
      },
      codeExecution: {
        name: 'Arbitrary Code Execution',
        description: 'The extension may execute arbitrary or remote code, which could be used to run malicious commands.'
      },
      excessivePermissions: {
        name: 'Excessive Permissions',
        description: 'The extension requests more permissions than necessary for its stated functionality.'
      },
      obfuscation: {
        name: 'Code Obfuscation',
        description: 'The extension uses obfuscation techniques that may hide malicious functionality.'
      },
      networkAbuse: {
        name: 'Network Abuse',
        description: 'The extension communicates with suspicious domains or uses unusual network patterns.'
      }
    };
  }
  
  /**
   * Classify threat level based on analysis results
   * @param {Object} analysisResults - Combined results from all analyzers
   * @returns {Object} Threat classification
   */
  classifyThreat(analysisResults) {
    // Extract scores from each analyzer
    const manifestScore = analysisResults.manifestAnalysis?.riskScore || 0;
    const staticScore = analysisResults.staticAnalysis?.riskScore || 0;
    const obfuscationScore = analysisResults.obfuscationAnalysis?.obfuscationScore || 0;
    const networkScore = analysisResults.networkAnalysis?.riskScore || 0;
    
    // Calculate weighted overall score
    const overallScore = this.calculateOverallScore(
      manifestScore,
      staticScore,
      obfuscationScore,
      networkScore
    );
    
    // Determine threat level
    const threatLevel = this.determineThreatLevel(overallScore);
    
    // Identify specific threat categories
    const threatCategories = this.identifyThreatCategories(analysisResults);
    
    // Generate recommendations
    const recommendations = this.generateRecommendations(
      threatLevel,
      threatCategories,
      analysisResults
    );
    
    return {
      level: threatLevel,
      score: overallScore,
      categories: threatCategories,
      summary: this.generateSummary(threatLevel, threatCategories),
      recommendations
    };
  }
  
  /**
   * Calculate overall threat score with weighted components
   * @param {number} manifestScore - Manifest analysis score
   * @param {number} staticScore - Static analysis score
   * @param {number} obfuscationScore - Obfuscation analysis score
   * @param {number} networkScore - Network analysis score
   * @returns {number} Overall threat score (0-100)
   */
  calculateOverallScore(manifestScore, staticScore, obfuscationScore, networkScore) {
    // Weights for each component
    const weights = {
      manifest: 0.25,
      static: 0.35,
      obfuscation: 0.20,
      network: 0.20
    };
    
    // Calculate weighted score
    const weightedScore = 
      (manifestScore * weights.manifest) +
      (staticScore * weights.static) +
      (obfuscationScore * weights.obfuscation) +
      (networkScore * weights.network);
    
    // Round to nearest integer and ensure it's in 0-100 range
    return Math.min(100, Math.max(0, Math.round(weightedScore)));
  }
  
  /**
   * Determine threat level based on overall score
   * @param {number} score - Overall threat score
   * @returns {string} Threat level (safe, low, medium, high, critical)
   */
  determineThreatLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'safe';
  }
  
  /**
   * Identify specific threat categories based on analysis results
   * @param {Object} analysisResults - Combined results from all analyzers
   * @returns {Object[]} Identified threat categories
   */
  identifyThreatCategories(analysisResults) {
    const categories = [];
    
    // Check for data theft indicators
    if (this.hasDataTheftIndicators(analysisResults)) {
      categories.push({
        ...this.threatCategories.dataTheft,
        severity: this.getCategorySeverity(analysisResults, 'dataTheft')
      });
    }
    
    // Check for privacy invasion indicators
    if (this.hasPrivacyInvasionIndicators(analysisResults)) {
      categories.push({
        ...this.threatCategories.privacyInvasion,
        severity: this.getCategorySeverity(analysisResults, 'privacyInvasion')
      });
    }
    
    // Check for code execution indicators
    if (this.hasCodeExecutionIndicators(analysisResults)) {
      categories.push({
        ...this.threatCategories.codeExecution,
        severity: this.getCategorySeverity(analysisResults, 'codeExecution')
      });
    }
    
    // Check for excessive permissions
    if (this.hasExcessivePermissions(analysisResults)) {
      categories.push({
        ...this.threatCategories.excessivePermissions,
        severity: this.getCategorySeverity(analysisResults, 'excessivePermissions')
      });
    }
    
    // Check for obfuscation
    if (this.hasObfuscation(analysisResults)) {
      categories.push({
        ...this.threatCategories.obfuscation,
        severity: this.getCategorySeverity(analysisResults, 'obfuscation')
      });
    }
    
    // Check for network abuse
    if (this.hasNetworkAbuse(analysisResults)) {
      categories.push({
        ...this.threatCategories.networkAbuse,
        severity: this.getCategorySeverity(analysisResults, 'networkAbuse')
      });
    }
    
    return categories;
  }
  
  /**
   * Check for data theft indicators
   * @param {Object} analysisResults - Analysis results
   * @returns {boolean} True if data theft indicators are present
   */
  hasDataTheftIndicators(analysisResults) {
    const staticResults = analysisResults.staticAnalysis?.results || {};
    
    // Check for cookie access or data exfiltration patterns
    return (
      (staticResults.cookieAccess?.length > 0) ||
      (staticResults.dataExfiltration?.length > 0)
    );
  }
  
  /**
   * Check for privacy invasion indicators
   * @param {Object} analysisResults - Analysis results
   * @returns {boolean} True if privacy invasion indicators are present
   */
  hasPrivacyInvasionIndicators(analysisResults) {
    const staticResults = analysisResults.staticAnalysis?.results || {};
    const manifestResults = analysisResults.manifestAnalysis || {};
    
    // Check for fingerprinting or privacy-sensitive permissions
    return (
      (staticResults.fingerprinting && staticResults.fingerprinting.length > 0) ||
      (manifestResults.permissions && (
        manifestResults.permissions.dangerous.permissions.includes('history') ||
        manifestResults.permissions.dangerous.permissions.includes('tabs')
      ))
    );
  }
  
  /**
   * Check for code execution indicators
   * @param {Object} analysisResults - Analysis results
   * @returns {boolean} True if code execution indicators are present
   */
  hasCodeExecutionIndicators(analysisResults) {
    const staticResults = analysisResults.staticAnalysis?.results || {};
    
    // Check for eval usage or remote code loading
    return (
      (staticResults.evalUsage && staticResults.evalUsage.length > 0) ||
      (staticResults.remoteCodeLoading && staticResults.remoteCodeLoading.length > 0)
    );
  }
  
  /**
   * Check for excessive permissions
   * @param {Object} analysisResults - Analysis results
   * @returns {boolean} True if excessive permissions are present
   */
  hasExcessivePermissions(analysisResults) {
    const manifestResults = analysisResults.manifestAnalysis || {};
    
    // Check for dangerous or critical permissions
    return (
      manifestResults.permissions && (
        manifestResults.permissions.dangerous.count > 2 ||
        manifestResults.permissions.critical.count > 0
      )
    );
  }
  
  /**
   * Check for obfuscation
   * @param {Object} analysisResults - Analysis results
   * @returns {boolean} True if obfuscation is detected
   */
  hasObfuscation(analysisResults) {
    const obfuscationResults = analysisResults.obfuscationAnalysis || {};
    return obfuscationResults.obfuscationDetected;
  }
  
  /**
   * Check for network abuse
   * @param {Object} analysisResults - Analysis results
   * @returns {boolean} True if network abuse is detected
   */
  hasNetworkAbuse(analysisResults) {
    const networkResults = analysisResults.networkAnalysis || {};
    
    // Check for suspicious URLs or IP addresses
    return (
      (networkResults.suspiciousDomains?.length > 0) ||
      (networkResults.suspiciousIpAddresses?.length > 0)
    );
  }
  
  /**
   * Determine severity for a specific threat category
   * @param {Object} analysisResults - Analysis results
   * @param {string} category - Threat category
   * @returns {string} Severity level (low, medium, high)
   */
  getCategorySeverity(analysisResults, category) {
    switch (category) {
      case 'dataTheft':
        const staticResults = analysisResults.staticAnalysis?.results || {};
        const cookieCount = staticResults.cookieAccess?.length || 0;
        const exfilCount = staticResults.dataExfiltration?.length || 0;
        if (cookieCount > 2 || exfilCount > 2) return 'high';
        if (cookieCount > 0 || exfilCount > 0) return 'medium';
        return 'low';
        
      case 'privacyInvasion':
        const fingerprintingCount = analysisResults.staticAnalysis?.results?.fingerprinting?.length || 0;
        if (fingerprintingCount > 3) return 'high';
        if (fingerprintingCount > 0) return 'medium';
        return 'low';
        
      case 'codeExecution':
        const evalCount = analysisResults.staticAnalysis?.results?.evalUsage?.length || 0;
        const remoteCount = analysisResults.staticAnalysis?.results?.remoteCodeLoading?.length || 0;
        if (remoteCount > 0) return 'high';
        if (evalCount > 1) return 'medium';
        return 'low';
        
      case 'excessivePermissions':
        const manifestResults = analysisResults.manifestAnalysis || {};
        const dangerousCount = manifestResults.permissions?.dangerous?.count || 0;
        const criticalCount = manifestResults.permissions?.critical?.count || 0;
        if (criticalCount > 0) return 'high';
        if (dangerousCount > 4) return 'medium';
        return 'low';
        
      case 'obfuscation':
        const obfuscationScore = analysisResults.obfuscationAnalysis?.obfuscationScore || 0;
        if (obfuscationScore > 70) return 'high';
        if (obfuscationScore > 40) return 'medium';
        return 'low';
        
      case 'networkAbuse':
        const networkResults = analysisResults.networkAnalysis || {};
        const suspiciousCount = networkResults.endpoints?.suspicious?.length || 0;
        if (suspiciousCount > 3) return 'high';
        if (suspiciousCount > 0) return 'medium';
        return 'low';
        
      default:
        return 'low';
    }
  }
  
  /**
   * Generate a summary message based on threat level and categories
   * @param {string} threatLevel - Overall threat level
   * @param {Object[]} categories - Identified threat categories
   * @returns {string} Summary message
   */
  generateSummary(threatLevel, categories) {
    if (threatLevel === 'safe') {
      return 'No significant threats detected. The extension appears to be safe.';
    }
    
    let summary = `The extension poses a ${threatLevel} threat level. Key areas of concern include:\n`;
    
    categories.forEach(category => {
      summary += `- **${category.name}**: ${category.description}\n`;
    });
    
    return summary;
  }
  
  /**
   * Generate recommendations to mitigate identified threats
   * @param {string} threatLevel - Overall threat level
   * @param {Object[]} categories - Identified threat categories
   * @param {Object} analysisResults - Analysis results for detailed recommendations
   * @returns {Object[]} Recommendations
   */
  generateRecommendations(threatLevel, categories, analysisResults) {
    if (threatLevel === 'safe') {
      return [{
        recommendation: 'This extension appears safe to use.',
        priority: 'low'
      }];
    }
    
    const recommendations = [];

    if (threatLevel === 'critical') {
      recommendations.push({
        recommendation: 'Uninstall this extension immediately.',
        priority: 'critical'
      });
    }
    
    categories.forEach(category => {
      switch (category.name) {
        case 'Data Theft':
          recommendations.push({
            recommendation: 'Review code that accesses cookies or browsing history. Ensure data is handled securely and not sent to unauthorized domains.',
            priority: 'high'
          });
          break;
          
        case 'Privacy Invasion':
          recommendations.push({
            recommendation: 'Minimize the collection of user data and avoid browser fingerprinting techniques.',
            priority: 'medium'
          });
          break;
          
        case 'Arbitrary Code Execution':
          recommendations.push({
            recommendation: 'Remove all uses of eval(), new Function(), and other dynamic code execution methods. Avoid loading code from remote sources.',
            priority: 'critical'
          });
          break;
          
        case 'Excessive Permissions':
          recommendations.push({
            recommendation: 'Review the permissions requested in the manifest.json file. Only request permissions that are essential for the extension to function.',
            priority: 'medium'
          });
          break;
          
        case 'Code Obfuscation':
          recommendations.push({
            recommendation: 'If you are the developer, provide the original, unobfuscated source code for analysis. Obfuscated code is often used to hide malicious behavior.',
            priority: 'high'
          });
          break;
          
        case 'Network Abuse':
          const suspiciousDomains = (analysisResults.networkAnalysis?.suspiciousDomains || []).join(', ');
          
          if (suspiciousDomains) {
            recommendations.push({
              recommendation: `The extension communicates with the following suspicious domains: ${suspiciousDomains}. Investigate these network requests to ensure they are legitimate.`,
              priority: 'high'
            });
          }
          break;
      }
    });
    
    return recommendations;
  }
}

export default ThreatClassifier;
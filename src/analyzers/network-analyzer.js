/**
 * Network Analyzer Module
 * Analyzes network endpoints and requests in extension code
 */

class NetworkAnalyzer {
  constructor() {
    // Known suspicious domains and patterns
    this.suspiciousDomains = [
      // Data collection services often used for exfiltration
      'mixpanel.com',
      'amplitude.com',
      'segment.io',
      'segment.com',
      'analytics.',
      'tracker.',
      'tracking.',
      'telemetry.',
      
      // URL shorteners (can hide malicious destinations)
      'bit.ly',
      'goo.gl',
      'tinyurl.com',
      't.co',
      'is.gd',
      
      // Temporary/disposable domains
      '.000webhost.',
      '.freehostia.',
      '.herokuapp.com',
      '.glitch.me',
      '.repl.co',
      
      // Known malicious patterns
      'pastebin.com',
      'paste.ee',
      'ghostbin.co',
      'hastebin.com',
      'rentry.co',
      
      // Cryptocurrency related (often used in cryptojacking)
      'coin-hive.com',
      'coinhive.com',
      'cryptoloot.pro',
      'crypto-loot.com',
      'minero.cc',
      'ppoi.org',
      'browsermine.com'
    ];
    
    // Suspicious URL patterns
    this.suspiciousUrlPatterns = [
      // IP address URLs (suspicious in extensions)
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
      
      // Base64 in URLs
      /https?:\/\/[^/]*base64/g,
      
      // Unusual ports
      /https?:\/\/[^/]*:[^0-9]*(2121|8118|6666|1337|31337)/g,
      
      // Excessively long domain names (often algorithmically generated)
      /https?:\/\/[a-z0-9]{25,}\.[a-z]{2,}/g,
      
      // Uncommon TLDs often used in malicious campaigns
      /https?:\/\/[^/]*\.(xyz|top|club|gq|tk|ml|ga|cf)/g
    ];
    
    // Suspicious request patterns
    this.suspiciousRequestPatterns = [
      // Fetch API
      /fetch\s*\(\s*['"`][^'"`]+['"`]/g,
      
      // XMLHttpRequest
      /new\s+XMLHttpRequest\s*\(\s*\)/g,
      /\.open\s*\(\s*['"`]GET['"`]|\.open\s*\(\s*['"`]POST['"`]/g,
      
      // jQuery AJAX
      /\$\.ajax\s*\(|\$\.get\s*\(|\$\.post\s*\(/g,
      
      // WebSockets
      /new\s+WebSocket\s*\(\s*['"`][^'"`]+['"`]/g
    ];
  }
  
  /**
   * Analyze JavaScript code for network endpoints and requests
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
        endpoints: { total: 0, suspicious: [] },
        riskScore: 0,
        suspiciousPatterns: []
      };
    }
    
    // Size limit: 10MB to prevent DoS
    const MAX_CODE_SIZE = 10 * 1024 * 1024;
    if (code.length > MAX_CODE_SIZE) {
      console.warn(`Code size ${code.length} exceeds maximum ${MAX_CODE_SIZE} bytes`);
      throw new Error(`Code exceeds maximum size of ${MAX_CODE_SIZE} bytes`);
    }
    
    // Extract all URLs from the code
    const urls = this.extractUrls(code);
    
    // Detect suspicious domains
    const suspiciousDomains = this.detectSuspiciousDomains(urls);
    
    // Detect suspicious URL patterns
    const suspiciousUrls = this.detectSuspiciousUrlPatterns(code);
    
    // Detect suspicious request patterns
    const requestPatterns = this.detectRequestPatterns(code);
    
    // Calculate risk score
    const riskScore = this.calculateRiskScore(
      suspiciousDomains, 
      suspiciousUrls, 
      requestPatterns
    );
    
    return {
      endpoints: {
        total: urls.length,
        unique: [...new Set(urls)].length,
        suspicious: suspiciousDomains
      },
      suspiciousUrls,
      requestPatterns,
      riskScore
    };
  }
  
  /**
   * Extract all URLs from code
   * @param {string} code - JavaScript code to analyze
   * @returns {string[]} Array of extracted URLs
   */
  extractUrls(code) {
    // Regular expression to match URLs
    const urlRegex = /https?:\/\/[^\s'"`)]+/g;
    
    // Extract all matches
    const matches = code.match(urlRegex) || [];
    
    // Clean up the URLs
    return matches.map(url => {
      // Remove trailing punctuation or code syntax
      return url.replace(/[.,;:)}\\'\"]$/, '');
    });
  }
  
  /**
   * Detect suspicious domains in URLs
   * @param {string[]} urls - Array of URLs to check
   * @returns {Object[]} Suspicious domains found
   */
  detectSuspiciousDomains(urls) {
    const suspicious = [];
    
    urls.forEach(url => {
      try {
        // Extract domain from URL
        const domain = new URL(url).hostname;
        
        // Check against suspicious domains list
        this.suspiciousDomains.forEach(pattern => {
          if (domain.includes(pattern)) {
            suspicious.push({
              url,
              domain,
              reason: `Contains suspicious pattern: ${pattern}`,
              severity: this.getDomainSeverity(pattern)
            });
          }
        });
      } catch (error) {
        // Invalid URL, skip
      }
    });
    
    return suspicious;
  }
  
  /**
   * Determine severity level for suspicious domain
   * @param {string} pattern - The matched suspicious pattern
   * @returns {string} Severity level (low, medium, high)
   */
  getDomainSeverity(pattern) {
    // Cryptocurrency miners and known malicious domains are high severity
    if (
      pattern.includes('coin') || 
      pattern.includes('crypto') || 
      pattern.includes('mine') ||
      pattern === 'pastebin.com' ||
      pattern.includes('paste.')
    ) {
      return 'high';
    }
    
    // URL shorteners and temporary domains are medium severity
    if (
      pattern.includes('.ly') || 
      pattern.includes('tinyurl') || 
      pattern.includes('herokuapp') ||
      pattern.includes('000webhost') ||
      pattern.includes('glitch.me')
    ) {
      return 'medium';
    }
    
    // Analytics and tracking are lower severity (but still suspicious)
    return 'low';
  }
  
  /**
   * Detect suspicious URL patterns in code
   * @param {string} code - JavaScript code to analyze
   * @returns {Object[]} Suspicious URL patterns found
   */
  detectSuspiciousUrlPatterns(code) {
    const suspicious = [];
    
    this.suspiciousUrlPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        suspicious.push({
          pattern: pattern.toString(),
          match: match[0],
          reason: this.getUrlPatternReason(pattern),
          severity: this.getUrlPatternSeverity(pattern)
        });
      }
    });
    
    return suspicious;
  }
  
  /**
   * Get reason for suspicious URL pattern
   * @param {RegExp} pattern - The pattern that matched
   * @returns {string} Reason description
   */
  getUrlPatternReason(pattern) {
    const patternStr = pattern.toString();
    
    if (patternStr.includes('\\d{1,3}\\.\\d{1,3}')) {
      return 'Uses IP address directly instead of domain name';
    } else if (patternStr.includes('base64')) {
      return 'Contains base64 in URL, possibly attempting to hide payload';
    } else if (patternStr.includes(':[^0-9]*')) {
      return 'Uses suspicious port number often associated with malware';
    } else if (patternStr.includes('[a-z0-9]{25,}')) {
      return 'Unusually long domain name, possibly algorithmically generated';
    } else if (patternStr.includes('xyz|top|club')) {
      return 'Uses uncommon TLD often associated with malicious campaigns';
    }
    
    return 'Matches suspicious URL pattern';
  }
  
  /**
   * Get severity for suspicious URL pattern
   * @param {RegExp} pattern - The pattern that matched
   * @returns {string} Severity level
   */
  getUrlPatternSeverity(pattern) {
    const patternStr = pattern.toString();
    
    if (patternStr.includes('base64') || patternStr.includes(':[^0-9]*')) {
      return 'high';
    } else if (patternStr.includes('\\d{1,3}\\.\\d{1,3}')) {
      return 'medium';
    }
    
    return 'low';
  }
  
  /**
   * Detect suspicious request patterns in code
   * @param {string} code - JavaScript code to analyze
   * @returns {Object[]} Suspicious request patterns found
   */
  detectRequestPatterns(code) {
    const suspicious = [];
    
    this.suspiciousRequestPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        suspicious.push({
          pattern: pattern.toString(),
          match: match[0],
          reason: 'Suspicious network request API used'
        });
      }
    });
    
    return suspicious;
  }
  
  /**
   * Calculate risk score based on network analysis
   * @param {Object[]} suspiciousDomains - Suspicious domains found
   * @param {Object[]} suspiciousUrls - Suspicious URLs found
   * @param {Object[]} requestPatterns - Suspicious request patterns found
   * @returns {number} Risk score (0-100)
   */
  calculateRiskScore(suspiciousDomains, suspiciousUrls, requestPatterns) {
    let score = 0;
    
    // Score based on suspicious domains
    suspiciousDomains.forEach(domain => {
      if (domain.severity === 'high') {
        score += 25;
      } else if (domain.severity === 'medium') {
        score += 15;
      } else {
        score += 5;
      }
    });
    
    // Score based on suspicious URL patterns
    suspiciousUrls.forEach(url => {
      if (url.severity === 'high') {
        score += 20;
      } else if (url.severity === 'medium') {
        score += 10;
      } else {
        score += 5;
      }
    });
    
    // Score based on request patterns
    score += requestPatterns.length * 5;
    
    return Math.min(100, score);
  }
}

export default NetworkAnalyzer;

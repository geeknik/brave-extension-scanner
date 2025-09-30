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
      'short.link',
      'cutt.ly',
      'rebrand.ly',
      
      // Temporary/disposable domains
      '.000webhost.',
      '.freehostia.',
      '.herokuapp.com',
      '.glitch.me',
      '.repl.co',
      '.netlify.app',
      '.vercel.app',
      '.github.io',
      '.firebaseapp.com',
      
      // Known malicious patterns
      'pastebin.com',
      'paste.ee',
      'ghostbin.co',
      'hastebin.com',
      'rentry.co',
      'dpaste.com',
      'pastebin.ir',
      
      // Cryptocurrency related (often used in cryptojacking)
      'coin-hive.com',
      'coinhive.com',
      'cryptoloot.pro',
      'crypto-loot.com',
      'minero.cc',
      'ppoi.org',
      'browsermine.com',
      'webmine.pro',
      'cryptonight.wasm',
      'monero-miner.com',
      
      // Command & Control servers
      'c2.',
      'command.',
      'control.',
      'botnet.',
      'malware.',
      'trojan.',
      'backdoor.',
      
      // Data exfiltration services
      'exfiltrator.',
      'stealer.',
      'keylogger.',
      'spy.',
      'harvester.',
      'collector.',
      
      // Suspicious hosting providers
      'noip.com',
      'duckdns.org',
      'freedns.afraid.org',
      'dynu.com',
      
      // Tor and anonymity networks
      '.onion',
      'tor2web.org',
      'torproject.org',
      
      // File sharing services (often used for payload delivery)
      'dropbox.com',
      'drive.google.com',
      'onedrive.live.com',
      'mega.nz',
      'wetransfer.com',
      
      // Social media (can be used for C2)
      'twitter.com',
      'facebook.com',
      'instagram.com',
      'telegram.org',
      'discord.com',
      
      // Email services (for data exfiltration)
      'gmail.com',
      'outlook.com',
      'yahoo.com',
      'protonmail.com'
    ];
    
    // Suspicious URL patterns
    this.suspiciousUrlPatterns = [
      // IP address URLs (suspicious in extensions)
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/g,
      
      // Base64 in URLs
      /https?:\/\/[^/]*base64/g,
      /https?:\/\/[^/]*[A-Za-z0-9+/]{20,}={0,2}/g,
      
      // Unusual ports (commonly used by malware)
      /https?:\/\/[^/]*:(2121|8118|6666|1337|31337|4444|8080|8888|9999)/g,
      
      // Excessively long domain names (often algorithmically generated)
      /https?:\/\/[a-z0-9]{25,}\.[a-z]{2,}/g,
      /https?:\/\/[a-z0-9-]{30,}\.[a-z]{2,}/g,
      
      // Uncommon TLDs often used in malicious campaigns
      /https?:\/\/[^/]*\.(xyz|top|club|gq|tk|ml|ga|cf|click|download|exe|zip)/g,
      
      // Suspicious subdomain patterns
      /https?:\/\/[a-z0-9-]*\.(c2|command|control|botnet|malware|trojan|backdoor)\.[a-z]{2,}/g,
      
      // Dynamic DNS services
      /https?:\/\/[^/]*\.(no-ip|duckdns|freedns|dynu|myq-see|ddns)\.[a-z]{2,}/g,
      
      // Tor hidden services
      /https?:\/\/[a-z2-7]{16,56}\.onion/g,
      
      // Suspicious file extensions in URLs
      /https?:\/\/[^/]*\.(exe|scr|bat|cmd|com|pif|vbs|js|jar|php|asp|jsp)/g,
      
      // Encoded URLs (potential obfuscation)
      /https?:\/\/[^/]*%[0-9A-Fa-f]{2}/g,
      
      // Suspicious query parameters
      /https?:\/\/[^/]*\?[^&]*(cmd|exec|eval|shell|system|download|payload)/g,
      
      // Double encoding attempts
      /https?:\/\/[^/]*%25[0-9A-Fa-f]{2}/g,
      
      // Suspicious path patterns
      /https?:\/\/[^/]*\/(admin|wp-admin|phpmyadmin|backup|config|test|debug)/g,
      
      // UUID-like patterns (often used in malware)
      /https?:\/\/[^/]*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g
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
    } else if (patternStr.includes('6666') || patternStr.includes('1337') || patternStr.includes('2121') || patternStr.includes('8118')) {
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
  
  /**
   * Analyze network behavior patterns
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Network behavior analysis
   */
  analyzeNetworkBehavior(code) {
    const behaviors = {
      bulkRequests: this.detectBulkRequests(code),
      stealthRequests: this.detectStealthRequests(code),
      dataExfiltration: this.detectDataExfiltration(code),
      c2Communication: this.detectC2Communication(code),
      evasionTechniques: this.detectEvasionTechniques(code)
    };
    
    return behaviors;
  }
  
  /**
   * Detect bulk request patterns (potential DDoS or data harvesting)
   * @param {string} code - JavaScript code to analyze
   * @returns {Object[]} Bulk request patterns found
   */
  detectBulkRequests(code) {
    const patterns = [
      // Loops with network requests
      /for\s*\([^)]*\)\s*\{[^}]*fetch\s*\(/g,
      /while\s*\([^)]*\)\s*\{[^}]*XMLHttpRequest/g,
      /setInterval\s*\([^,]*,\s*\d+\)[^}]*fetch/g,
      
      // Array operations with requests
      /\.forEach\s*\([^)]*fetch/g,
      /\.map\s*\([^)]*XMLHttpRequest/g,
      /\.filter\s*\([^)]*fetch/g
    ];
    
    const matches = [];
    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        matches.push({
          type: 'bulk_request',
          match: match[0],
          severity: 'high',
          description: 'Potential bulk network requests detected'
        });
      }
    });
    
    return matches;
  }
  
  /**
   * Detect stealth request patterns (attempts to hide network activity)
   * @param {string} code - JavaScript code to analyze
   * @returns {Object[]} Stealth request patterns found
   */
  detectStealthRequests(code) {
    const patterns = [
      // Random delays
      /setTimeout\s*\([^,]*,\s*Math\.random/g,
      /setInterval\s*\([^,]*,\s*Math\.random/g,
      
      // User agent spoofing
      /headers\s*:\s*\{[^}]*User-Agent/g,
      /setRequestHeader\s*\(\s*['"`]User-Agent['"`]/g,
      
      // Referrer manipulation
      /referrer\s*:\s*['"`]/g,
      /setRequestHeader\s*\(\s*['"`]Referer['"`]/g,
      
      // Request timing manipulation
      /Date\.now\s*\(\s*\)/g,
      /new\s+Date\s*\(\s*\)/g
    ];
    
    const matches = [];
    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        matches.push({
          type: 'stealth_request',
          match: match[0],
          severity: 'medium',
          description: 'Stealth network request technique detected'
        });
      }
    });
    
    return matches;
  }
  
  /**
   * Detect data exfiltration patterns
   * @param {string} code - JavaScript code to analyze
   * @returns {Object[]} Data exfiltration patterns found
   */
  detectDataExfiltration(code) {
    const patterns = [
      // Sensitive data in requests
      /fetch\s*\([^)]*JSON\.stringify\s*\(/g,
      /XMLHttpRequest[^}]*send\s*\([^)]*document\.cookie/g,
      /fetch\s*\([^)]*localStorage/g,
      /fetch\s*\([^)]*sessionStorage/g,
      
      // Form data exfiltration
      /FormData\s*\([^)]*fetch/g,
      /new\s+FormData[^}]*send/g,
      
      // File uploads
      /input\s*\[.*type.*file.*\][^}]*fetch/g,
      /\.files[^}]*FormData/g
    ];
    
    const matches = [];
    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        matches.push({
          type: 'data_exfiltration',
          match: match[0],
          severity: 'high',
          description: 'Potential data exfiltration detected'
        });
      }
    });
    
    return matches;
  }
  
  /**
   * Detect command and control communication patterns
   * @param {string} code - JavaScript code to analyze
   * @returns {Object[]} C2 communication patterns found
   */
  detectC2Communication(code) {
    const patterns = [
      // Heartbeat/beacon patterns
      /setInterval\s*\([^,]*,\s*\d{4,}/g, // Long intervals
      /fetch\s*\([^)]*ping/g,
      /fetch\s*\([^)]*heartbeat/g,
      /fetch\s*\([^)]*beacon/g,
      
      // Command execution patterns
      /fetch\s*\([^)]*cmd/g,
      /fetch\s*\([^)]*command/g,
      /fetch\s*\([^)]*exec/g,
      
      // Status reporting
      /fetch\s*\([^)]*status/g,
      /fetch\s*\([^)]*report/g,
      /fetch\s*\([^)]*update/g
    ];
    
    const matches = [];
    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        matches.push({
          type: 'c2_communication',
          match: match[0],
          severity: 'high',
          description: 'Potential command and control communication detected'
        });
      }
    });
    
    return matches;
  }
  
  /**
   * Detect network evasion techniques
   * @param {string} code - JavaScript code to analyze
   * @returns {Object[]} Evasion techniques found
   */
  detectEvasionTechniques(code) {
    const patterns = [
      // Proxy usage
      /proxy\s*:/g,
      /socks\s*:/g,
      /tunnel\s*:/g,
      
      // Request modification
      /headers\s*:\s*\{[^}]*X-/g,
      /setRequestHeader\s*\(\s*['"`]X-/g,
      
      // Protocol switching
      /ws:\/\//g,
      /wss:\/\//g,
      /ftp:\/\//g,
      
      // Domain generation algorithms
      /Math\.random\s*\(\s*\)[^}]*\.com/g,
      /Date\.now\s*\(\s*\)[^}]*\.org/g
    ];
    
    const matches = [];
    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        matches.push({
          type: 'evasion_technique',
          match: match[0],
          severity: 'medium',
          description: 'Network evasion technique detected'
        });
      }
    });
    
    return matches;
  }
  
  /**
   * Get comprehensive network analysis report
   * @param {string} code - JavaScript code to analyze
   * @returns {Object} Comprehensive network analysis
   */
  getComprehensiveAnalysis(code) {
    const basicAnalysis = this.analyzeCode(code);
    const behaviorAnalysis = this.analyzeNetworkBehavior(code);
    
    // Calculate enhanced risk score
    let enhancedScore = basicAnalysis.riskScore;
    
    // Add behavior-based scoring
    Object.values(behaviorAnalysis).forEach(behaviors => {
      behaviors.forEach(behavior => {
        if (behavior.severity === 'high') {
          enhancedScore += 15;
        } else if (behavior.severity === 'medium') {
          enhancedScore += 10;
        } else {
          enhancedScore += 5;
        }
      });
    });
    
    return {
      ...basicAnalysis,
      behaviorAnalysis,
      enhancedRiskScore: Math.min(100, enhancedScore),
      summary: this.generateNetworkSummary(basicAnalysis, behaviorAnalysis)
    };
  }
  
  /**
   * Generate network analysis summary
   * @param {Object} basicAnalysis - Basic network analysis results
   * @param {Object} behaviorAnalysis - Behavior analysis results
   * @returns {string} Summary text
   */
  generateNetworkSummary(basicAnalysis, behaviorAnalysis) {
    const totalEndpoints = basicAnalysis.endpoints.total;
    const suspiciousEndpoints = basicAnalysis.endpoints.suspicious.length;
    const behaviorCount = Object.values(behaviorAnalysis).reduce((sum, behaviors) => sum + behaviors.length, 0);
    
    if (totalEndpoints === 0) {
      return 'No network activity detected.';
    }
    
    let summary = `Network analysis found ${totalEndpoints} endpoints`;
    if (suspiciousEndpoints > 0) {
      summary += `, ${suspiciousEndpoints} suspicious`;
    }
    if (behaviorCount > 0) {
      summary += `, and ${behaviorCount} suspicious behaviors`;
    }
    summary += '.';
    
    return summary;
  }
}

export default NetworkAnalyzer;

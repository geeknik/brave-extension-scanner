/**
npm ru * Manifest Analyzer Module
 * Analyzes extension manifests for dangerous permissions and suspicious configurations
 */

class ManifestAnalyzer {
  constructor() {
    // Define permission categories based on risk level
    this.dangerousPermissions = [
      "tabs", 
      "webRequest", 
      "cookies", 
      "<all_urls>",
      "bookmarks", 
      "history", 
      "management"
    ];
    
    this.criticalPermissions = [
      "declarativeNetRequest", 
      "debugger",
      "proxy", 
      "privacy", 
      "contentSettings"
    ];
    
    this.moderatePermissions = [
      "storage",
      "notifications",
      "contextMenus",
      "webNavigation",
      "activeTab"
    ];
    
    // Suspicious content security policy configurations
    this.suspiciousCSPDirectives = [
      "unsafe-eval",
      "unsafe-inline",
      "data:",
      "blob:",
      "filesystem:"
    ];
  }
  
  /**
   * Analyze a manifest.json file
   * @param {Object} manifest - The parsed manifest.json object
   * @returns {Object} Analysis results
   */
  analyzeManifest(manifest) {
    // Input validation
    if (!manifest || typeof manifest !== 'object') {
      console.error('Invalid manifest: must be an object');
      return {
        error: "Invalid manifest: must be an object",
        riskScore: 100
      };
    }
    
    // Validate required fields
    if (!manifest.name || typeof manifest.name !== 'string') {
      console.warn('Manifest missing required field: name');
    }
    
    if (!manifest.version || typeof manifest.version !== 'string') {
      console.warn('Manifest missing required field: version');
    }
    
    if (!manifest.manifest_version || typeof manifest.manifest_version !== 'number') {
      console.warn('Manifest missing required field: manifest_version');
    }
    
    const results = {
      manifestVersion: manifest.manifest_version || 2,
      permissions: this.analyzePermissions(manifest),
      contentScripts: this.analyzeContentScripts(manifest),
      csp: this.analyzeCSP(manifest),
      externalConnections: this.analyzeExternalConnections(manifest),
      backgroundPersistence: this.checkBackgroundPersistence(manifest),
      hostPermissions: this.analyzeHostPermissions(manifest)
    };
    
    // Calculate overall risk score
    results.riskScore = this.calculateRiskScore(results);
    
    return results;
  }
  
  /**
   * Analyze permissions requested by the extension
   * @param {Object} manifest - The manifest object
   * @returns {Object} Permission analysis results
   */
  analyzePermissions(manifest) {
    const permissions = (manifest.permissions || []).filter(p => typeof p === 'string');
    const optionalPermissions = (manifest.optional_permissions || []).filter(p => typeof p === 'string');
    
    // Check for dangerous permissions
    const dangerousFound = permissions.filter(p => 
      this.dangerousPermissions.includes(p)
    );
    
    // Check for critical permissions
    const criticalFound = permissions.filter(p => 
      this.criticalPermissions.includes(p)
    );
    
    // Check for moderate permissions
    const moderateFound = permissions.filter(p => 
      this.moderatePermissions.includes(p)
    );
    
    // Check optional permissions too
    const optionalDangerous = optionalPermissions.filter(p => 
      this.dangerousPermissions.includes(p)
    );
    
    const optionalCritical = optionalPermissions.filter(p => 
      this.criticalPermissions.includes(p)
    );
    
    return {
      total: permissions.length,
      dangerous: {
        count: dangerousFound.length,
        permissions: dangerousFound
      },
      critical: {
        count: criticalFound.length,
        permissions: criticalFound
      },
      moderate: {
        count: moderateFound.length,
        permissions: moderateFound
      },
      optional: {
        dangerous: optionalDangerous,
        critical: optionalCritical
      }
    };
  }
  
  /**
   * Analyze content scripts for suspicious patterns
   * @param {Object} manifest - The manifest object
   * @returns {Object} Content script analysis results
   */
  analyzeContentScripts(manifest) {
    const contentScripts = manifest.content_scripts || [];
    
    // Check for content scripts with broad matches
    const broadMatches = contentScripts.filter(cs => {
      const matches = cs.matches || [];
      return matches.some(m => m === "<all_urls>" || m === "*://*/*");
    });
    
    // Check for content scripts that run at document_start
    const documentStartScripts = contentScripts.filter(cs => 
      cs.run_at === "document_start"
    );
    
    return {
      count: contentScripts.length,
      broadMatchCount: broadMatches.length,
      documentStartCount: documentStartScripts.length,
      broadMatches: broadMatches.map(cs => cs.matches),
      riskLevel: this.assessContentScriptRisk(contentScripts)
    };
  }
  
  /**
   * Analyze Content Security Policy for suspicious directives
   * @param {Object} manifest - The manifest object
   * @returns {Object} CSP analysis results
   */
  analyzeCSP(manifest) {
    const csp = manifest.content_security_policy || "";
    
    // Check for suspicious CSP directives
    const suspiciousDirectives = this.suspiciousCSPDirectives.filter(directive => 
      csp.includes(directive)
    );
    
    return {
      policy: csp,
      suspiciousDirectives,
      hasSuspiciousDirectives: suspiciousDirectives.length > 0
    };
  }
  
  /**
   * Analyze external connections
   * @param {Object} manifest - The manifest object
   * @returns {Object} External connections analysis
   */
  analyzeExternalConnections(manifest) {
    const externallyConnectable = manifest.externally_connectable || {};
    const matches = externallyConnectable.matches || [];
    
    // Check for broad connection patterns
    const broadMatches = matches.filter(m => 
      m === "<all_urls>" || m === "*://*/*" || (typeof m === 'string' && m.includes("*."))
    );
    
    return {
      enabled: matches.length > 0,
      matchCount: matches.length,
      broadMatchCount: broadMatches.length,
      acceptsConnections: externallyConnectable.accepts_tls_channel_id || false,
      riskLevel: broadMatches.length > 0 ? "high" : 
                (matches.length > 0 ? "medium" : "low")
    };
  }
  
  /**
   * Check if background page is persistent
   * @param {Object} manifest - The manifest object
   * @returns {Object} Background persistence analysis
   */
  checkBackgroundPersistence(manifest) {
    const background = manifest.background || {};
    
    // In Manifest V2, persistent: true is higher risk
    // In Manifest V3, service workers are used instead
    const isPersistent = manifest.manifest_version === 2 && 
                        background.persistent === true;
    
    return {
      persistent: isPersistent,
      riskLevel: isPersistent ? "medium" : "low"
    };
  }
  
  /**
   * Analyze host permissions
   * @param {Object} manifest - The manifest object
   * @returns {Object} Host permissions analysis
   */
  analyzeHostPermissions(manifest) {
    const hostPermissions = [];
    
    // In Manifest V2, host permissions can be in the permissions array
    if (manifest.permissions) {
      const urlPatterns = manifest.permissions.filter(p => 
        typeof p === 'string' && (p.includes("://") || p === "<all_urls>")
      );
      hostPermissions.push(...urlPatterns);
    }
    
    // In Manifest V3, host permissions are in host_permissions
    if (manifest.host_permissions) {
      hostPermissions.push(...manifest.host_permissions);
    }
    
    // Check for broad host permissions
    const broadPermissions = hostPermissions.filter(p => 
      p === "<all_urls>" || p === "*://*/*"
    );
    
    return {
      count: hostPermissions.length,
      broadPermissionCount: broadPermissions.length,
      permissions: hostPermissions,
      riskLevel: broadPermissions.length > 0 ? "high" : 
                (hostPermissions.length > 5 ? "medium" : "low")
    };
  }
  
  /**
   * Assess the risk level of content scripts
   * @param {Array} contentScripts - Content scripts array from manifest
   * @returns {string} Risk level (low, medium, high)
   */
  assessContentScriptRisk(contentScripts) {
    if (contentScripts.length === 0) {
      return "low";
    }
    
    const broadMatchScripts = contentScripts.filter(cs => {
      const matches = cs.matches || [];
      return matches.some(m => m === "<all_urls>" || m === "*://*/*");
    });
    
    const documentStartScripts = contentScripts.filter(cs => 
      cs.run_at === "document_start"
    );
    
    if (broadMatchScripts.length > 0 && documentStartScripts.length > 0) {
      return "high";
    } else if (broadMatchScripts.length > 0 || documentStartScripts.length > 0) {
      return "medium";
    }
    
    return "low";
  }
  
  /**
   * Calculate overall risk score based on manifest analysis
   * @param {Object} results - Analysis results
   * @returns {number} Risk score (0-100)
   */
  calculateRiskScore(results) {
    let score = 0;
    
    // Permissions score (0-40)
    const permissionScore = 
      (results.permissions.dangerous.count * 10) + 
      (results.permissions.critical.count * 15) +
      (results.permissions.moderate.count * 2);
    score += Math.min(40, permissionScore);
    
    // Content scripts score (0-20)
    let contentScriptScore = results.contentScripts.count * 2;
    if (results.contentScripts.broadMatchCount > 0) {
      contentScriptScore += 10;
    }
    if (results.contentScripts.documentStartCount > 0) {
      contentScriptScore += 5;
    }
    score += Math.min(20, contentScriptScore);
    
    // CSP score (0-15)
    if (results.csp.hasSuspiciousDirectives) {
      score += Math.min(15, results.csp.suspiciousDirectives.length * 5);
    }
    
    // External connections score (0-10)
    if (results.externalConnections.enabled) {
      score += 5;
      if (results.externalConnections.broadMatchCount > 0) {
        score += 5;
      }
    }
    
    // Background persistence score (0-5)
    if (results.backgroundPersistence.persistent) {
      score += 5;
    }
    
    // Host permissions score (0-10)
    let hostScore = Math.min(5, results.hostPermissions.count);
    if (results.hostPermissions.broadPermissionCount > 0) {
      hostScore += 5;
    }
    score += hostScore;
    
    return Math.min(100, score);
  }
}

export default ManifestAnalyzer;
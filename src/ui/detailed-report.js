/**
 * Detailed Report Module
 * Generates detailed HTML reports for extension scan results
 */

import { capitalizeFirst, getThreatLevelClass, escapeHtml } from '../utils/common.js';

class DetailedReport {
  /**
   * Generate a detailed HTML report for scan results
   * @param {Object} scanResult - The scan result object
   * @returns {string} HTML content for the report
   */
  generateReport(scanResult) {
    const { extensionInfo, threatClassification, details } = scanResult;
    
    // Start building the HTML
    let html = `
      <div class="detailed-report">
        <div class="report-header">
          <h2>${escapeHtml(extensionInfo.name)}</h2>
          <div class="extension-meta">
            <span>Version: ${escapeHtml(extensionInfo.version)}</span>
            <span>ID: ${escapeHtml(extensionInfo.id)}</span>
          </div>
          <div class="threat-badge threat-${threatClassification.level}">
            ${capitalizeFirst(threatClassification.level)} Risk
          </div>
        </div>
        
        <div class="report-summary">
          <h3>Summary</h3>
          <p>${escapeHtml(threatClassification.summary)}</p>
          
          <div class="threat-score">
            <div class="score-label">Threat Score</div>
            <div class="score-value">${threatClassification.score}/100</div>
            <div class="score-bar">
              <div class="score-fill" style="width: ${threatClassification.score}%"></div>
            </div>
          </div>
        </div>
        
        <div class="report-recommendations">
          <h3>Recommendations</h3>
          <ul class="recommendations-list">
            ${threatClassification.recommendations.map(rec => `<li>${escapeHtml(rec.recommendation)}</li>`).join('')}
          </ul>
        </div>
        
        <div class="report-categories">
          <h3>Detected Issues</h3>
          ${this.generateCategoriesSection(threatClassification.categories)}
        </div>
        
        <div class="report-details">
          <h3>Technical Details</h3>
          
          <div class="details-section">
            <h4>Permissions Analysis</h4>
            ${this.generatePermissionsSection(details.manifestAnalysis)}
          </div>
          
          <div class="details-section">
            <h4>Code Analysis</h4>
            ${this.generateCodeAnalysisSection(details.staticAnalysis)}
          </div>
          
          <div class="details-section">
            <h4>Obfuscation Analysis</h4>
            ${this.generateObfuscationSection(details.obfuscationAnalysis)}
          </div>
          
          <div class="details-section">
            <h4>Network Analysis</h4>
            ${this.generateNetworkSection(details.networkAnalysis)}
          </div>
        </div>
      </div>
    `;
    
    return html;
  }
  
  /**
   * Generate HTML for threat categories section
   * @param {Object[]} categories - Threat categories
   * @returns {string} HTML content
   */
  generateCategoriesSection(categories) {
    if (!categories || categories.length === 0) {
      return '<p>No specific threat categories detected.</p>';
    }
    
    return `
      <div class="categories-list">
        ${categories.map(category => `
          <div class="category-item severity-${category.severity}">
            <div class="category-header">
              <h4>${escapeHtml(category.name)}</h4>
              <span class="severity-badge">${capitalizeFirst(category.severity)}</span>
            </div>
            <p>${escapeHtml(category.description)}</p>
          </div>
        `).join('')}
      </div>
    `;
  }
  
  /**
   * Generate HTML for permissions section
   * @param {Object} manifestAnalysis - Manifest analysis results
   * @returns {string} HTML content
   */
  generatePermissionsSection(manifestAnalysis) {
    if (!manifestAnalysis || !manifestAnalysis.permissions) {
      return '<p>No permission data available.</p>';
    }
    
    const { permissions } = manifestAnalysis;
    
    let html = `
      <div class="permissions-summary">
        <div class="permission-stat">
          <span class="stat-label">Total Permissions:</span>
          <span class="stat-value">${permissions.total}</span>
        </div>
        <div class="permission-stat">
          <span class="stat-label">Dangerous Permissions:</span>
          <span class="stat-value">${permissions.dangerous.count}</span>
        </div>
        <div class="permission-stat">
          <span class="stat-label">Critical Permissions:</span>
          <span class="stat-value">${permissions.critical.count}</span>
        </div>
      </div>
    `;
    
    // Add dangerous permissions
    if (permissions.dangerous.count > 0) {
      html += `
        <div class="permission-group danger">
          <h5>Dangerous Permissions</h5>
          <ul>
            ${permissions.dangerous.permissions.map(perm => 
              `<li>${escapeHtml(perm)}</li>`
            ).join('')}
          </ul>
        </div>
      `;
    }
    
    // Add critical permissions
    if (permissions.critical.count > 0) {
      html += `
        <div class="permission-group critical">
          <h5>Critical Permissions</h5>
          <ul>
            ${permissions.critical.permissions.map(perm => 
              `<li>${escapeHtml(perm)}</li>`
            ).join('')}
          </ul>
        </div>
      `;
    }
    
    return html;
  }
  
  /**
   * Generate HTML for code analysis section
   * @param {Object} staticAnalysis - Static analysis results
   * @returns {string} HTML content
   */
  generateCodeAnalysisSection(staticAnalysis) {
    if (!staticAnalysis || !staticAnalysis.suspiciousPatterns) {
      return '<p>No code analysis data available.</p>';
    }
    
    const { suspiciousPatterns } = staticAnalysis;
    
    if (suspiciousPatterns.length === 0) {
      return '<p>No suspicious code patterns detected.</p>';
    }
    
    return `
      <div class="code-patterns">
        ${suspiciousPatterns.map(pattern => `
          <div class="pattern-item severity-${pattern.severity}">
            <div class="pattern-header">
              <h5>${escapeHtml(pattern.category)}</h5>
              <span class="count-badge">${pattern.count} instance${pattern.count !== 1 ? 's' : ''}</span>
            </div>
            <p>${escapeHtml(pattern.description)}</p>
          </div>
        `).join('')}
      </div>
    `;
  }
  
  /**
   * Generate HTML for obfuscation section
   * @param {Object} obfuscationAnalysis - Obfuscation analysis results
   * @returns {string} HTML content
   */
  generateObfuscationSection(obfuscationAnalysis) {
    if (!obfuscationAnalysis) {
      return '<p>No obfuscation analysis data available.</p>';
    }
    
    let html = `
      <div class="obfuscation-summary">
        <div class="obfuscation-stat">
          <span class="stat-label">Obfuscation Detected:</span>
          <span class="stat-value ${obfuscationAnalysis.obfuscationDetected ? 'text-danger' : 'text-success'}">
            ${obfuscationAnalysis.obfuscationDetected ? 'Yes' : 'No'}
          </span>
        </div>
        <div class="obfuscation-stat">
          <span class="stat-label">Obfuscation Score:</span>
          <span class="stat-value">${obfuscationAnalysis.obfuscationScore}/100</span>
        </div>
        <div class="obfuscation-stat">
          <span class="stat-label">Code Entropy:</span>
          <span class="stat-value">${obfuscationAnalysis.entropy.toFixed(2)}</span>
        </div>
      </div>
    `;
    
    // Add techniques if any were detected
    if (obfuscationAnalysis.techniques && obfuscationAnalysis.techniques.length > 0) {
      html += `
        <div class="obfuscation-techniques">
          <h5>Detected Techniques</h5>
          ${obfuscationAnalysis.techniques.map(technique => `
            <div class="technique-item severity-${technique.severity}">
              <div class="technique-header">
                <span>${escapeHtml(technique.name)}</span>
                <span class="severity-badge">${capitalizeFirst(technique.severity)}</span>
              </div>
              <p>${escapeHtml(technique.description)}</p>
              ${technique.count ? `<div class="technique-count">Instances: ${technique.count}</div>` : ''}
            </div>
          `).join('')}
        </div>
      `;
    }
    
    return html;
  }
  
  /**
   * Generate HTML for network analysis section
   * @param {Object} networkAnalysis - Network analysis results
   * @returns {string} HTML content
   */
  generateNetworkSection(networkAnalysis) {
    if (!networkAnalysis) {
      return '<p>No network analysis data available.</p>';
    }
    
    let html = `
      <div class="network-summary">
        <div class="network-stat">
          <span class="stat-label">Total Endpoints:</span>
          <span class="stat-value">${networkAnalysis.endpoints?.total || 0}</span>
        </div>
        <div class="network-stat">
          <span class="stat-label">Suspicious Endpoints:</span>
          <span class="stat-value">${networkAnalysis.endpoints?.suspicious?.length || 0}</span>
        </div>
        <div class="network-stat">
          <span class="stat-label">Risk Score:</span>
          <span class="stat-value">${networkAnalysis.riskScore}/100</span>
        </div>
      </div>
    `;
    
    // Add suspicious domains if any were detected
    if (networkAnalysis.endpoints?.suspicious?.length > 0) {
      html += `
        <div class="suspicious-domains">
          <h5>Suspicious Domains</h5>
          <div class="domains-list">
            ${networkAnalysis.endpoints.suspicious.map(domain => `
              <div class="domain-item severity-${domain.severity}">
                <div class="domain-header">
                  <span>${escapeHtml(domain.domain)}</span>
                  <span class="severity-badge">${capitalizeFirst(domain.severity)}</span>
                </div>
                <p>${escapeHtml(domain.reason)}</p>
                <div class="domain-url">${escapeHtml(domain.url)}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }
    
    // Add suspicious URL patterns if any were detected
    if (networkAnalysis.suspiciousUrls?.length > 0) {
      html += `
        <div class="suspicious-urls">
          <h5>Suspicious URL Patterns</h5>
          <div class="urls-list">
            ${networkAnalysis.suspiciousUrls.map(url => `
              <div class="url-item severity-${url.severity}">
                <div class="url-header">
                  <span>${escapeHtml(url.pattern)}</span>
                  <span class="severity-badge">${capitalizeFirst(url.severity)}</span>
                </div>
                <p>${escapeHtml(url.reason)}</p>
                <div class="url-match">${escapeHtml(url.match)}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }
    
    return html;
  }
}

// Export the detailed report generator
// Make DetailedReport available globally for importScripts
if (typeof window !== "undefined") {
  window.DetailedReport = DetailedReport;
} else if (typeof self !== "undefined") {
  self.DetailedReport = DetailedReport;
}
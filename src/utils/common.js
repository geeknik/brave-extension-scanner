/**
 * Common utility functions for Brave Extension Scanner
 * Provides helper functions used throughout the extension
 */

/**
 * Sanitize error for safe logging (removes sensitive data)
 * @param {Error|string} error - Error object or message
 * @returns {Object} Sanitized error object
 */
function sanitizeError(error) {
  if (!error) {
    return { message: 'Unknown error', type: 'Error' };
  }
  
  // If it's a string, return as-is (assumed to be safe)
  if (typeof error === 'string') {
    return { message: error, type: 'Error' };
  }
  
  // Extract safe information from Error object
  const sanitized = {
    message: error.message || 'Unknown error',
    type: error.constructor?.name || 'Error'
  };
  
  // Remove potentially sensitive information from error messages
  const sensitivePatterns = [
    /chrome-extension:\/\/[a-z]+/gi,  // Extension IDs
    /file:\/\/[^\s]+/gi,              // File paths
    /\/Users\/[^\s]+/gi,              // User paths  
    /\/home\/[^\s]+/gi,               // Linux paths
    /C:\\Users\\[^\s]+/gi,            // Windows paths
    /"id":"[a-z]+"/gi,                // Extension IDs in JSON
  ];
  
  for (const pattern of sensitivePatterns) {
    sanitized.message = sanitized.message.replace(pattern, '[REDACTED]');
  }
  
  return sanitized;
}

/**
 * Log error safely without exposing sensitive information
 * @param {string} context - Context where error occurred
 * @param {Error|string} error - Error to log
 */
function logError(context, error) {
  const sanitized = sanitizeError(error);
  console.error(`[${context}]`, sanitized.type, ':', sanitized.message);
}

// Format a date for display
function formatDate(date) {
  // If less than 24 hours ago, show relative time
  const now = new Date();
  const diffMs = now - date;
  const diffHours = diffMs / (1000 * 60 * 60);
  
  if (diffHours < 24) {
    if (diffHours < 1) {
      const diffMinutes = Math.floor(diffMs / (1000 * 60));
      return diffMinutes === 0 ? 'Just now' : `${diffMinutes} minute${diffMinutes === 1 ? '' : 's'} ago`;
    } else {
      const hours = Math.floor(diffHours);
      return `${hours} hour${hours === 1 ? '' : 's'} ago`;
    }
  } else {
    // Format as date
    return date.toLocaleDateString(undefined, { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }
}

// Get CSS class for threat level
function getThreatLevelClass(level) {
  switch (level) {
    case 'critical':
    case 'high':
      return 'danger';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    case 'safe':
    default:
      return 'success';
  }
}

// Capitalize first letter of a string
function capitalizeFirst(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

// Calculate Shannon entropy of a string
function calculateEntropy(str) {
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

// Extract URLs from a string
function extractUrls(text) {
  const urlRegex = /https?:\/\/[^\s'"`)]+/g;
  const matches = text.match(urlRegex) || [];
  
  // Clean up the URLs
  return matches.map(url => {
    // Remove trailing punctuation or code syntax
    return url.replace(/[.,;:)}\\'\"]$/, '');
  });
}

// Check if a string is likely minified
function isMinified(code) {
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

// Deep clone an object
function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

// Generate a unique ID
function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

// Safely parse JSON with error handling
function safeJsonParse(str, fallback = null) {
  try {
    return JSON.parse(str);
  } catch (error) {
    console.error('Error parsing JSON:', error);
    return fallback;
  }
}

// Truncate a string to a maximum length with ellipsis
function truncate(str, maxLength = 100) {
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength - 3) + '...';
}

// Escape HTML to prevent XSS
function escapeHtml(html) {
  const div = document.createElement('div');
  div.textContent = html;
  return div.innerHTML;
}

// Debounce function to limit how often a function can be called
function debounce(func, wait) {
  let timeout;
  return function(...args) {
    const context = this;
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(context, args), wait);
  };
}

// Throttle function to limit how often a function can be called
function throttle(func, limit) {
  let inThrottle;
  return function(...args) {
    const context = this;
    if (!inThrottle) {
      func.apply(context, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// Check if a URL is suspicious
function isSuspiciousUrl(url) {
  try {
    const urlObj = new URL(url);
    
    // Check for IP address URLs
    const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipRegex.test(urlObj.hostname)) {
      return true;
    }
    
    // Check for suspicious TLDs
    const suspiciousTlds = ['xyz', 'top', 'club', 'gq', 'tk', 'ml', 'ga', 'cf'];
    const tld = urlObj.hostname.split('.').pop();
    if (suspiciousTlds.includes(tld)) {
      return true;
    }
    
    // Check for excessively long domain names (often algorithmically generated)
    const domainParts = urlObj.hostname.split('.');
    if (domainParts.some(part => part.length > 25)) {
      return true;
    }
    
    // Check for unusual ports
    const suspiciousPorts = [2121, 8118, 6666, 1337, 31337];
    if (urlObj.port && suspiciousPorts.includes(parseInt(urlObj.port))) {
      return true;
    }
    
    // Check for base64 in URL
    if (urlObj.pathname.includes('base64') || urlObj.search.includes('base64')) {
      return true;
    }
    
    return false;
  } catch (error) {
    // Invalid URL
    return false;
  }
}

// Check if a string contains obfuscated code patterns
function hasObfuscationPatterns(code) {
  // Check for common obfuscation patterns
  const patterns = [
    /eval\s*\(/g,                                // eval()
    /String\.fromCharCode\s*\(/g,                // String.fromCharCode()
    /\\x[0-9a-fA-F]{2}/g,                        // \xNN hex escapes
    /\\u[0-9a-fA-F]{4}/g,                        // \uNNNN unicode escapes
    /['"`]\s*\+\s*['"`]/g,                       // String concatenation
    /\(\s*\+\s*\+\s*\!/g,                        // (++!...) constructs
    /\!\s*\+\s*\[\]/g,                           // !+[] constructs
    /atob\s*\(/g,                                // atob()
    /btoa\s*\(/g                                 // btoa()
  ];
  
  // Check each pattern
  for (const pattern of patterns) {
    if (pattern.test(code)) {
      return true;
    }
  }
  
  // Check entropy
  const entropy = calculateEntropy(code);
  if (entropy > 5.5) {
    return true;
  }
  
  return false;
}

// Format a risk score as a percentage with color coding
function formatRiskScore(score) {
  let color;
  
  if (score >= 80) {
    color = '#d9534f'; // Danger red
  } else if (score >= 60) {
    color = '#f0ad4e'; // Warning orange
  } else if (score >= 40) {
    color = '#5bc0de'; // Info blue
  } else if (score >= 20) {
    color = '#5cb85c'; // Success green
  } else {
    color = '#5cb85c'; // Success green
  }
  
  return {
    value: score,
    display: `${score}%`,
    color: color
  };
}

// Get a human-readable description of a permission
function getPermissionDescription(permission) {
  const descriptions = {
    'tabs': 'Can access your open tabs and browsing activity',
    'webRequest': 'Can monitor and modify your web requests',
    'cookies': 'Can access and modify browser cookies',
    '<all_urls>': 'Can access all websites you visit',
    'bookmarks': 'Can read and modify your bookmarks',
    'history': 'Can access your browsing history',
    'management': 'Can manage your installed extensions',
    'declarativeNetRequest': 'Can block content on websites you visit',
    'debugger': 'Can debug and modify other extensions',
    'proxy': 'Can control your proxy settings',
    'privacy': 'Can change your privacy settings',
    'contentSettings': 'Can change your content settings',
    'storage': 'Can store data on your device',
    'notifications': 'Can show notifications',
    'contextMenus': 'Can add items to your right-click menu',
    'webNavigation': 'Can track your navigation between websites',
    'activeTab': 'Can access the currently active tab'
  };
  
  return descriptions[permission] || `Can use the ${permission} permission`;
}

// Categorize a permission by risk level
function categorizePermission(permission) {
  const dangerousPermissions = [
    'tabs', 'webRequest', 'cookies', '<all_urls>',
    'bookmarks', 'history', 'management'
  ];
  
  const criticalPermissions = [
    'declarativeNetRequest', 'debugger',
    'proxy', 'privacy', 'contentSettings'
  ];
  
  const moderatePermissions = [
    'storage', 'notifications', 'contextMenus',
    'webNavigation', 'activeTab'
  ];
  
  if (dangerousPermissions.includes(permission)) {
    return 'dangerous';
  } else if (criticalPermissions.includes(permission)) {
    return 'critical';
  } else if (moderatePermissions.includes(permission)) {
    return 'moderate';
  } else {
    return 'low';
  }
}

// Export all functions
export {
  sanitizeError,
  logError,
  formatDate,
  getThreatLevelClass,
  capitalizeFirst,
  calculateEntropy,
  extractUrls,
  isMinified,
  deepClone,
  generateId,
  safeJsonParse,
  truncate,
  escapeHtml,
  debounce,
  throttle,
  isSuspiciousUrl,
  hasObfuscationPatterns,
  formatRiskScore,
  getPermissionDescription,
  categorizePermission
};

// Make functions available globally for importScripts
if (typeof window !== 'undefined') {
  window.formatDate = formatDate;
  window.getThreatLevelClass = getThreatLevelClass;
  window.capitalizeFirst = capitalizeFirst;
  window.calculateEntropy = calculateEntropy;
  window.extractUrls = extractUrls;
  window.isMinified = isMinified;
  window.deepClone = deepClone;
  window.generateId = generateId;
  window.safeJsonParse = safeJsonParse;
  window.truncate = truncate;
  window.escapeHtml = escapeHtml;
  window.debounce = debounce;
  window.throttle = throttle;
  window.isSuspiciousUrl = isSuspiciousUrl;
  window.hasObfuscationPatterns = hasObfuscationPatterns;
  window.formatRiskScore = formatRiskScore;
  window.getPermissionDescription = getPermissionDescription;
  window.categorizePermission = categorizePermission;
} else if (typeof self !== 'undefined') {
  self.formatDate = formatDate;
  self.getThreatLevelClass = getThreatLevelClass;
  self.capitalizeFirst = capitalizeFirst;
  self.calculateEntropy = calculateEntropy;
  self.extractUrls = extractUrls;
  self.isMinified = isMinified;
  self.deepClone = deepClone;
  self.generateId = generateId;
  self.safeJsonParse = safeJsonParse;
  self.truncate = truncate;
  self.escapeHtml = escapeHtml;
  self.debounce = debounce;
  self.throttle = throttle;
  self.isSuspiciousUrl = isSuspiciousUrl;
  self.hasObfuscationPatterns = hasObfuscationPatterns;
  self.formatRiskScore = formatRiskScore;
  self.getPermissionDescription = getPermissionDescription;
  self.categorizePermission = categorizePermission;
}
/**
 * Runtime Monitor Module
 * Monitors extension behavior in real-time to detect malicious activities
 * This works around Chrome's file reading restrictions by monitoring actual behavior
 */

class RuntimeMonitor {
  constructor() {
    this.monitoredExtensions = new Map();
    this.behavioralPatterns = {
      // Network monitoring
      suspiciousRequests: [],
      dataExfiltration: [],
      c2Communication: [],
      
      // DOM monitoring
      keylogging: [],
      formHijacking: [],
      clickjacking: [],
      
      // Storage monitoring
      dataAccess: [],
      persistence: [],
      
      // API monitoring
      dangerousAPIs: [],
      permissionAbuse: []
    };
    
    this.setupMonitoring();
  }
  
  /**
   * Setup runtime monitoring for all installed extensions
   */
  async setupMonitoring() {
    try {
      // Check if we're in a context where runtime monitoring is possible
      if (typeof window === 'undefined') {
        console.log('⚠️ Runtime monitoring not available in service worker context');
        return;
      }
      
      // Monitor network requests
      this.monitorNetworkRequests();
      
      // Monitor DOM modifications
      this.monitorDOMModifications();
      
      // Monitor storage access
      this.monitorStorageAccess();
      
      // Monitor API usage
      this.monitorAPIUsage();
      
      console.log('✅ Runtime monitoring setup complete');
    } catch (error) {
      console.error('❌ Failed to setup runtime monitoring:', error);
    }
  }
  
  /**
   * Monitor network requests from extensions
   */
  monitorNetworkRequests() {
    if (typeof window === 'undefined') return;
    
    // Override fetch to monitor requests
    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
      const [url, options] = args;
      
      // Check if this is a suspicious request
      const suspicious = this.analyzeNetworkRequest(url, options);
      if (suspicious) {
        this.behavioralPatterns.suspiciousRequests.push({
          url,
          options,
          timestamp: Date.now(),
          suspicious: suspicious
        });
      }
      
      return originalFetch.apply(this, args);
    };
    
    // Override XMLHttpRequest
    const originalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
      const xhr = new originalXHR();
      const originalOpen = xhr.open;
      const originalSend = xhr.send;
      
      xhr.open = function(method, url, ...args) {
        this._method = method;
        this._url = url;
        return originalOpen.apply(this, [method, url, ...args]);
      };
      
      xhr.send = function(data) {
        const suspicious = this.analyzeNetworkRequest(this._url, { method: this._method, body: data });
        if (suspicious) {
          this.behavioralPatterns.suspiciousRequests.push({
            url: this._url,
            method: this._method,
            data,
            timestamp: Date.now(),
            suspicious: suspicious
          });
        }
        return originalSend.apply(this, arguments);
      };
      
      return xhr;
    };
  }
  
  /**
   * Monitor DOM modifications for keylogging and form hijacking
   */
  monitorDOMModifications() {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;
    
    // Monitor for keylogging
    document.addEventListener('keydown', (event) => {
      // Check if this is from an extension context
      if (this.isFromExtension(event)) {
        this.behavioralPatterns.keylogging.push({
          key: event.key,
          code: event.code,
          timestamp: Date.now(),
          target: event.target.tagName
        });
      }
    }, true);
    
    // Monitor for form submissions
    document.addEventListener('submit', (event) => {
      if (this.isFromExtension(event)) {
        const formData = this.extractFormData(event.target);
        this.behavioralPatterns.formHijacking.push({
          formData,
          timestamp: Date.now(),
          target: event.target
        });
      }
    }, true);
    
    // Monitor for clickjacking
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'attributes' && 
            (mutation.attributeName === 'style' || mutation.attributeName === 'class')) {
          const element = mutation.target;
          if (this.isClickjackingElement(element)) {
            this.behavioralPatterns.clickjacking.push({
              element: element.tagName,
              styles: element.style.cssText,
              timestamp: Date.now()
            });
          }
        }
      });
    });
    
    observer.observe(document.body, {
      attributes: true,
      subtree: true,
      attributeFilter: ['style', 'class']
    });
  }
  
  /**
   * Monitor storage access
   */
  monitorStorageAccess() {
    if (typeof window === 'undefined' || typeof localStorage === 'undefined') return;
    
    // Monitor localStorage
    const originalSetItem = localStorage.setItem;
    localStorage.setItem = function(key, value) {
      this.behavioralPatterns.dataAccess.push({
        type: 'localStorage',
        action: 'set',
        key,
        value: value.substring(0, 100), // Truncate for privacy
        timestamp: Date.now()
      });
      return originalSetItem.apply(this, arguments);
    };
    
    const originalGetItem = localStorage.getItem;
    localStorage.getItem = function(key) {
      this.behavioralPatterns.dataAccess.push({
        type: 'localStorage',
        action: 'get',
        key,
        timestamp: Date.now()
      });
      return originalGetItem.apply(this, arguments);
    };
    
    // Monitor sessionStorage
    const originalSessionSetItem = sessionStorage.setItem;
    sessionStorage.setItem = function(key, value) {
      this.behavioralPatterns.dataAccess.push({
        type: 'sessionStorage',
        action: 'set',
        key,
        value: value.substring(0, 100),
        timestamp: Date.now()
      });
      return originalSessionSetItem.apply(this, arguments);
    };
  }
  
  /**
   * Monitor API usage
   */
  monitorAPIUsage() {
    if (typeof window === 'undefined') return;
    
    // Monitor Chrome extension APIs
    if (window.chrome) {
      const originalSendMessage = chrome.runtime.sendMessage;
      if (originalSendMessage) {
        chrome.runtime.sendMessage = function(...args) {
          this.behavioralPatterns.dangerousAPIs.push({
            api: 'chrome.runtime.sendMessage',
            args: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg).substring(0, 100) : arg),
            timestamp: Date.now()
          });
          return originalSendMessage.apply(this, arguments);
        };
      }
      
      // Monitor tabs API
      if (chrome.tabs) {
        const originalQuery = chrome.tabs.query;
        if (originalQuery) {
          chrome.tabs.query = function(...args) {
            this.behavioralPatterns.dangerousAPIs.push({
              api: 'chrome.tabs.query',
              args,
              timestamp: Date.now()
            });
            return originalQuery.apply(this, arguments);
          };
        }
      }
    }
  }
  
  /**
   * Analyze network request for suspicious patterns
   */
  analyzeNetworkRequest(url, options = {}) {
    const suspiciousPatterns = {
      dataExfiltration: /\/api\/data|\/collect|\/track|\/steal|\/exfiltrate/i,
      c2Communication: /\/c2|\/command|\/control|\/botnet/i,
      suspiciousDomains: /\.tk$|\.ml$|\.ga$|\.cf$|\.onion$/i,
      encodedPayloads: /base64|%[0-9a-f]{2}/i,
      suspiciousPorts: /:6666|:1337|:2121|:8118/
    };
    
    for (const [type, pattern] of Object.entries(suspiciousPatterns)) {
      if (pattern.test(url)) {
        return { type, pattern: pattern.toString(), url };
      }
    }
    
    return null;
  }
  
  /**
   * Check if event is from an extension
   */
  isFromExtension(event) {
    // Check if the event target is in an extension context
    try {
      const target = event.target;
      if (target && target.ownerDocument) {
        const url = target.ownerDocument.URL;
        return url.startsWith('chrome-extension://');
      }
    } catch (e) {
      // Ignore errors
    }
    return false;
  }
  
  /**
   * Extract form data
   */
  extractFormData(form) {
    const formData = {};
    const inputs = form.querySelectorAll('input, textarea, select');
    inputs.forEach(input => {
      if (input.name) {
        formData[input.name] = input.type === 'password' ? '[PASSWORD]' : input.value;
      }
    });
    return formData;
  }
  
  /**
   * Check if element is used for clickjacking
   */
  isClickjackingElement(element) {
    const style = window.getComputedStyle(element);
    return (
      style.pointerEvents === 'none' ||
      parseFloat(style.opacity) === 0 ||
      style.visibility === 'hidden' ||
      style.position === 'absolute' && 
      (parseInt(style.left) < 0 || parseInt(style.top) < 0)
    );
  }
  
  /**
   * Check if runtime monitoring is available in current context
   */
  isRuntimeMonitoringAvailable() {
    return typeof window !== 'undefined' && typeof document !== 'undefined';
  }
  
  /**
   * Get behavioral analysis results
   */
  getBehavioralAnalysis() {
    const analysis = {
      available: this.isRuntimeMonitoringAvailable(),
      suspiciousRequests: this.behavioralPatterns.suspiciousRequests.length,
      keylogging: this.behavioralPatterns.keylogging.length,
      formHijacking: this.behavioralPatterns.formHijacking.length,
      clickjacking: this.behavioralPatterns.clickjacking.length,
      dataAccess: this.behavioralPatterns.dataAccess.length,
      dangerousAPIs: this.behavioralPatterns.dangerousAPIs.length,
      riskScore: this.calculateBehavioralRiskScore(),
      patterns: this.behavioralPatterns
    };
    
    return analysis;
  }
  
  /**
   * Calculate risk score based on behavioral patterns
   */
  calculateBehavioralRiskScore() {
    let score = 0;
    
    // Network-based threats
    score += this.behavioralPatterns.suspiciousRequests.length * 15;
    score += this.behavioralPatterns.dataExfiltration.length * 25;
    score += this.behavioralPatterns.c2Communication.length * 30;
    
    // DOM-based threats
    score += this.behavioralPatterns.keylogging.length * 20;
    score += this.behavioralPatterns.formHijacking.length * 25;
    score += this.behavioralPatterns.clickjacking.length * 15;
    
    // Storage and API threats
    score += this.behavioralPatterns.dataAccess.length * 5;
    score += this.behavioralPatterns.dangerousAPIs.length * 10;
    
    return Math.min(100, score);
  }
  
  /**
   * Start monitoring a specific extension
   */
  startMonitoringExtension(extensionId) {
    this.monitoredExtensions.set(extensionId, {
      startTime: Date.now(),
      behaviors: []
    });
  }
  
  /**
   * Stop monitoring a specific extension
   */
  stopMonitoringExtension(extensionId) {
    this.monitoredExtensions.delete(extensionId);
  }
  
  /**
   * Get monitoring results for an extension
   */
  getExtensionMonitoringResults(extensionId) {
    const monitoring = this.monitoredExtensions.get(extensionId);
    if (!monitoring) {
      return null;
    }
    
    return {
      extensionId,
      monitoringDuration: Date.now() - monitoring.startTime,
      behaviors: monitoring.behaviors,
      riskScore: this.calculateBehavioralRiskScore()
    };
  }
}

export default RuntimeMonitor;

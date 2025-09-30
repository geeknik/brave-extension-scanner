/**
 * CRX Analyzer Module
 * Downloads and analyzes CRX files from the Chrome Web Store
 * This provides real code analysis for Web Store extensions
 */

import JSZip from 'jszip';

class CRXAnalyzer {
  constructor() {
    this.downloadedCRXs = new Map();
    this.analysisCache = new Map();
  }
  
  /**
   * Download and analyze a CRX file from the Chrome Web Store
   * @param {string} extensionId - The extension ID
   * @returns {Object} Analysis results
   */
  async analyzeCRX(extensionId) {
    try {
      console.log(`🔍 CRX Analysis: Starting analysis for extension ${extensionId}`);
      
      // Check cache first
      if (this.analysisCache.has(extensionId)) {
        console.log(`📋 Using cached analysis for ${extensionId}`);
        return this.analysisCache.get(extensionId);
      }
      
      // Download CRX file
      const crxData = await this.downloadCRX(extensionId);
      if (!crxData) {
        throw new Error('Failed to download CRX file');
      }
      
      // Extract and analyze files
      const analysis = await this.extractAndAnalyze(crxData, extensionId);
      
      // Cache results
      this.analysisCache.set(extensionId, analysis);
      
      console.log(`✅ CRX Analysis complete for ${extensionId}`);
      return analysis;
      
    } catch (error) {
      console.error(`❌ CRX Analysis failed for ${extensionId}:`, error);
      return {
        error: error.message,
        riskScore: 0,
        files: [],
        manifest: null
      };
    }
  }
  
  /**
   * Download CRX file from Chrome Web Store
   * @param {string} extensionId - The extension ID
   * @returns {ArrayBuffer} CRX file data
   */
  async downloadCRX(extensionId) {
    try {
      // Multiple download URLs to try (in order of preference)
      const downloadUrls = [
        // Primary CRX download URL (most reliable)
        `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=100.0&acceptformat=crx3&x=id%3D${extensionId}%26installsource%3Dondemand%26uc`,
        // Alternative CRX download URL
        `https://clients2.google.com/service/update2/crx?response=redirect&x=id%3D${extensionId}%26uc`,
        // Alternative format with different parameters
        `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0&acceptformat=crx3&x=id%3D${extensionId}%26installsource%3Dondemand%26uc`,
        // Another alternative
        `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=100.0&x=id%3D${extensionId}%26uc`
      ];
      
      for (let i = 0; i < downloadUrls.length; i++) {
        const url = downloadUrls[i];
        try {
          console.log(`📥 Attempting to download CRX from: ${url}`);
          
          const response = await fetch(url, {
            method: 'GET',
            credentials: 'omit',
            redirect: 'follow',
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36',
              'Accept': 'application/x-chrome-extension,application/octet-stream,*/*'
            }
          });
          
          if (response.ok) {
            const arrayBuffer = await response.arrayBuffer();
            console.log(`✅ Successfully downloaded CRX (${arrayBuffer.byteLength} bytes)`);
            
            // Check if the downloaded file is too small to be a valid CRX
            if (arrayBuffer.byteLength < 12) {
              console.log(`⚠️ Downloaded file is too small (${arrayBuffer.byteLength} bytes) to be a valid CRX file`);
              // Continue to next URL instead of returning invalid data
              continue;
            }
            
            // Debug: Check what we actually downloaded
            if (arrayBuffer.byteLength > 0) {
              const data = new Uint8Array(arrayBuffer);
              const firstBytes = Array.from(data.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' ');
              console.log(`🔍 First 8 bytes: ${firstBytes}`);
              
              // Check if this looks like an HTML error page instead of a CRX
              const textContent = new TextDecoder().decode(data.slice(0, 100));
              if (textContent.includes('<html') || textContent.includes('<!DOCTYPE')) {
                console.log(`⚠️ Downloaded content appears to be HTML, not a CRX file`);
                continue;
              }
            }
            
            return arrayBuffer;
          } else {
            console.log(`❌ HTTP ${response.status} from ${url}`);
            if (response.status === 404) {
              console.log(`📋 Extension not found or not available for download`);
            } else if (response.status === 403) {
              console.log(`🚫 Access forbidden - extension may be private or restricted`);
            }
          }
        } catch (error) {
          console.log(`❌ Download failed from ${url}: ${error.message}`);
          
          // Check if it's a CORS error
          if (error.message.includes('CORS') || error.message.includes('Access-Control-Allow-Origin')) {
            console.log(`🚫 CORS policy blocked access to ${url}`);
            // Continue to next URL instead of throwing immediately
          } else if (error.message.includes('Content Security Policy') || error.message.includes('CSP')) {
            console.log(`🚫 CSP violation detected - extension may need additional permissions`);
            // Continue to next URL instead of throwing immediately
          } else if (error.message.includes('Failed to fetch')) {
            console.log(`🌐 Network error or blocked request to ${url}`);
            // Continue to next URL instead of throwing immediately
          }
          
          // Continue to next URL unless it's the last one
          if (i === downloadUrls.length - 1) {
            throw new Error(`All CRX download URLs failed. Last error: ${error.message}`);
          }
        }
      }
      
      throw new Error('All download URLs failed');
      
    } catch (error) {
      console.error('❌ CRX download failed:', error);
      throw error;
    }
  }
  
  /**
   * Extract and analyze files from CRX data
   * @param {ArrayBuffer} crxData - CRX file data
   * @param {string} extensionId - Extension ID
   * @returns {Object} Analysis results
   */
  async extractAndAnalyze(crxData, extensionId) {
    try {
      // Parse CRX header
      const parseResult = await this.parseCRX(crxData);
      const { zipData, manifest, error: parseError } = parseResult;
      
      let files = [];
      let analysis = { riskScore: 0, threats: [], totalFiles: 0 };
      
      // Try to extract files if we have valid ZIP data
      if (zipData && zipData.byteLength > 0) {
        try {
          const zip = await JSZip.loadAsync(zipData);
          files = await this.extractFiles(zip);
          analysis = await this.analyzeFiles(files, manifest);
          console.log(`✅ Successfully extracted ${files.length} files from CRX`);
        } catch (zipError) {
          console.warn('⚠️ ZIP extraction failed, but continuing with manifest analysis:', zipError);
          // Continue with manifest-only analysis
        }
      }
      
      // If we have a manifest, analyze it even if file extraction failed
      if (manifest) {
        const manifestAnalysis = this.analyzeManifest(manifest);
        analysis.manifestAnalysis = manifestAnalysis;
        analysis.threats.push(...manifestAnalysis.threats);
        analysis.riskScore = Math.max(analysis.riskScore, manifestAnalysis.riskScore);
      }
      
      return {
        extensionId,
        manifest,
        files: files,
        analysis,
        riskScore: analysis.riskScore,
        timestamp: Date.now(),
        parseError: parseError || null,
        analysisMethod: 'crx_download'
      };
      
    } catch (error) {
      console.error('❌ CRX extraction failed:', error);
      
      // Return a minimal analysis result instead of throwing
      return {
        extensionId,
        manifest: null,
        files: [],
        analysis: {
          riskScore: 0,
          threats: [],
          totalFiles: 0,
          error: error.message
        },
        riskScore: 0,
        timestamp: Date.now(),
        parseError: error.message,
        analysisMethod: 'crx_download_failed'
      };
    }
  }
  
  /**
   * Parse CRX file format
   * @param {ArrayBuffer} crxData - CRX file data
   * @returns {Object} Parsed CRX data
   */
  async parseCRX(crxData) {
    try {
      const data = new Uint8Array(crxData);
      
      // Enhanced debugging for CRX format issues
      console.log(`🔍 CRX Debug: File size: ${crxData.byteLength} bytes`);
      if (data.length >= 4) {
        const magic = String.fromCharCode(data[0], data[1], data[2], data[3]);
        console.log(`🔍 CRX Debug: Magic bytes: ${data[0].toString(16).padStart(2, '0')} ${data[1].toString(16).padStart(2, '0')} ${data[2].toString(16).padStart(2, '0')} ${data[3].toString(16).padStart(2, '0')} (${magic})`);
        
        // Check for different CRX formats
        if (magic === 'Cr24') {
          console.log(`✅ CRX3 format detected`);
        } else if (magic === 'Cr23') {
          console.log(`✅ CRX2 format detected`);
        } else if (magic === 'PK') {
          console.log(`⚠️ Direct ZIP file detected (not CRX format)`);
          // Handle direct ZIP files (some extensions might be served as ZIP)
          return await this.parseDirectZIP(crxData);
        } else {
          console.log(`❌ Unknown format. First 16 bytes:`, Array.from(data.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' '));
          throw new Error(`Invalid CRX file format. Expected 'Cr24' or 'Cr23', got '${magic}'`);
        }
      } else {
        throw new Error(`CRX file too small to contain magic number (${crxData.byteLength} bytes, minimum 4 bytes required)`);
      }
      
      // Parse header for CRX2/CRX3
      const version = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
      const headerSize = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
      
      console.log(`📋 CRX Version: ${version}, Header Size: ${headerSize}`);
      
      // Extract ZIP data
      const zipStartOffset = 12 + headerSize;
      const zipData = crxData.slice(zipStartOffset);
      
      console.log(`📦 ZIP data size: ${zipData.byteLength} bytes`);
      
      // Try to get manifest from ZIP
      let manifest = null;
      try {
        const zip = await JSZip.loadAsync(zipData);
        const manifestFile = zip.file('manifest.json');
        if (manifestFile) {
          const manifestContent = await manifestFile.async('string');
          manifest = JSON.parse(manifestContent);
          console.log(`✅ Manifest extracted successfully`);
        } else {
          console.log(`⚠️ No manifest.json found in CRX`);
        }
      } catch (e) {
        console.warn('Could not extract manifest from CRX:', e);
        // Try to extract as much as possible even if ZIP is corrupted
        return { zipData, manifest: null, error: 'ZIP extraction failed' };
      }
      
      return { zipData, manifest };
      
    } catch (error) {
      console.error('❌ CRX parsing failed:', error);
      throw error;
    }
  }
  
  /**
   * Parse direct ZIP file (fallback for non-CRX formats)
   * @param {ArrayBuffer} zipData - ZIP file data
   * @returns {Object} Parsed data
   */
  async parseDirectZIP(zipData) {
    try {
      console.log(`📦 Parsing as direct ZIP file`);
      const zip = await JSZip.loadAsync(zipData);
      const manifestFile = zip.file('manifest.json');
      let manifest = null;
      
      if (manifestFile) {
        const manifestContent = await manifestFile.async('string');
        manifest = JSON.parse(manifestContent);
        console.log(`✅ Manifest extracted from ZIP`);
      }
      
      return { zipData, manifest };
    } catch (error) {
      console.error('❌ ZIP parsing failed:', error);
      throw new Error(`Failed to parse ZIP file: ${error.message}`);
    }
  }
  
  /**
   * Extract files from ZIP
   * @param {JSZip} zip - JSZip instance
   * @returns {Array} Extracted files
   */
  async extractFiles(zip) {
    const files = [];
    
    for (const [relativePath, zipEntry] of Object.entries(zip.files)) {
      if (zipEntry.dir) continue;
      
      try {
        const content = await zipEntry.async('string');
        const fileName = relativePath.split('/').pop();
        const fileType = this.detectFileType(fileName, content);
        
        files.push({
          name: fileName,
          path: relativePath,
          content: content,
          type: fileType,
          size: content.length
        });
        
        console.log(`📄 Extracted ${fileName} (${fileType}, ${content.length} bytes)`);
        
      } catch (error) {
        console.warn(`⚠️ Could not extract ${relativePath}:`, error);
      }
    }
    
    return files;
  }
  
  /**
   * Detect file type based on extension and content
   * @param {string} fileName - File name
   * @param {string} content - File content
   * @returns {string} File type
   */
  detectFileType(fileName, content) {
    const extension = fileName.split('.').pop().toLowerCase();
    
    switch (extension) {
      case 'js':
        return 'javascript';
      case 'html':
        return 'html';
      case 'css':
        return 'css';
      case 'json':
        return 'json';
      case 'png':
      case 'jpg':
      case 'jpeg':
      case 'gif':
      case 'svg':
        return 'image';
      case 'woff':
      case 'woff2':
      case 'ttf':
      case 'otf':
        return 'font';
      default:
        // Try to detect by content
        if (content.includes('<html') || content.includes('<!DOCTYPE')) {
          return 'html';
        } else if (content.includes('function') || content.includes('var ') || content.includes('const ')) {
          return 'javascript';
        } else if (content.includes('{') && content.includes('}') && content.includes('"')) {
          return 'json';
        }
        return 'unknown';
    }
  }
  
  /**
   * Analyze extracted files
   * @param {Array} files - Extracted files
   * @param {Object} manifest - Extension manifest
   * @returns {Object} Analysis results
   */
  async analyzeFiles(files, manifest) {
    const analysis = {
      totalFiles: files.length,
      javascriptFiles: files.filter(f => f.type === 'javascript'),
      htmlFiles: files.filter(f => f.type === 'html'),
      cssFiles: files.filter(f => f.type === 'css'),
      suspiciousFiles: [],
      riskScore: 0,
      threats: []
    };
    
    // Analyze JavaScript files
    for (const file of analysis.javascriptFiles) {
      const fileAnalysis = this.analyzeJavaScriptFile(file);
      if (fileAnalysis.riskScore > 0) {
        analysis.suspiciousFiles.push(fileAnalysis);
        analysis.threats.push(...fileAnalysis.threats);
      }
    }
    
    // Analyze manifest
    if (manifest) {
      const manifestAnalysis = this.analyzeManifest(manifest);
      analysis.manifestAnalysis = manifestAnalysis;
      analysis.threats.push(...manifestAnalysis.threats);
    }
    
    // Calculate overall risk score
    analysis.riskScore = this.calculateOverallRiskScore(analysis);
    
    return analysis;
  }
  
  /**
   * Analyze JavaScript file for threats
   * @param {Object} file - File object
   * @returns {Object} File analysis
   */
  analyzeJavaScriptFile(file) {
    const analysis = {
      fileName: file.name,
      filePath: file.path,
      riskScore: 0,
      threats: [],
      patterns: []
    };
    
    const content = file.content;
    
    // Check for malicious patterns
    const maliciousPatterns = [
      { pattern: /eval\s*\(/g, type: 'eval', severity: 'high' },
      { pattern: /new\s+Function\s*\(/g, type: 'dynamicCode', severity: 'high' },
      { pattern: /document\.cookie/g, type: 'cookieAccess', severity: 'medium' },
      { pattern: /addEventListener\s*\(\s*['"`]keydown['"`]/g, type: 'keylogging', severity: 'critical' },
      { pattern: /XMLHttpRequest|fetch\s*\(/g, type: 'networkRequest', severity: 'medium' },
      { pattern: /chrome\.tabs\.query/g, type: 'tabAccess', severity: 'medium' },
      { pattern: /chrome\.history\./g, type: 'historyAccess', severity: 'high' },
      { pattern: /chrome\.bookmarks\./g, type: 'bookmarkAccess', severity: 'high' },
      { pattern: /localStorage|sessionStorage/g, type: 'storageAccess', severity: 'low' },
      { pattern: /innerHTML\s*=/g, type: 'domManipulation', severity: 'medium' }
    ];
    
    for (const { pattern, type, severity } of maliciousPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        analysis.threats.push({
          type,
          severity,
          count: matches.length,
          matches: matches.slice(0, 5) // Limit to first 5 matches
        });
        
        analysis.patterns.push({
          type,
          severity,
          count: matches.length
        });
      }
    }
    
    // Calculate risk score
    analysis.riskScore = this.calculateFileRiskScore(analysis.threats);
    
    return analysis;
  }
  
  /**
   * Analyze manifest for threats
   * @param {Object} manifest - Extension manifest
   * @returns {Object} Manifest analysis
   */
  analyzeManifest(manifest) {
    const analysis = {
      riskScore: 0,
      threats: [],
      permissions: (manifest.permissions || []).filter(p => typeof p === 'string'),
      hostPermissions: (manifest.host_permissions || []).filter(p => typeof p === 'string')
    };
    
    // Check for dangerous permissions
    const dangerousPermissions = [
      'tabs', 'cookies', 'history', 'bookmarks', 'downloads', 'management',
      'debugger', 'proxy', 'webRequest', 'webRequestBlocking', 'declarativeNetRequest'
    ];
    
    for (const permission of analysis.permissions) {
      if (typeof permission === 'string' && dangerousPermissions.includes(permission)) {
        analysis.threats.push({
          type: 'dangerousPermission',
          severity: 'high',
          permission
        });
      }
    }
    
    // Check for broad host permissions
    for (const hostPermission of analysis.hostPermissions) {
      if (typeof hostPermission === 'string' && (hostPermission === '<all_urls>' || hostPermission === '*://*/*')) {
        analysis.threats.push({
          type: 'broadHostPermission',
          severity: 'critical',
          permission: hostPermission
        });
      }
    }
    
    // Calculate risk score
    analysis.riskScore = this.calculateFileRiskScore(analysis.threats);
    
    return analysis;
  }
  
  /**
   * Calculate risk score for a file
   * @param {Array} threats - Detected threats
   * @returns {number} Risk score (0-100)
   */
  calculateFileRiskScore(threats) {
    let score = 0;
    
    for (const threat of threats) {
      switch (threat.severity) {
        case 'critical':
          score += 25;
          break;
        case 'high':
          score += 15;
          break;
        case 'medium':
          score += 10;
          break;
        case 'low':
          score += 5;
          break;
      }
    }
    
    return Math.min(100, score);
  }
  
  /**
   * Calculate overall risk score
   * @param {Object} analysis - Analysis results
   * @returns {number} Overall risk score (0-100)
   */
  calculateOverallRiskScore(analysis) {
    let score = 0;
    
    // File-based threats
    for (const file of analysis.suspiciousFiles) {
      score += file.riskScore * 0.3; // Weight file analysis
    }
    
    // Manifest-based threats
    if (analysis.manifestAnalysis) {
      score += analysis.manifestAnalysis.riskScore * 0.7; // Weight manifest analysis
    }
    
    return Math.min(100, Math.round(score));
  }
  
  /**
   * Get cached analysis for an extension
   * @param {string} extensionId - Extension ID
   * @returns {Object|null} Cached analysis or null
   */
  getCachedAnalysis(extensionId) {
    return this.analysisCache.get(extensionId) || null;
  }
  
  /**
   * Clear analysis cache
   */
  clearCache() {
    this.analysisCache.clear();
    this.downloadedCRXs.clear();
  }
}

export default CRXAnalyzer;

/**
 * Brave Extension Scanner - Background Script
 * Handles extension installation interception and coordinates scanning
 */
import StaticAnalyzer from './src/analyzers/static-analyzer.js';
import ManifestAnalyzer from './src/analyzers/manifest-analyzer.js';
import ObfuscationDetector from './src/analyzers/obfuscation-detector.js';
import NetworkAnalyzer from './src/analyzers/network-analyzer.js';
import HeuristicAnalyzer from './src/analyzers/heuristic-analyzer.js';
import ThreatClassifier from './src/analyzers/threat-classifier.js';
import CRXAnalyzer from './src/analyzers/crx-analyzer.js';
import RuntimeMonitor from './src/analyzers/runtime-monitor.js';
import AlertSystem from './src/ui/alert-system.js';
import * as ExtensionFiles from './src/utils/extension-files.js';
import * as CommonUtils from './src/utils/common.js';

// Initialize analyzers (these will be available after importScripts)
let staticAnalyzer, manifestAnalyzer, obfuscationDetector, networkAnalyzer, heuristicAnalyzer, threatClassifier, crxAnalyzer, runtimeMonitor, alertSystem;

// Initialize after scripts are loaded
try {
  staticAnalyzer = new StaticAnalyzer();
  manifestAnalyzer = new ManifestAnalyzer();
  obfuscationDetector = new ObfuscationDetector();
  networkAnalyzer = new NetworkAnalyzer();
  heuristicAnalyzer = new HeuristicAnalyzer();
  threatClassifier = new ThreatClassifier();
  crxAnalyzer = new CRXAnalyzer();
  runtimeMonitor = new RuntimeMonitor();
  alertSystem = new AlertSystem();
  console.log('✅ All analyzers initialized successfully');
} catch (error) {
  console.error('❌ Failed to initialize analyzers:', error);
}

// Global state
const state = {
  scanInProgress: false,
  scanResults: {},
  scanHistory: []
};

// Default settings
const defaultSettings = {
  interceptInstallations: true,
  alertThreshold: 'medium',
  autoBlockHigh: true
};

// Service worker startup
console.log('🚀 Brave Extension Scanner service worker starting...');
console.log('📋 Permissions:', chrome.runtime.getManifest().permissions);

// Initialize AlertSystem with user settings on startup
(async () => {
  try {
    const data = await chrome.storage.local.get(['settings']);
    const settings = data.settings || defaultSettings;
    if (alertSystem && settings.alertThreshold) {
      alertSystem.setThreshold(settings.alertThreshold);
      console.log(`🔔 AlertSystem initialized with threshold: ${settings.alertThreshold}`);
    }
  } catch (error) {
    console.error('❌ Error initializing AlertSystem:', error);
  }
})();

// Set up extension installation listener immediately when service worker starts
setupExtensionListener();

// Note: Web request blocking not available in Manifest V3
// We'll focus on post-installation scanning instead

// Initialize extension
chrome.runtime.onInstalled.addListener(async () => {
  console.log('Brave Extension Scanner initialized');
  
  // Initialize storage with default settings if not already set
  const data = await chrome.storage.local.get(['settings', 'scanHistory', 'recentActivity']);
  
  if (!data.settings) {
    await chrome.storage.local.set({ settings: defaultSettings });
  }
  
  if (!data.scanHistory) {
    await chrome.storage.local.set({ scanHistory: [] });
  }
  
  if (!data.recentActivity) {
    await chrome.storage.local.set({ recentActivity: [] });
  }
  
  // Initialize AlertSystem with user settings
  const settings = data.settings || defaultSettings;
  if (alertSystem && settings.alertThreshold) {
    alertSystem.setThreshold(settings.alertThreshold);
    console.log(`🔔 AlertSystem initialized with threshold: ${settings.alertThreshold}`);
  }
  
  // Update stats
  await updateStats({
    extensionsScanned: 0,
    threatsDetected: 0,
    lastScan: null
  });
});

// Note: CRX interception functions removed due to Manifest V3 limitations
// True installation blocking requires declarativeNetRequest API

/**
 * Decide whether to allow a CRX installation based on scan results
 * @param {Object} scanResults - The results from scanning the extension
 * @param {Object} extensionInfo - Basic extension information
 * @returns {boolean} - Whether to allow the installation
 */
async function decideCrxInstallation(scanResults, extensionInfo) {
  try {
    const settings = await getSettings();
    const threatLevel = scanResults.threatClassification?.level || 'unknown';
    const threatScore = scanResults.threatClassification?.score || 0;
    
    console.log(`🔍 Deciding installation for threat level: ${threatLevel} (score: ${threatScore})`);
    
    // Always block critical threats
    if (threatLevel === 'critical' || threatScore >= 9) {
      console.log('🚫 Blocking critical threat');
      return false;
    }
    
    // Block high threats if auto-block is enabled
    if ((threatLevel === 'high' || threatScore >= 15) && settings.autoBlockHigh) {
      console.log('🚫 Auto-blocking high threat');
      return false;
    }
    
    // Check specific threat indicators
    const threats = scanResults.threats || [];
    const hasHighRiskThreats = threats.some(threat => 
      threat.severity === 'critical' || 
      threat.type === 'malware' ||
      threat.type === 'data_exfiltration' ||
      threat.type === 'keylogger'
    );
    
    if (hasHighRiskThreats) {
      console.log('🚫 Blocking due to high-risk threat indicators');
      return false;
    }
    
    // Check obfuscation levels
    if (scanResults.obfuscationAnalysis) {
      const obfuscationScore = scanResults.obfuscationAnalysis.obfuscationScore;
      if (obfuscationScore >= 50) {
        console.log('🚫 Blocking due to excessive obfuscation');
        return false;
      }
    }
    
    // Check excessive permissions
    if (scanResults.manifestAnalysis?.excessivePermissions) {
      const excessiveCount = scanResults.manifestAnalysis.excessivePermissions.length;
      if (excessiveCount >= 5) {
        console.log('🚫 Blocking due to excessive permissions');
        return false;
      }
    }
    
    // Allow low/medium threats or if user has disabled auto-blocking
    console.log(`✅ Allowing installation - threat level: ${threatLevel}`);
    return true;
    
  } catch (error) {
    console.error('❌ Error in decideCrxInstallation:', error);
    // On error, err on the side of caution but don't break user experience
    return true;
  }
}

// Handle unpacked extension installation
async function handleUnpackedExtensionInstallation(extensionInfo) {
  try {
    console.log('🔧 Handling unpacked extension installation...');
    
    // Temporarily disable the extension while we scan it
    const wasEnabled = extensionInfo.enabled;
    if (wasEnabled) {
      console.log('⏸️ Temporarily disabling extension for scanning...');
      await chrome.management.setEnabled(extensionInfo.id, false);
    }
    
    // Add activity record
    await addToRecentActivity({
      type: 'unpacked_installation_detected',
      extensionId: extensionInfo.id,
      extensionName: extensionInfo.name,
      time: new Date().toISOString()
    });
    
    // For unpacked extensions, we can try to scan using alternative methods
    console.log('🔍 Starting unpacked extension scan...');
    
    // Method 1: Try to get files through content script injection (if possible)
    const scanResults = await scanUnpackedExtension(extensionInfo);
    
    if (scanResults) {
      const threatLevel = scanResults.threatClassification.level;
      console.log(`📊 Unpacked extension scan complete: ${threatLevel}`);
      
      // Show alert to user if threat level warrants it (regardless of blocking decision)
      if (threatLevel !== 'safe' && alertSystem) {
        console.log(`🚨 Showing alert for ${threatLevel} threat level`);
        alertSystem.showAlert(extensionInfo, scanResults.threatClassification);
      }
      
      // Decide whether to allow the extension to run
      const shouldAllow = await decideCrxInstallation(scanResults, { manifest: scanResults.manifest });
      
      if (shouldAllow) {
        console.log('✅ Unpacked extension scan passed - re-enabling extension');
        
        if (wasEnabled) {
          await chrome.management.setEnabled(extensionInfo.id, true);
        }
        
        await addToRecentActivity({
          type: 'unpacked_allowed',
          extensionId: extensionInfo.id,
          extensionName: extensionInfo.name,
          threatLevel: threatLevel,
          time: new Date().toISOString()
        });
      } else {
        console.log('🚫 Unpacked extension scan failed - keeping extension disabled');
        
        // Show notification about blocking
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: 'Unpacked Extension Blocked',
          message: `Blocked "${extensionInfo.name}" - ${threatLevel} security risk detected`,
          buttons: [
            { title: 'View Details' },
            { title: 'Enable Anyway' }
          ]
        });
        
        await addToRecentActivity({
          type: 'unpacked_blocked',
          extensionId: extensionInfo.id,
          extensionName: extensionInfo.name,
          threatLevel: threatLevel,
          reason: scanResults.threatClassification.summary,
          time: new Date().toISOString()
        });
      }
    } else {
      console.log('⚠️ Could not scan unpacked extension files - allowing with warning');
      
      if (wasEnabled) {
        await chrome.management.setEnabled(extensionInfo.id, true);
      }
      
      // Show warning notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'Unpacked Extension Warning',
        message: `Could not fully scan "${extensionInfo.name}" - please review manually`,
        buttons: [
          { title: 'Manual Scan' }
        ]
      });
      
      await addToRecentActivity({
        type: 'unpacked_scan_limited',
        extensionId: extensionInfo.id,
        extensionName: extensionInfo.name,
        time: new Date().toISOString()
      });
    }
  } catch (error) {
    console.error('❌ Error handling unpacked extension installation:', error);
    
    // On error, re-enable the extension to avoid breaking user experience
    if (extensionInfo.enabled) {
      try {
        await chrome.management.setEnabled(extensionInfo.id, true);
      } catch (e) {
        console.error('❌ Error re-enabling extension:', e);
      }
    }
  }
}

// Scan an unpacked extension using available methods
async function scanUnpackedExtension(extensionInfo) {
  try {
    console.log('🔍 Attempting to scan unpacked extension...');
    
    // Method 1: Get basic manifest info from management API
    const manifest = await getBasicManifestFromManagementAPI(extensionInfo);
    
    // Method 2: Try to construct file paths and analyze what we can
    const analysisResults = await analyzeUnpackedExtensionStructure(extensionInfo, manifest);
    
    if (analysisResults) {
      // Classify threat level
      const threatClassification = threatClassifier.classifyThreat(analysisResults);
      
      return {
        manifest,
        ...analysisResults,
        threatClassification
      };
    }
    
    return null;
  } catch (error) {
    console.error('❌ Error scanning unpacked extension:', error);
    return null;
  }
}

// Get basic manifest information from management API
async function getBasicManifestFromManagementAPI(extensionInfo) {
  return {
    name: extensionInfo.name,
    version: extensionInfo.version,
    description: extensionInfo.description,
    manifest_version: extensionInfo.manifestVersion || 3,
    permissions: extensionInfo.permissions || [],
    host_permissions: extensionInfo.hostPermissions || [],
    install_type: extensionInfo.installType,
    enabled: extensionInfo.enabled,
    id: extensionInfo.id
  };
}

// Analyze unpacked extension structure using available information
async function analyzeUnpackedExtensionStructure(extensionInfo, manifest) {
  try {
    console.log('🔍 Analyzing unpacked extension structure...');
    
    // Analyze manifest (we have this from management API)
    const manifestAnalysis = manifestAnalyzer.analyzeManifest(manifest);
    
    // Try to read and analyze JavaScript files from the unpacked extension
    const jsFiles = await readUnpackedExtensionFiles(extensionInfo);
    
    let staticAnalysis, obfuscationAnalysis, networkAnalysis;
    
    if (jsFiles && jsFiles.length > 0) {
      console.log(`📄 Successfully read ${jsFiles.length} JavaScript files from unpacked extension`);
      
      // Combine all JavaScript code for analysis
      const allCode = jsFiles.map(file => file.content).join('\n\n');
      
      // Run static analysis on the actual code
      staticAnalysis = staticAnalyzer.analyzeCode(allCode);
      
      // Run obfuscation detection on the actual code
      obfuscationAnalysis = obfuscationDetector.analyzeCode(allCode);
      
      // Run network analysis on the actual code
      networkAnalysis = networkAnalyzer.analyzeCode(allCode);
      
      console.log(`📊 Unpacked extension analysis complete - Obfuscation Score: ${obfuscationAnalysis.obfuscationScore}, Static Risk: ${staticAnalysis.riskScore}`);
      
    } else {
      console.error('🚨 UNPACKED EXTENSION: JavaScript files cannot be read due to Chrome security restrictions');
      console.error('🚨 Switching to MANIFEST-BASED THREAT ANALYSIS for unpacked extensions');
      
      // For unpacked extensions, we must rely on manifest analysis and behavioral indicators
      // This is more aggressive since we can't verify the actual code
      staticAnalysis = {
        results: {
          evalUsage: [],
          remoteCodeLoading: [],
          cookieAccess: [],
          dataExfiltration: [],
          keylogging: [],
          fingerprinting: []
        },
        riskScore: 40, // Higher base risk for unpacked extensions we can't fully analyze
        suspiciousPatterns: [
          {
            category: 'Unpacked Extension Analysis',
            severity: 'high',
            count: 1,
            description: 'UNPACKED EXTENSION: Cannot read JavaScript files due to browser security. Analysis based on manifest and behavioral indicators only.'
          }
        ]
      };
      
      // AGGRESSIVE MANIFEST-BASED ANALYSIS
      // Look for indicators of malicious behavior in the manifest itself
      
      // 1. Check content scripts - keyloggers often inject into all pages
      if (manifestData && manifestData.content_scripts) {
        manifestData.content_scripts.forEach((cs, index) => {
          // Suspicious: content scripts that run on all URLs
          if (cs.matches && cs.matches.some(match => match === '<all_urls>' || match === 'http://*/*' || match === 'https://*/*')) {
            staticAnalysis.riskScore += 25;
            staticAnalysis.suspiciousPatterns.push({
              category: 'Broad Content Script Injection',
              severity: 'high',
              count: 1,
              description: `Content script ${index + 1} runs on all websites - potential keylogger/data theft risk`
            });
            
            // Extra suspicious if it runs at document_start
            if (cs.run_at === 'document_start') {
              staticAnalysis.riskScore += 15;
              staticAnalysis.suspiciousPatterns.push({
                category: 'Early Script Injection',
                severity: 'high',
                count: 1,
                description: 'Content script runs at document_start - can intercept all page interactions'
              });
            }
            
            // Extra suspicious if it runs in all frames
            if (cs.all_frames === true) {
              staticAnalysis.riskScore += 10;
              staticAnalysis.suspiciousPatterns.push({
                category: 'All Frames Access',
                severity: 'medium',
                count: 1,
                description: 'Content script runs in all frames - can access embedded content'
              });
            }
          }
          
          // Suspicious: Scripts with suspicious names
          if (cs.js) {
            const suspiciousNames = ['keylogger', 'logger', 'spy', 'track', 'monitor', 'steal', 'collect', 'harvest'];
            cs.js.forEach(jsFile => {
              const fileName = typeof jsFile === 'string' ? jsFile.toLowerCase() : String(jsFile).toLowerCase();
              if (suspiciousNames.some(name => fileName.includes(name))) {
                staticAnalysis.riskScore += 40; // Very high penalty for obvious malicious names
                staticAnalysis.suspiciousPatterns.push({
                  category: 'Suspicious Script Name',
                  severity: 'critical',
                  count: 1,
                  description: `CRITICAL: Script file "${jsFile}" has suspicious name indicating potential malicious behavior`
                });
              }
            });
          }
        });
      }
      
              // 2. Check for dangerous permissions - be more aggressive for unpacked extensions
        if (manifest.permissions) {
          const dangerousPerms = ['history', 'bookmarks', 'cookies', 'management', 'debugger', 'tabs'];
          const keyloggerPerms = ['activeTab', 'storage']; // Common for keyloggers
          const networkPerms = ['http://*/*', 'https://*/*', '<all_urls>'];
          
          const foundDangerous = manifest.permissions.filter(p => typeof p === 'string' && dangerousPerms.includes(p));
          const foundKeylogger = manifest.permissions.filter(p => typeof p === 'string' && keyloggerPerms.includes(p));
          const foundNetwork = manifest.permissions.filter(p => networkPerms.some(np => typeof p === 'string' && typeof np === 'string' && (p.includes(np) || np.includes(p))));
          
          if (foundDangerous.length > 0) {
            staticAnalysis.riskScore += foundDangerous.length * 25; // Higher penalty for unpacked
            staticAnalysis.suspiciousPatterns.push({
              category: 'Dangerous Permissions',
              severity: 'critical',
              count: foundDangerous.length,
              description: `CRITICAL: Unpacked extension requests dangerous permissions: ${foundDangerous.join(', ')}`
            });
          }
          
          // Special detection for keylogger permission patterns
          if (foundKeylogger.includes('activeTab') && foundKeylogger.includes('storage')) {
            staticAnalysis.riskScore += 30; // High penalty for keylogger pattern
            staticAnalysis.suspiciousPatterns.push({
              category: 'Keylogger Permission Pattern',
              severity: 'critical',
              count: 1,
              description: 'CRITICAL: Permission pattern matches keylogger behavior (activeTab + storage)'
            });
          }
          
          if (foundNetwork.length > 0) {
            staticAnalysis.riskScore += foundNetwork.length * 20; // Higher penalty for unpacked
            staticAnalysis.suspiciousPatterns.push({
              category: 'Broad Network Access',
              severity: 'high',
              count: foundNetwork.length,
              description: `Unpacked extension requests broad network access: ${foundNetwork.join(', ')}`
            });
          }
        }
      
      // Check host_permissions for additional network access
      if (manifest.host_permissions) {
        const hostPerms = manifest.host_permissions;
        if (hostPerms.length > 0) {
          staticAnalysis.riskScore += hostPerms.length * 15;
          staticAnalysis.suspiciousPatterns.push({
            category: 'Host Permissions',
            severity: 'high',
            count: hostPerms.length,
            description: `Host permissions without readable code: ${hostPerms.join(', ')}`
          });
        }
      }
      
      // Basic obfuscation analysis (assume potential obfuscation since we can't read)
      obfuscationAnalysis = {
        obfuscationDetected: true, // Assume potential obfuscation
        obfuscationScore: 30, // Moderate obfuscation score due to unreadable files
        entropy: 6.0, // Higher entropy assumption
        suspiciousPatterns: [
          {
            category: 'Unreadable Files',
            severity: 'high',
            description: 'JavaScript files could not be read - potential obfuscation or access restrictions'
          }
        ]
      };
      
      // Network analysis - assume potential risk
      networkAnalysis = {
        endpoints: { total: 0, suspicious: [] },
        riskScore: 20, // Assume network risk due to unanalyzable code
        suspiciousPatterns: [
          {
            category: 'Unanalyzable Network Behavior',
            severity: 'medium',
            description: 'Cannot analyze network behavior due to unreadable JavaScript files'
          }
        ]
      };
    }
    
    // Perform heuristic analysis
    const heuristicAnalysis = heuristicAnalyzer.analyze({
      manifestAnalysis,
      staticAnalysis,
      obfuscationAnalysis,
      networkAnalysis
    });

    return {
      manifestAnalysis,
      staticAnalysis,
      obfuscationAnalysis,
      networkAnalysis,
      heuristicAnalysis
    };
  } catch (error) {
    console.error('❌ Error analyzing unpacked extension structure:', error);
    return null;
  }
}

// Read ALL JavaScript files from an unpacked extension - COMPREHENSIVE ANALYSIS
async function readUnpackedExtensionFiles(extensionInfo) {
  try {
    const files = [];
    const extensionId = extensionInfo.id;
    
    console.log(`🔍 REAL FILE ANALYSIS: Attempting to read actual files from extension ${extensionId}`);
    
    // For unpacked extensions, we can try to access the file system directly
    // This is a workaround for Chrome's security restrictions
    
    // Step 1: Get manifest using chrome.management API
    let manifestData = null;
    try {
      // Use chrome.management.get to get extension details
      const extensionDetails = await chrome.management.get(extensionId);
      console.log(`📋 Extension details retrieved:`, extensionDetails);
      
      // Try to get the manifest from the extension's install type
      if (extensionDetails.installType === 'development') {
        console.log(`🔧 Development extension detected - attempting direct file access`);
        
        // For development extensions, we can try to access files directly
        // This is a workaround that may work in some cases
        manifestData = await getManifestFromDevelopmentExtension(extensionId);
      } else {
        console.log(`📦 Packed extension detected - using management API data`);
        // For packed extensions, we'll use what we can get from the management API
        manifestData = createManifestFromManagementAPI(extensionDetails);
      }
    } catch (e) {
      console.error('❌ Could not get extension details:', e.message);
    }
    
    // Step 2: Try to read actual files using multiple methods
    const discoveredFiles = new Set();
    const manifestFiles = []; // Declare outside the if block to ensure proper scope
    
    if (manifestData) {
      // Extract script files from manifest
      if (manifestData.background?.service_worker && typeof manifestData.background.service_worker === 'string') {
        manifestFiles.push(manifestData.background.service_worker);
      }
      if (manifestData.background?.scripts && Array.isArray(manifestData.background.scripts)) {
        manifestFiles.push(...manifestData.background.scripts.filter(script => typeof script === 'string'));
      }
      if (manifestData.content_scripts && Array.isArray(manifestData.content_scripts)) {
        manifestData.content_scripts.forEach(cs => {
          if (cs.js && Array.isArray(cs.js)) {
            manifestFiles.push(...cs.js.filter(js => typeof js === 'string'));
          }
        });
      }
      if (manifestData.web_accessible_resources && Array.isArray(manifestData.web_accessible_resources)) {
        manifestData.web_accessible_resources.forEach(resource => {
          if (resource.resources && Array.isArray(resource.resources)) {
            resource.resources.forEach(res => {
              if (typeof res === 'string' && res.endsWith('.js')) manifestFiles.push(res);
            });
          }
        });
      }
      
      console.log(`📄 Found ${manifestFiles.length} script files in manifest: ${manifestFiles.join(', ')}`);
      manifestFiles.forEach(file => {
        if (typeof file === 'string') {
          discoveredFiles.add(file);
        }
      });
    }
    
    // Common directories in extensions
    const commonDirectories = [
      '', // root
      'js/',
      'scripts/',
      'src/',
      'lib/',
      'libs/',
      'vendor/',
      'assets/',
      'content/',
      'background/',
      'popup/',
      'options/',
      'inject/',
      'build/',
      'dist/',
      'min/',
      'obfuscated/',
      'hidden/',
      'utils/',
      'modules/',
      'components/'
    ];
    
    // Comprehensive list of potential JavaScript filenames
    const potentialFiles = [
      // Standard files
      'background.js', 'content.js', 'popup.js', 'options.js', 'inject.js', 'script.js',
      // Common variations
      'main.js', 'index.js', 'app.js', 'core.js', 'init.js', 'loader.js', 'bootstrap.js',
      // Obfuscated/hidden files
      'obfuscated.js', 'min.js', 'bundle.js', 'packed.js', 'compressed.js',
      // Suspicious names
      'keylogger.js', 'logger.js', 'tracker.js', 'monitor.js', 'spy.js', 'stealer.js',
      'collector.js', 'harvester.js', 'exfiltrator.js', 'backdoor.js', 'payload.js',
      // Generic suspicious patterns
      'a.js', 'b.js', 'c.js', 'x.js', 'y.js', 'z.js', '1.js', '2.js', '3.js',
      'temp.js', 'tmp.js', 'test.js', 'debug.js', 'dev.js',
      // Common library names that could be malicious
      'jquery.js', 'lodash.js', 'underscore.js', 'moment.js', 'axios.js', 'utils.js',
      // Encoded/Base64 style names
      'YWRtaW4.js', 'cGF5bG9hZA.js', 'bWFsd2FyZQ.js',
      // Numbers/random looking
      '0.js', '00.js', '000.js', 'f1.js', 'f2.js', 'f3.js',
      // Extensions trying to hide
      'content_script.js', 'background_script.js', 'injected.js', 'embedded.js'
    ];
    
    // Try every combination of directory + filename
    for (const dir of commonDirectories) {
      for (const file of potentialFiles) {
        const fullPath = dir + file;
        if (!discoveredFiles.has(fullPath)) {
          discoveredFiles.add(fullPath);
        }
      }
    }
    
    // Step 3: Try to read ALL discovered files
    console.log(`🎯 Attempting to read ${discoveredFiles.size} potential files...`);
    
    let successCount = 0;
    let totalSize = 0;
    
    for (const filename of discoveredFiles) {
      try {
        const url = `chrome-extension://${extensionId}/${filename}`;
        const response = await fetch(url);
        
        if (response.ok) {
          const content = await response.text();
          if (content && content.trim().length > 0) {
            files.push({
              filename,
              content,
              size: content.length,
              fromManifest: typeof filename === 'string' && manifestFiles.includes(filename)
            });
            successCount++;
            totalSize += content.length;
            console.log(`✅ Successfully read ${filename} (${content.length} bytes)${typeof filename === 'string' && manifestFiles.includes(filename) ? ' [MANIFEST]' : ' [DISCOVERED]'}`);
          }
        }
      } catch (error) {
        // File doesn't exist - this is expected for most attempts
        // Only log errors for manifest files
        if (typeof filename === 'string' && manifestFiles.includes(filename)) {
          console.log(`❌ Could not read manifest file ${filename}: ${error.message}`);
        }
      }
    }
    
    console.log(`📊 SCAN COMPLETE: Found ${successCount} JavaScript files (${totalSize} total bytes)`);
    
    if (successCount === 0) {
      console.error('🚨 CRITICAL: No JavaScript files could be read - this may indicate access restrictions or the extension has no JS files');
    }
    
    return files;
  } catch (error) {
    console.error('❌ Error in comprehensive file scan:', error);
    return [];
  }
}

// Set up listener for extension installations
function setupExtensionListener() {
  console.log('Setting up extension installation listener');
  
  chrome.management.onInstalled.addListener(async (extensionInfo) => {
    try {
      console.log('🚨 EXTENSION INSTALLATION DETECTED:', {
        name: extensionInfo.name,
        id: extensionInfo.id,
        version: extensionInfo.version,
        enabled: extensionInfo.enabled
      });
      
      // Skip our own extension
      if (extensionInfo.id === chrome.runtime.id) {
        console.log('Skipping our own extension');
        return;
      }
      
      // Check if this is an unpacked extension
      const isUnpacked = extensionInfo.installType === 'development';
      console.log('📦 Extension type:', isUnpacked ? 'UNPACKED' : 'PACKAGED');
      
      // Check if we should intercept installations
      const { settings } = await chrome.storage.local.get('settings');
      console.log('Current interception settings:', settings);
      
      if (settings && settings.interceptInstallations) {
        if (isUnpacked) {
          console.log(`🔍 AUTO-SCANNING unpacked extension: ${extensionInfo.name}`);
          await handleUnpackedExtensionInstallation(extensionInfo);
        } else {
          console.log(`🔍 AUTO-SCANNING packaged extension: ${extensionInfo.name}`);
          
          // Add activity record for the installation detection
          await addToRecentActivity({
            type: 'installation_detected',
            extensionId: extensionInfo.id,
            extensionName: extensionInfo.name,
            time: new Date().toISOString()
          });
          
          // Scan the newly installed extension (will use limited analysis)
          try {
            await scanExtension(extensionInfo.id);
            console.log(`✅ Auto-scan completed for: ${extensionInfo.name}`);
          } catch (scanError) {
            console.error('❌ Auto-scan failed:', scanError);
            
            await addToRecentActivity({
              type: 'scan_failed',
              extensionId: extensionInfo.id,
              extensionName: extensionInfo.name,
              error: scanError.message,
              time: new Date().toISOString()
            });
          }
        }
      } else {
        console.log('⏸️ Installation interception is disabled');
        
        // Still log the installation for user awareness
        await addToRecentActivity({
          type: 'installation_detected',
          extensionId: extensionInfo.id,
          extensionName: extensionInfo.name,
          intercepted: false,
          time: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('❌ Error handling extension installation:', error);
    }
  });
  
  console.log('✅ Extension installation listener set up successfully');
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Make sure we handle the response asynchronously
  const asyncResponse = async () => {
    try {
      switch (message.action) {
        case 'getDashboardData':
          return await getDashboardData();
          
        case 'getInstalledExtensions':
          return await getInstalledExtensions();
          
        case 'startScan':
          return await handleScanRequest(message);
          
        case 'getScanHistory':
          return await getScanHistory();
          
        case 'getSettings':
          return await getSettings();
          
        case 'updateSetting':
          return await updateSetting(message.key, message.value);
          
        case 'disableExtension':
          return await disableExtension(message.extensionId);
          
        case 'getExtensionDetails':
          return await getExtensionDetails(message.extensionId);
          
        case 'getScanDetails':
          return await getScanDetails(message.scanId);
          
        case 'testInstallationListener':
          return await testInstallationListener();
          
        default:
          return { error: 'Unknown action' };
      }
    } catch (error) {
      console.error('Error handling message:', error);
      return { error: error.message };
    }
  };
  
  // Execute async response and send result
  asyncResponse().then(sendResponse);
  
  // Return true to indicate we'll respond asynchronously
  return true;
});

// Handle notification button clicks
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  if (notificationId.startsWith('extension-alert-')) {
    alertSystem.handleNotificationButtonClick(notificationId, buttonIndex);
  }
});

/**
 * Get dashboard data for popup
 * @returns {Object} Dashboard data
 */
async function getDashboardData() {
  const data = await chrome.storage.local.get(['stats', 'recentActivity', 'settings']);
  
  return {
    protectionStatus: data.settings?.interceptInstallations ? 'active' : 'inactive',
    stats: data.stats || {
      extensionsScanned: 0,
      threatsDetected: 0,
      lastScan: null
    },
    recentActivity: data.recentActivity || []
  };
}

/**
 * Get list of installed extensions
 * @returns {Array} List of installed extensions
 */
async function getInstalledExtensions() {
  try {
    const extensions = await chrome.management.getAll();
    
    // Filter out our own extension and system extensions
    return extensions
      .filter(ext => ext.id !== chrome.runtime.id && !ext.isApp)
      .map(ext => ({
        id: ext.id,
        name: ext.name,
        version: ext.version,
        description: ext.description,
        enabled: ext.enabled,
        icons: ext.icons
      }));
  } catch (error) {
    console.error('Error getting installed extensions:', error);
    throw new Error(`Failed to get installed extensions: ${error.message}`);
  }
}

/**
 * Handle scan request from popup
 * @param {Object} request - Scan request
 * @returns {Object} Scan results
 */
async function handleScanRequest(request) {
  try {
    const { scanType, scanDepth, extensionId } = request;
    
    if (scanType === 'single' && extensionId) {
      // Scan a single extension
      return await scanExtension(extensionId, scanDepth);
    } else if (scanType === 'all') {
      // Scan all installed extensions
      return await scanAllExtensions(scanDepth);
    } else if (scanType === 'recent') {
      // Scan recently installed extensions
      return await scanRecentExtensions(scanDepth);
    } else {
      throw new Error('Invalid scan type');
    }
  } catch (error) {
    console.error('Error handling scan request:', error);
    throw new Error(`Failed to handle scan request: ${error.message}`);
  }
}

/**
 * Scan a single extension
 * @param {string} extensionId - ID of the extension to scan
 * @param {string} scanDepth - Scan depth (basic, thorough, advanced)
 * @returns {Object} Scan results
 */
async function scanExtension(extensionId, scanDepth = 'thorough') {
  try {
    state.scanInProgress = true;
    console.log(`🔍 Starting REAL ${scanDepth} scan for extension: ${extensionId}`);
    
    // Get extension info
    const extensionInfo = await chrome.management.get(extensionId);
    console.log(`📋 Extension info:`, extensionInfo);
    
    let analysisResults = {};
    
    // Determine analysis method based on extension type
    if (extensionInfo.installType === 'development') {
      console.log(`🔧 Development extension - attempting direct file access`);
      analysisResults = await analyzeDevelopmentExtension(extensionId, extensionInfo, scanDepth);
    } else if (extensionInfo.installType === 'normal') {
      console.log(`📦 Web Store extension - attempting CRX download and analysis`);
      analysisResults = await analyzeWebStoreExtension(extensionId, extensionInfo, scanDepth);
    } else {
      console.log(`❓ Unknown extension type - falling back to manifest analysis`);
      analysisResults = await analyzeUnknownExtension(extensionId, extensionInfo, scanDepth);
    }
    
    // Perform heuristic analysis (always run regardless of scan depth)
    const heuristicAnalysis = heuristicAnalyzer.analyze(analysisResults);
    analysisResults.heuristicAnalysis = heuristicAnalysis;
    
    // Start runtime monitoring for behavioral analysis (if available)
    if (runtimeMonitor.isRuntimeMonitoringAvailable()) {
      runtimeMonitor.startMonitoringExtension(extensionId);
      // Add runtime monitoring results to analysis
      analysisResults.runtimeMonitoring = runtimeMonitor.getBehavioralAnalysis();
    } else {
      console.log('⚠️ Runtime monitoring not available in service worker context');
      analysisResults.runtimeMonitoring = {
        available: false,
        reason: 'Service worker context - runtime monitoring not available'
      };
    }
    
    // Classify threats
    const threatClassification = threatClassifier.classifyThreat(analysisResults);
    
    // Store results
    const scanResult = {
      extensionId,
      extensionInfo,
      analysisResults,
      threatClassification,
      timestamp: Date.now(),
      scanDepth,
      analysisMethod: analysisResults.analysisMethod || 'unknown'
    };
    
    state.scanResults[extensionId] = scanResult;
    
    // Save to history
    try {
      await saveScanToHistory(scanResult);
    } catch (historyError) {
      console.warn('Failed to save scan to history:', historyError);
    }
    
    console.log(`✅ REAL scan complete for ${extensionId}:`, scanResult);
    return scanResult;
    
  } catch (error) {
    console.error(`❌ Scan failed for ${extensionId}:`, error);
    throw error;
  } finally {
    state.scanInProgress = false;
  }
}

/**
 * Analyze development extension with direct file access
 */
async function analyzeDevelopmentExtension(extensionId, extensionInfo, scanDepth) {
  try {
    console.log(`🔧 Analyzing development extension: ${extensionId}`);
    
    // Try to read files directly from the extension directory
    const files = await readUnpackedExtensionFiles(extensionInfo);
    
    if (files.length > 0) {
      console.log(`✅ Successfully read ${files.length} real files from development extension`);
      
      // Analyze real files
      const jsCode = files.map(file => file.content).join('\n');
      
      const analysisResults = {
        analysisMethod: 'direct_file_access',
        manifestAnalysis: manifestAnalyzer.analyzeManifest(extensionInfo),
        staticAnalysis: staticAnalyzer.analyzeCode(jsCode),
        obfuscationAnalysis: obfuscationDetector.analyzeCode(jsCode),
        networkAnalysis: networkAnalyzer.analyzeCode(jsCode),
        files: files
      };
      
      return analysisResults;
    } else {
      throw new Error('Could not read any files from development extension');
    }
  } catch (error) {
    console.error(`❌ Development extension analysis failed:`, error);
    return await analyzeUnknownExtension(extensionId, extensionInfo, scanDepth);
  }
}

/**
 * Analyze Web Store extension using CRX download
 */
async function analyzeWebStoreExtension(extensionId, extensionInfo, scanDepth) {
  try {
    console.log(`📦 Analyzing Web Store extension: ${extensionId}`);
    
    // Use CRX analyzer to download and analyze the extension
    const crxAnalysis = await crxAnalyzer.analyzeCRX(extensionId);
    
    if (crxAnalysis && !crxAnalysis.error) {
      console.log(`✅ Successfully analyzed CRX with ${crxAnalysis.files.length} files`);
      
      // Analyze the real files from CRX
      const jsFiles = Array.isArray(crxAnalysis.files) ? crxAnalysis.files.filter(f => f && f.type === 'javascript') : [];
      const jsCode = jsFiles.map(file => file && file.content ? file.content : '').filter(content => content.length > 0).join('\n');
      
      const analysisResults = {
        analysisMethod: 'crx_download',
        manifestAnalysis: manifestAnalyzer.analyzeManifest(crxAnalysis.manifest),
        staticAnalysis: staticAnalyzer.analyzeCode(jsCode),
        obfuscationAnalysis: obfuscationDetector.analyzeCode(jsCode),
        networkAnalysis: networkAnalyzer.analyzeCode(jsCode),
        crxAnalysis: crxAnalysis,
        files: crxAnalysis.files
      };
      
      return analysisResults;
    } else {
      throw new Error(`CRX analysis failed: ${crxAnalysis?.error || 'Unknown error'}`);
    }
  } catch (error) {
    console.error(`❌ Web Store extension analysis failed:`, error);
    
    // Check if it's a CSP error and provide helpful message
    if (error.message && typeof error.message === 'string' && (error.message.includes('Content Security Policy') || error.message.includes('CSP'))) {
      console.log(`🚫 CSP violation detected - falling back to enhanced manifest analysis`);
      return await analyzeWebStoreExtensionWithFallback(extensionId, extensionInfo, scanDepth, error.message);
    }
    
    return await analyzeUnknownExtension(extensionId, extensionInfo, scanDepth);
  }
}

/**
 * Analyze Web Store extension with enhanced fallback when CRX download fails
 */
async function analyzeWebStoreExtensionWithFallback(extensionId, extensionInfo, scanDepth, cspError) {
  console.log(`🔄 Using enhanced manifest analysis due to CRX download restrictions`);
  
  // Enhanced manifest analysis for Web Store extensions
  const analysisResults = {
    analysisMethod: 'enhanced_manifest_analysis',
    manifestAnalysis: manifestAnalyzer.analyzeManifest(extensionInfo),
    staticAnalysis: { 
      results: {}, 
      riskScore: 0,
      suspiciousPatterns: [{
        category: 'CRX Download Analysis',
        description: `CRX download blocked by Content Security Policy: ${cspError}. Using enhanced manifest analysis.`
      }]
    },
    obfuscationAnalysis: { obfuscationDetected: false, obfuscationScore: 0 },
    networkAnalysis: { endpoints: { total: 0, suspicious: [] }, riskScore: 0 },
    cspRestriction: {
      blocked: true,
      reason: cspError,
      recommendation: 'Extension may need additional host permissions for Chrome Web Store domains'
    }
  };
  
  return analysisResults;
}

/**
 * Analyze unknown extension type with manifest-only analysis
 */
async function analyzeUnknownExtension(extensionId, extensionInfo, scanDepth) {
  console.log(`❓ Analyzing unknown extension type: ${extensionId}`);
  
  // Fall back to manifest-based analysis
  const analysisResults = {
    analysisMethod: 'manifest_only',
    manifestAnalysis: manifestAnalyzer.analyzeManifest(extensionInfo),
    staticAnalysis: { 
      results: {}, 
      riskScore: 0,
      suspiciousPatterns: [{
        category: 'Unpacked Extension Analysis',
        description: 'Cannot read JavaScript files - Chrome security restrictions prevent direct file access'
      }]
    },
    obfuscationAnalysis: { obfuscationDetected: false, obfuscationScore: 0 },
    networkAnalysis: { endpoints: { total: 0, suspicious: [] }, riskScore: 0 }
  };
  
  return analysisResults;
}

/**
 * Save scan result to history
 */
async function saveScanToHistory(scanResult) {
  try {
    const history = await chrome.storage.local.get(['scanHistory']) || { scanHistory: [] };
    
    // Format scan result for history display (lightweight version)
    const historyItem = {
      id: scanResult.extensionId,
      extensionName: scanResult.extensionInfo?.name || 'Unknown Extension',
      extensionId: scanResult.extensionId,
      scanTime: scanResult.timestamp,
      threatLevel: scanResult.threatClassification?.level || 'unknown',
      threatScore: scanResult.threatClassification?.score || 0,
      analysisMethod: scanResult.analysisMethod,
      summary: scanResult.threatClassification?.summary || 'No summary available',
      // Store only essential data to avoid quota issues
      keyFindings: {
        suspiciousPatterns: scanResult.analysisResults?.staticAnalysis?.suspiciousPatterns?.length || 0,
        obfuscationDetected: scanResult.analysisResults?.obfuscationAnalysis?.obfuscationDetected || false,
        networkEndpoints: scanResult.analysisResults?.networkAnalysis?.endpoints?.total || 0,
        dangerousPermissions: scanResult.analysisResults?.manifestAnalysis?.permissions?.dangerous?.permissions?.length || 0
      }
    };
    
    history.scanHistory.unshift(historyItem);
    
    // Keep only last 50 scans to reduce storage usage
    if (history.scanHistory.length > 50) {
      history.scanHistory = history.scanHistory.slice(0, 50);
    }
    
    // Clear old scan results from memory to free up space
    if (Object.keys(state.scanResults).length > 20) {
      const oldestKeys = Object.keys(state.scanResults).slice(0, 10);
      oldestKeys.forEach(key => delete state.scanResults[key]);
    }
    
    await chrome.storage.local.set({ scanHistory: history.scanHistory });
    console.log(`📝 Saved scan to history: ${historyItem.extensionName} (${historyItem.threatLevel})`);
  } catch (error) {
    console.error('Failed to save scan to history:', error);
    
    // If quota exceeded, try to clear some data and retry
    if (error.message && typeof error.message === 'string' && (error.message.includes('quota') || error.message.includes('Quota'))) {
      try {
        console.log('🧹 Clearing old data due to quota exceeded');
        await chrome.storage.local.clear();
        await chrome.storage.local.set({ scanHistory: [] });
        console.log('✅ Storage cleared, retrying history save');
      } catch (clearError) {
        console.error('Failed to clear storage:', clearError);
      }
    }
  }
}

/**
 * Update scan statistics
 */
async function updateScanStats(threatDetected = false) {
  try {
    const stats = await chrome.storage.local.get(['scanStats']) || { scanStats: { totalScans: 0, threatsDetected: 0 } };
    stats.scanStats.totalScans++;
    if (threatDetected) {
      stats.scanStats.threatsDetected++;
    }
    await chrome.storage.local.set({ scanStats: stats.scanStats });
  } catch (error) {
    console.error('Failed to update scan stats:', error);
  }
}

/**
 * Scan all installed extensions
 * @param {string} scanDepth - Scan depth (basic, thorough, advanced)
 * @returns {Array} Scan results for all extensions
 */
async function scanAllExtensions(scanDepth = 'thorough') {
  try {
    // Get all installed extensions
    const extensions = await getInstalledExtensions();
    
    // Scan each extension
    const results = [];
    for (const extension of extensions) {
      try {
        const result = await scanExtension(extension.id, scanDepth);
        results.push({
          extensionId: extension.id,
          extensionName: extension.name,
          threatLevel: result.threatClassification.level,
          threatScore: result.threatClassification.score,
          summary: result.threatClassification.summary
        });
      } catch (error) {
        console.error(`Error scanning extension ${extension.id}:`, error);
        results.push({
          extensionId: extension.id,
          extensionName: extension.name,
          threatLevel: 'error',
          summary: `Error scanning extension: ${error.message}`
        });
      }
    }
    
    return results;
  } catch (error) {
    console.error('Error scanning all extensions:', error);
    throw new Error(`Failed to scan all extensions: ${error.message}`);
  }
}

/**
 * Scan recently installed extensions
 * @param {string} scanDepth - Scan depth (basic, thorough, advanced)
 * @returns {Array} Scan results for recent extensions
 */
async function scanRecentExtensions(scanDepth = 'thorough') {
  try {
    // Get all installed extensions
    const extensions = await getInstalledExtensions();
    
    // Sort by installation time (if available) or just take the last 5
    // In a real implementation, we would track installation times
    const recentExtensions = extensions.slice(0, 5);
    
    // Scan each extension
    const results = [];
    for (const extension of recentExtensions) {
      try {
        const result = await scanExtension(extension.id, scanDepth);
        results.push({
          extensionId: extension.id,
          extensionName: extension.name,
          threatLevel: result.threatClassification.level,
          threatScore: result.threatClassification.score,
          summary: result.threatClassification.summary
        });
      } catch (error) {
        console.error(`Error scanning extension ${extension.id}:`, error);
        results.push({
          extensionId: extension.id,
          extensionName: extension.name,
          threatLevel: 'error',
          summary: `Error scanning extension: ${error.message}`
        });
      }
    }
    
    return results;
  } catch (error) {
    console.error('Error scanning recent extensions:', error);
    throw new Error(`Failed to scan recent extensions: ${error.message}`);
  }
}


/**
 * Add an activity to recent activity
 * @param {Object} activity - Activity to add
 */
async function addToRecentActivity(activity) {
  try {
    const { recentActivity } = await chrome.storage.local.get('recentActivity');
    
    // Add new activity to the beginning
    const updatedActivity = recentActivity || [];
    updatedActivity.unshift(activity);
    
    // Limit to 20 items
    if (updatedActivity.length > 20) {
      updatedActivity.pop();
    }
    
    // Save updated activity
    await chrome.storage.local.set({ recentActivity: updatedActivity });
  } catch (error) {
    console.error('Error adding to recent activity:', error);
  }
}


/**
 * Update stats in storage
 * @param {Object} stats - Stats to save
 */
async function updateStats(stats) {
  try {
    await chrome.storage.local.set({ stats });
  } catch (error) {
    console.error('Error updating stats:', error);
  }
}

/**
 * Get scan history
 * @returns {Array} Scan history
 */
async function getScanHistory() {
  try {
    const { scanHistory } = await chrome.storage.local.get('scanHistory');
    return scanHistory || [];
  } catch (error) {
    console.error('Error getting scan history:', error);
    throw new Error(`Failed to get scan history: ${error.message}`);
  }
}

/**
 * Get settings
 * @returns {Object} Settings
 */
async function getSettings() {
  try {
    const { settings } = await chrome.storage.local.get('settings');
    return settings || defaultSettings;
  } catch (error) {
    console.error('Error getting settings:', error);
    throw new Error(`Failed to get settings: ${error.message}`);
  }
}

/**
 * Update a setting
 * @param {string} key - Setting key
 * @param {any} value - Setting value
 * @returns {Object} Updated settings
 */
async function updateSetting(key, value) {
  try {
    const { settings } = await chrome.storage.local.get('settings');
    
    const updatedSettings = {
      ...(settings || defaultSettings),
      [key]: value
    };
    
    await chrome.storage.local.set({ settings: updatedSettings });
    
    // If we're updating the alert threshold, update the alert system
    if (key === 'alertThreshold') {
      alertSystem.setThreshold(value);
    }
    
    return updatedSettings;
  } catch (error) {
    console.error('Error updating setting:', error);
    throw new Error(`Failed to update setting: ${error.message}`);
  }
}

/**
 * Disable an extension
 * @param {string} extensionId - ID of the extension to disable
 * @returns {Object} Result
 */
async function disableExtension(extensionId) {
  try {
    // Get extension info
    const extensionInfo = await chrome.management.get(extensionId);
    
    // Disable the extension
    await chrome.management.setEnabled(extensionId, false);
    
    // Log the action
    const disableRecord = {
      type: 'block',
      extensionId: extensionId,
      extensionName: extensionInfo.name,
      reason: 'Disabled due to security risk',
      time: new Date().toISOString()
    };
    
    await addToRecentActivity(disableRecord);
    
    return {
      success: true,
      message: `Extension "${extensionInfo.name}" has been disabled.`
    };
  } catch (error) {
    console.error('Error disabling extension:', error);
    throw new Error(`Failed to disable extension: ${error.message}`);
  }
}

/**
 * Get detailed information about an extension
 * @param {string} extensionId - ID of the extension
 * @returns {Object} Detailed extension information
 */
async function getExtensionDetails(extensionId) {
  try {
    console.log(`Getting detailed information for extension: ${extensionId}`);
    console.log(`Available scan results:`, Object.keys(state.scanResults));
    
    // Check if we have scan results for this extension
    if (state.scanResults[extensionId]) {
      console.log(`Found existing scan results for ${extensionId}`);
      return state.scanResults[extensionId];
    }
    
    // If no scan results exist, get basic extension info
    const extensionInfo = await chrome.management.get(extensionId);
    
    // Perform a scan to get detailed information
    console.log(`No existing scan results found for ${extensionId}, performing scan now`);
    const scanResults = await scanExtension(extensionId, 'thorough');
    
    return scanResults;
  } catch (error) {
    console.error(`Error getting extension details for ${extensionId}:`, error);
    throw new Error(`Failed to get extension details: ${error.message}`);
  }
}

/**
 * Get manifest from development extension
 * @param {string} extensionId - Extension ID
 * @returns {Object} Manifest data
 */
async function getManifestFromDevelopmentExtension(extensionId) {
  try {
    console.log(`🔧 Attempting to get manifest from development extension: ${extensionId}`);
    
    // For development extensions, we can try to access the manifest directly
    // This is a workaround that may work in some cases
    const manifestUrl = `chrome-extension://${extensionId}/manifest.json`;
    
    try {
      const response = await fetch(manifestUrl);
      if (response.ok) {
        const manifestData = await response.json();
        console.log(`✅ Successfully retrieved manifest from development extension`);
        return manifestData;
      }
    } catch (fetchError) {
      console.log(`⚠️ Could not fetch manifest directly: ${fetchError.message}`);
    }
    
    // Fallback: create a basic manifest structure
    console.log(`📋 Creating fallback manifest structure for development extension`);
    return {
      manifest_version: 3,
      name: 'Development Extension',
      version: '1.0.0',
      permissions: [],
      host_permissions: []
    };
    
  } catch (error) {
    console.error(`❌ Error getting manifest from development extension: ${error.message}`);
    throw error;
  }
}

/**
 * Create manifest from management API data
 * @param {Object} extensionDetails - Extension details from chrome.management.get
 * @returns {Object} Manifest data
 */
function createManifestFromManagementAPI(extensionDetails) {
  try {
    console.log(`📦 Creating manifest from management API data`);
    
    // Extract what we can from the management API
    const manifest = {
      manifest_version: extensionDetails.manifest_version || 3,
      name: extensionDetails.name || 'Unknown Extension',
      version: extensionDetails.version || '1.0.0',
      permissions: extensionDetails.permissions || [],
      host_permissions: extensionDetails.host_permissions || [],
      description: extensionDetails.description || '',
      homepage_url: extensionDetails.homepage_url || '',
      install_type: extensionDetails.installType || 'unknown'
    };
    
    // Add background script info if available
    if (extensionDetails.background) {
      manifest.background = extensionDetails.background;
    }
    
    // Add content scripts if available
    if (extensionDetails.content_scripts) {
      manifest.content_scripts = extensionDetails.content_scripts;
    }
    
    console.log(`✅ Created manifest from management API:`, manifest);
    return manifest;
    
  } catch (error) {
    console.error(`❌ Error creating manifest from management API: ${error.message}`);
    throw error;
  }
}

/**
 * Get details of a specific scan by ID
 * @param {string} scanId - ID of the scan
 * @returns {Object} Scan details
 */
async function getScanDetails(scanId) {
  try {
    console.log(`Getting details for scan: ${scanId}`);
    
    // Get scan history from storage
    const { scanHistory } = await chrome.storage.local.get('scanHistory');
    
    if (!scanHistory || scanHistory.length === 0) {
      console.log('No scan history found');
      return null;
    }
    
    // Find the scan with the matching ID
    const scanDetails = scanHistory.find(scan => scan.id === scanId);
    
    if (!scanDetails) {
      console.log(`No scan found with ID: ${scanId}`);
      return null;
    }
    
    return scanDetails;
  } catch (error) {
    console.error(`Error getting scan details for ${scanId}:`, error);
    throw new Error(`Failed to get scan details: ${error.message}`);
  }
}

/**
 * Test the installation listener functionality
 * @returns {Object} Test results
 */
async function testInstallationListener() {
  try {
    console.log('🧪 Testing installation listener functionality');
    
    // Check if we have the management permission
    const manifest = chrome.runtime.getManifest();
    const hasManagementPermission = manifest.permissions && Array.isArray(manifest.permissions) && manifest.permissions.includes('management');
    console.log('📋 Has management permission:', hasManagementPermission);
    
    // Check current settings
    const { settings } = await chrome.storage.local.get('settings');
    console.log('⚙️ Current settings:', settings);
    
    // Get list of all extensions to verify management API works
    let extensionCount = 0;
    try {
      const extensions = await chrome.management.getAll();
      extensionCount = extensions.length;
      console.log('📦 Found', extensionCount, 'extensions via management API');
    } catch (e) {
      console.error('❌ Management API failed:', e);
    }
    
    // Add a test activity to verify the activity system works
    await addToRecentActivity({
      type: 'installation_listener_test',
      message: 'Installation listener test completed',
      time: new Date().toISOString()
    });
    
    return {
      success: true,
      hasManagementPermission,
      interceptInstallationsEnabled: settings?.interceptInstallations || false,
      extensionCount,
      message: 'Installation listener test completed. Check console logs for details.'
    };
  } catch (error) {
    console.error('❌ Test failed:', error);
    return {
      success: false,
      error: error.message
    };
  }
}
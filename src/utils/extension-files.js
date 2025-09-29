/**
 * Extension Files Utility
 * Handles extraction and processing of extension files
 */

// Import real JSZip library (bundled by webpack)
import JSZip from 'jszip';

// Extract ZIP files using JSZip
async function extractZipFromArrayBuffer(zipData) {
  try {
    console.log('📦 Loading ZIP data with JSZip...');
    const zip = await JSZip.loadAsync(zipData);
    console.log('✅ ZIP loaded successfully');
    return zip;
  } catch (error) {
    console.error('❌ Error loading ZIP with JSZip:', error);
    throw new Error(`Failed to load ZIP: ${error.message}`);
  }
}

// Get files from an installed extension
async function getExtensionFiles(extensionId) {
  try {
    // Get extension info
    const extensionInfo = await chrome.management.get(extensionId);
    
    // Get the manifest
    const manifest = await getExtensionManifest(extensionId);
    
    // For Chrome/Brave extensions, we can't directly access the files of installed extensions
    // due to security restrictions. However, we can:
    // 1. Analyze the manifest which we can access via the management API
    // 2. For content scripts, we can analyze their behavior at runtime
    // 3. For Web Store extensions, we can download the CRX file from the store
    
    // Try to download the CRX if it's from the Web Store
    let jsFiles = [];
    let htmlFiles = [];
    let cssFiles = [];
    let otherFiles = [];
    
    // Check if this is a Web Store extension
    const isWebStoreExtension = extensionInfo.updateUrl && 
      (extensionInfo.updateUrl.includes('chrome.google.com') || 
       extensionInfo.updateUrl.includes('edge.microsoft.com'));
    
    if (isWebStoreExtension) {
      try {
        // Try to download and extract the CRX
        const crxData = await downloadCrxFromWebStore(extensionId);
        
        if (crxData) {
          // Extract files from the CRX
          const extractedFiles = await extractCrxFiles(crxData);
          jsFiles = extractedFiles.jsFiles || [];
          htmlFiles = extractedFiles.htmlFiles || [];
          cssFiles = extractedFiles.cssFiles || [];
          otherFiles = extractedFiles.otherFiles || [];
        }
      } catch (error) {
        console.warn('Could not download CRX file:', error);
        // Continue with limited analysis
      }
    }
    
    // If we couldn't get the files, create synthetic JS files from content scripts
    // and background scripts that we know about from the manifest
    if (jsFiles.length === 0 && manifest) {
      // Create synthetic JS files for content scripts
      if (manifest.content_scripts && manifest.content_scripts.length > 0) {
        for (const contentScript of manifest.content_scripts) {
          if (contentScript.js && contentScript.js.length > 0) {
            for (const jsFile of contentScript.js) {
              jsFiles.push({
                name: jsFile,
                path: jsFile,
                content: `// Content script: ${jsFile}\n// Matches: ${contentScript.matches.join(', ')}\n// Note: Actual code not available for analysis`,
                type: 'javascript'
              });
            }
          }
        }
      }
      
      // Create synthetic JS file for background script
      if (manifest.background) {
        if (manifest.background.scripts && manifest.background.scripts.length > 0) {
          for (const script of manifest.background.scripts) {
            jsFiles.push({
              name: script,
              path: script,
              content: `// Background script: ${script}\n// Note: Actual code not available for analysis`,
              type: 'javascript'
            });
          }
        } else if (manifest.background.service_worker) {
          jsFiles.push({
            name: manifest.background.service_worker,
            path: manifest.background.service_worker,
            content: `// Service worker: ${manifest.background.service_worker}\n// Note: Actual code not available for analysis`,
            type: 'javascript'
          });
        }
      }
      
      // Add synthetic JS for event pages
      if (manifest.event_page) {
        jsFiles.push({
          name: manifest.event_page,
          path: manifest.event_page,
          content: `// Event page: ${manifest.event_page}\n// Note: Actual code not available for analysis`,
          type: 'javascript'
        });
      }
      
      // Add synthetic JS for browser actions
      if (manifest.browser_action && manifest.browser_action.default_popup) {
        htmlFiles.push({
          name: manifest.browser_action.default_popup,
          path: manifest.browser_action.default_popup,
          content: `<!-- Browser action popup: ${manifest.browser_action.default_popup} -->\n<!-- Note: Actual code not available for analysis -->`,
          type: 'html'
        });
      }
      
      // Add synthetic JS for page actions
      if (manifest.page_action && manifest.page_action.default_popup) {
        htmlFiles.push({
          name: manifest.page_action.default_popup,
          path: manifest.page_action.default_popup,
          content: `<!-- Page action popup: ${manifest.page_action.default_popup} -->\n<!-- Note: Actual code not available for analysis -->`,
          type: 'html'
        });
      }
    }
    
    // Add a synthetic JS file with permissions info for analysis
    if (manifest.permissions && manifest.permissions.length > 0) {
      jsFiles.push({
        name: '_permissions.js',
        path: '_permissions.js',
        content: `// Permissions requested by this extension:\n// ${manifest.permissions.join('\n// ')}`,
        type: 'javascript'
      });
    }
    
    // Add a synthetic JS file with host permissions info for analysis
    if (manifest.host_permissions && manifest.host_permissions.length > 0) {
      jsFiles.push({
        name: '_host_permissions.js',
        path: '_host_permissions.js',
        content: `// Host permissions requested by this extension:\n// ${manifest.host_permissions.join('\n// ')}`,
        type: 'javascript'
      });
    }
    
    // Add manifest as a file for analysis
    otherFiles.push({
      name: 'manifest.json',
      path: 'manifest.json',
      content: JSON.stringify(manifest, null, 2),
      type: 'json'
    });
    
    return {
      extensionInfo,
      manifest,
      jsFiles,
      htmlFiles,
      cssFiles,
      otherFiles
    };
  } catch (error) {
    console.error('Error getting extension files:', error);
    throw new Error(`Failed to get extension files: ${error.message}`);
  }
}

// Get the manifest of an installed extension
async function getExtensionManifest(extensionId) {
  try {
    // Get extension info from management API
    const extensionInfo = await chrome.management.get(extensionId);
    
    // Try to get the actual manifest by downloading the CRX
    // This is the most reliable way to get the complete manifest
    try {
      // Check if this is a Web Store extension
      const isWebStoreExtension = extensionInfo.updateUrl && 
        (extensionInfo.updateUrl.includes('chrome.google.com') || 
         extensionInfo.updateUrl.includes('edge.microsoft.com'));
      
      if (isWebStoreExtension) {
        // Download the CRX and extract the manifest
        const crxData = await downloadCrxFromWebStore(extensionId);
        if (crxData) {
          // Extract the manifest from the CRX
          const data = new Uint8Array(crxData);
          
          // Check magic number
          const magic = String.fromCharCode(data[0], data[1], data[2], data[3]);
          if (magic === 'Cr24') {
            // Get header size
            const version = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
            const headerSize = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
            const zipStartOffset = 12 + headerSize;
            
            // Extract the ZIP data
            const zipData = crxData.slice(zipStartOffset);
            
            // Extract using real JSZip library
            const zip = await extractZipFromArrayBuffer(zipData);
            const manifestFile = zip.file('manifest.json');
            
            if (manifestFile) {
              const manifestContent = await manifestFile.async('string');
              try {
                const manifest = JSON.parse(manifestContent);
                return manifest;
              } catch (e) {
                console.error('Error parsing manifest.json from CRX:', e);
              }
            }
          }
        }
      }
    } catch (e) {
      console.warn('Could not get manifest from CRX:', e);
      // Continue with fallback method
    }
    
    // Fallback: Create a manifest based on extension info from management API
    // This won't have all the details but is better than nothing
    const manifest = {
      name: extensionInfo.name,
      version: extensionInfo.version,
      description: extensionInfo.description,
      manifest_version: extensionInfo.manifestVersion || 2,
      permissions: extensionInfo.permissions || [],
      host_permissions: extensionInfo.hostPermissions || [],
      content_scripts: [], // We can't get these from the management API
      background: {}
    };
    
    // Add background info based on what we know
    if (extensionInfo.type === 'extension') {
      manifest.background = {
        // For Manifest V3, service workers are used
        service_worker: extensionInfo.manifestVersion === 3 ? 'background.js' : undefined,
        // For Manifest V2, persistent background pages are common
        persistent: extensionInfo.manifestVersion === 2 ? true : undefined
      };
    }
    
    // Add icons
    if (extensionInfo.icons && extensionInfo.icons.length > 0) {
      manifest.icons = extensionInfo.icons.reduce((acc, icon) => {
        acc[icon.size] = icon.url;
        return acc;
      }, {});
    }
    
    return manifest;
  } catch (error) {
    console.error('Error getting extension manifest:', error);
    throw new Error(`Failed to get extension manifest: ${error.message}`);
  }
}

// Extract files from a CRX file
async function extractCrxFiles(crxData) {
  try {
    // CRX3 format:
    // https://chromium.googlesource.com/chromium/src/+/master/components/crx_file/crx3.proto
    //
    // Format:
    // 1. "Cr24" magic number (4 bytes)
    // 2. Version number (4 bytes)
    // 3. Header size (4 bytes)
    // 4. CRX3 header (protobuf)
    // 5. ZIP data
    
    // Convert ArrayBuffer to Uint8Array for easier manipulation
    const data = new Uint8Array(crxData);
    
    // Check magic number
    const magic = String.fromCharCode(data[0], data[1], data[2], data[3]);
    if (magic !== 'Cr24') {
      throw new Error('Invalid CRX file: wrong magic number');
    }
    
    // Check version
    const version = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
    console.log(`CRX version: ${version}`);
    
    // Get header size
    const headerSize = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
    console.log(`CRX header size: ${headerSize} bytes`);
    
    // Skip the header to get to the ZIP data
    // For CRX3, the ZIP data starts after the 12-byte CRX header and the protobuf header
    const zipStartOffset = 12 + headerSize;
    
    // Extract the ZIP data
    const zipData = crxData.slice(zipStartOffset);
    
    console.log(`ZIP data size: ${zipData.byteLength} bytes`);
    
    // Use a real ZIP extraction method
    // We need to implement actual ZIP parsing since we're now getting real CRX files
    const zip = await extractZipFromArrayBuffer(zipData);
    
    // Initialize file collections
    const jsFiles = [];
    const htmlFiles = [];
    const cssFiles = [];
    const otherFiles = [];
    let manifest = null;
    
    // Process each file in the ZIP
    const filePromises = [];
    
    // JSZip forEach API
    zip.forEach((relativePath, zipEntry) => {
      // Skip directories
      if (zipEntry.dir) return;
      
      console.log(`📄 Processing file: ${relativePath}`);
      
      // Process the file based on its extension
      const filePromise = zipEntry.async('string').then(content => {
        const fileName = relativePath.split('/').pop();
        const fileType = detectFileType(fileName, content);
        
        const fileObj = {
          name: fileName,
          path: relativePath,
          content: content,
          type: fileType,
          size: content.length
        };
        
        console.log(`📝 Extracted ${fileName} (${fileType}, ${content.length} bytes)`);
        
        // Sort files by type
        if (fileName === 'manifest.json') {
          try {
            manifest = JSON.parse(content);
            console.log('📋 Parsed manifest:', manifest.name, manifest.version);
            otherFiles.push(fileObj);
          } catch (e) {
            console.error('❌ Error parsing manifest.json:', e);
            otherFiles.push(fileObj);
          }
        } else if (fileType === 'javascript') {
          jsFiles.push(fileObj);
        } else if (fileType === 'html') {
          htmlFiles.push(fileObj);
        } else if (fileType === 'css') {
          cssFiles.push(fileObj);
        } else {
          otherFiles.push(fileObj);
        }
      }).catch(error => {
        console.error(`❌ Error processing file ${relativePath}:`, error);
      });
      
      filePromises.push(filePromise);
    });
    
    // Wait for all files to be processed
    await Promise.all(filePromises);
    
    // If no manifest was found, create a default one
    if (!manifest) {
      manifest = {
        name: "Unknown Extension",
        version: "0.0.0",
        manifest_version: 2,
        description: "No manifest.json found in the CRX file"
      };
    }
    
    return {
      manifest,
      jsFiles,
      htmlFiles,
      cssFiles,
      otherFiles
    };
  } catch (error) {
    console.error('Error extracting CRX files:', error);
    throw new Error(`Failed to extract CRX files: ${error.message}`);
  }
}

// Download a CRX file from the Chrome Web Store
async function downloadCrxFromWebStore(extensionId) {
  try {
    // Chrome Web Store CRX download URL format
    // Note: This URL format may change and is not officially documented
    const chromeWebStoreUrl = `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=100.0&acceptformat=crx3&x=id%3D${extensionId}%26installsource%3Dondemand%26uc`;
    
    console.log(`Attempting to download CRX for extension ${extensionId}`);
    
    // Fetch the CRX file
    const response = await fetch(chromeWebStoreUrl, {
      method: 'GET',
      credentials: 'omit',
      redirect: 'follow'
    });
    
    if (!response.ok) {
      throw new Error(`Failed to download CRX: ${response.status} ${response.statusText}`);
    }
    
    // Get the binary data
    const arrayBuffer = await response.arrayBuffer();
    
    console.log(`Successfully downloaded CRX for extension ${extensionId} (${arrayBuffer.byteLength} bytes)`);
    
    return arrayBuffer;
  } catch (error) {
    console.error('Error downloading CRX:', error);
    throw new Error(`Failed to download CRX: ${error.message}`);
  }
}

// Parse a manifest.json file
function parseManifest(manifestJson) {
  try {
    // Parse the manifest JSON
    const manifest = JSON.parse(manifestJson);
    
    // Validate required fields
    if (!manifest.name || !manifest.version || !manifest.manifest_version) {
      throw new Error('Invalid manifest: missing required fields');
    }
    
    return manifest;
  } catch (error) {
    console.error('Error parsing manifest:', error);
    throw new Error(`Failed to parse manifest: ${error.message}`);
  }
}

// Get content of a file as text
function getFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = event => resolve(event.target.result);
    reader.onerror = error => reject(error);
    reader.readAsText(file);
  });
}

// Get content of a file as array buffer
function getFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = event => resolve(event.target.result);
    reader.onerror = error => reject(error);
    reader.readAsArrayBuffer(file);
  });
}

// Detect file type based on extension and content
function detectFileType(filename, content) {
  // Check file extension
  const extension = filename.split('.').pop().toLowerCase();
  
  switch (extension) {
    case 'js':
      return 'javascript';
    case 'html':
    case 'htm':
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
    case 'webp':
      return 'image';
    default:
      // Try to detect based on content
      if (typeof content === 'string') {
        if (content.trim().startsWith('{') && content.trim().endsWith('}')) {
          try {
            JSON.parse(content);
            return 'json';
          } catch (e) {
            // Not valid JSON
          }
        }
        
        if (content.includes('<!DOCTYPE html>') || content.includes('<html')) {
          return 'html';
        }
        
        if (content.includes('function') || content.includes('var ') || 
            content.includes('let ') || content.includes('const ')) {
          return 'javascript';
        }
      }
      
      return 'unknown';
  }
}

// Export all functions
export {
  extractZipFromArrayBuffer,
  getExtensionFiles,
  getExtensionManifest,
  extractCrxFiles,
  downloadCrxFromWebStore,
  parseManifest,
  getFileAsText,
  getFileAsArrayBuffer,
  detectFileType
};

// Make functions available globally for importScripts
if (typeof window !== 'undefined') {
  window.getExtensionFiles = getExtensionFiles;
  window.extractCrxFiles = extractCrxFiles;
  window.downloadCrxFromWebStore = downloadCrxFromWebStore;
  window.parseManifest = parseManifest;
  window.getFileAsText = getFileAsText;
  window.getFileAsArrayBuffer = getFileAsArrayBuffer;
  window.detectFileType = detectFileType;
} else if (typeof self !== 'undefined') {
  self.getExtensionFiles = getExtensionFiles;
  self.extractCrxFiles = extractCrxFiles;
  self.downloadCrxFromWebStore = downloadCrxFromWebStore;
  self.parseManifest = parseManifest;
  self.getFileAsText = getFileAsText;
  self.getFileAsArrayBuffer = getFileAsArrayBuffer;
  self.detectFileType = detectFileType;
}
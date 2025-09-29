// TEST EXTENSION: Clean background script with no suspicious patterns

console.log('Clean extension background script loaded');

// Safe and legitimate functionality only
const cleanExtension = {
  name: 'Clean Test Extension',
  version: '1.0.0',
  features: ['popup', 'content-script']
};

// Pattern 1: Safe storage usage
function saveUserPreferences(preferences) {
  chrome.storage.local.set({
    userPreferences: preferences,
    lastUpdated: Date.now()
  }, () => {
    if (chrome.runtime.lastError) {
      console.log('Error saving preferences:', chrome.runtime.lastError);
    } else {
      console.log('Preferences saved successfully');
    }
  });
}

// Pattern 2: Safe tab interaction (only activeTab permission)
function getActiveTabInfo() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (chrome.runtime.lastError) {
      console.log('Error querying tabs:', chrome.runtime.lastError);
      return;
    }
    
    if (tabs[0]) {
      console.log('Active tab title:', tabs[0].title);
      // Only basic info, no sensitive data collection
    }
  });
}

// Pattern 3: Safe message handling
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case 'getExtensionInfo':
      sendResponse({
        name: cleanExtension.name,
        version: cleanExtension.version,
        features: cleanExtension.features
      });
      break;
      
    case 'updatePreferences':
      if (message.preferences) {
        saveUserPreferences(message.preferences);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false, error: 'Invalid preferences' });
      }
      break;
      
    default:
      sendResponse({ error: 'Unknown action' });
  }
  
  return true; // Keep message channel open for async response
});

// Pattern 4: Safe initialization
chrome.runtime.onInstalled.addListener((details) => {
  console.log('Clean extension installed:', details.reason);
  
  if (details.reason === 'install') {
    // Set default preferences
    const defaultPreferences = {
      theme: 'light',
      notifications: true,
      autoStart: false
    };
    
    saveUserPreferences(defaultPreferences);
  }
});

// Pattern 5: Safe utility functions
function sanitizeInput(input) {
  if (typeof input !== 'string') {
    return '';
  }
  
  // Basic HTML entity encoding
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function validateUrl(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === 'https:' || urlObj.protocol === 'http:';
  } catch (e) {
    return false;
  }
}

// Pattern 6: Safe periodic tasks
function performMaintenanceTasks() {
  console.log('Performing routine maintenance');
  
  // Clean up old storage data
  chrome.storage.local.get(['userPreferences'], (result) => {
    if (result.userPreferences) {
      // Update last access time
      const updatedPreferences = {
        ...result.userPreferences,
        lastAccessed: Date.now()
      };
      
      saveUserPreferences(updatedPreferences);
    }
  });
}

// Run maintenance every hour
setInterval(performMaintenanceTasks, 60 * 60 * 1000);

// Pattern 7: Safe error handling
window.addEventListener('error', (event) => {
  console.log('Extension error caught:', {
    message: event.message,
    filename: event.filename,
    lineno: event.lineno,
    colno: event.colno
  });
  
  // Log error to extension storage for debugging (no external transmission)
  chrome.storage.local.get(['errorLog'], (result) => {
    const errorLog = result.errorLog || [];
    errorLog.push({
      message: event.message,
      timestamp: Date.now(),
      filename: event.filename,
      line: event.lineno
    });
    
    // Keep only last 10 errors
    if (errorLog.length > 10) {
      errorLog.shift();
    }
    
    chrome.storage.local.set({ errorLog });
  });
});

console.log('Clean extension background script initialized successfully');
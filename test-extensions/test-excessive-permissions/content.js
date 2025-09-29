// TEST EXTENSION: Content script with permission usage patterns

console.log('TEST: Excessive permissions content script loaded');

// Pattern 1: Document cookie access
function accessDocumentCookies() {
  const cookies = document.cookie;
  console.log('TEST: Document cookies accessed:', cookies.length, 'characters');
}

// Pattern 2: Location tracking
function trackLocation() {
  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(
      (position) => {
        console.log('TEST: Location obtained:', position.coords.latitude, position.coords.longitude);
      },
      (error) => {
        console.log('TEST: Location access denied:', error.message);
      }
    );
  }
}

// Pattern 3: Collect browser information
function collectBrowserInfo() {
  const info = {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    languages: navigator.languages,
    cookieEnabled: navigator.cookieEnabled,
    onLine: navigator.onLine,
    screenWidth: screen.width,
    screenHeight: screen.height,
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth,
    timezoneOffset: new Date().getTimezoneOffset(),
    plugins: Array.from(navigator.plugins).map(p => p.name),
    mimeTypes: Array.from(navigator.mimeTypes).map(m => m.type)
  };
  
  console.log('TEST: Browser fingerprint collected:', info);
}

// Pattern 4: DOM manipulation for data collection
function collectFormData() {
  const forms = document.querySelectorAll('form');
  forms.forEach((form, index) => {
    console.log(`TEST: Found form ${index}:`, form.action);
    
    const inputs = form.querySelectorAll('input');
    inputs.forEach(input => {
      if (input.type === 'password' || input.type === 'email' || input.type === 'text') {
        console.log('TEST: Sensitive input found:', input.type, input.name);
      }
    });
  });
}

// Execute when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    accessDocumentCookies();
    trackLocation();
    collectBrowserInfo();
    collectFormData();
  });
} else {
  accessDocumentCookies();
  trackLocation();
  collectBrowserInfo();
  collectFormData();
}
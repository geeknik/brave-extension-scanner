// TEST EXTENSION: Clean content script with no suspicious patterns

console.log('Clean extension content script loaded on:', window.location.href);

// Only run on allowed domains (example.com)
if (!window.location.hostname.includes('example.com')) {
  console.log('Clean extension: Not running on this domain');
  // Exit early if not on allowed domain
} else {
  
  // Pattern 1: Safe DOM manipulation
  function addWelcomeMessage() {
    // Only add if not already present
    if (document.getElementById('clean-extension-welcome')) {
      return;
    }
    
    const welcomeDiv = document.createElement('div');
    welcomeDiv.id = 'clean-extension-welcome';
    welcomeDiv.style.cssText = `
      position: fixed;
      top: 10px;
      right: 10px;
      background: #e8f5e8;
      padding: 10px;
      border: 1px solid #4caf50;
      border-radius: 4px;
      font-family: Arial, sans-serif;
      font-size: 12px;
      color: #2e7d32;
      z-index: 10000;
      max-width: 200px;
    `;
    welcomeDiv.textContent = 'Clean Extension: Safe functionality active';
    
    document.body.appendChild(welcomeDiv);
    
    // Remove after 3 seconds
    setTimeout(() => {
      if (welcomeDiv.parentNode) {
        welcomeDiv.parentNode.removeChild(welcomeDiv);
      }
    }, 3000);
  }
  
  // Pattern 2: Safe event listening (no sensitive data capture)
  function setupSafeEventListeners() {
    // Listen for clicks on specific safe elements only
    document.addEventListener('click', (event) => {
      const target = event.target;
      
      // Only react to buttons or links with specific classes
      if (target.classList.contains('clean-extension-target')) {
        console.log('Clean extension: Safe element clicked');
        
        // Safe action - just log the event type
        chrome.runtime.sendMessage({
          action: 'logSafeEvent',
          eventType: 'click',
          timestamp: Date.now()
        });
      }
    });
  }
  
  // Pattern 3: Safe page analysis (no sensitive data)
  function analyzePage() {
    const pageInfo = {
      title: document.title,
      domain: window.location.hostname,
      protocol: window.location.protocol,
      hasImages: document.images.length > 0,
      hasLinks: document.links.length > 0,
      timestamp: Date.now()
    };
    
    console.log('Clean extension: Safe page analysis:', pageInfo);
    
    // Send safe page info to background
    chrome.runtime.sendMessage({
      action: 'updatePreferences',
      preferences: {
        lastVisitedPage: {
          domain: pageInfo.domain,
          timestamp: pageInfo.timestamp,
          hasContent: pageInfo.hasImages || pageInfo.hasLinks
        }
      }
    });
  }
  
  // Pattern 4: Safe utility functions
  function isElementVisible(element) {
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && 
           rect.top >= 0 && rect.left >= 0 &&
           rect.bottom <= window.innerHeight &&
           rect.right <= window.innerWidth;
  }
  
  function sanitizeText(text) {
    return text.replace(/[<>]/g, '').trim();
  }
  
  // Pattern 5: Safe message handling
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
      case 'getPageInfo':
        sendResponse({
          title: document.title,
          url: window.location.href,
          timestamp: Date.now()
        });
        break;
        
      case 'highlightElement':
        if (message.selector) {
          const element = document.querySelector(message.selector);
          if (element) {
            element.style.outline = '2px solid #4caf50';
            setTimeout(() => {
              element.style.outline = '';
            }, 2000);
            sendResponse({ success: true });
          } else {
            sendResponse({ success: false, error: 'Element not found' });
          }
        }
        break;
        
      default:
        sendResponse({ error: 'Unknown action' });
    }
    
    return true;
  });
  
  // Pattern 6: Safe initialization
  function initializeCleanExtension() {
    console.log('Clean extension: Initializing safe functionality');
    
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        addWelcomeMessage();
        setupSafeEventListeners();
        analyzePage();
      });
    } else {
      addWelcomeMessage();
      setupSafeEventListeners();
      analyzePage();
    }
  }
  
  // Pattern 7: Safe error handling
  window.addEventListener('error', (event) => {
    console.log('Clean extension content script error:', event.message);
    
    // Report error to background script (no external transmission)
    chrome.runtime.sendMessage({
      action: 'logError',
      error: {
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        timestamp: Date.now(),
        url: window.location.href
      }
    });
  });
  
  // Initialize the clean extension
  initializeCleanExtension();
}

console.log('Clean extension content script initialization complete');
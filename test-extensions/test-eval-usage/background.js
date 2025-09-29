// TEST EXTENSION: Eval Usage Patterns
// This extension contains various eval() usage patterns for testing the scanner

console.log('TEST: Background script loaded');

// Pattern 1: Direct eval usage
function testDirectEval() {
  // This should trigger the eval detection
  const code = "console.log('Dynamic code execution')";
  eval(code);
}

// Pattern 2: Function constructor
function testFunctionConstructor() {
  // This should trigger the Function constructor detection
  const dynamicFunc = new Function('x', 'return x * 2');
  return dynamicFunc(5);
}

// Pattern 3: setTimeout with string
function testSetTimeoutWithString() {
  // This should trigger the setTimeout with string detection
  setTimeout("console.log('Delayed execution')", 1000);
}

// Pattern 4: setInterval with string
function testSetIntervalWithString() {
  // This should trigger the setInterval with string detection
  const intervalId = setInterval("console.log('Repeated execution')", 5000);
  setTimeout(() => clearInterval(intervalId), 10000);
}

// Pattern 5: document.write (if available in service worker context)
function testDocumentWrite() {
  // This might not work in service worker but should still be detected
  if (typeof document !== 'undefined') {
    document.write('<script>console.log("Injected script")</script>');
  }
}

// Simulate some legitimate usage that might trigger false positives
function legitimateStringProcessing() {
  const userInput = "user data";
  const processedData = userInput.replace(/[<>]/g, '');
  console.log('Processed:', processedData);
}

// Execute test functions when extension loads
chrome.runtime.onInstalled.addListener(() => {
  console.log('TEST: Extension installed, running eval tests...');
  
  // Run the test functions
  testDirectEval();
  testFunctionConstructor();
  testSetTimeoutWithString();
  testSetIntervalWithString();
  testDocumentWrite();
  legitimateStringProcessing();
});
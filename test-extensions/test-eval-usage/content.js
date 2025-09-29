// TEST EXTENSION: Content script with eval patterns
// This content script contains additional eval patterns

console.log('TEST: Content script loaded');

// Pattern 6: Eval in content script context
function contentScriptEval() {
  const dynamicCode = "document.title = 'Modified by eval'";
  eval(dynamicCode);
}

// Pattern 7: Creating script elements dynamically
function createDynamicScript() {
  const script = document.createElement('script');
  script.textContent = 'console.log("Dynamic script created")';
  document.head.appendChild(script);
}

// Pattern 8: innerHTML with script tag
function injectScriptViaInnerHTML() {
  const div = document.createElement('div');
  div.innerHTML = '<script>console.log("Script via innerHTML")</script>';
  document.body.appendChild(div);
}

// Pattern 9: More complex eval usage
function complexEvalUsage() {
  const operations = {
    add: '(a, b) => a + b',
    multiply: '(a, b) => a * b'
  };
  
  for (const [name, func] of Object.entries(operations)) {
    const operation = eval(func);
    console.log(`${name}:`, operation(2, 3));
  }
}

// Execute when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    contentScriptEval();
    createDynamicScript();
    injectScriptViaInnerHTML();
    complexEvalUsage();
  });
} else {
  contentScriptEval();
  createDynamicScript();
  injectScriptViaInnerHTML();
  complexEvalUsage();
}
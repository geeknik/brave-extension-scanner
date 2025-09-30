// Test extension with various obfuscation techniques

// JSFuck obfuscation examples
var _0x1234 = [][+[]]; // [][+[]] = undefined
var _0x5678 = !+[]; // !+[] = true
var _0x9abc = (++![]); // (++![]) = 1

// AAEncode-style obfuscation (simplified)
var ﾟωﾟﾉ = /test/;
var ﾟДﾟ = ﾟωﾟﾉ;

// Control flow obfuscation
var _0xabcd = Math.random();
switch (_0xabcd > 0.5 ? 1 : 0) {
  case 1:
    console.log('Branch 1');
    break;
  case 0:
    console.log('Branch 2');
    break;
}

// Dead code
if (false) {
  console.log('This will never execute');
  var secret = 'hidden data';
}

if (0) {
  console.log('This is also dead code');
}

// Variable name obfuscation
var _0xverylongvariablenamethatlookssuspicious = 'data';
var _0xanotherverylongvariablename = _0xverylongvariablenamethatlookssuspicious + 'concatenated';

// Function call obfuscation
window['console']['log']('Dynamic function call');
this['setTimeout'](function() {
  console.log('Delayed execution');
}, 1000);

// String obfuscation
var _0xstring = String.fromCharCode(72, 101, 108, 108, 111); // "Hello"
var _0xencoded = btoa('secret data');
var _0xdecoded = atob(_0xencoded);

// Anti-debugging
setInterval(function() {
  if (Math.random() > 0.9) {
    debugger;
  }
}, 5000);

// Advanced string manipulation
var _0xparts = 'Hello World'.split('').map(function(c) {
  return c.charCodeAt(0);
});

// Mathematical obfuscation
var _0xrandom = Math.floor(Math.random() * 100);
var _0xparsed = parseInt('123', 10);

// Prototype pollution attempt
var _0xproto = {};
_0xproto['__proto__']['isAdmin'] = true;

// Complex obfuscated function
function _0xcomplex() {
  var _0xa = 'test';
  var _0xb = _0xa + 'ing';
  return _0xb;
}

// Eval usage
var _0xcode = 'console.log("Dynamic code execution")';
eval(_0xcode);

// Function constructor
var _0xfunc = new Function('return "constructed function"');
_0xfunc();

// Hex literals
var _0xhex = 0x1234;
var _0xcolor = 0xFF0000;

// Unicode escapes
var _0xunicode = '\u0048\u0065\u006c\u006c\u006f'; // "Hello"

// Complex obfuscated expression
var _0xresult = (function() {
  var _0xarr = [1, 2, 3, 4, 5];
  return _0xarr.map(function(x) { return x * 2; });
})();

console.log('Obfuscated test extension loaded');

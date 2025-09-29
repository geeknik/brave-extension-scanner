// TEST EXTENSION: Background script with various obfuscation patterns

console.log('TEST: Obfuscated extension loaded');

// Pattern 1: Hex encoded strings
var _0x1234 = ['TEST', 'obfuscated', 'string', 'patterns'];
var _0x5678 = '\x54\x45\x53\x54\x3a\x20\x48\x65\x78\x20\x65\x6e\x63\x6f\x64\x65\x64';
console.log(_0x5678);

// Pattern 2: Unicode escape sequences
var _unicode = '\u0054\u0045\u0053\u0054\u003a\u0020\u0055\u006e\u0069\u0063\u006f\u0064\u0065';
console.log(_unicode);

// Pattern 3: Heavily minified variable names
var a=function(b,c){return b+c},d=function(e){return e*2},f=function(g){return g.split('')},h=['test','data','array'];

// Pattern 4: String concatenation obfuscation
var _str1 = 'con' + 'sole' + '.' + 'log';
var _str2 = 'TEST: ' + 'Obf' + 'usc' + 'ated ' + 'str' + 'ing';
window[_str1](_str2);

// Pattern 5: Base64 encoded strings
var _base64 = 'VEVTVDogQmFzZTY0IGVuY29kZWQgc3RyaW5n';
var _decoded = atob(_base64);
console.log(_decoded);

// Pattern 6: Array access obfuscation
var _0xabcd = ['log', 'TEST: Array access obfuscation'];
console[_0xabcd[0]](_0xabcd[1]);

// Pattern 7: Property access via brackets
var _obj = {};
_obj['prop' + 'erty'] = 'TEST: Dynamic property access';
console['l' + 'og'](_obj['prop' + 'erty']);

// Pattern 8: Function name obfuscation
var _0xef12 = function() {
    var _0x3456 = 'TEST: Obfuscated function';
    return _0x3456;
};

// Pattern 9: Complex string building
var _parts = ['T', 'E', 'S', 'T', ':', ' ', 'C', 'o', 'm', 'p', 'l', 'e', 'x'];
var _result = _parts.join('') + ' string building';
console.log(_result);

// Pattern 10: Eval-like obfuscation (without actual eval)
var _func = 'console.log("TEST: Function-like string")';
// Note: Not actually calling eval here, just the pattern

chrome.runtime.onInstalled.addListener(() => {
    var _msg = _0x1234[0] + ': ' + _0x1234[1] + ' extension installed';
    console.log(_msg);
    
    // Execute obfuscated functions
    console.log(_0xef12());
});
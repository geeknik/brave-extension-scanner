// TEST EXTENSION: Heavily obfuscated content script
// This simulates what heavily obfuscated malicious code might look like

!function(){var _0x1234=['TEST','obfuscated','content','script','loaded'],_0x5678=function(a,b){return a+b},_0x9abc=function(c){return c['split']('')},_0xdef0=function(){var d=_0x1234[0x0]+': '+_0x1234[0x1]+' '+_0x1234[0x2]+' '+_0x1234[0x3]+' '+_0x1234[0x4];console['log'](d)};_0xdef0()}();

// More obfuscation patterns
var _=function(s){return s},__=function(a,b,c){return a[b](c)},___=console;___[_('log')](_('TEST: Triple underscore obfuscation'));

// Hexadecimal encoding
var _hex='\x54\x45\x53\x54\x3a\x20\x48\x65\x78\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x20\x69\x6e\x20\x63\x6f\x6e\x74\x65\x6e\x74\x20\x73\x63\x72\x69\x70\x74';console.log(_hex);

// Unicode escape sequences in an array-like structure
var _unicode_arr=['\u0054\u0045\u0053\u0054','\u0020\u006f\u0062\u0066\u0075\u0073\u0063\u0061\u0074\u0065\u0064','\u0020\u0075\u006e\u0069\u0063\u006f\u0064\u0065'];console.log(_unicode_arr.join(''));

// Simulated packed/minified code structure
(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+c+'\\b','g'),k[c])}}return p}('4 3="2: 1 0 5";6.7(3);',8,8,'code|packed|TEST|msg|var|structure|console|log'.split('|')));

// Pattern with computed property names
var _computed={};_computed['prop'+'erty']='TEST: Computed properties';_computed[String.fromCharCode(116,101,115,116)]='character codes';console.log(_computed.property,_computed.test);

// Base64 with additional obfuscation
var _b64data=['VEVTVDog','QmFzZTY0','IG9iZnVzY2F0aW9u'];var _combined=_b64data.map(function(x){return atob(x)}).join('');console.log(_combined);

// Array of functions for execution
var _funcs=[function(){return 'TEST'},function(){return ': Array'},function(){return ' of'},function(){return ' functions'}];console.log(_funcs.map(function(f){return f()}).join(''));

// Self-executing function with parameters
(function($,_,$_){var __$=$+'';var $_$=__$.charAt(0);console.log($_$+$_+$_$+'T: IIFE obfuscation');})(1,2,3);

// Complex string manipulation
var _chars=[84,69,83,84,58,32,67,104,97,114,32,99,111,100,101,115];var _str=String.fromCharCode.apply(null,_chars);console.log(_str);

// Nested ternary operations
var _x=1,_y=2,_z=3;var _result=(_x>0?(_y>1?(_z>2?'TEST: Nested ternary':'no'):'no'):'no');console.log(_result);

// Document ready with obfuscated event listener
if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',function(){var _msg=String.fromCharCode(84,69,83,84)+': '+'DOM ready with obfuscation';console.log(_msg)});}else{console.log('TEST: Already loaded');}

// Timeout with encoded function
setTimeout(function(){var _delayed=[0x54,0x45,0x53,0x54,0x3a,0x20,0x44,0x65,0x6c,0x61,0x79,0x65,0x64];console.log(String.fromCharCode.apply(null,_delayed));},100);
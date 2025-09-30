/**
 * Tests for HeuristicAnalyzer
 */

import HeuristicAnalyzer from '../../src/analyzers/heuristic-analyzer.js';

describe('HeuristicAnalyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new HeuristicAnalyzer();
  });

  describe('constructor', () => {
    test('should initialize with correct heuristic weights', () => {
      expect(analyzer.heuristicWeights).toBeDefined();
      expect(analyzer.heuristicWeights.dangerousPermissions).toBe(20);
      expect(analyzer.heuristicWeights.keylogging).toBe(40);
      expect(analyzer.heuristicWeights.c2Communication).toBe(35);
      expect(analyzer.heuristicWeights.dynamicCodeExecution).toBe(35);
    });
  });

  describe('analyze', () => {
    test('should return zero score for empty analysis results', () => {
      const results = analyzer.analyze({});
      
      expect(results.heuristicScore).toBe(0);
      expect(results.detectedHeuristics).toEqual([]);
    });

    test('should detect dangerous permissions', () => {
      const analysisResults = {
        manifestAnalysis: {
          permissions: {
            dangerous: {
              count: 2,
              permissions: ['tabs', 'cookies']
            }
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(40); // 2 * 20
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('dangerousPermissions');
      expect(results.detectedHeuristics[0].count).toBe(2);
    });

    test('should detect broad host permissions', () => {
      const analysisResults = {
        manifestAnalysis: {
          hostPermissions: {
            broad: {
              count: 1,
              permissions: ['<all_urls>']
            }
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(15); // 1 * 15
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('broadHostPermissions');
    });

    test('should detect suspicious content scripts', () => {
      const analysisResults = {
        manifestAnalysis: {
          contentScripts: {
            suspicious: {
              count: 1
            }
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(25); // 1 * 25
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('suspiciousContentScripts');
    });

    test('should detect high obfuscation', () => {
      const analysisResults = {
        obfuscationAnalysis: {
          obfuscationDetected: true,
          obfuscationScore: 75
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(30); // High obfuscation weight
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('highObfuscation');
    });

    test('should detect dynamic code execution', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            evalUsage: [
              { type: 'eval', match: 'eval("code")' },
              { type: 'newFunction', match: 'new Function("code")' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(70); // 2 * 35
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('dynamicCodeExecution');
    });

    test('should detect remote code loading', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            remoteCodeLoading: [
              { type: 'fetch', match: 'fetch("script.js")' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(30); // 1 * 30
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('remoteCodeLoading');
    });

    test('should detect keylogging', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            keylogging: [
              { type: 'keydown', match: 'addEventListener("keydown")' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(40); // 1 * 40
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('keylogging');
    });

    test('should detect data exfiltration', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            dataExfiltration: [
              { type: 'fetch', match: 'fetch("steal-data.com")' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(30); // 1 * 30
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('dataExfiltration');
    });

    test('should detect fingerprinting', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            fingerprinting: [
              { type: 'navigator', match: 'navigator.userAgent' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(10); // 1 * 10
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('fingerprinting');
    });

    test('should detect anti-debugging', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            malware: [
              { type: 'debuggerStatement', match: 'debugger;' },
              { type: 'consoleClear', match: 'console.clear()' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(25); // Anti-debugging weight
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('antiDebugging');
    });

    test('should detect persistence mechanisms', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            malware: [
              { type: 'storageAccess', match: 'localStorage.setItem' },
              { type: 'chromeStorage', match: 'chrome.storage.local' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(15); // Persistence mechanisms weight
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('persistenceMechanisms');
    });

    test('should detect environment detection', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            behavioral: [
              { type: 'chromeDetection', match: 'window.chrome' },
              { type: 'webdriverDetection', match: 'navigator.webdriver' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(10); // Environment detection weight
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('environmentDetection');
    });

    test('should detect long delays', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            behavioral: [
              { type: 'longTimeout', match: 'setTimeout(..., 30000)' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(5); // Long delays weight
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('longDelays');
    });

    test('should detect suspicious network endpoints', () => {
      const analysisResults = {
        networkAnalysis: {
          endpoints: {
            suspicious: [
              { domain: 'evil.com', reason: 'Known malicious domain' },
              { domain: 'steal-data.com', reason: 'Suspicious domain' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(40); // 2 * 20
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('suspiciousNetworkEndpoints');
    });

    test('should detect bulk requests', () => {
      const analysisResults = {
        networkAnalysis: {
          behaviorAnalysis: {
            bulkRequests: [
              { type: 'bulk', match: 'Multiple fetch calls' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(20); // 1 * 20
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('bulkRequests');
    });

    test('should detect stealth requests', () => {
      const analysisResults = {
        networkAnalysis: {
          behaviorAnalysis: {
            stealthRequests: [
              { type: 'stealth', match: 'Hidden network request' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(15); // 1 * 15
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('stealthRequests');
    });

    test('should detect C2 communication', () => {
      const analysisResults = {
        networkAnalysis: {
          behaviorAnalysis: {
            c2Communication: [
              { type: 'c2', match: 'Command and control communication' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(35); // 1 * 35
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('c2Communication');
    });

    test('should detect evasion techniques', () => {
      const analysisResults = {
        networkAnalysis: {
          behaviorAnalysis: {
            evasionTechniques: [
              { type: 'evasion', match: 'Network evasion technique' }
            ]
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(20); // 1 * 20
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('evasionTechniques');
    });

    test('should detect suspicious file names', () => {
      const analysisResults = {
        manifestAnalysis: {
          suspiciousFileNames: ['keylogger.js', 'steal.js']
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(20); // 2 * 10
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('suspiciousFileNames');
    });

    test('should detect unreadable files', () => {
      const analysisResults = {
        staticAnalysis: {
          suspiciousPatterns: [
            {
              category: 'Unpacked Extension Analysis',
              description: 'Cannot read JavaScript files due to browser security'
            }
          ]
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(15); // Unreadable files weight
      expect(results.detectedHeuristics).toHaveLength(1);
      expect(results.detectedHeuristics[0].type).toBe('unreadableFiles');
    });

    test('should combine multiple indicators', () => {
      const analysisResults = {
        manifestAnalysis: {
          permissions: {
            dangerous: {
              count: 1,
              permissions: ['tabs']
            }
          }
        },
        staticAnalysis: {
          results: {
            keylogging: [
              { type: 'keydown', match: 'addEventListener("keydown")' }
            ],
            dataExfiltration: [
              { type: 'fetch', match: 'fetch("steal.com")' }
            ]
          }
        },
        obfuscationAnalysis: {
          obfuscationDetected: true,
          obfuscationScore: 60
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      // 20 (dangerous permissions) + 40 (keylogging) + 30 (data exfiltration) + 30 (high obfuscation) = 120, capped at 100
      expect(results.heuristicScore).toBe(100);
      expect(results.detectedHeuristics).toHaveLength(4);
    });

    test('should cap score at 100', () => {
      const analysisResults = {
        manifestAnalysis: {
          permissions: {
            dangerous: {
              count: 10, // 10 * 20 = 200
              permissions: ['tabs', 'cookies', 'storage', 'webRequest', 'webRequestBlocking', 'tabs', 'cookies', 'storage', 'webRequest', 'webRequestBlocking']
            }
          }
        }
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(100); // Capped at 100
    });

    test('should handle missing analysis results gracefully', () => {
      const analysisResults = {
        manifestAnalysis: null,
        staticAnalysis: undefined,
        obfuscationAnalysis: {},
        networkAnalysis: null
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(0);
      expect(results.detectedHeuristics).toEqual([]);
    });

    test('should handle partial analysis results', () => {
      const analysisResults = {
        manifestAnalysis: {
          permissions: {
            dangerous: {
              count: 1,
              permissions: ['tabs']
            }
          }
        }
        // Missing other analysis results
      };

      const results = analyzer.analyze(analysisResults);
      
      expect(results.heuristicScore).toBe(20); // Only dangerous permissions detected
      expect(results.detectedHeuristics).toHaveLength(1);
    });
  });

  describe('analyzeCode (legacy method)', () => {
    test('should handle empty code', () => {
      const results = analyzer.analyzeCode('');
      expect(results.heuristicScore).toBe(0);
      expect(results.threatLevel).toBe('safe');
    });

    test('should handle invalid input', () => {
      expect(() => analyzer.analyzeCode(null)).toThrow('Code must be a string');
      expect(() => analyzer.analyzeCode(123)).toThrow('Code must be a string');
    });

    test('should analyze simple code', () => {
      const code = 'console.log("hello");';
      const results = analyzer.analyzeCode(code);
      expect(results.heuristicScore).toBeDefined();
      expect(results.threatLevel).toBeDefined();
      expect(results.indicators).toBeDefined();
    });
  });

  describe('analyzeComplexity', () => {
    test('should analyze code complexity', () => {
      const code = `
        function complexFunction() {
          for (let i = 0; i < 100; i++) {
            if (i % 2 === 0) {
              console.log(i);
            }
          }
        }
      `;
      const results = analyzer.analyzeComplexity(code);
      expect(results.score).toBeDefined();
      expect(results.indicators).toBeDefined();
    });
  });

  describe('analyzeBehavior', () => {
    test('should analyze behavioral patterns', () => {
      const code = `
        setTimeout(() => {
          fetch('https://example.com');
        }, 1000);
      `;
      const results = analyzer.analyzeBehavior(code);
      expect(results.score).toBeDefined();
      expect(results.indicators).toBeDefined();
    });
  });

  describe('analyzeStatistics', () => {
    test('should analyze statistical patterns', () => {
      const code = 'var a = "hello"; var b = "world";';
      const results = analyzer.analyzeStatistics(code);
      expect(results.score).toBeDefined();
      expect(results.indicators).toBeDefined();
      expect(results.statistics).toBeDefined();
    });
  });

  describe('analyzeContext', () => {
    test('should analyze contextual patterns', () => {
      const code = 'chrome.tabs.query({}, () => {});';
      const manifest = { permissions: ['tabs'] };
      const context = { permissions: ['tabs'] };
      const results = analyzer.analyzeContext(code, manifest, context);
      expect(results.score).toBeDefined();
      expect(results.indicators).toBeDefined();
    });
  });

  describe('calculateEntropy', () => {
    test('should calculate entropy for text', () => {
      const entropy = analyzer.calculateEntropy('hello world');
      expect(typeof entropy).toBe('number');
      expect(entropy).toBeGreaterThan(0);
    });

    test('should handle empty string', () => {
      const entropy = analyzer.calculateEntropy('');
      expect(entropy).toBe(0);
    });
  });

  describe('analyzeCharacterFrequency', () => {
    test('should analyze character frequency', () => {
      const code = 'var a = "hello";';
      const results = analyzer.analyzeCharacterFrequency(code);
      expect(results.frequencies).toBeDefined();
      expect(results.anomalyScore).toBeDefined();
    });
  });

  describe('analyzeCodeDistribution', () => {
    test('should analyze code distribution', () => {
      const code = `
        function test() {
          var x = 1;
          return x;
        }
      `;
      const results = analyzer.analyzeCodeDistribution(code);
      expect(results.distribution).toBeDefined();
      expect(results.distribution.functions).toBeDefined();
      expect(results.distribution.variables).toBeDefined();
      expect(results.anomalyScore).toBeDefined();
    });
  });
});

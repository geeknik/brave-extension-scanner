/**
 * Threat Classifier Tests
 * Tests the classification of threats based on combined analysis results
 */

import ThreatClassifier from '../../src/analyzers/threat-classifier.js';

describe('ThreatClassifier', () => {
  let classifier;

  beforeEach(() => {
    classifier = new ThreatClassifier();
  });

  describe('calculateOverallScore', () => {
    test('should calculate weighted score correctly', () => {
      const manifestScore = 60;
      const staticScore = 80;
      const obfuscationScore = 40;
      const networkScore = 20;
      
      // Expected: (60 * 0.25) + (80 * 0.35) + (40 * 0.20) + (20 * 0.20) = 15 + 28 + 8 + 4 = 55
      const score = classifier.calculateOverallScore(manifestScore, staticScore, obfuscationScore, networkScore);
      
      expect(score).toBe(55);
    });

    test('should cap score at 100', () => {
      const manifestScore = 100;
      const staticScore = 100;
      const obfuscationScore = 100;
      const networkScore = 100;
      
      const score = classifier.calculateOverallScore(manifestScore, staticScore, obfuscationScore, networkScore);
      
      expect(score).toBe(100);
    });

    test('should handle zero scores', () => {
      const manifestScore = 0;
      const staticScore = 0;
      const obfuscationScore = 0;
      const networkScore = 0;
      
      const score = classifier.calculateOverallScore(manifestScore, staticScore, obfuscationScore, networkScore);
      
      expect(score).toBe(0);
    });
  });

  describe('determineThreatLevel', () => {
    test('should classify as critical for high scores', () => {
      expect(classifier.determineThreatLevel(100)).toBe('critical');
      expect(classifier.determineThreatLevel(85)).toBe('critical');
      expect(classifier.determineThreatLevel(80)).toBe('critical');
    });

    test('should classify as high for moderately high scores', () => {
      expect(classifier.determineThreatLevel(79)).toBe('high');
      expect(classifier.determineThreatLevel(70)).toBe('high');
      expect(classifier.determineThreatLevel(60)).toBe('high');
    });

    test('should classify as medium for moderate scores', () => {
      expect(classifier.determineThreatLevel(59)).toBe('medium');
      expect(classifier.determineThreatLevel(50)).toBe('medium');
      expect(classifier.determineThreatLevel(40)).toBe('medium');
    });

    test('should classify as low for low scores', () => {
      expect(classifier.determineThreatLevel(39)).toBe('low');
      expect(classifier.determineThreatLevel(30)).toBe('low');
      expect(classifier.determineThreatLevel(20)).toBe('low');
    });

    test('should classify as safe for very low scores', () => {
      expect(classifier.determineThreatLevel(19)).toBe('safe');
      expect(classifier.determineThreatLevel(10)).toBe('safe');
      expect(classifier.determineThreatLevel(0)).toBe('safe');
    });
  });

  describe('hasDataTheftIndicators', () => {
    test('should detect cookie access', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            cookieAccess: [
              { match: 'document.cookie' }
            ],
            dataExfiltration: []
          }
        }
      };
      
      expect(classifier.hasDataTheftIndicators(analysisResults)).toBe(true);
    });

    test('should detect data exfiltration', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            cookieAccess: [],
            dataExfiltration: [
              { match: 'chrome.history.search' }
            ]
          }
        }
      };
      
      expect(classifier.hasDataTheftIndicators(analysisResults)).toBe(true);
    });

    test('should return false when no indicators are present', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            cookieAccess: [],
            dataExfiltration: []
          }
        }
      };
      
      expect(classifier.hasDataTheftIndicators(analysisResults)).toBe(false);
    });

    test('should handle missing results', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {}
        }
      };
      
      expect(classifier.hasDataTheftIndicators(analysisResults)).toBe(false);
    });
  });

  describe('hasPrivacyInvasionIndicators', () => {
    test('should detect fingerprinting', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            fingerprinting: [
              { match: 'navigator.userAgent' }
            ]
          }
        }
      };
      
      expect(classifier.hasPrivacyInvasionIndicators(analysisResults)).toBe(true);
    });

    test('should detect privacy-sensitive permissions', () => {
      const analysisResults = {
        manifestAnalysis: {
          permissions: {
            dangerous: {
              permissions: ['history', 'webRequest']
            }
          }
        }
      };
      
      expect(classifier.hasPrivacyInvasionIndicators(analysisResults)).toBe(true);
    });

    test('should return false when no indicators are present', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            fingerprinting: []
          }
        },
        manifestAnalysis: {
          permissions: {
            dangerous: {
              permissions: ['storage']
            }
          }
        }
      };
      
      expect(classifier.hasPrivacyInvasionIndicators(analysisResults)).toBe(false);
    });
  });

  describe('hasCodeExecutionIndicators', () => {
    test('should detect eval usage', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            evalUsage: [
              { match: 'eval("alert(1)")' }
            ],
            remoteCodeLoading: []
          }
        }
      };
      
      expect(classifier.hasCodeExecutionIndicators(analysisResults)).toBe(true);
    });

    test('should detect remote code loading', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            evalUsage: [],
            remoteCodeLoading: [
              { match: 'document.createElement("script")' }
            ]
          }
        }
      };
      
      expect(classifier.hasCodeExecutionIndicators(analysisResults)).toBe(true);
    });

    test('should return false when no indicators are present', () => {
      const analysisResults = {
        staticAnalysis: {
          results: {
            evalUsage: [],
            remoteCodeLoading: []
          }
        }
      };
      
      expect(classifier.hasCodeExecutionIndicators(analysisResults)).toBe(false);
    });
  });

  describe('hasExcessivePermissions', () => {
    test('should detect many dangerous permissions', () => {
      const analysisResults = {
        manifestAnalysis: {
          permissions: {
            dangerous: {
              count: 3
            },
            critical: {
              count: 0
            }
          }
        }
      };
      
      expect(classifier.hasExcessivePermissions(analysisResults)).toBe(true);
    });

    test('should detect critical permissions', () => {
      const analysisResults = {
        manifestAnalysis: {
          permissions: {
            dangerous: {
              count: 1
            },
            critical: {
              count: 1
            }
          }
        }
      };
      
      expect(classifier.hasExcessivePermissions(analysisResults)).toBe(true);
    });

    test('should return false for reasonable permissions', () => {
      const analysisResults = {
        manifestAnalysis: {
          permissions: {
            dangerous: {
              count: 1
            },
            critical: {
              count: 0
            }
          }
        }
      };
      
      expect(classifier.hasExcessivePermissions(analysisResults)).toBe(false);
    });
  });

  describe('hasObfuscation', () => {
    test('should detect obfuscation', () => {
      const analysisResults = {
        obfuscationAnalysis: {
          obfuscationDetected: true,
          obfuscationScore: 75
        }
      };
      
      expect(classifier.hasObfuscation(analysisResults)).toBe(true);
    });

    test('should return false when no obfuscation is detected', () => {
      const analysisResults = {
        obfuscationAnalysis: {
          obfuscationDetected: false,
          obfuscationScore: 30
        }
      };
      
      expect(classifier.hasObfuscation(analysisResults)).toBe(false);
    });
  });

  describe('hasNetworkAbuse', () => {
    test('should detect suspicious domains', () => {
      const analysisResults = {
        networkAnalysis: {
          suspiciousDomains: ['evil.com'],
          suspiciousIpAddresses: []
        }
      };
      expect(classifier.hasNetworkAbuse(analysisResults)).toBe(true);
    });

    test('should detect suspicious IP addresses', () => {
      const analysisResults = {
        networkAnalysis: {
          suspiciousDomains: [],
          suspiciousIpAddresses: ['1.2.3.4']
        }
      };
      
      expect(classifier.hasNetworkAbuse(analysisResults)).toBe(true);
    });

    test('should return false when no network abuse is detected', () => {
      const analysisResults = {
        networkAnalysis: {
          suspiciousDomains: [],
          suspiciousIpAddresses: []
        }
      };
      
      expect(classifier.hasNetworkAbuse(analysisResults)).toBe(false);
    });

    test('should handle missing results', () => {
      const analysisResults = {
        networkAnalysis: {}
      };
      
      expect(classifier.hasNetworkAbuse(analysisResults)).toBe(false);
    });
  });

  describe('getCategorySeverity', () => {
    test('should determine data theft severity correctly', () => {
      // High severity
      let analysisResults = { staticAnalysis: { results: { cookieAccess: [{}, {}, {}] } } };
      expect(classifier.getCategorySeverity(analysisResults, 'dataTheft')).toBe('high');
      
      // Medium severity
      analysisResults = { staticAnalysis: { results: { cookieAccess: [{}] } } };
      expect(classifier.getCategorySeverity(analysisResults, 'dataTheft')).toBe('medium');
      
      // Low severity
      analysisResults = { staticAnalysis: { results: {} } };
      expect(classifier.getCategorySeverity(analysisResults, 'dataTheft')).toBe('low');
    });

    test('should determine code execution severity correctly', () => {
      // High severity
      let analysisResults = { staticAnalysis: { results: { remoteCodeLoading: [{}] } } };
      expect(classifier.getCategorySeverity(analysisResults, 'codeExecution')).toBe('high');
      
      // Medium severity
      analysisResults = { staticAnalysis: { results: { evalUsage: [{}, {}] } } };
      expect(classifier.getCategorySeverity(analysisResults, 'codeExecution')).toBe('medium');

      // Low severity
      analysisResults = { staticAnalysis: { results: { evalUsage: [{}] } } };
      expect(classifier.getCategorySeverity(analysisResults, 'codeExecution')).toBe('low');
    });

    test('should determine network abuse severity correctly', () => {
      // High severity
      let analysisResults = { networkAnalysis: { endpoints: { suspicious: [{}, {}, {}, {}] } } };
      expect(classifier.getCategorySeverity(analysisResults, 'networkAbuse')).toBe('high');

      // Medium severity
      analysisResults = { networkAnalysis: { endpoints: { suspicious: [{}] } } };
      expect(classifier.getCategorySeverity(analysisResults, 'networkAbuse')).toBe('medium');

      // Low severity
      analysisResults = { networkAnalysis: { endpoints: {} } };
      expect(classifier.getCategorySeverity(analysisResults, 'networkAbuse')).toBe('low');
    });
  });

  describe('generateSummary', () => {
    test('should generate summary for critical threat', () => {
      const summary = classifier.generateSummary('critical', [ { name: 'Data Theft' } ]);
      expect(summary).toContain('critical threat level');
      expect(summary).toContain('Data Theft');
    });

    test('should generate summary for safe threat', () => {
      const summary = classifier.generateSummary('safe', []);
      expect(summary).toContain('appears to be safe');
    });

    test('should handle empty categories', () => {
      const summary = classifier.generateSummary('medium', []);
      expect(summary).toContain('medium threat level');
      if (summary.includes('Key areas of concern')) {
        expect(summary).toContain('Key areas of concern');
      }
    });
  });

  describe('generateRecommendations', () => {
    test('should generate recommendations for critical threat', () => {
      const recs = classifier.generateRecommendations('critical', [], {});
      expect(recs.some(r => r.recommendation === 'Uninstall this extension immediately.')).toBe(true);
    });

    test('should generate recommendations for safe threat', () => {
      const recs = classifier.generateRecommendations('safe', [], {});
      expect(recs.some(r => r.recommendation === 'This extension appears safe to use.')).toBe(true);
    });

    test('should include specific recommendations for network abuse', () => {
      const analysisResults = { networkAnalysis: { suspiciousDomains: ['evil.com'] } };
      const categories = classifier.identifyThreatCategories(analysisResults);
      const recs = classifier.generateRecommendations('high', categories, analysisResults);
      expect(recs.some(r => r.recommendation.includes('evil.com'))).toBe(true);
    });

    test('should include specific recommendations for excessive permissions', () => {
      const analysisResults = { 
        manifestAnalysis: { 
          permissions: { 
            dangerous: { permissions: ['tabs', 'cookies'], count: 3 }, 
            critical: { count: 1, permissions: ['debugger'] } 
          } 
        } 
      };
      const categories = classifier.identifyThreatCategories(analysisResults);
      const recs = classifier.generateRecommendations('high', categories, analysisResults);
      expect(recs.some(r => r.recommendation.includes('Review the permissions requested'))).toBe(true);
    });
  });

  describe('classifyThreat integration', () => {
    test('should classify benign extension correctly', () => {
      const analysisResults = {
        manifestAnalysis: { riskScore: 10 },
        staticAnalysis: { riskScore: 0 },
        obfuscationAnalysis: { obfuscationScore: 0 },
        networkAnalysis: { riskScore: 0 }
      };
      const classification = classifier.classifyThreat(analysisResults);
      expect(classification.level).toBe('safe');
      expect(classification.score).toBeLessThan(20);
    });

    test('should classify malicious extension correctly', async () => {
      const analysisResults = {
        manifestAnalysis: { 
          riskScore: 70, 
          permissions: { 
            dangerous: { 
              count: 3,
              permissions: ['tabs', 'cookies', '<all_urls>'] 
            }, 
            critical: { 
              count: 1,
              permissions: ['debugger']
            } 
          } 
        },
        staticAnalysis: { riskScore: 90, results: { remoteCodeLoading: [{}] } },
        obfuscationAnalysis: { obfuscationScore: 80 },
        networkAnalysis: { riskScore: 90, suspiciousDomains: ['evil.com'] }
      };
      const classification = classifier.classifyThreat(analysisResults);
      expect(classification.level).toBe('critical');
      expect(classification.score).toBeGreaterThan(80);
      expect(classification.summary).toContain('critical threat level');
      expect(classification.recommendations.some(r => r.recommendation === 'Uninstall this extension immediately.')).toBe(true);
    });

    test('should handle missing analysis results', () => {
      const classification = classifier.classifyThreat({});
      expect(classification.level).toBe('safe');
      expect(classification.score).toBe(0);
      expect(classification.summary).toContain('appears to be safe');
    });
  });
});
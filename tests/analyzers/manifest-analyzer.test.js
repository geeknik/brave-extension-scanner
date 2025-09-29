/**
 * Manifest Analyzer Tests
 * Tests the detection of dangerous permissions and suspicious configurations in extension manifests
 */

import ManifestAnalyzer from '../../src/analyzers/manifest-analyzer.js';

describe('ManifestAnalyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new ManifestAnalyzer();
  });

  describe('analyzePermissions', () => {
    test('should detect dangerous permissions', () => {
      const manifest = {
        permissions: ['tabs', 'cookies', '<all_urls>', 'storage']
      };
      
      const result = analyzer.analyzePermissions(manifest);
      
      expect(result.dangerous.count).toBe(3);
      expect(result.dangerous.permissions).toContain('tabs');
      expect(result.dangerous.permissions).toContain('cookies');
      expect(result.dangerous.permissions).toContain('<all_urls>');
      expect(result.moderate.count).toBe(1);
      expect(result.moderate.permissions).toContain('storage');
    });

    test('should detect critical permissions', () => {
      const manifest = {
        permissions: ['debugger', 'proxy', 'privacy']
      };
      
      const result = analyzer.analyzePermissions(manifest);
      
      expect(result.critical.count).toBe(3);
      expect(result.critical.permissions).toContain('debugger');
      expect(result.critical.permissions).toContain('proxy');
      expect(result.critical.permissions).toContain('privacy');
    });

    test('should handle optional permissions', () => {
      const manifest = {
        permissions: ['storage'],
        optional_permissions: ['tabs', 'cookies', 'debugger']
      };
      
      const result = analyzer.analyzePermissions(manifest);
      
      expect(result.dangerous.count).toBe(0);
      expect(result.critical.count).toBe(0);
      expect(result.moderate.count).toBe(1);
      expect(result.optional.dangerous).toHaveLength(2);
      expect(result.optional.dangerous).toContain('tabs');
      expect(result.optional.dangerous).toContain('cookies');
      expect(result.optional.critical).toHaveLength(1);
      expect(result.optional.critical).toContain('debugger');
    });

    test('should handle missing permissions', () => {
      const manifest = {};
      
      const result = analyzer.analyzePermissions(manifest);
      
      expect(result.total).toBe(0);
      expect(result.dangerous.count).toBe(0);
      expect(result.critical.count).toBe(0);
      expect(result.moderate.count).toBe(0);
    });
  });

  describe('analyzeContentScripts', () => {
    test('should detect broad match content scripts', () => {
      const manifest = {
        content_scripts: [
          {
            matches: ['<all_urls>'],
            js: ['content.js'],
            run_at: 'document_idle'
          },
          {
            matches: ['https://example.com/*'],
            js: ['specific.js'],
            run_at: 'document_end'
          }
        ]
      };
      
      const result = analyzer.analyzeContentScripts(manifest);
      
      expect(result.count).toBe(2);
      expect(result.broadMatchCount).toBe(1);
      expect(result.documentStartCount).toBe(0);
      expect(result.riskLevel).toBe('medium');
    });

    test('should detect document_start content scripts', () => {
      const manifest = {
        content_scripts: [
          {
            matches: ['https://example.com/*'],
            js: ['early.js'],
            run_at: 'document_start'
          }
        ]
      };
      
      const result = analyzer.analyzeContentScripts(manifest);
      
      expect(result.count).toBe(1);
      expect(result.broadMatchCount).toBe(0);
      expect(result.documentStartCount).toBe(1);
      expect(result.riskLevel).toBe('medium');
    });

    test('should detect high risk content scripts', () => {
      const manifest = {
        content_scripts: [
          {
            matches: ['<all_urls>'],
            js: ['early.js'],
            run_at: 'document_start'
          }
        ]
      };
      
      const result = analyzer.analyzeContentScripts(manifest);
      
      expect(result.count).toBe(1);
      expect(result.broadMatchCount).toBe(1);
      expect(result.documentStartCount).toBe(1);
      expect(result.riskLevel).toBe('high');
    });

    test('should handle missing content scripts', () => {
      const manifest = {};
      
      const result = analyzer.analyzeContentScripts(manifest);
      
      expect(result.count).toBe(0);
      expect(result.broadMatchCount).toBe(0);
      expect(result.documentStartCount).toBe(0);
      expect(result.riskLevel).toBe('low');
    });
  });

  describe('analyzeCSP', () => {
    test('should detect suspicious CSP directives', () => {
      const manifest = {
        content_security_policy: "script-src 'self' 'unsafe-eval'; object-src 'self'"
      };
      
      const result = analyzer.analyzeCSP(manifest);
      
      expect(result.hasSuspiciousDirectives).toBe(true);
      expect(result.suspiciousDirectives).toContain('unsafe-eval');
    });

    test('should detect multiple suspicious CSP directives', () => {
      const manifest = {
        content_security_policy: "script-src 'self' 'unsafe-eval' 'unsafe-inline' data:; object-src 'self'"
      };
      
      const result = analyzer.analyzeCSP(manifest);
      
      expect(result.hasSuspiciousDirectives).toBe(true);
      expect(result.suspiciousDirectives).toHaveLength(3);
      expect(result.suspiciousDirectives).toContain('unsafe-eval');
      expect(result.suspiciousDirectives).toContain('unsafe-inline');
      expect(result.suspiciousDirectives).toContain('data:');
    });

    test('should handle safe CSP', () => {
      const manifest = {
        content_security_policy: "script-src 'self'; object-src 'self'"
      };
      
      const result = analyzer.analyzeCSP(manifest);
      
      expect(result.hasSuspiciousDirectives).toBe(false);
      expect(result.suspiciousDirectives).toHaveLength(0);
    });

    test('should handle missing CSP', () => {
      const manifest = {};
      
      const result = analyzer.analyzeCSP(manifest);
      
      expect(result.hasSuspiciousDirectives).toBe(false);
      expect(result.suspiciousDirectives).toHaveLength(0);
      expect(result.policy).toBe('');
    });
  });

  describe('analyzeExternalConnections', () => {
    test('should detect broad external connections', () => {
      const manifest = {
        externally_connectable: {
          matches: ['*://*/*'],
          accepts_tls_channel_id: true
        }
      };
      
      const result = analyzer.analyzeExternalConnections(manifest);
      
      expect(result.enabled).toBe(true);
      expect(result.matchCount).toBe(1);
      expect(result.broadMatchCount).toBe(1);
      expect(result.acceptsConnections).toBe(true);
      expect(result.riskLevel).toBe('high');
    });

    test('should detect wildcard domain connections', () => {
      const manifest = {
        externally_connectable: {
          matches: ['https://*.example.com/*']
        }
      };
      
      const result = analyzer.analyzeExternalConnections(manifest);
      
      expect(result.enabled).toBe(true);
      expect(result.matchCount).toBe(1);
      expect(result.broadMatchCount).toBe(1);
      expect(result.riskLevel).toBe('high');
    });

    test('should handle specific domain connections', () => {
      const manifest = {
        externally_connectable: {
          matches: ['https://example.com/*', 'https://api.example.com/*']
        }
      };
      
      const result = analyzer.analyzeExternalConnections(manifest);
      
      expect(result.enabled).toBe(true);
      expect(result.matchCount).toBe(2);
      expect(result.broadMatchCount).toBe(0);
      expect(result.riskLevel).toBe('medium');
    });

    test('should handle missing external connections', () => {
      const manifest = {};
      
      const result = analyzer.analyzeExternalConnections(manifest);
      
      expect(result.enabled).toBe(false);
      expect(result.matchCount).toBe(0);
      expect(result.broadMatchCount).toBe(0);
      expect(result.riskLevel).toBe('low');
    });
  });

  describe('checkBackgroundPersistence', () => {
    test('should detect persistent background in Manifest V2', () => {
      const manifest = {
        manifest_version: 2,
        background: {
          scripts: ['background.js'],
          persistent: true
        }
      };
      
      const result = analyzer.checkBackgroundPersistence(manifest);
      
      expect(result.persistent).toBe(true);
      expect(result.riskLevel).toBe('medium');
    });

    test('should handle non-persistent background in Manifest V2', () => {
      const manifest = {
        manifest_version: 2,
        background: {
          scripts: ['background.js'],
          persistent: false
        }
      };
      
      const result = analyzer.checkBackgroundPersistence(manifest);
      
      expect(result.persistent).toBe(false);
      expect(result.riskLevel).toBe('low');
    });

    test('should handle service worker in Manifest V3', () => {
      const manifest = {
        manifest_version: 3,
        background: {
          service_worker: 'background.js'
        }
      };
      
      const result = analyzer.checkBackgroundPersistence(manifest);
      
      expect(result.persistent).toBe(false);
      expect(result.riskLevel).toBe('low');
    });

    test('should handle missing background', () => {
      const manifest = {
        manifest_version: 2
      };
      
      const result = analyzer.checkBackgroundPersistence(manifest);
      
      expect(result.persistent).toBe(false);
      expect(result.riskLevel).toBe('low');
    });
  });

  describe('analyzeHostPermissions', () => {
    test('should detect broad host permissions in Manifest V2', () => {
      const manifest = {
        manifest_version: 2,
        permissions: ['<all_urls>', 'tabs']
      };
      
      const result = analyzer.analyzeHostPermissions(manifest);
      
      expect(result.count).toBe(1);
      expect(result.broadPermissionCount).toBe(1);
      expect(result.permissions).toContain('<all_urls>');
      expect(result.riskLevel).toBe('high');
    });

    test('should detect broad host permissions in Manifest V3', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['*://*/*']
      };
      
      const result = analyzer.analyzeHostPermissions(manifest);
      
      expect(result.count).toBe(1);
      expect(result.broadPermissionCount).toBe(1);
      expect(result.permissions).toContain('*://*/*');
      expect(result.riskLevel).toBe('high');
    });

    test('should handle multiple specific host permissions', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: [
          'https://example.com/*',
          'https://api.example.com/*',
          'https://cdn.example.com/*',
          'https://auth.example.com/*',
          'https://shop.example.com/*',
          'https://blog.example.com/*'
        ]
      };
      
      const result = analyzer.analyzeHostPermissions(manifest);
      
      expect(result.count).toBe(6);
      expect(result.broadPermissionCount).toBe(0);
      expect(result.riskLevel).toBe('medium');
    });

    test('should handle few specific host permissions', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: [
          'https://example.com/*',
          'https://api.example.com/*'
        ]
      };
      
      const result = analyzer.analyzeHostPermissions(manifest);
      
      expect(result.count).toBe(2);
      expect(result.broadPermissionCount).toBe(0);
      expect(result.riskLevel).toBe('low');
    });

    test('should handle missing host permissions', () => {
      const manifest = {
        manifest_version: 3
      };
      
      const result = analyzer.analyzeHostPermissions(manifest);
      
      expect(result.count).toBe(0);
      expect(result.broadPermissionCount).toBe(0);
      expect(result.riskLevel).toBe('low');
    });
  });

  describe('calculateRiskScore', () => {
    test('should calculate low risk score for benign manifest', () => {
      const results = {
        permissions: {
          dangerous: { count: 0 },
          critical: { count: 0 },
          moderate: { count: 1 }
        },
        contentScripts: {
          count: 1,
          broadMatchCount: 0,
          documentStartCount: 0
        },
        csp: {
          hasSuspiciousDirectives: false,
          suspiciousDirectives: []
        },
        externalConnections: {
          enabled: false,
          broadMatchCount: 0
        },
        backgroundPersistence: {
          persistent: false
        },
        hostPermissions: {
          count: 1,
          broadPermissionCount: 0
        }
      };
      
      const score = analyzer.calculateRiskScore(results);
      
      expect(score).toBeLessThan(20);
    });

    test('should calculate medium risk score for somewhat suspicious manifest', () => {
      const results = {
        permissions: {
          dangerous: { count: 1 },
          critical: { count: 0 },
          moderate: { count: 2 }
        },
        contentScripts: {
          count: 2,
          broadMatchCount: 0,
          documentStartCount: 1
        },
        csp: {
          hasSuspiciousDirectives: true,
          suspiciousDirectives: ['unsafe-eval']
        },
        externalConnections: {
          enabled: true,
          broadMatchCount: 0
        },
        backgroundPersistence: {
          persistent: false
        },
        hostPermissions: {
          count: 3,
          broadPermissionCount: 0
        }
      };
      
      const score = analyzer.calculateRiskScore(results);
      
      expect(score).toBeGreaterThan(20);
      expect(score).toBeLessThan(70);
    });

    test('should calculate high risk score for suspicious manifest', () => {
      const results = {
        permissions: {
          dangerous: { count: 2 },
          critical: { count: 1 },
          moderate: { count: 3 }
        },
        contentScripts: {
          count: 3,
          broadMatchCount: 1,
          documentStartCount: 2
        },
        csp: {
          hasSuspiciousDirectives: true,
          suspiciousDirectives: ['unsafe-eval', 'unsafe-inline', 'data:']
        },
        externalConnections: {
          enabled: true,
          broadMatchCount: 1
        },
        backgroundPersistence: {
          persistent: true
        },
        hostPermissions: {
          count: 2,
          broadPermissionCount: 1
        }
      };
      
      const score = analyzer.calculateRiskScore(results);
      
      expect(score).toBeGreaterThan(70);
    });

    test('should cap risk score at 100', () => {
      const results = {
        permissions: {
          dangerous: { count: 10 },
          critical: { count: 5 },
          moderate: { count: 5 }
        },
        contentScripts: {
          count: 10,
          broadMatchCount: 5,
          documentStartCount: 5
        },
        csp: {
          hasSuspiciousDirectives: true,
          suspiciousDirectives: ['unsafe-eval', 'unsafe-inline', 'data:', 'blob:', 'filesystem:']
        },
        externalConnections: {
          enabled: true,
          broadMatchCount: 5
        },
        backgroundPersistence: {
          persistent: true
        },
        hostPermissions: {
          count: 10,
          broadPermissionCount: 5
        }
      };
      
      const score = analyzer.calculateRiskScore(results);
      
      expect(score).toBe(100);
    });
  });

  describe('analyzeManifest integration', () => {
    test('should analyze benign manifest correctly', () => {
      const manifest = {
        manifest_version: 3,
        name: 'Benign Extension',
        version: '1.0.0',
        description: 'A harmless extension',
        permissions: ['storage', 'activeTab'],
        host_permissions: ['https://api.example.com/*'],
        content_scripts: [
          {
            matches: ['https://example.com/*'],
            js: ['content.js'],
            run_at: 'document_end'
          }
        ],
        background: {
          service_worker: 'background.js'
        },
        content_security_policy: "script-src 'self'; object-src 'self'"
      };
      
      const result = analyzer.analyzeManifest(manifest);
      
      expect(result.manifestVersion).toBe(3);
      expect(result.permissions.dangerous.count).toBe(0);
      expect(result.permissions.critical.count).toBe(0);
      expect(result.permissions.moderate.count).toBe(2);
      expect(result.contentScripts.riskLevel).toBe('low');
      expect(result.csp.hasSuspiciousDirectives).toBe(false);
      expect(result.externalConnections.riskLevel).toBe('low');
      expect(result.backgroundPersistence.persistent).toBe(false);
      expect(result.hostPermissions.riskLevel).toBe('low');
      expect(result.riskScore).toBeLessThan(30);
    });

    test('should analyze suspicious manifest correctly', () => {
      const manifest = {
        manifest_version: 2,
        name: 'Suspicious Extension',
        version: '1.0.0',
        description: 'An extension with suspicious permissions',
        permissions: ['tabs', 'cookies', '<all_urls>', 'webRequest', 'storage'],
        content_scripts: [
          {
            matches: ['<all_urls>'],
            js: ['content.js'],
            run_at: 'document_start'
          }
        ],
        background: {
          scripts: ['background.js'],
          persistent: true
        },
        content_security_policy: "script-src 'self' 'unsafe-eval' data:; object-src 'self'",
        externally_connectable: {
          matches: ['*://*/*'],
          accepts_tls_channel_id: true
        }
      };
      
      const result = analyzer.analyzeManifest(manifest);
      
      expect(result.manifestVersion).toBe(2);
      expect(result.permissions.dangerous.count).toBeGreaterThan(3);
      expect(result.contentScripts.riskLevel).toBe('high');
      expect(result.csp.hasSuspiciousDirectives).toBe(true);
      expect(result.csp.suspiciousDirectives.length).toBeGreaterThan(1);
      expect(result.externalConnections.riskLevel).toBe('high');
      expect(result.backgroundPersistence.persistent).toBe(true);
      expect(result.hostPermissions.riskLevel).toBe('high');
      expect(result.riskScore).toBeGreaterThan(70);
    });

    test('should handle invalid manifest', () => {
      const result = analyzer.analyzeManifest(null);
      
      expect(result.error).toBe('Invalid manifest: must be an object');
      expect(result.riskScore).toBe(100);
    });
  });
});
/**
 * CRX Analyzer Tests
 * Tests for downloading and analyzing CRX files from Chrome Web Store
 */

import CRXAnalyzer from '../../src/analyzers/crx-analyzer.js';

describe('CRXAnalyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new CRXAnalyzer();
  });

  afterEach(() => {
    analyzer.clearCache();
  });

  describe('constructor', () => {
    test('should initialize with empty cache', () => {
      expect(analyzer.downloadedCRXs).toBeInstanceOf(Map);
      expect(analyzer.analysisCache).toBeInstanceOf(Map);
      expect(analyzer.downloadedCRXs.size).toBe(0);
      expect(analyzer.analysisCache.size).toBe(0);
    });
  });

  describe('parseCRX', () => {
    test('should parse valid CRX3 file format', async () => {
      // Create a mock CRX3 file structure
      const mockCRXData = new ArrayBuffer(1000);
      const data = new Uint8Array(mockCRXData);
      
      // Set magic number 'Cr24'
      data[0] = 0x43; // 'C'
      data[1] = 0x72; // 'r'
      data[2] = 0x32; // '2'
      data[3] = 0x34; // '4'
      
      // Set version (3)
      data[4] = 3;
      data[5] = 0;
      data[6] = 0;
      data[7] = 0;
      
      // Set header size (0 for simplicity)
      data[8] = 0;
      data[9] = 0;
      data[10] = 0;
      data[11] = 0;
      
      // Add some ZIP-like data after header
      const zipData = new Uint8Array([0x50, 0x4B, 0x03, 0x04]); // ZIP signature
      data.set(zipData, 12);
      
      const result = await analyzer.parseCRX(mockCRXData);
      
      expect(result).toHaveProperty('zipData');
      expect(result).toHaveProperty('manifest');
      expect(result.zipData).toBeInstanceOf(ArrayBuffer);
    });

    test('should throw error for invalid magic number', async () => {
      const mockCRXData = new ArrayBuffer(100);
      const data = new Uint8Array(mockCRXData);
      
      // Set invalid magic number
      data[0] = 0x00;
      data[1] = 0x00;
      data[2] = 0x00;
      data[3] = 0x00;
      
      await expect(analyzer.parseCRX(mockCRXData)).rejects.toThrow('Invalid CRX file format');
    });

    test('should throw error for empty data', async () => {
      const emptyData = new ArrayBuffer(0);
      
      await expect(analyzer.parseCRX(emptyData)).rejects.toThrow();
    });

    test('should throw error for data too small', async () => {
      const smallData = new ArrayBuffer(3); // Less than 4 bytes for magic number
      
      await expect(analyzer.parseCRX(smallData)).rejects.toThrow();
    });
  });

  describe('detectFileType', () => {
    test('should detect JavaScript files', () => {
      expect(analyzer.detectFileType('script.js', 'function test() {}')).toBe('javascript');
      expect(analyzer.detectFileType('background.js', 'var x = 1;')).toBe('javascript');
    });

    test('should detect HTML files', () => {
      expect(analyzer.detectFileType('popup.html', '<html><body></body></html>')).toBe('html');
      expect(analyzer.detectFileType('index.html', '<!DOCTYPE html>')).toBe('html');
    });

    test('should detect CSS files', () => {
      expect(analyzer.detectFileType('style.css', '.class { color: red; }')).toBe('css');
    });

    test('should detect JSON files', () => {
      expect(analyzer.detectFileType('manifest.json', '{"name": "test"}')).toBe('json');
    });

    test('should detect images', () => {
      expect(analyzer.detectFileType('icon.png', 'binary data')).toBe('image');
      expect(analyzer.detectFileType('logo.jpg', 'binary data')).toBe('image');
      expect(analyzer.detectFileType('banner.svg', 'binary data')).toBe('image');
    });

    test('should detect fonts', () => {
      expect(analyzer.detectFileType('font.woff', 'binary data')).toBe('font');
      expect(analyzer.detectFileType('font.ttf', 'binary data')).toBe('font');
    });

    test('should detect by content when extension is unknown', () => {
      expect(analyzer.detectFileType('unknown', '<html><body></body></html>')).toBe('html');
      expect(analyzer.detectFileType('unknown', 'function test() { return true; }')).toBe('javascript');
      expect(analyzer.detectFileType('unknown', '{"key": "value"}')).toBe('json');
    });

    test('should return unknown for unrecognized content', () => {
      expect(analyzer.detectFileType('unknown', 'random binary data')).toBe('unknown');
    });
  });

  describe('analyzeJavaScriptFile', () => {
    test('should detect eval usage', () => {
      const file = {
        name: 'test.js',
        path: 'test.js',
        content: 'eval("alert(1)");'
      };
      
      const result = analyzer.analyzeJavaScriptFile(file);
      
      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.threats).toContainEqual(
        expect.objectContaining({
          type: 'eval',
          severity: 'high'
        })
      );
    });

    test('should detect keylogging patterns', () => {
      const file = {
        name: 'keylogger.js',
        path: 'keylogger.js',
        content: 'document.addEventListener("keydown", function(e) { console.log(e.key); });'
      };
      
      const result = analyzer.analyzeJavaScriptFile(file);
      
      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.threats).toContainEqual(
        expect.objectContaining({
          type: 'keylogging',
          severity: 'critical'
        })
      );
    });

    test('should detect network requests', () => {
      const file = {
        name: 'network.js',
        path: 'network.js',
        content: 'fetch("https://example.com/api");'
      };
      
      const result = analyzer.analyzeJavaScriptFile(file);
      
      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.threats).toContainEqual(
        expect.objectContaining({
          type: 'networkRequest',
          severity: 'medium'
        })
      );
    });

    test('should detect chrome API usage', () => {
      const file = {
        name: 'chrome.js',
        path: 'chrome.js',
        content: 'chrome.tabs.query({}, function(tabs) {});'
      };
      
      const result = analyzer.analyzeJavaScriptFile(file);
      
      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.threats).toContainEqual(
        expect.objectContaining({
          type: 'tabAccess',
          severity: 'medium'
        })
      );
    });

    test('should return zero risk for safe code', () => {
      const file = {
        name: 'safe.js',
        path: 'safe.js',
        content: 'console.log("Hello World");'
      };
      
      const result = analyzer.analyzeJavaScriptFile(file);
      
      expect(result.riskScore).toBe(0);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('analyzeManifest', () => {
    test('should detect dangerous permissions', () => {
      const manifest = {
        permissions: ['tabs', 'cookies', 'history']
      };
      
      const result = analyzer.analyzeManifest(manifest);
      
      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.threats).toContainEqual(
        expect.objectContaining({
          type: 'dangerousPermission',
          severity: 'high'
        })
      );
    });

    test('should detect broad host permissions', () => {
      const manifest = {
        host_permissions: ['<all_urls>']
      };
      
      const result = analyzer.analyzeManifest(manifest);
      
      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.threats).toContainEqual(
        expect.objectContaining({
          type: 'broadHostPermission',
          severity: 'critical'
        })
      );
    });

    test('should return zero risk for safe manifest', () => {
      const manifest = {
        permissions: ['storage']
      };
      
      const result = analyzer.analyzeManifest(manifest);
      
      expect(result.riskScore).toBe(0);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('calculateFileRiskScore', () => {
    test('should calculate correct risk scores', () => {
      const criticalThreats = [{ severity: 'critical' }];
      const highThreats = [{ severity: 'high' }];
      const mediumThreats = [{ severity: 'medium' }];
      const lowThreats = [{ severity: 'low' }];
      
      expect(analyzer.calculateFileRiskScore(criticalThreats)).toBe(25);
      expect(analyzer.calculateFileRiskScore(highThreats)).toBe(15);
      expect(analyzer.calculateFileRiskScore(mediumThreats)).toBe(10);
      expect(analyzer.calculateFileRiskScore(lowThreats)).toBe(5);
    });

    test('should cap risk score at 100', () => {
      const manyThreats = Array(10).fill({ severity: 'critical' });
      
      expect(analyzer.calculateFileRiskScore(manyThreats)).toBe(100);
    });

    test('should return 0 for empty threats', () => {
      expect(analyzer.calculateFileRiskScore([])).toBe(0);
    });
  });

  describe('calculateOverallRiskScore', () => {
    test('should calculate weighted risk score', () => {
      const analysis = {
        suspiciousFiles: [
          { riskScore: 50 }
        ],
        manifestAnalysis: {
          riskScore: 30
        }
      };
      
      const result = analyzer.calculateOverallRiskScore(analysis);
      
      // 50 * 0.3 + 30 * 0.7 = 15 + 21 = 36
      expect(result).toBe(36);
    });

    test('should handle missing manifest analysis', () => {
      const analysis = {
        suspiciousFiles: [
          { riskScore: 50 }
        ]
      };
      
      const result = analyzer.calculateOverallRiskScore(analysis);
      
      // 50 * 0.3 = 15
      expect(result).toBe(15);
    });

    test('should cap at 100', () => {
      const analysis = {
        suspiciousFiles: [
          { riskScore: 100 }
        ],
        manifestAnalysis: {
          riskScore: 100
        }
      };
      
      const result = analyzer.calculateOverallRiskScore(analysis);
      
      expect(result).toBe(100);
    });
  });

  describe('cache management', () => {
    test('should cache analysis results', () => {
      const extensionId = 'test123';
      const analysis = { riskScore: 50, files: [] };
      
      analyzer.analysisCache.set(extensionId, analysis);
      
      expect(analyzer.getCachedAnalysis(extensionId)).toEqual(analysis);
    });

    test('should return null for non-cached analysis', () => {
      expect(analyzer.getCachedAnalysis('nonexistent')).toBeNull();
    });

    test('should clear cache', () => {
      analyzer.analysisCache.set('test1', {});
      analyzer.analysisCache.set('test2', {});
      
      analyzer.clearCache();
      
      expect(analyzer.analysisCache.size).toBe(0);
      expect(analyzer.downloadedCRXs.size).toBe(0);
    });
  });

  describe('error handling', () => {
    test('should handle analyzeCRX errors gracefully', async () => {
      // Mock downloadCRX to throw an error
      jest.spyOn(analyzer, 'downloadCRX').mockRejectedValue(new Error('Download failed'));
      
      const result = await analyzer.analyzeCRX('test123');
      
      expect(result).toHaveProperty('error');
      expect(result.error).toBe('Download failed');
      expect(result.riskScore).toBe(0);
      expect(result.files).toEqual([]);
      expect(result.manifest).toBeNull();
    });

    test('should return cached result on second call', async () => {
      const extensionId = 'test123';
      const cachedResult = { riskScore: 50, files: [], manifest: {} };
      
      analyzer.analysisCache.set(extensionId, cachedResult);
      
      const result = await analyzer.analyzeCRX(extensionId);
      
      expect(result).toEqual(cachedResult);
    });
  });

  describe('downloadCRX', () => {
    beforeEach(() => {
      global.fetch = jest.fn();
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('should successfully download CRX file', async () => {
      const mockCRXData = new ArrayBuffer(1000);
      const data = new Uint8Array(mockCRXData);
      data[0] = 0x43; // 'C'
      data[1] = 0x72; // 'r'
      data[2] = 0x32; // '2'
      data[3] = 0x34; // '4'

      global.fetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => mockCRXData
      });

      const result = await analyzer.downloadCRX('test-extension-id');

      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(1000);
    });

    test('should retry with alternative URLs on HTTP error', async () => {
      const mockCRXData = new ArrayBuffer(1000);
      const data = new Uint8Array(mockCRXData);
      data[0] = 0x43;

      // First call fails with 404
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 404
      });

      // Second call succeeds
      global.fetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => mockCRXData
      });

      const result = await analyzer.downloadCRX('test-extension-id');

      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    test('should skip files that are too small', async () => {
      const smallData = new ArrayBuffer(5); // Less than 12 bytes

      global.fetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => smallData
      });

      const largeCRXData = new ArrayBuffer(1000);
      const data = new Uint8Array(largeCRXData);
      data[0] = 0x43;

      global.fetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => largeCRXData
      });

      const result = await analyzer.downloadCRX('test-extension-id');

      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(1000);
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    test('should skip HTML error pages', async () => {
      const htmlData = new TextEncoder().encode('<!DOCTYPE html><html><body>Error</body></html>');
      const htmlBuffer = htmlData.buffer;

      global.fetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => htmlBuffer
      });

      const validCRXData = new ArrayBuffer(1000);
      const data = new Uint8Array(validCRXData);
      data[0] = 0x43;

      global.fetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => validCRXData
      });

      const result = await analyzer.downloadCRX('test-extension-id');

      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(1000);
    });

    test('should throw error when all URLs fail', async () => {
      global.fetch.mockRejectedValue(new Error('Network error'));

      await expect(analyzer.downloadCRX('test-extension-id')).rejects.toThrow('All CRX download URLs failed');
    });

    test('should handle CORS errors', async () => {
      global.fetch.mockRejectedValueOnce(new Error('CORS policy blocked access'));
      
      const validCRXData = new ArrayBuffer(1000);
      const data = new Uint8Array(validCRXData);
      data[0] = 0x43;

      global.fetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => validCRXData
      });

      const result = await analyzer.downloadCRX('test-extension-id');
      expect(result).toBeInstanceOf(ArrayBuffer);
    });

    test('should handle CSP errors', async () => {
      global.fetch.mockRejectedValueOnce(new Error('Content Security Policy violation'));
      
      const validCRXData = new ArrayBuffer(1000);
      global.fetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => validCRXData
      });

      const result = await analyzer.downloadCRX('test-extension-id');
      expect(result).toBeInstanceOf(ArrayBuffer);
    });

    test('should handle 403 forbidden errors', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 403
      });

      const validCRXData = new ArrayBuffer(1000);
      global.fetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => validCRXData
      });

      const result = await analyzer.downloadCRX('test-extension-id');
      expect(result).toBeInstanceOf(ArrayBuffer);
    });
  });

  describe('extractAndAnalyze', () => {
    test('should extract and analyze CRX3 format', async () => {
      const mockCRXData = new ArrayBuffer(1000);
      const data = new Uint8Array(mockCRXData);
      data[0] = 0x43; // 'C'
      data[1] = 0x72; // 'r'
      data[2] = 0x32; // '2'
      data[3] = 0x34; // '4'
      data[4] = 3; // version

      jest.spyOn(analyzer, 'parseCRX').mockResolvedValue({
        zipData: new ArrayBuffer(500),
        manifest: { name: 'Test Extension', version: '1.0' }
      });

      jest.spyOn(analyzer, 'analyzeFiles').mockResolvedValue({
        riskScore: 10,
        threats: []
      });

      const result = await analyzer.extractAndAnalyze(mockCRXData, 'test-id');

      expect(result).toHaveProperty('manifest');
      expect(result).toHaveProperty('files');
      expect(result).toHaveProperty('riskScore');
    });
  });

  describe('parseDirectZIP', () => {
    test('should handle invalid ZIP data gracefully', async () => {
      const invalidZipData = new ArrayBuffer(100);
      
      await expect(analyzer.parseDirectZIP(invalidZipData)).rejects.toThrow();
    });
  });

  describe('calculateFileRiskScore', () => {
    test('should calculate risk score based on threats', () => {
      const threats = [
        { type: 'dangerousPermission', severity: 'high' },
        { type: 'suspiciousCode', severity: 'medium' }
      ];

      const score = analyzer.calculateFileRiskScore(threats);

      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(100);
    });

    test('should return 0 for no threats', () => {
      const score = analyzer.calculateFileRiskScore([]);
      expect(score).toBe(0);
    });

    test('should cap score at 100', () => {
      const manyThreats = Array(50).fill({ type: 'dangerousPermission', severity: 'critical' });
      const score = analyzer.calculateFileRiskScore(manyThreats);
      expect(score).toBeLessThanOrEqual(100);
    });
  });

  describe('calculateOverallRiskScore', () => {
    test('should calculate weighted risk score', () => {
      const analysis = {
        manifestAnalysis: { riskScore: 50 },
        fileAnalysis: { riskScore: 30 },
        suspiciousFiles: [
          { riskScore: 20 },
          { riskScore: 15 }
        ]
      };

      const score = analyzer.calculateOverallRiskScore(analysis);

      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(100);
    });

    test('should handle missing analysis data', () => {
      const analysis = {
        suspiciousFiles: []
      };
      const score = analyzer.calculateOverallRiskScore(analysis);
      expect(score).toBeGreaterThanOrEqual(0);
    });
  });

  describe('analyzeManifest', () => {
    test('should analyze manifest for dangerous permissions', () => {
      const manifest = {
        permissions: ['tabs', 'cookies', 'debugger'],
        host_permissions: ['<all_urls>']
      };

      const analysis = analyzer.analyzeManifest(manifest);

      expect(analysis).toHaveProperty('permissions');
      expect(analysis).toHaveProperty('threats');
      expect(analysis.threats.length).toBeGreaterThan(0);
    });

    test('should detect broad host permissions', () => {
      const manifest = {
        permissions: [],
        host_permissions: ['*://*/*']
      };

      const analysis = analyzer.analyzeManifest(manifest);

      expect(analysis.threats.some(t => t.type === 'broadHostPermission')).toBe(true);
    });

    test('should handle empty manifest', () => {
      const manifest = {};
      const analysis = analyzer.analyzeManifest(manifest);
      
      expect(analysis).toHaveProperty('permissions');
      expect(analysis).toHaveProperty('threats');
    });
  });
});

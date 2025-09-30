/**
 * Runtime Monitor Tests
 * Tests for monitoring extension behavior at runtime
 */

import RuntimeMonitor from '../../src/analyzers/runtime-monitor.js';

describe('RuntimeMonitor', () => {
  let monitor;

  beforeEach(() => {
    monitor = new RuntimeMonitor();
  });

  describe('constructor', () => {
    test('should initialize with empty state', () => {
      expect(monitor.monitoredExtensions).toBeInstanceOf(Map);
      expect(monitor.behavioralPatterns).toBeDefined();
      expect(monitor.monitoredExtensions.size).toBe(0);
      expect(monitor.behavioralPatterns).toHaveProperty('suspiciousRequests');
      expect(monitor.behavioralPatterns).toHaveProperty('keylogging');
      expect(monitor.behavioralPatterns).toHaveProperty('formHijacking');
    });
  });

  describe('isRuntimeMonitoringAvailable', () => {
    test('should return false in Node.js environment', () => {
      // In Node.js test environment, window and document are undefined
      expect(monitor.isRuntimeMonitoringAvailable()).toBe(false);
    });
  });

  describe('startMonitoringExtension', () => {
    test('should handle monitoring when not available', () => {
      const extensionId = 'test123';
      
      // Should not throw error even when monitoring is not available
      expect(() => {
        monitor.startMonitoringExtension(extensionId);
      }).not.toThrow();
    });

    test('should add extension to monitored list', () => {
      const extensionId = 'test123';
      
      monitor.startMonitoringExtension(extensionId);
      
      expect(monitor.monitoredExtensions.has(extensionId)).toBe(true);
    });
  });

  describe('stopMonitoringExtension', () => {
    test('should remove extension from monitored list', () => {
      const extensionId = 'test123';
      
      monitor.startMonitoringExtension(extensionId);
      expect(monitor.monitoredExtensions.has(extensionId)).toBe(true);
      
      monitor.stopMonitoringExtension(extensionId);
      expect(monitor.monitoredExtensions.has(extensionId)).toBe(false);
    });

    test('should handle non-existent extension gracefully', () => {
      expect(() => {
        monitor.stopMonitoringExtension('nonexistent');
      }).not.toThrow();
    });
  });

  describe('getBehavioralAnalysis', () => {
    test('should return analysis structure', () => {
      const analysis = monitor.getBehavioralAnalysis();
      
      expect(analysis).toHaveProperty('available');
      expect(analysis).toHaveProperty('suspiciousRequests');
      expect(analysis).toHaveProperty('keylogging');
      expect(analysis).toHaveProperty('formHijacking');
      expect(analysis).toHaveProperty('clickjacking');
      expect(analysis).toHaveProperty('dataAccess');
      expect(analysis).toHaveProperty('dangerousAPIs');
      expect(analysis).toHaveProperty('riskScore');
    });

    test('should indicate monitoring not available in Node.js', () => {
      const analysis = monitor.getBehavioralAnalysis();
      
      expect(analysis.available).toBe(false);
    });
  });

  describe('calculateBehavioralRiskScore', () => {
    test('should calculate risk based on behavioral patterns', () => {
      const riskScore = monitor.calculateBehavioralRiskScore();
      
      expect(typeof riskScore).toBe('number');
      expect(riskScore).toBeGreaterThanOrEqual(0);
      expect(riskScore).toBeLessThanOrEqual(100);
    });
  });

  describe('getExtensionMonitoringResults', () => {
    test('should return monitoring results for extension', () => {
      const extensionId = 'test123';
      monitor.startMonitoringExtension(extensionId);
      
      const results = monitor.getExtensionMonitoringResults(extensionId);
      
      expect(results).toBeDefined();
      expect(results).toHaveProperty('extensionId');
      expect(results).toHaveProperty('behaviors');
      expect(results).toHaveProperty('riskScore');
    });

    test('should return null for non-monitored extension', () => {
      const results = monitor.getExtensionMonitoringResults('nonexistent');
      
      expect(results).toBeNull();
    });
  });
});

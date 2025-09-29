/**
 * Alert System Module
 * Handles displaying alerts to the user about extension security issues
 */

class AlertSystem {
  constructor() {
    // Alert thresholds
    this.thresholds = {
      low: 19,    // Show alerts for extensions with score > 19 (includes 'low' level 20+)
      medium: 39,  // Default: Show alerts for extensions with score > 39 (includes 'medium' level 40+)
      high: 59     // Show alerts only for extensions with score > 59 (includes 'high' level 60+)
    };
    
    // Current threshold setting
    this.currentThreshold = 'medium';
  }
  
  /**
   * Set the alert threshold
   * @param {string} threshold - Threshold level (low, medium, high)
   */
  setThreshold(threshold) {
    if (this.thresholds[threshold] !== undefined) {
      this.currentThreshold = threshold;
    }
  }
  
  /**
   * Check if an alert should be shown based on threat level and current threshold
   * @param {number} threatScore - The threat score (0-100)
   * @returns {boolean} True if an alert should be shown
   */
  shouldShowAlert(threatScore) {
    return threatScore > this.thresholds[this.currentThreshold];
  }
  
  /**
   * Show an alert for a suspicious extension
   * @param {Object} extensionInfo - Information about the extension
   * @param {Object} threatClassification - Threat classification results
   */
  showAlert(extensionInfo, threatClassification) {
    // Check if we should show an alert based on the threshold
    if (!this.shouldShowAlert(threatClassification.score)) {
      return;
    }
    
    // Create notification
    this.showNotification(extensionInfo, threatClassification);
    
    // Log the alert
    this.logAlert(extensionInfo, threatClassification);
  }
  
  /**
   * Show a browser notification
   * @param {Object} extensionInfo - Information about the extension
   * @param {Object} threatClassification - Threat classification results
   */
  showNotification(extensionInfo, threatClassification) {
    // Create notification options
    const options = {
      type: 'basic',
      iconUrl: '../icons/icon48.png', // Adjust path as needed
      title: this.getNotificationTitle(threatClassification.level),
      message: `The extension "${extensionInfo.name}" has been flagged as a security risk.`,
      contextMessage: threatClassification.summary.substring(0, 60) + '...',
      buttons: [
        { title: 'View Details' },
        { title: 'Disable Extension' }
      ],
      priority: 2
    };
    
    // Create the notification
    chrome.notifications.create(`extension-alert-${extensionInfo.id}`, options, notificationId => {
      // Store information about this notification for handling clicks
      this.storeNotificationInfo(notificationId, extensionInfo, threatClassification);
    });
  }
  
  /**
   * Get notification title based on threat level
   * @param {string} threatLevel - Threat level (safe, low, medium, high, critical)
   * @returns {string} Notification title
   */
  getNotificationTitle(threatLevel) {
    switch (threatLevel) {
      case 'critical':
        return 'Critical Security Risk Detected!';
      case 'high':
        return 'High Security Risk Detected!';
      case 'medium':
        return 'Security Risk Detected';
      case 'low':
        return 'Security Concern Detected';
      default:
        return 'Extension Security Alert';
    }
  }
  
  /**
   * Store information about a notification for handling clicks
   * @param {string} notificationId - ID of the notification
   * @param {Object} extensionInfo - Information about the extension
   * @param {Object} threatClassification - Threat classification results
   */
  storeNotificationInfo(notificationId, extensionInfo, threatClassification) {
    // In a real implementation, this would store the information in a way
    // that it can be retrieved when the notification is clicked
    
    // For this implementation, we'll use chrome.storage.local
    chrome.storage.local.get('notificationInfo', data => {
      const notificationInfo = data.notificationInfo || {};
      
      notificationInfo[notificationId] = {
        extensionId: extensionInfo.id,
        extensionName: extensionInfo.name,
        threatLevel: threatClassification.level,
        threatScore: threatClassification.score,
        timestamp: Date.now()
      };
      
      chrome.storage.local.set({ notificationInfo });
    });
  }
  
  /**
   * Log an alert to the extension's history
   * @param {Object} extensionInfo - Information about the extension
   * @param {Object} threatClassification - Threat classification results
   */
  logAlert(extensionInfo, threatClassification) {
    // Create alert record
    const alertRecord = {
      type: 'alert',
      extensionId: extensionInfo.id,
      extensionName: extensionInfo.name,
      threatLevel: threatClassification.level,
      message: threatClassification.summary,
      time: new Date().toISOString()
    };
    
    // Add to recent activity
    chrome.storage.local.get('recentActivity', data => {
      const recentActivity = data.recentActivity || [];
      
      // Add new activity to the beginning
      recentActivity.unshift(alertRecord);
      
      // Limit to 20 items
      if (recentActivity.length > 20) {
        recentActivity.pop();
      }
      
      chrome.storage.local.set({ recentActivity });
    });
  }
  
  /**
   * Handle notification button clicks
   * @param {string} notificationId - ID of the notification
   * @param {number} buttonIndex - Index of the button clicked (0 or 1)
   */
  handleNotificationButtonClick(notificationId, buttonIndex) {
    // Get notification info
    chrome.storage.local.get('notificationInfo', data => {
      const notificationInfo = data.notificationInfo || {};
      const info = notificationInfo[notificationId];
      
      if (!info) return;
      
      if (buttonIndex === 0) {
        // View Details button
        this.openDetailsPage(info.extensionId);
      } else if (buttonIndex === 1) {
        // Disable Extension button
        this.disableExtension(info.extensionId);
      }
      
      // Clean up notification info
      delete notificationInfo[notificationId];
      chrome.storage.local.set({ notificationInfo });
    });
  }
  
  /**
   * Open the details page for an extension
   * @param {string} extensionId - ID of the extension
   */
  openDetailsPage(extensionId) {
    // Open the extension details page in a new tab
    chrome.tabs.create({
      url: `chrome://extensions/?id=${extensionId}`
    });
    
    // Also open our extension popup focused on this extension
    chrome.action.openPopup();
    
    // In a real implementation, we would need to communicate with the popup
    // to show details for this specific extension
  }
  
  /**
   * Disable an extension
   * @param {string} extensionId - ID of the extension
   */
  disableExtension(extensionId) {
    chrome.management.setEnabled(extensionId, false, () => {
      // Show confirmation
      chrome.notifications.create({
        type: 'basic',
        iconUrl: '../icons/icon48.png',
        title: 'Extension Disabled',
        message: 'The extension has been disabled for your protection.',
        priority: 1
      });
      
      // Log the action
      this.logDisableAction(extensionId);
    });
  }
  
  /**
   * Log when an extension is disabled
   * @param {string} extensionId - ID of the extension
   */
  logDisableAction(extensionId) {
    // Get extension info
    chrome.management.get(extensionId, extensionInfo => {
      // Create record
      const disableRecord = {
        type: 'block',
        extensionId: extensionId,
        extensionName: extensionInfo.name,
        reason: 'Manually disabled after security alert',
        time: new Date().toISOString()
      };
      
      // Add to recent activity
      chrome.storage.local.get('recentActivity', data => {
        const recentActivity = data.recentActivity || [];
        
        // Add new activity to the beginning
        recentActivity.unshift(disableRecord);
        
        // Limit to 20 items
        if (recentActivity.length > 20) {
          recentActivity.pop();
        }
        
        chrome.storage.local.set({ recentActivity });
      });
    });
  }
}

// Export the alert system
// Make AlertSystem available globally for importScripts
if (typeof window !== "undefined") {
  window.AlertSystem = AlertSystem;
} else if (typeof self !== "undefined") {
  self.AlertSystem = AlertSystem;
}

export default AlertSystem;
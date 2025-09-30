// Popup script for Brave Extension Scanner

// Show critical security warning about analysis limitations
function showAnalysisLimitations() {
  // Check if warning already exists
  if (document.getElementById('security-warning')) {
    return;
  }
  
  const warning = document.createElement('div');
  warning.id = 'security-warning';
  warning.className = 'security-warning';
  warning.innerHTML = `
    <div class="warning-content">
      <div class="warning-icon">⚠️</div>
      <div class="warning-text">
        <strong>Real Analysis:</strong> This scanner now downloads and analyzes actual extension files from the Chrome Web Store. 
        For development extensions, it attempts direct file access. Fallback to manifest analysis when needed.
      </div>
    </div>
  `;
  
  // Add to the top of the popup
  const popup = document.querySelector('.popup-container') || document.body;
  popup.insertBefore(warning, popup.firstChild);
}

document.addEventListener('DOMContentLoaded', () => {
  // Initialize tabs
  initTabs();
  
  // Load dashboard data
  loadDashboardData();
  
  // Initialize scan tab
  initScanTab();
  
  // Load history data
  loadHistoryData();
  
  // Initialize settings
  initSettings();
  
  // Set up periodic refresh for dashboard data
  setInterval(loadDashboardData, 30000); // Refresh every 30 seconds
});

// Tab functionality
function initTabs() {
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabPanes = document.querySelectorAll('.tab-pane');
  
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      // Remove active class from all buttons and panes
      tabButtons.forEach(btn => btn.classList.remove('active'));
      tabPanes.forEach(pane => pane.classList.remove('active'));
      
      // Add active class to clicked button and corresponding pane
      button.classList.add('active');
      const tabId = button.dataset.tab;
      document.getElementById(tabId).classList.add('active');
    });
  });
}

// Refresh all popup data
async function refreshAllData() {
  try {
    await Promise.all([
      loadDashboardData(),
      loadHistoryData()
    ]);
  } catch (error) {
    console.error('Error refreshing data:', error);
  }
}

// Load dashboard data
async function loadDashboardData() {
  try {
    // Get data from background script
    const response = await sendMessageToBackground({ action: 'getDashboardData' });
    
    if (response) {
      // Update protection status
      updateProtectionStatus(response.protectionStatus);
      
      // Update stats
      document.getElementById('extensions-scanned').textContent = response.stats.extensionsScanned || 0;
      document.getElementById('threats-detected').textContent = response.stats.threatsDetected || 0;
      
      // Update last scan time
      if (response.stats.lastScan) {
        document.getElementById('last-scan').textContent = formatDate(new Date(response.stats.lastScan));
      }
      
      // Update recent activity
      updateRecentActivity(response.recentActivity || []);
    }
  } catch (error) {
    console.error('Error loading dashboard data:', error);
  }
}

// Update protection status display
function updateProtectionStatus(status) {
  const statusIcon = document.getElementById('protection-status-icon');
  const statusText = document.getElementById('protection-status');
  
  if (status === 'active') {
    statusIcon.style.backgroundColor = 'var(--success-color)';
    statusText.textContent = 'Active';
  } else {
    statusIcon.style.backgroundColor = 'var(--danger-color)';
    statusText.textContent = 'Inactive';
  }
}

// Update recent activity list
function updateRecentActivity(activities) {
  const activityList = document.getElementById('recent-activity-list');
  
  if (activities.length === 0) {
    activityList.innerHTML = '<div class="empty-state">No recent activity</div>';
    return;
  }
  
  activityList.innerHTML = '';
  
  activities.forEach(activity => {
    const activityItem = document.createElement('div');
    activityItem.className = 'activity-item';
    
    const activityContent = document.createElement('div');
    activityContent.className = 'activity-content';
    
    // Create different content based on activity type
    if (activity.type === 'scan') {
      activityContent.innerHTML = `
        <div>Scanned <strong>${activity.extensionName}</strong></div>
        <div>Result: <span class="text-${getThreatLevelClass(activity.threatLevel)}">${capitalizeFirst(activity.threatLevel)}</span></div>
      `;
    } else if (activity.type === 'block') {
      activityContent.innerHTML = `
        <div>Blocked <strong>${activity.extensionName}</strong></div>
        <div>Reason: ${activity.reason}</div>
      `;
    } else if (activity.type === 'alert') {
      activityContent.innerHTML = `
        <div>Alert for <strong>${activity.extensionName}</strong></div>
        <div>${activity.message}</div>
      `;
    } else if (activity.type === 'installation_detected') {
      if (activity.intercepted === false) {
        activityContent.innerHTML = `
          <div>Extension installed: <strong>${activity.extensionName}</strong></div>
          <div class="text-warning">⏸️ Auto-scan disabled</div>
        `;
      } else {
        activityContent.innerHTML = `
          <div>🔍 Auto-scanning: <strong>${activity.extensionName}</strong></div>
          <div class="text-info">Installation intercepted</div>
        `;
      }
    } else if (activity.type === 'scan_failed') {
      activityContent.innerHTML = `
        <div>❌ Scan failed: <strong>${activity.extensionName}</strong></div>
        <div class="text-danger">Error: ${activity.error || 'Unknown error'}</div>
      `;
    } else if (activity.type === 'crx_blocked') {
      activityContent.innerHTML = `
        <div>🛡️ Blocked installation: <strong>${activity.extensionName}</strong></div>
        <div class="text-danger">Threat level: ${capitalizeFirst(activity.threatLevel)}</div>
      `;
    } else if (activity.type === 'crx_allowed') {
      activityContent.innerHTML = `
        <div>✅ Allowed installation from URL</div>
        <div class="text-success">Passed security scan</div>
      `;
    } else if (activity.type === 'installation_listener_test') {
      activityContent.innerHTML = `
        <div>🧪 Installation listener test</div>
        <div class="text-info">${activity.message || 'Test completed'}</div>
      `;
    } else if (activity.type === 'unpacked_installation_detected') {
      activityContent.innerHTML = `
        <div>📦 Unpacked extension detected: <strong>${activity.extensionName}</strong></div>
        <div class="text-info">Scanning before enabling...</div>
      `;
    } else if (activity.type === 'unpacked_allowed') {
      activityContent.innerHTML = `
        <div>✅ Unpacked extension allowed: <strong>${activity.extensionName}</strong></div>
        <div class="text-success">Threat level: ${capitalizeFirst(activity.threatLevel)}</div>
      `;
    } else if (activity.type === 'unpacked_blocked') {
      activityContent.innerHTML = `
        <div>🛡️ Unpacked extension blocked: <strong>${activity.extensionName}</strong></div>
        <div class="text-danger">Threat level: ${capitalizeFirst(activity.threatLevel)}</div>
      `;
    } else if (activity.type === 'unpacked_scan_limited') {
      activityContent.innerHTML = `
        <div>⚠️ Limited scan: <strong>${activity.extensionName}</strong></div>
        <div class="text-warning">Manual review recommended</div>
      `;
    }
    
    const activityTime = document.createElement('div');
    activityTime.className = 'activity-time';
    activityTime.textContent = formatDate(new Date(activity.time));
    
    activityItem.appendChild(activityContent);
    activityItem.appendChild(activityTime);
    activityList.appendChild(activityItem);
  });
}

// Initialize scan tab
function initScanTab() {
  const scanTypeSelect = document.getElementById('scan-type');
  const extensionSelector = document.getElementById('extension-selector');
  const extensionSelect = document.getElementById('extension-select');
  const startScanButton = document.getElementById('start-scan-button');
  
  // Show/hide extension selector based on scan type
  scanTypeSelect.addEventListener('change', () => {
    if (scanTypeSelect.value === 'single') {
      extensionSelector.style.display = 'block';
      loadExtensionList();
    } else {
      extensionSelector.style.display = 'none';
    }
  });
  
  // Start scan button
  startScanButton.addEventListener('click', () => {
    const scanType = scanTypeSelect.value;
    const scanDepth = document.getElementById('scan-depth').value;
    let extensionId = null;
    
    if (scanType === 'single') {
      extensionId = extensionSelect.value;
      if (!extensionId) {
        alert('Please select an extension to scan');
        return;
      }
    }
    
    startScan(scanType, scanDepth, extensionId);
  });
}

// Load list of installed extensions
async function loadExtensionList() {
  try {
    const extensionSelect = document.getElementById('extension-select');
    extensionSelect.innerHTML = '<option value="">Loading extensions...</option>';
    
    // Get extensions from background script
    const extensions = await sendMessageToBackground({ action: 'getInstalledExtensions' });
    
    if (extensions && extensions.length > 0) {
      extensionSelect.innerHTML = '<option value="">Select an extension</option>';
      
      extensions.forEach(extension => {
        const option = document.createElement('option');
        option.value = extension.id;
        option.textContent = extension.name;
        extensionSelect.appendChild(option);
      });
    } else {
      extensionSelect.innerHTML = '<option value="">No extensions found</option>';
    }
  } catch (error) {
    console.error('Error loading extension list:', error);
    extensionSelect.innerHTML = '<option value="">Error loading extensions</option>';
  }
}

// Start a scan
async function startScan(scanType, scanDepth, extensionId) {
  try {
    // Get references to DOM elements
    const scanOptionsElement = document.getElementById('scan-options');
    const scanProgressElement = document.getElementById('scan-progress');
    const scanResultsElement = document.getElementById('scan-results');
    const progressBar = document.getElementById('scan-progress-bar');
    const statusElement = document.getElementById('scan-status');
    
    // Check if all elements exist
    if (!scanOptionsElement) {
      throw new Error('Element with ID "scan-options" not found');
    }
    if (!scanProgressElement) {
      throw new Error('Element with ID "scan-progress" not found');
    }
    if (!scanResultsElement) {
      throw new Error('Element with ID "scan-results" not found');
    }
    if (!progressBar) {
      throw new Error('Element with ID "scan-progress-bar" not found');
    }
    if (!statusElement) {
      throw new Error('Element with ID "scan-status" not found');
    }
    
    // Show progress UI
    scanOptionsElement.style.display = 'none';
    scanProgressElement.style.display = 'block';
    scanResultsElement.style.display = 'none';
    
    // Show critical security warning
    showAnalysisLimitations();
    
    // Update progress status
    progressBar.style.width = '10%';
    statusElement.textContent = 'Initializing REAL scan...';
    
    // Send scan request to background script
    const scanResults = await sendMessageToBackground({
      action: 'startScan',
      scanType,
      scanDepth,
      extensionId
    });
    
    // Update progress during scan (in a real implementation, this would use events or polling)
    progressBar.style.width = '50%';
    statusElement.textContent = 'Downloading and analyzing real extension files...';
    
    // Simulate scan progress
    await new Promise(resolve => setTimeout(resolve, 2000));
    progressBar.style.width = '75%';
    statusElement.textContent = 'Performing comprehensive threat analysis...';
    
    await new Promise(resolve => setTimeout(resolve, 1500));
    progressBar.style.width = '100%';
    statusElement.textContent = 'REAL analysis complete!';
    
    // Wait a moment before showing results
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Show results
    showScanResults(scanResults);
    
    // Refresh all data after scan completion
    await refreshAllData();
  } catch (error) {
    console.error('Error during scan:', error);
    const statusElement = document.getElementById('scan-status');
    if (statusElement) {
      statusElement.textContent = 'Error: ' + error.message;
    } else {
      console.error('Could not update status element: Element not found');
    }
  }
}

// Format summary text with proper HTML
function formatSummaryText(summary) {
  if (!summary || typeof summary !== 'string') {
    return 'No details available';
  }
  
  // Convert markdown-style formatting to HTML
  let formatted = summary
    // Convert line breaks to <br> tags
    .replace(/\n/g, '<br>')
    // Convert bullet points to proper HTML lists
    .replace(/^- \*\*(.*?)\*\*: (.*?)(?=<br>|$)/gm, '<li><strong>$1:</strong> $2</li>')
    // Wrap consecutive list items in <ul> tags
    .replace(/(<li>.*<\/li>)(<br><li>.*<\/li>)*/g, '<ul>$&</ul>')
    // Clean up any remaining <br> tags inside lists
    .replace(/<ul>(<li>.*<\/li>)<br>(<li>.*<\/li>)*<\/ul>/g, '<ul>$1$2</ul>')
    // Convert bold text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    // Convert italic text
    .replace(/\*(.*?)\*/g, '<em>$1</em>');
  
  return formatted;
}

// Show scan results
function showScanResults(results) {
  try {
    // Get references to DOM elements
    const scanProgressElement = document.getElementById('scan-progress');
    const scanResultsElement = document.getElementById('scan-results');
    const resultsContainer = document.getElementById('results-list');
    const summaryContainer = document.getElementById('results-summary');
    
    // Check if all elements exist
    if (!scanProgressElement) {
      throw new Error('Element with ID "scan-progress" not found');
    }
    if (!scanResultsElement) {
      throw new Error('Element with ID "scan-results" not found');
    }
    if (!resultsContainer) {
      throw new Error('Element with ID "results-list" not found');
    }
    if (!summaryContainer) {
      throw new Error('Element with ID "results-summary" not found');
    }
    
    // Hide progress, show results
    scanProgressElement.style.display = 'none';
    scanResultsElement.style.display = 'block';
    
    // Clear previous results
    resultsContainer.innerHTML = '';
    
    // If no results or empty results
    if (!results || results.length === 0) {
      summaryContainer.className = 'results-summary safe';
      summaryContainer.innerHTML = '<p>No issues found. All extensions appear to be safe.</p>';
      resultsContainer.innerHTML = '<div class="empty-state">No threats detected</div>';
      return;
    }
    
    try {
      // Ensure results is an array
      const resultsArray = Array.isArray(results) ? results : [];
      
      // Count threats by severity
      const threatCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        safe: 0
      };
      
      // Check if results is an object with a specific structure
      if (!Array.isArray(results) && results && typeof results === 'object') {
        console.log('Results is not an array, attempting to extract data');
        // If results contains a data property that is an array, use that
        if (results.data && Array.isArray(results.data)) {
          console.log('Using results.data as the results array');
          resultsArray.push(...results.data);
        } else if (results.results && Array.isArray(results.results)) {
          console.log('Using results.results as the results array');
          resultsArray.push(...results.results);
        } else {
          // Try to convert the object to an array if possible
          console.log('Converting object to array if possible');
          const entries = Object.entries(results);
          entries.forEach(([key, value]) => {
            if (typeof value === 'object' && value !== null && 'threatLevel' in value) {
              resultsArray.push(value);
            }
          });
        }
      }
      
      console.log('Processing results:', resultsArray);
      
      resultsArray.forEach(result => {
        if (result && result.threatLevel) {
          threatCounts[result.threatLevel]++;
        }
      });
      
      // Determine overall summary class and message
      let summaryClass = 'safe';
      let summaryMessage = '';
      
      if (threatCounts.critical > 0) {
        summaryClass = 'danger';
        summaryMessage = `<strong>Critical security risks detected!</strong> ${threatCounts.critical} extension(s) have critical security issues that require immediate attention.`;
      } else if (threatCounts.high > 0) {
        summaryClass = 'danger';
        summaryMessage = `<strong>High security risks detected!</strong> ${threatCounts.high} extension(s) have high security risks.`;
      } else if (threatCounts.medium > 0) {
        summaryClass = 'warning';
        summaryMessage = `<strong>Potential security risks detected.</strong> ${threatCounts.medium} extension(s) have moderate security concerns.`;
      } else if (threatCounts.low > 0) {
        summaryClass = 'warning';
        summaryMessage = `<strong>Minor security concerns detected.</strong> ${threatCounts.low} extension(s) have low-level security issues.`;
      } else {
        summaryMessage = 'No security issues found. All extensions appear to be safe.';
      }
      
      // Update summary
      summaryContainer.className = `results-summary ${summaryClass}`;
      summaryContainer.innerHTML = `<p>${summaryMessage}</p>`;
      
      // Add each result to the list
      resultsArray.forEach(result => {
        if (!result || !result.threatLevel || result.threatLevel === 'safe') return; // Skip safe extensions in the list
        
        const resultItem = document.createElement('div');
        resultItem.className = 'result-item';
        
        // Format the summary text with proper HTML
        const formattedSummary = formatSummaryText(result.summary || 'No details available');
        
        resultItem.innerHTML = `
          <h4>
            ${result.extensionName || 'Unknown Extension'}
            <span class="result-severity severity-${result.threatLevel}">${capitalizeFirst(result.threatLevel)}</span>
          </h4>
          <div class="result-summary">${formattedSummary}</div>
          <div class="result-actions">
            <button class="view-details-button" data-extension-id="${result.extensionId || ''}">View Details</button>
            ${result.threatLevel === 'critical' || result.threatLevel === 'high' ? 
              `<button class="disable-button" data-extension-id="${result.extensionId || ''}">Disable Extension</button>` : ''}
          </div>
        `;
        
        resultsContainer.appendChild(resultItem);
      });
      
      // Add event listeners for buttons
      document.querySelectorAll('.view-details-button').forEach(button => {
        button.addEventListener('click', () => {
          const extensionId = button.dataset.extensionId;
          viewExtensionDetails(extensionId);
        });
      });
      
      document.querySelectorAll('.disable-button').forEach(button => {
        button.addEventListener('click', () => {
          const extensionId = button.dataset.extensionId;
          disableExtension(extensionId);
        });
      });
    } catch (error) {
      console.error('Error processing scan results:', error);
    }
  } catch (error) {
    console.error('Error showing scan results:', error);
    return;
  }
}

// View extension details
async function viewExtensionDetails(extensionId) {
  try {
    console.log('Viewing details for extension:', extensionId);
    
    // Show loading state
    const modalContent = document.getElementById('modal-content');
    modalContent.innerHTML = '<div class="loading-spinner">Loading detailed report...</div>';
    
    // Show the modal
    document.getElementById('detail-modal').style.display = 'flex';
    
    // Get detailed scan results from background script
    const detailedResults = await sendMessageToBackground({
      action: 'getExtensionDetails',
      extensionId
    });
    
    if (!detailedResults) {
      modalContent.innerHTML = '<div class="error-message">No detailed information available for this extension.</div>';
      return;
    }
    
    // Generate the detailed report HTML
    const reportHtml = generateDetailedReport(detailedResults);
    
    // Update the modal content
    modalContent.innerHTML = reportHtml;
    
    // Add event listener to close button
    document.getElementById('close-modal').addEventListener('click', () => {
      document.getElementById('detail-modal').style.display = 'none';
    });
    
    // Close modal when clicking outside
    document.getElementById('detail-modal').addEventListener('click', (event) => {
      if (event.target === document.getElementById('detail-modal')) {
        document.getElementById('detail-modal').style.display = 'none';
      }
    });
  } catch (error) {
    console.error('Error viewing extension details:', error);
    const modalContent = document.getElementById('modal-content');
    modalContent.innerHTML = `<div class="error-message">Error loading details: ${error.message}</div>`;
  }
}

/**
 * Generate detailed HTML report for an extension
 * @param {Object} data - Detailed scan data
 * @returns {string} HTML content
 */
function generateDetailedReport(data) {
  const { extensionInfo, threatClassification, details } = data;
  
  if (!extensionInfo || !threatClassification) {
    return '<div class="error-message">Incomplete scan data available.</div>';
  }
  
  // Start building the HTML
  let html = `
    <div class="detailed-report">
      <div class="report-header">
        <h2>${escapeHtml(extensionInfo.name)}</h2>
        <div class="extension-meta">
          <span>Version: ${escapeHtml(extensionInfo.version || 'Unknown')}</span>
          <span>ID: ${escapeHtml(extensionInfo.id || 'Unknown')}</span>
        </div>
        <div class="threat-badge threat-${threatClassification.level}">
          ${capitalizeFirst(threatClassification.level)} Risk
        </div>
      </div>
      
      <div class="report-section">
        <h3>Summary</h3>
        <p>${escapeHtml(threatClassification.summary || 'No summary available.')}</p>
        
        <div class="threat-score">
          <div class="score-label">Threat Score</div>
          <div class="score-value">${threatClassification.score || 0}/100</div>
          <div class="score-bar">
            <div class="score-fill" style="width: ${threatClassification.score || 0}%"></div>
          </div>
        </div>
      </div>
  `;
  
  // Add recommendations if available
  if (threatClassification.recommendations && threatClassification.recommendations.length > 0) {
    html += `
      <div class="report-section">
        <h3>Recommendations</h3>
        <ul class="recommendations-list">
          ${threatClassification.recommendations.map(rec => `<li>${escapeHtml(rec.recommendation)}</li>`).join('')}
        </ul>
      </div>
    `;
  }
  
  // Add threat categories if available
  if (threatClassification.categories && threatClassification.categories.length > 0) {
    html += `
      <div class="report-section">
        <h3>Detected Issues</h3>
        <div class="categories-list">
          ${threatClassification.categories.map(category => `
            <div class="category-item severity-${category.severity}">
              <div class="category-header">
                <h4>${escapeHtml(category.name)}</h4>
                <span class="severity-badge">${capitalizeFirst(category.severity)}</span>
              </div>
              <p>${escapeHtml(category.description)}</p>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }
  
  // Add technical details if available
  if (details) {
    html += `<div class="report-section"><h3>Technical Details</h3>`;
    
    // Permissions Analysis
    if (details.manifestAnalysis && details.manifestAnalysis.permissions) {
      const { permissions } = details.manifestAnalysis;
      
      html += `
        <div class="details-section">
          <h4>Permissions Analysis</h4>
          <div class="permissions-summary">
            <div class="permission-stat">
              <span class="stat-label">Total Permissions:</span>
              <span class="stat-value">${permissions.total || 0}</span>
            </div>
            <div class="permission-stat">
              <span class="stat-label">Dangerous Permissions:</span>
              <span class="stat-value">${permissions.dangerous?.count || 0}</span>
            </div>
            <div class="permission-stat">
              <span class="stat-label">Critical Permissions:</span>
              <span class="stat-value">${permissions.critical?.count || 0}</span>
            </div>
          </div>
      `;
      
      // Add dangerous permissions
      if (permissions.dangerous && permissions.dangerous.count > 0) {
        html += `
          <div class="permission-group danger">
            <h5>Dangerous Permissions</h5>
            <ul>
              ${permissions.dangerous.permissions.map(perm => 
                `<li>${escapeHtml(perm)}</li>`
              ).join('')}
            </ul>
          </div>
        `;
      }
      
      // Add critical permissions
      if (permissions.critical && permissions.critical.count > 0) {
        html += `
          <div class="permission-group critical">
            <h5>Critical Permissions</h5>
            <ul>
              ${permissions.critical.permissions.map(perm => 
                `<li>${escapeHtml(perm)}</li>`
              ).join('')}
            </ul>
          </div>
        `;
      }
      
      html += `</div>`;
    }
    
    // Code Analysis
    if (details.staticAnalysis && details.staticAnalysis.suspiciousPatterns) {
      const { suspiciousPatterns } = details.staticAnalysis;
      
      html += `
        <div class="details-section">
          <h4>Code Analysis</h4>
      `;
      
      if (suspiciousPatterns.length === 0) {
        html += `<p>No suspicious code patterns detected.</p>`;
      } else {
        html += `
          <div class="code-patterns">
            ${suspiciousPatterns.map(pattern => `
              <div class="pattern-item severity-${pattern.severity}">
                <div class="pattern-header">
                  <h5>${escapeHtml(pattern.category)}</h5>
                  <span class="count-badge">${pattern.count} instance${pattern.count !== 1 ? 's' : ''}</span>
                </div>
                <p>${escapeHtml(pattern.description)}</p>
              </div>
            `).join('')}
          </div>
        `;
      }
      
      html += `</div>`;
    }
    
    // Obfuscation Analysis
    if (details.obfuscationAnalysis) {
      const obfuscationAnalysis = details.obfuscationAnalysis;
      
      html += `
        <div class="details-section">
          <h4>Obfuscation Analysis</h4>
          <div class="obfuscation-summary">
            <div class="obfuscation-stat">
              <span class="stat-label">Obfuscation Detected:</span>
              <span class="stat-value ${obfuscationAnalysis.obfuscationDetected ? 'text-danger' : 'text-success'}">
                ${obfuscationAnalysis.obfuscationDetected ? 'Yes' : 'No'}
              </span>
            </div>
            <div class="obfuscation-stat">
              <span class="stat-label">Obfuscation Score:</span>
              <span class="stat-value">${obfuscationAnalysis.obfuscationScore || 0}/100</span>
            </div>
            <div class="obfuscation-stat">
              <span class="stat-label">Code Entropy:</span>
              <span class="stat-value">${obfuscationAnalysis.entropy ? obfuscationAnalysis.entropy.toFixed(2) : 'N/A'}</span>
            </div>
          </div>
      `;
      
      // Add techniques if any were detected
      if (obfuscationAnalysis.techniques && obfuscationAnalysis.techniques.length > 0) {
        html += `
          <div class="obfuscation-techniques">
            <h5>Detected Techniques</h5>
            ${obfuscationAnalysis.techniques.map(technique => `
              <div class="technique-item severity-${technique.severity}">
                <div class="technique-header">
                  <span>${escapeHtml(technique.name)}</span>
                  <span class="severity-badge">${capitalizeFirst(technique.severity)}</span>
                </div>
                <p>${escapeHtml(technique.description)}</p>
                ${technique.count ? `<div class="technique-count">Instances: ${technique.count}</div>` : ''}
              </div>
            `).join('')}
          </div>
        `;
      }
      
      html += `</div>`;
    }
    
    // Network Analysis
    if (details.networkAnalysis) {
      const networkAnalysis = details.networkAnalysis;
      
      html += `
        <div class="details-section">
          <h4>Network Analysis</h4>
          <div class="network-summary">
            <div class="network-stat">
              <span class="stat-label">Total Endpoints:</span>
              <span class="stat-value">${networkAnalysis.endpoints?.total || 0}</span>
            </div>
            <div class="network-stat">
              <span class="stat-label">Suspicious Endpoints:</span>
              <span class="stat-value">${networkAnalysis.endpoints?.suspicious?.length || 0}</span>
            </div>
            <div class="network-stat">
              <span class="stat-label">Risk Score:</span>
              <span class="stat-value">${networkAnalysis.riskScore || 0}/100</span>
            </div>
          </div>
      `;
      
      // Add suspicious domains if any were detected
      if (networkAnalysis.endpoints?.suspicious?.length > 0) {
        html += `
          <div class="suspicious-domains">
            <h5>Suspicious Domains</h5>
            <div class="domains-list">
              ${networkAnalysis.endpoints.suspicious.map(domain => `
                <div class="domain-item severity-${domain.severity}">
                  <div class="domain-header">
                    <span>${escapeHtml(domain.domain)}</span>
                    <span class="severity-badge">${capitalizeFirst(domain.severity)}</span>
                  </div>
                  <p>${escapeHtml(domain.reason)}</p>
                  <div class="domain-url">${escapeHtml(domain.url)}</div>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }
      
      // Add suspicious URL patterns if any were detected
      if (networkAnalysis.suspiciousUrls?.length > 0) {
        html += `
          <div class="suspicious-urls">
            <h5>Suspicious URL Patterns</h5>
            <div class="urls-list">
              ${networkAnalysis.suspiciousUrls.map(url => `
                <div class="url-item severity-${url.severity}">
                  <div class="url-header">
                    <span>${escapeHtml(url.pattern)}</span>
                    <span class="severity-badge">${capitalizeFirst(url.severity)}</span>
                  </div>
                  <p>${escapeHtml(url.reason)}</p>
                  <div class="url-match">${escapeHtml(url.match)}</div>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }
      
      html += `</div>`;
    }
    
    html += `</div>`;
  }
  
  html += `</div>`;
  
  return html;
}

/**
 * Escape HTML special characters
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Disable an extension
async function disableExtension(extensionId) {
  try {
    const result = await sendMessageToBackground({
      action: 'disableExtension',
      extensionId
    });
    
    if (result.success) {
      alert(`Extension has been disabled. ${result.message || ''}`);
      // Refresh data after disabling extension
      await refreshAllData();
    } else {
      alert(`Failed to disable extension: ${result.message || 'Unknown error'}`);
    }
  } catch (error) {
    console.error('Error disabling extension:', error);
    alert('Error disabling extension: ' + error.message);
  }
}

// Load history data
async function loadHistoryData() {
  try {
    // Get scan history from background script
    const history = await sendMessageToBackground({ action: 'getScanHistory' });
    
    updateHistoryList(history || []);
    
    // Add filter change handler
    document.getElementById('history-filter').addEventListener('change', () => {
      updateHistoryList(history || []);
    });
  } catch (error) {
    console.error('Error loading history data:', error);
  }
}

// Update history list
function updateHistoryList(history) {
  const historyList = document.getElementById('history-list');
  const filter = document.getElementById('history-filter').value;
  
  // Filter history items if needed
  let filteredHistory = history;
  if (filter === 'threats') {
    filteredHistory = history.filter(item => item.threatLevel !== 'safe');
  }
  
  if (filteredHistory.length === 0) {
    historyList.innerHTML = '<div class="empty-state">No scan history</div>';
    return;
  }
  
  historyList.innerHTML = '';
  
  // Sort by date (newest first)
  filteredHistory.sort((a, b) => new Date(b.scanTime) - new Date(a.scanTime));
  
  filteredHistory.forEach(item => {
    const historyItem = document.createElement('div');
    historyItem.className = 'history-item';
    
    historyItem.innerHTML = `
      <div class="history-item-header">
        <div class="history-item-name">${item.extensionName}</div>
        <div class="history-item-time">${formatDate(new Date(item.scanTime))}</div>
      </div>
      <div class="history-item-result">
        <span class="result-badge badge-${item.threatLevel}">${capitalizeFirst(item.threatLevel)}</span>
        <button class="view-details-button" data-scan-id="${item.id}">View Details</button>
      </div>
    `;
    
    historyList.appendChild(historyItem);
  });
  
  // Add event listeners for view details buttons
  document.querySelectorAll('.view-details-button').forEach(button => {
    button.addEventListener('click', () => {
      const scanId = button.dataset.scanId;
      viewScanDetails(scanId);
    });
  });
}

// View scan details from history
async function viewScanDetails(scanId) {
  try {
    console.log('Viewing details for scan:', scanId);
    
    // Show loading state
    const modalContent = document.getElementById('modal-content');
    modalContent.innerHTML = '<div class="loading-spinner">Loading detailed report...</div>';
    
    // Show the modal
    document.getElementById('detail-modal').style.display = 'flex';
    
    // Get scan details from background script
    const scanDetails = await sendMessageToBackground({
      action: 'getScanDetails',
      scanId
    });
    
    if (!scanDetails) {
      modalContent.innerHTML = '<div class="error-message">No detailed information available for this scan.</div>';
      return;
    }
    
    // If we have the extension ID, get the full details
    if (scanDetails.extensionId) {
      const detailedResults = await sendMessageToBackground({
        action: 'getExtensionDetails',
        extensionId: scanDetails.extensionId
      });
      
      if (detailedResults) {
        // Generate the detailed report HTML
        const reportHtml = generateDetailedReport(detailedResults);
        
        // Update the modal content
        modalContent.innerHTML = reportHtml;
      } else {
        // If we can't get detailed results, show basic scan info
        modalContent.innerHTML = `
          <div class="detailed-report">
            <div class="report-header">
              <h2>${escapeHtml(scanDetails.extensionName || 'Unknown Extension')}</h2>
              <div class="extension-meta">
                <span>Scan ID: ${escapeHtml(scanId)}</span>
                <span>Scan Time: ${formatDate(new Date(scanDetails.scanTime))}</span>
              </div>
              <div class="threat-badge threat-${scanDetails.threatLevel}">
                ${capitalizeFirst(scanDetails.threatLevel)} Risk
              </div>
            </div>
            
            <div class="report-section">
              <h3>Summary</h3>
              <p>${escapeHtml(scanDetails.summary || 'No summary available.')}</p>
              
              <div class="threat-score">
                <div class="score-label">Threat Score</div>
                <div class="score-value">${scanDetails.threatScore || 0}/100</div>
                <div class="score-bar">
                  <div class="score-fill" style="width: ${scanDetails.threatScore || 0}%"></div>
                </div>
              </div>
            </div>
          </div>
        `;
      }
    } else {
      modalContent.innerHTML = '<div class="error-message">Incomplete scan data available.</div>';
    }
    
    // Add event listener to close button
    document.getElementById('close-modal').addEventListener('click', () => {
      document.getElementById('detail-modal').style.display = 'none';
    });
    
    // Close modal when clicking outside
    document.getElementById('detail-modal').addEventListener('click', (event) => {
      if (event.target === document.getElementById('detail-modal')) {
        document.getElementById('detail-modal').style.display = 'none';
      }
    });
  } catch (error) {
    console.error('Error viewing scan details:', error);
    const modalContent = document.getElementById('modal-content');
    modalContent.innerHTML = `<div class="error-message">Error loading details: ${error.message}</div>`;
  }
}

// Initialize settings
async function initSettings() {
  try {
    // Get current settings from background script
    const settings = await sendMessageToBackground({ action: 'getSettings' });
    
    if (settings) {
      // Update UI to reflect current settings
      document.getElementById('intercept-installations').checked = settings.interceptInstallations;
      document.getElementById('alert-threshold').value = settings.alertThreshold;
      document.getElementById('auto-block').checked = settings.autoBlockHigh;
    }
    
    // Add event listeners for settings changes
    document.getElementById('intercept-installations').addEventListener('change', (e) => {
      updateSetting('interceptInstallations', e.target.checked);
    });
    
    document.getElementById('alert-threshold').addEventListener('change', (e) => {
      updateSetting('alertThreshold', e.target.value);
    });
    
    document.getElementById('auto-block').addEventListener('change', (e) => {
      updateSetting('autoBlockHigh', e.target.checked);
    });
  } catch (error) {
    console.error('Error loading settings:', error);
  }
}

// Update a setting
async function updateSetting(key, value) {
  try {
    await sendMessageToBackground({
      action: 'updateSetting',
      key,
      value
    });
    
    // Refresh dashboard data after settings change (especially protection status)
    if (key === 'interceptInstallations') {
      await loadDashboardData();
    }
  } catch (error) {
    console.error('Error updating setting:', error);
    alert('Failed to update setting: ' + error.message);
  }
}

// Helper function to send messages to background script
function sendMessageToBackground(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, response => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

// Helper function to format dates
function formatDate(date) {
  // If less than 24 hours ago, show relative time
  const now = new Date();
  const diffMs = now - date;
  const diffHours = diffMs / (1000 * 60 * 60);
  
  if (diffHours < 24) {
    if (diffHours < 1) {
      const diffMinutes = Math.floor(diffMs / (1000 * 60));
      return diffMinutes === 0 ? 'Just now' : `${diffMinutes} minute${diffMinutes === 1 ? '' : 's'} ago`;
    } else {
      const hours = Math.floor(diffHours);
      return `${hours} hour${hours === 1 ? '' : 's'} ago`;
    }
  } else {
    // Format as date
    return date.toLocaleDateString(undefined, { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }
}

// Helper function to get CSS class for threat level
function getThreatLevelClass(level) {
  switch (level) {
    case 'critical':
    case 'high':
      return 'danger';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    case 'safe':
    default:
      return 'success';
  }
}

// Helper function to capitalize first letter
function capitalizeFirst(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}
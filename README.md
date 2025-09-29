# Brave Extension Scanner

A security-focused browser extension that scans other extensions for malicious code patterns, dangerous permissions, and obfuscated functionality to protect users from extension-based attacks.

## Features

- **Post-Installation Scanning**: Automatically scans extensions immediately after they're installed
- **Static Analysis**: Detects suspicious code patterns, dangerous API usage, and obfuscated code using AST parsing
- **Permission Analysis**: Identifies extensions requesting excessive or dangerous permissions
- **Obfuscation Detection**: Uses entropy analysis to detect code obfuscation and packing
- **Network Analysis**: Detects suspicious network endpoints and data exfiltration attempts
- **Threat Classification**: Provides clear risk assessments with actionable recommendations
- **Auto-Protection**: Can automatically disable high-risk extensions
- **Zero Telemetry**: All analysis happens locally - no data is sent to external servers

## ⚠️ Important Limitations

### Chrome Manifest V3 Restrictions

Due to Chrome's Manifest V3 security architecture, this extension **cannot**:

❌ **Block extensions before installation completes**  
- Extensions are scanned **after** they're installed (Manifest V3 limitation)
- We can alert and disable, but cannot prevent the initial installation
- Think of this as "antivirus for extensions" rather than a firewall

❌ **Access files from Chrome Web Store extensions**  
- Can only analyze metadata and manifest information
- Cannot read actual JavaScript code for Web Store extensions  
- Full code analysis only works for unpacked/developer extensions

❌ **Monitor all network requests globally**  
- Limited to declarativeNetRequest API
- Cannot intercept/modify extension network traffic in real-time

### ✅ What This Extension CAN Do

✅ **Scan extensions immediately after installation**  
✅ **Fully analyze unpacked/developer extensions**  
✅ **Detect dangerous permissions and suspicious patterns**  
✅ **Alert you to potential threats with detailed reports**  
✅ **Automatically disable malicious extensions**  
✅ **Track scan history and provide actionable insights**

### How It Works

1. **Installation Detection**: When you install an extension, we detect it immediately via `chrome.management.onInstalled`
2. **Post-Install Scanning**: We scan the extension's manifest and available metadata
3. **Threat Assessment**: Multiple analyzers check for malicious patterns and dangerous configurations
4. **User Alert**: If threats are found, you receive a notification with recommended actions
5. **Auto-Protection**: High-risk extensions can be disabled automatically based on your settings

## Technical Architecture

The extension consists of six core components:

1. **Installation Monitor**: Detects when extensions are installed via `chrome.management.onInstalled` API
2. **Static Analyzer**: Performs AST-based analysis using acorn parser to detect malicious code patterns
3. **Manifest Analyzer**: Examines permissions, content scripts, and CSP configurations for security risks
4. **Obfuscation Detector**: Uses Shannon entropy analysis and pattern matching to detect code obfuscation
5. **Network Analyzer**: Identifies suspicious endpoints, domains, and data exfiltration patterns
6. **Threat Classifier**: Combines all analysis results using weighted scoring to determine threat level

**Analysis Flow:**
```
Extension Installed → Monitor Detects → Fetch Manifest → Run Analyzers → 
Classify Threat → Alert User → Auto-Disable (if configured)
```

## Installation

### For Users

1. Download from the Chrome Web Store (coming soon)
2. Or install from source (see Developer Installation below)
3. Grant requested permissions when prompted
4. Configure security settings in the extension popup

### For Developers

#### Prerequisites
- Node.js 14+ and npm
- Git
- Brave or Chrome browser

#### Build from Source

```bash
# Clone the repository
git clone https://github.com/geeknik/brave-extension-scanner.git
cd brave-extension-scanner

# Install dependencies
npm install

# Run tests to verify everything works
npm test

# Build for production
npm run build

# Or build for development (with source maps)
npm run build:dev

# Or use watch mode (auto-rebuild on changes)
npm run watch
```

#### Load in Brave/Chrome

1. Open `brave://extensions` (or `chrome://extensions`)
2. Enable "Developer mode" (toggle in top-right)
3. Click "Load unpacked"
4. Select the `dist/` directory from your build

#### Testing

We have comprehensive test coverage (87%) with test extensions for validation:

```bash
# Run all tests
npm test

# Run tests with coverage report
npm run test:coverage

# Run tests in watch mode (for development)
npm run test:watch

# Lint code
npm run lint
```

## Usage

1. **Automatic Scanning**: By default, the extension will automatically scan new extensions when they are installed

2. **Manual Scanning**: You can manually scan installed extensions by:
   - Opening the extension popup
   - Selecting the "Scan" tab
   - Choosing scan options and clicking "Start Scan"

3. **Viewing Results**: Scan results will show:
   - Overall threat level
   - Specific security concerns detected
   - Recommendations for action

4. **Settings**: Customize the extension's behavior in the Settings tab:
   - Enable/disable automatic scanning
   - Adjust alert thresholds
   - Configure automatic blocking of high-risk extensions

## Privacy

This extension is designed with privacy as a core principle:

- All analysis happens locally on your device
- No extension code or analysis data is sent to external servers
- No telemetry or usage statistics are collected
- Pattern updates are delivered via signed, verifiable packages

## Development

### Project Structure

```
brave-extension-scanner/
├── manifest.json           # Extension manifest
├── background.js           # Background script
├── popup.html              # Popup UI
├── popup.js                # Popup logic
├── styles.css              # Styles for popup
├── src/
│   ├── analyzers/          # Analysis modules
│   │   ├── static-analyzer.js
│   │   ├── manifest-analyzer.js
│   │   ├── obfuscation-detector.js
│   │   ├── network-analyzer.js
│   │   └── threat-classifier.js
│   ├── utils/              # Utility functions
│   └── ui/                 # UI components
└── icons/                  # Extension icons
```

### Building

```bash
# Install dependencies
npm install

# Build for development
npm run build:dev

# Build for production
npm run build:prod

# Watch for changes during development
npm run watch
```

### Key Technologies

- **AST Parsing**: Uses Acorn and Acorn-walk for accurate JavaScript code analysis
- **ZIP Extraction**: Uses JSZip to extract and analyze extension packages
- **Pattern Matching**: Combines regex and AST-based pattern matching for high accuracy
- **Entropy Analysis**: Measures Shannon entropy to detect obfuscated code
- **Heuristic Analysis**: Uses multiple detection methods to reduce false positives

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Recent Changes

We've made several improvements to the extension:

1. **AST-based Analysis**: Replaced simple regex patterns with more accurate AST-based analysis
2. **Improved CRX Extraction**: Enhanced the CRX file extraction process
3. **Better Threat Classification**: More sophisticated threat detection and classification
4. **Enhanced Utility Functions**: Added more helper functions for common tasks
5. **Simplified Dependencies**: Reduced external dependencies for better compatibility

See the [CHANGES.md](CHANGES.md) file for more details on recent updates.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Brave Browser team for their work on browser security
- Security researchers who have documented extension-based attacks
- Open source security tools that inspired this project

# Brave Extension Scanner

A security-focused browser extension that scans other extensions for malicious code patterns, dangerous permissions, and obfuscated functionality to protect users from extension-based attacks.

## Features

- **Installation Interception**: Automatically scans extensions when they are installed
- **Static Analysis**: Detects suspicious code patterns, dangerous API usage, and obfuscated code
- **Permission Analysis**: Identifies extensions requesting excessive or dangerous permissions
- **Network Analysis**: Detects suspicious network endpoints and data exfiltration attempts
- **Threat Classification**: Provides clear risk assessments with actionable recommendations
- **Zero Telemetry**: All analysis happens locally - no data is sent to external servers

## Technical Architecture

The extension consists of five core components:

1. **Installation Interceptor**: Hooks into Brave's extension installation flow to capture and analyze extensions before installation completes
2. **Static Analyzer**: Performs AST-based analysis of JavaScript code to detect malicious patterns with high accuracy
3. **Manifest Analyzer**: Examines extension permissions and configurations to identify potential security risks
4. **Obfuscation Detector**: Uses entropy analysis and pattern matching to detect code obfuscation techniques
5. **Network Analyzer**: Identifies suspicious network endpoints and potential data exfiltration
6. **Threat Classifier**: Combines analysis results to determine overall risk level and provide actionable recommendations

## Installation

### Development Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/brave-extension-scanner.git
   ```

2. Open Brave browser and navigate to `brave://extensions`

3. Enable "Developer mode" in the top-right corner

4. Click "Load unpacked" and select the extension directory

### Production Installation

*Coming soon to the Chrome Web Store*

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
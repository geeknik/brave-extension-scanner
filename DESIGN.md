# DESIGN.md - Extension Scanner for Brave

## TL;DR
Browser extension that scans other extensions before installation, detecting malicious code patterns, dangerous permissions, and obfuscated functionality to protect users from extension-based attacks.

## Key Objectives
- Intercept extension installation process in Brave
- Perform static and dynamic analysis on extension code
- Flag high-risk behaviors and permissions
- Present findings in actionable, user-friendly alerts
- Zero telemetry, fully private operation

## Technical Architecture

### Core Components
1. **Installation Interceptor**
   - Hooks into Brave's extension installation flow
   - Captures extension files before installation completes
   - Supports both Web Store and sideloaded extensions

2. **Static Analyzer**
   - Decompresses extension package (.crx/.zip)
   - Parses manifest for permission profiling
   - Tokenizes JavaScript for pattern matching
   - Checks resources against known malware signatures
   - Detects obfuscation techniques (eval chains, string encryption)

3. **Dynamic Analyzer**
   - Sandboxed execution environment
   - API call monitoring
   - Network request interception
   - DOM manipulation tracking
   - Storage access patterns

4. **Threat Classifier**
   - Permission abuse detection
   - Data exfiltration patterns
   - Malicious behavior heuristics
   - Obfuscation scoring system

5. **Alert System**
   - Severity-based classification
   - User-friendly explanations
   - Technical details on demand
   - Installation block recommendations

## Implementation Details

### Manifest Analysis
```javascript
function analyzeManifest(manifest) {
  const dangerousPermissions = [
    "tabs", "webRequest", "cookies", "<all_urls>",
    "bookmarks", "history", "management"
  ];
  
  const criticalPermissions = [
    "declarativeNetRequest", "debugger",
    "proxy", "privacy", "contentSettings"
  ];
  
  // Score calculation logic
  // ...
}
```

### Code Pattern Detection
- AST-based analysis for detecting:
  - Eval chains and dynamic code execution
  - Remote code loading attempts
  - Cookie theft patterns
  - History/bookmark exfiltration
  - DOM-based keyloggers
  - Browser fingerprinting techniques

### Obfuscation Detection
- Shannon entropy measurement
- String concatenation/manipulation patterns
- Base64/hex encoding chains
- Character code manipulation
- Uncommon JavaScript features with high obfuscation correlation

### Network Analysis
- Endpoint reputation checking
- Suspicious domain detection
- Known C2 server matching
- Data exfiltration pattern recognition

## Technical Challenges & Mitigations

### Challenge: Extensions Using Legitimate Obfuscation
**Mitigation:** Context-aware heuristics that differentiate between legitimate minification/obfuscation and malicious behavior patterns. Use machine learning classifier trained on both legitimate and malicious obfuscated extensions.

### Challenge: Performance Impact During Analysis
**Mitigation:** Multi-threaded analysis process with priority-based scanning. Critical security checks run first, followed by deeper analysis while maintaining UI responsiveness.

### Challenge: Detecting Novel Threats
**Mitigation:** Behavior-based detection rather than pure signature matching. Regular pattern database updates via offline, encrypted channel.

### Challenge: False Positives
**Mitigation:** Confidence scoring system combining multiple detection methods. User feedback loop to improve detection accuracy.

## Security Model

### Principles
- Zero telemetry - all analysis happens locally
- No cloud submission of extension code
- Pattern updates via signed, verifiable packages
- Minimal permission requirements for the scanner itself
- Defense-in-depth approach with multiple detection methods

### Our Extension's Permissions
- `management`: Required to intercept new extension installations
- `storage`: Local storage of detection patterns and user preferences
- `webRequest`: Only for the extension store domains to intercept downloads

## Development Roadmap

### Phase 1: Core Detection Engine
- Basic static analysis implementation
- Permission-based risk assessment
- Simple obfuscation detection

### Phase 2: Advanced Detection
- Dynamic analysis integration
- Machine learning classifier
- Extended pattern library

### Phase 3: User Experience Refinement
- Customizable alerting thresholds
- Detailed technical reports
- Extension remediation suggestions

### Phase 4: Ecosystem Integration
- Sharing anonymized signatures (opt-in)
- Integration with extension reputation systems
- Support for Firefox and other Chromium browsers

## Final Notes
This extension aims to bring enterprise-grade extension security to everyday users. Our design principles emphasize privacy, transparency, and user empowerment. Keeping malicious extensions off users' browsers without introducing new privacy or security risks is our primary goal.

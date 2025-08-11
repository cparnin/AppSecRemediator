# Changelog

All notable changes to AppSec AI Scanner are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2025-01-28

### Major Features
- **Enhanced Multi-Language Cross-File Analysis**: Comprehensive cross-file vulnerability analysis across 15+ programming languages
- **Smart Finding Prioritization**: Increased from 3 to 8 most critical findings with intelligent severity sorting
- **Universal Framework Detection**: Automatic detection of Express, Spring, Django, Rails, Laravel, ASP.NET, React, Vue, Angular, and more
- **Real Attack Chain Detection**: AST-based data flow tracing across multiple files and languages

### Improvements
- **Consolidated Cross-File Analysis Reporting**: Eliminated duplicate analysis sections in HTML reports
- **Actionable Remediation Details**: Enhanced reports with specific file paths, line numbers, and remediation steps
- **Human-Readable Timestamps**: Improved report formatting and readability
- **Framework-Aware Context**: Cross-file analysis now provides context based on detected web frameworks

### Bug Fixes
- Fixed cross-file analysis integration with all deployment modes (CLI, Web, CI/CD)
- Resolved CrossFileAnalyzer performance issues with large codebases
- Improved error handling in multi-language AST parsing

### Security
- Enhanced auto-remediation logging for better CI/CD debugging
- Improved fix generation tracking with detailed success/failure metrics

## [1.2.0] - 2025-01-27

### Major Features
- **Cross-File Analysis Integration**: Real cross-file vulnerability analysis engine
- **CrossFileAnalyzer Engine**: Static analysis with AST parsing for multiple programming languages
- **Enhanced Business Impact Assessment**: Context-aware risk analysis based on file locations
- **Advanced Import Graph Resolution**: Dependency tracking across project files

### Improvements
- **Multi-Language AST Support**: JavaScript/TypeScript, Python, Java, Go, Rust, C#, Ruby, Kotlin, PHP, Swift
- **Smart Vulnerability Prioritization**: Intelligent ranking by severity and attack potential
- **Enhanced PR Context**: MCP analysis included in GitHub PR comments
- **Comprehensive Framework Support**: Detection of modern web frameworks across all languages

### Compliance
- **Automatic SBOM Generation**: CycloneDX and SPDX format support in all deployment modes
- **Enhanced Web Interface**: Auto-generates compliance files with direct download links

## [1.1.0] - 2025-01-24

### Code Quality Improvements
- **Shared Validation Framework**: Centralized input validation across all scanner modules
- **Structured Exception Handling**: Enhanced error classes with detailed context information
- **Consistent Logging System**: Standardized logging across all modules for better debugging
- **Maintainability Enhancements**: Eliminated code duplication and improved modularity

### Web Interface Enhancements
- **Automatic SBOM Generation**: Web interface now auto-generates compliance files
- **Improved HTML Reports**: Fixed table layout issues and long file path wrapping
- **Enhanced User Experience**: Better progress tracking and error reporting

### Security Hardening
- **Input Validation**: Enhanced validation for all user inputs and file operations
- **Path Traversal Protection**: Comprehensive security checks for file access
- **Binary Path Sanitization**: Environment variable validation for scanner binaries

## [1.0.0] - 2025-01-23

### Initial Release
- **Multi-Scanner Architecture**: Integrated Semgrep (SAST), Gitleaks (secrets), and Trivy (dependencies)
- **AI-Powered Auto-Remediation**: Automatic code fixes using OpenAI GPT-4 and Anthropic Claude
- **Three Deployment Modes**: CLI, Web interface, and CI/CD integration
- **Universal Language Support**: JavaScript, Python, Java, Go, Rust, C#, Ruby, PHP, Swift, Kotlin, and more

### Security Analysis
- **SAST Scanning**: Static application security testing across 15+ programming languages
- **Secrets Detection**: Git history and codebase scanning for exposed credentials
- **Dependency Scanning**: CVE detection and automated version updates
- **Comprehensive Reporting**: HTML reports with business impact analysis

### Auto-Remediation
- **Intelligent Code Fixes**: AI-generated patches for common vulnerabilities
- **Separate PR Creation**: Code fixes and dependency updates in separate pull requests
- **Context-Aware Fixes**: Framework-specific remediation strategies
- **Manual Review Workflow**: Flagged secrets require manual review for security

### Deployment Options
- **Interactive CLI**: `python main.py` with repository discovery and selection
- **Web Interface**: Flask app at `localhost:8000` with point-and-click scanning
- **GitHub Actions**: Drop-in workflow with automatic PR creation and artifact uploads
- **API Integration**: RESTful endpoints for custom tool integration

### Reporting & Compliance
- **HTML Security Reports**: Comprehensive analysis with executive summaries
- **Business Impact Analysis**: Cost estimates and risk assessments
- **SBOM Generation**: Software Bill of Materials in CycloneDX and SPDX formats
- **Artifact Management**: Automatic uploads in CI/CD mode

### Configuration
- **Flexible Scan Levels**: `critical-high` (default) or `all` findings
- **Auto-Fix Modes**: Configurable remediation behavior (1=SAST+secrets, 2=dependencies, 3=both, 4=skip)
- **Provider Choice**: Support for both OpenAI and Anthropic Claude AI providers
- **Environment Integration**: Comprehensive environment variable configuration

### Technical Architecture
- **Async Scanner Execution**: Parallel scanning for 60-70% performance improvement
- **Secure File Operations**: Path traversal protection and input validation
- **Error Handling**: Comprehensive exception management with structured logging
- **Extensible Design**: Modular architecture for easy scanner integration

---

## Upgrade Notes

### From v1.2.x to v1.3.x
- MCP analysis now provides 8 prioritized findings instead of 3
- Enhanced framework detection may identify additional vulnerabilities
- Improved reporting format with consolidated sections

### From v1.1.x to v1.2.x
- New MCP dependency requires no configuration changes
- Enhanced findings may increase total vulnerability counts
- SBOM generation now automatic in all modes

### From v1.0.x to v1.1.x
- Shared validation may catch previously missed input issues
- Enhanced logging provides more detailed debug information
- Web interface SBOM generation requires no user configuration

## Support

For issues, feature requests, or questions:
- Documentation: See README.md and main_logic.md
- Contact: chadparnin@gmail.com

# AppSec AI Scanner - Claude Assistant Instructions

## Project Overview

Production-ready security scanner with AI-powered auto-remediation for any programming language. Combines static analysis (SAST), secrets detection, and dependency scanning with advanced Model Context Protocol (MCP) integration for cross-file vulnerability analysis across 15+ programming languages.

**Core Mission**: Provide comprehensive security analysis with intelligent remediation, seamless CI/CD integration, and automatic compliance reporting.

## Key Components & Architecture

### Main Entry Points
- **CLI Interface**: `src/main.py` - Interactive command-line scanner for security professionals
- **Web Interface**: `src/web_app.py` - Flask application at `localhost:8000` for teams
- **GitHub Action**: `action.yml` - Containerized CI/CD integration
- **Client Workflow**: `clients/security-scan.yml` - Drop-in workflow template

### Core Technologies
- **Security Scanners**: Semgrep (SAST), Gitleaks (secrets), Trivy (dependencies)
- **AI Integration**: OpenAI GPT-4 or Anthropic Claude for analysis and auto-remediation
- **MCP Engine**: Cross-file attack chain detection with AST parsing for 15+ languages
- **Compliance**: Automatic SBOM generation in CycloneDX and SPDX formats
- **Framework Support**: Express, React, Vue, Angular, Spring, Django, Flask, Rails, Laravel, ASP.NET

## Deployment Modes & Use Cases

### 1. Web Interface (Recommended for Teams)
```bash
cd src && python web_app.py
# → Opens http://localhost:8000
```
**Features**: Point-and-click scanning, real-time progress, automatic SBOM generation, visual reports

### 2. CLI Mode (Security Professionals)
```bash
cd src && python main.py
# → Interactive menu with repository selection
```
**Features**: Deep MCP analysis, manual control, detailed explanations, consultant workflow

### 3. CI/CD Integration (Development Teams)
```bash
cp clients/security-scan.yml .github/workflows/
# → Automated scanning with PR creation
```
**Features**: Automatic triggers, PR comments, artifact uploads, configurable auto-remediation

## Core Functionality Deep Dive

### Security Analysis Pipeline
1. **Parallel Scanner Execution** (60-70% faster than sequential)
   - Semgrep: SAST analysis across 15+ programming languages
   - Gitleaks: Secrets detection in code and git history
   - Trivy: Dependency vulnerabilities and CVE detection

2. **MCP Cross-File Analysis** (Advanced)
   - Multi-language AST parsing for real code understanding
   - Framework detection and context-aware analysis
   - Attack chain tracing across files and languages
   - Business impact assessment with cost calculations

3. **AI-Powered Auto-Remediation**
   - Context-aware code fixes using GPT-4 or Claude
   - Framework-specific remediation strategies
   - Separate PR creation for code fixes vs dependency updates
   - Manual review workflow for secrets detection

4. **Comprehensive Reporting**
   - HTML reports with executive summaries and technical details
   - Automatic SBOM generation for compliance (no configuration)
   - GitHub PR comments with MCP-enhanced context
   - Workflow artifacts with 90-day retention

### Auto-Remediation Modes
- **Mode 1**: SAST vulnerabilities + secret flagging (creates 1 PR)
- **Mode 2**: Dependency updates only (creates 1 PR)
- **Mode 3**: Both SAST and dependencies (creates 2 separate PRs)
- **Mode 4**: Scan only, no auto-remediation

### Scan Levels
- **critical-high** (default): Focus on actionable, high-impact vulnerabilities
- **all**: Include medium and low severity findings for comprehensive analysis

## Configuration & Environment

### Required Environment Variables
```bash
# AI Provider Configuration
OPENAI_API_KEY=sk-your-key-here          # OpenAI GPT-4 (recommended)
CLAUDE_API_KEY=claude-key-here           # Anthropic Claude (alternative)
AI_PROVIDER=openai                       # 'openai' or 'claude'

# Scanning Configuration  
APPSEC_SCAN_LEVEL=critical-high          # 'critical-high' or 'all'
APPSEC_DEBUG=false                       # Enable debug logging
APPSEC_LOG_LEVEL=INFO                    # DEBUG/INFO/WARNING/ERROR

# CI/CD Auto-Remediation
APPSEC_AUTO_FIX=true                     # Enable automatic remediation
APPSEC_AUTO_FIX_MODE=3                   # 1=SAST+secrets, 2=deps, 3=both, 4=skip

# Business Configuration
SECURITY_ENGINEER_HOURLY_RATE=150       # For cost estimation calculations
```

### GitHub Actions Configuration
```yaml
# .github/workflows/security-scan.yml
uses: cparnin/appsec_ai_mcp_scanner@main
with:
  openai-api-key: ${{ secrets.OPENAI_API_KEY }}
  auto-fix: 'true'
  auto-fix-mode: '3'                     # Both SAST and dependencies
  fail-on-critical: 'false'              # Don't break CI by default
  scan-level: 'critical-high'
env:
  GH_TOKEN: ${{ github.token }}          # Required for PR creation
```

## Common Issues & Troubleshooting

### Workflow & CI/CD Problems
1. **No PR Creation**: 
   - Missing `GH_TOKEN: ${{ github.token }}` in workflow environment
   - Insufficient permissions: Need `contents: write` and `pull-requests: write`

2. **Permission Denied**:
   - Repository settings → Actions → General → Workflow permissions → "Read and write"
   - Check branch protection rules don't prevent bot PRs

3. **Scanner Binary Missing**:
   - Web interface auto-installs binaries
   - CLI requires manual installation: `pip install semgrep`
   - CI/CD uses pre-installed binaries in action environment

4. **API Rate Limiting**:
   - OpenAI: 3,500 requests/minute (default tier)
   - Claude: 5,000 requests/minute (default tier)
   - Enable debug logging to track API usage: `APPSEC_DEBUG=true`

### Configuration Issues
1. **Scan Level Confusion**:
   - `critical-high`: Shows only actionable, high-impact vulnerabilities
   - `all`: Shows everything including low-priority findings
   - Default is `critical-high` to avoid noise

2. **Auto-Fix Mode Selection**:
   - Mode 1: Fast, single PR for code fixes + secret flagging
   - Mode 2: Dependency updates only (safer for production)
   - Mode 3: Comprehensive, creates 2 separate PRs (recommended)
   - Mode 4: Analysis only, no auto-remediation

3. **AI Provider Selection**:
   - OpenAI GPT-4: Better for complex code analysis, slightly more expensive
   - Claude: Better for large context, cost-effective for bulk operations
   - Both support the same remediable vulnerability patterns

### Performance & Scaling
1. **Large Repository Handling**:
   - Git-aware scanning: Only scans changed files for performance
   - Memory optimization: Streaming processing for large codebases
   - Timeout configuration: Adjustable per scanner via environment variables

2. **MCP Analysis Performance**:
   - File analysis caching to avoid re-parsing
   - Smart prioritization: Shows 8 most critical findings
   - Framework detection optimization for faster analysis

## Testing & Validation Commands

### Local Development Testing
```bash
# Web interface (comprehensive testing)
cd src && python web_app.py
# → Open http://localhost:8000, test with sample repository

# CLI mode (detailed analysis)
cd src && python main.py
# → Follow interactive prompts, test auto-remediation

# Configuration validation
grep -r "APPSEC_" src/                   # Check configuration constants
APPSEC_DEBUG=true python main.py         # Enable debug logging
```

### API Integration Testing
```bash
# Health check
curl http://localhost:8000/health

# Scan API endpoint
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/repo", "scan_level": "critical-high"}'

# SBOM downloads
curl http://localhost:8000/reports/sbom.cyclonedx.json
curl http://localhost:8000/reports/sbom.spdx.json
```

### Scanner Output Analysis
```bash
# View raw scanner results
cat outputs/raw/semgrep.json | jq '.[] | {severity: .severity, message: .message}'
cat outputs/raw/gitleaks.json | jq '.[] | {description: .Description, file: .File}'
cat outputs/raw/trivy.json | jq '.Results[].Vulnerabilities[] | {pkg: .PkgName, severity: .Severity}'

# Check SBOM generation
ls -la outputs/sbom/
head outputs/sbom/sbom.cyclonedx.json
```

## File Structure & Key Locations

```
appsec_scanner/
├── src/                           # Core application code
│   ├── main.py                   # CLI entry point - interactive scanning
│   ├── web_app.py               # Flask web interface - team collaboration  
│   ├── mcp_server.py            # MCP engine - cross-file analysis
│   ├── mcp_integration.py       # MCP enhancement layer
│   ├── config.py                # Configuration constants and validation
│   ├── exceptions.py            # Centralized error handling
│   ├── logging_config.py        # Structured logging system
│   ├── scanners/                # Individual security scanners
│   │   ├── validation.py        # Shared security validation utilities
│   │   ├── semgrep.py          # SAST scanning with timeout handling
│   │   ├── gitleaks.py         # Secrets detection with git integration
│   │   └── trivy.py            # Dependency scanning with CVE database
│   ├── auto_remediation/        # AI-powered fix generation
│   │   └── remediation.py      # Core auto-fix engine with PR creation
│   ├── reporting/              # Report generation and templates
│   │   ├── html.py             # HTML report generation with MCP data
│   │   └── templates/          # Jinja2 templates for reports
│   ├── templates/              # Web interface templates  
│   │   └── index.html          # Main web interface with drag-drop
│   ├── sbom_generator.py       # SBOM compliance file generation
│   └── tool_ingestion.py       # External tool integration capabilities

├── clients/                      # Client integration templates
│   ├── security-scan.yml       # Drop-in GitHub Actions workflow
│   ├── SETUP.md                # Client setup instructions
│   └── CLIENT_ENGAGEMENT_TEMPLATE.md  # Professional services guide

├── outputs/                     # Generated reports and artifacts
│   ├── report.html             # Main security analysis report
│   ├── sbom/                   # Compliance files directory
│   │   ├── sbom.cyclonedx.json # CycloneDX SBOM format
│   │   └── sbom.spdx.json      # SPDX SBOM format
│   └── raw/                    # Raw scanner JSON outputs

├── action.yml                   # GitHub Action composite action definition
├── README.md                    # User documentation and quick start
├── CHANGELOG.md                 # Version history and upgrade notes
├── main_logic.md               # Technical architecture documentation
├── requirements.txt            # Python dependencies for CLI/CI
├── requirements-web.txt        # Additional web interface dependencies
├── env.example                 # Environment variable template
└── start_web.sh               # Zero-config web interface launcher
```

## Security Implementation & Best Practices

### Input Validation & Security
- **Path Traversal Protection**: All file operations validate against directory traversal
- **Command Injection Prevention**: Parameterized commands, no shell=True usage
- **API Security**: Only vulnerability metadata sent to AI, never full source code
- **Binary Validation**: Scanner binary paths validated and sanitized
- **File Size Limits**: Prevent memory exhaustion with configurable file size limits

### Error Handling & Logging  
- **Structured Logging**: Consistent log format across all components
- **Exception Hierarchy**: Custom exception classes with detailed context
- **Security Event Logging**: All security-relevant operations logged
- **Debug Mode**: Detailed troubleshooting without exposing sensitive data

### Performance & Scalability
- **Async/Await**: 60-70% performance improvement with parallel execution
- **Caching Strategy**: File analysis and AST parsing cached for efficiency
- **Memory Management**: Streaming processing and garbage collection optimization
- **Resource Limits**: Configurable timeouts and resource constraints

## Recent Updates & Current Status

### Version 1.3.0 (Latest) - Enhanced Multi-Language MCP Analysis
- **Smart Finding Prioritization**: Increased from 3 to 8 most critical findings
- **Universal Framework Detection**: Enhanced detection across all supported languages
- **Real Attack Chain Detection**: AST-based data flow tracing across multiple files
- **Consolidated Reporting**: Eliminated duplicate analysis sections in reports
- **Improved Auto-Remediation Logging**: Better CI/CD debugging with detailed tracking

### Version 1.2.0 - MCP Integration
- **Model Context Protocol**: Real cross-file vulnerability analysis engine
- **Multi-Language AST Support**: JavaScript, Python, Java, Go, Rust, C#, Ruby, PHP, Swift, Kotlin
- **Business Impact Assessment**: Context-aware risk analysis with cost estimates
- **Enhanced GitHub Integration**: MCP context in PR comments and descriptions

### Version 1.1.0 - Code Quality & Security
- **Shared Validation Framework**: Centralized security validation across modules
- **Structured Exception Handling**: Enhanced error management with detailed context
- **Web Interface SBOM**: Automatic compliance file generation in web mode
- **Security Hardening**: Path traversal protection and input sanitization

## Assistant Guidelines for User Interactions

### When Helping Users
1. **Environment Setup**: Always verify API keys and environment variables first
2. **Mode Selection**: Recommend web interface for teams, CLI for consultants, CI/CD for automation
3. **Troubleshooting**: Check logs first (`APPSEC_DEBUG=true`), then configuration
4. **Security**: Never log or expose API keys, use sanitized examples
5. **Performance**: For large repos, recommend `critical-high` scan level initially

### Common User Questions & Responses
**Q: "Why no vulnerabilities found?"**
A: Check scan level (`APPSEC_SCAN_LEVEL=all` to see all findings), verify scanners ran successfully in `outputs/raw/`

**Q: "Auto-fix not working in CI/CD?"**
A: Verify `APPSEC_AUTO_FIX=true`, check GitHub token permissions, ensure `contents: write` access

**Q: "MCP analysis missing?"**
A: MCP enhancement automatic if findings exist, check for sufficient findings to trigger analysis

**Q: "SBOM files not generated?"**
A: SBOM generation automatic in all modes, check `outputs/sbom/` directory or web interface downloads

### Debug Investigation Process
1. **Check Configuration**: Validate environment variables and API keys
2. **Review Logs**: Enable debug mode and check structured logs
3. **Scanner Status**: Verify individual scanner outputs in `outputs/raw/`
4. **Network Issues**: Check AI API connectivity and rate limits
5. **Permissions**: Verify file system and GitHub repository permissions

This comprehensive guide enables effective AI assistant support for the AppSec Scanner across all deployment modes and use cases.
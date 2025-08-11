# Technical Architecture

## Overview

Production-ready security scanner with AI-powered auto-remediation across 15+ programming languages. Combines static analysis, secrets detection, and dependency scanning with advanced cross-file vulnerability analysis.

## Core Architecture

### Multi-Scanner Engine
- **Semgrep (SAST)**: Code vulnerabilities across 15+ languages
- **Gitleaks**: Secret detection in git history  
- **Trivy**: Dependency vulnerability scanning with CVE database
- **Parallel execution**: 60-70% faster than sequential scanning

### Cross-File Analysis Integration
Advanced cross-file analysis beyond traditional SAST:
- **AST parsing** for multiple languages (Python, JavaScript, Java, Go, etc.)
- **Data flow tracing** across files and imports
- **Attack chain detection** from entry points to vulnerable sinks
- **Framework detection** (Express, Spring, Django, Rails, Laravel, ASP.NET)

### AI-Powered Remediation
- **Context-aware fixes** using OpenAI GPT-4 or Anthropic Claude
- **Framework-specific** remediation strategies
- **Separate PRs** for code fixes vs dependency updates
- **Business impact** analysis for prioritization

## Deployment Modes

### 1. CLI Mode
Interactive terminal interface with repository discovery and manual remediation control.

### 2. Web Interface  
Local web server with drag-and-drop scanning and real-time progress tracking.

### 3. CI/CD Integration
GitHub Actions workflow with automatic PR creation and compliance reporting.

## Key Features

### Security Analysis
- **15+ programming languages** supported
- **Cross-file vulnerability detection** with cross-file analysis
- **Real attack chain analysis** across multiple files
- **Framework-aware context** for accurate vulnerability assessment

### Auto-Remediation
- **AI-generated code fixes** with line-specific changes
- **Dependency version updates** to secure releases
- **Contextual explanations** for each remediation
- **Validation testing** before PR creation

### Compliance & Reporting
- **SBOM generation** (CycloneDX & SPDX formats)
- **HTML reports** with executive summaries
- **GitHub Actions artifacts** for audit trails
- **Compliance tracking** across repositories

## File Structure

```
src/
├── main.py                 # CLI entry point
├── web_app.py             # Web interface
├── mcp_server.py          # Cross-file analysis server
├── mcp_integration.py     # Cross-file analysis
├── scanners/              # Security scanners
├── auto_remediation/      # AI fix generation
└── reporting/             # HTML report generation
```

## Configuration

### Environment Variables
- `OPENAI_API_KEY` or `CLAUDE_API_KEY`: AI remediation
- `GITHUB_TOKEN`: PR creation and repository access
- `APPSEC_AUTO_FIX`: Enable/disable automatic remediation
- `APPSEC_SCAN_LEVEL`: Vulnerability severity threshold

### GitHub Actions
```yaml
uses: cparnin/appsec-ai-scanner@main
with:
  scan-level: 'critical-high'
  auto-fix: 'true'
  auto-fix-mode: '3'  # Both code and dependency fixes
```

## Performance

- **Parallel scanning**: 60-70% faster execution
- **Smart caching**: Reduced scan times for incremental changes  
- **Memory efficient**: Handles large repositories (1000+ files)
- **Rate limiting**: Prevents API quota exhaustion

## Contributing

This project welcomes contributions! Key areas:
- Additional language support for cross-file analysis
- New framework detection patterns
- Enhanced remediation strategies
- Performance optimizations

## License

MIT License - see [LICENSE](LICENSE) for details.
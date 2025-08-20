<div align="center">

<img width="400" height="400" alt="AppSecRemediator" src="https://github.com/user-attachments/assets/86732011-0dc0-4fd7-bc80-6d12eb98c5cd" />

</div>


Production-ready security scanner with AI-powered auto-remediation.

Combines static analysis (SAST), secrets detection, and dependency scanning with intelligent cross-file vulnerability analysis and automatic remediation. Features advanced cross-file analysis integration for real attack chain detection across 15+ programming languages.

## Key Features

- **Multi-Scanner Analysis**: Combines Semgrep (SAST), Gitleaks (secrets), and Trivy (dependencies)
- **Advanced Cross-File Analysis**: Cross-file attack chain detection with AST parsing and data flow tracing
- **AI-Powered Auto-Remediation**: Automatic GitHub PRs with context-aware code fixes and dependency updates
- **Automatic Compliance**: SBOM generation (CycloneDX & SPDX) in all deployment modes
- **Universal Language Support**: JavaScript/TypeScript, Python, Java, Go, Rust, C#, Ruby, PHP, Swift, Kotlin, and more
- **3 Deployment Modes**: Web interface, CLI, and CI/CD workflows optimized for different use cases
- **Smart Prioritization**: Intelligent vulnerability ranking with business impact analysis

## Quick Start Guide

### Web Interface (Scan locally, push PRs for code fixes)

**Zero-configuration setup:**
```bash
git clone https://github.com/cparnin/AppSecRemediator.git
cd AppSecRemediator
./start_web.sh
# → Automatically opens http://localhost:8000
```

**Manual installation:**
```bash
# 1. Clone and setup environment
git clone https://github.com/cparnin/AppSecRemediator.git
cd AppSecRemediator
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt requirements-web.txt

# 3. Configure API key
cp env.example .env
# Edit .env: OPENAI_API_KEY=sk-your-key-here

# 4. Launch web interface
cd src && python web_app.py
```

**Web Interface Features:**
- **Point-and-Click Scanning**: Drag-and-drop directory selection with real-time progress
- **Interactive Dashboards**: Visual vulnerability reports with filtering and sorting
- **Automatic SBOM Generation**: Compliance files generated and downloadable immediately
- **Business Impact Analysis**: Executive-level summaries with cost estimates

<img width="1019" height="725" alt="web_ui" src="https://github.com/user-attachments/assets/d2000bc7-596a-407e-8a48-e3fed5ae81f2" />

### CLI Mode (Terminal - scan locally, push PRs for code fixes)

**Interactive security analysis:**
```bash
cd src && python main.py
# Follow interactive prompts for repository selection and analysis
```

**CLI Features:**
- **Smart Repository Discovery**: Automatic git repository detection within current directory tree
- **Detailed Cross-File Analysis**: Cross-file vulnerability analysis with attack chain visualization
- **Manual Remediation Control**: Choose specific auto-fix modes (1=SAST+secrets, 2=dependencies, 3=both, 4=skip)
- **Rich Console Output**: Progress bars, color-coded findings, and detailed explanations

<img width="738" height="239" alt="Screenshot 2025-08-01 at 8 24 06 AM" src="https://github.com/user-attachments/assets/93bfff32-f88f-448c-a5b2-62f17dd88fe0" />

### CI/CD Integration (GitHub Action workflow file)

**Drop-in GitHub Actions workflow:**
```bash
# 1. Copy workflow file
cp clients/security-scan.yml .github/workflows/

# 2. Add API key to repository secrets
# GitHub Settings → Secrets → Actions → New repository secret
# Name: OPENAI_API_KEY, Value: sk-your-key-here

# 3. Commit and push
git add .github/workflows/security-scan.yml
git commit -m "Add AppSec AI Scanner workflow"
git push
```

**CI/CD Features:**
- **Automatic Trigger**: Scans on pull requests and main branch pushes
- **Intelligent PR Comments**: Security findings summary with cross-file analysis-enhanced context
- **Separate Auto-Remediation PRs**: Code fixes and dependency updates never mixed
- **Does Not Modify Pipeline Files**: Actions workflows (yml), GitLab, Jenkins, Azure Devops, Bitbucket
- **Artifact Management**: Reports and SBOM files automatically uploaded as workflow artifacts
- **Configurable Thresholds**: Optional fail conditions for critical vulnerabilities

<img width="801" height="136" alt="pr" src="https://github.com/user-attachments/assets/95367709-cc19-486e-a691-cad409acdbd5" />

<img width="1093" height="236" alt="code_fix" src="https://github.com/user-attachments/assets/d82e3f95-6b93-4f84-b5b0-39c1775e160a" />

## Comprehensive Security Coverage

### Core Security Scanners

| Scanner | Coverage | Languages | Auto-Fix Capability |
|---------|----------|-----------|-------------------|
| **Semgrep (SAST)** | SQL injection, XSS, command injection, auth bypass, crypto issues | 15+ languages | ✅ Context-aware code fixes |
| **Gitleaks (Secrets)** | API keys, passwords, tokens, certificates in code/history | Universal | ✅ Secret removal & rotation guidance |
| **Trivy (Dependencies)** | CVEs, outdated packages, license compliance | Universal ecosystems | ✅ Automated version updates |

### Advanced Cross-File Analysis Enhancement

The cross-file analysis integration provides production-ready analysis beyond standard scanning:

**🔗 Cross-File Attack Chain Detection**
- **Multi-Language AST Parsing**: Real code understanding across JavaScript, Python, Java, Go, Rust, C#, Ruby, PHP, Swift, Kotlin
- **Data Flow Tracing**: Follows vulnerability paths from entry points to sensitive operations across files
- **Framework-Aware Analysis**: Specialized detection for Express, React, Vue, Angular, Spring, Django, Flask, Rails, Laravel, ASP.NET

**📊 Business Impact Assessment**
- **Risk Scoring**: Context-aware severity based on file locations and framework usage
- **Cost Estimation**: Remediation time and business impact calculations
- **Executive Summaries**: Non-technical explanations for stakeholder communication

<img width="1124" height="430" alt="business_impact" src="https://github.com/user-attachments/assets/fa298f7d-039b-410f-a99f-e317c574402c" />

**Example Cross-File Analysis Enhancement:**

**Standard Scanner Output:**
```
[semgrep] SQL Injection detected in auth.py:42
Severity: High
```

**Cross-File Analysis Enhanced:**
```
🔴 Critical Authentication Bypass via SQL Injection

CROSS-FILE ATTACK CHAIN:
├── Express route (routes/auth.js:15) → receives user input
├── Middleware validation (middleware/auth.py:42) → bypassed validation  
└── Database query (models/user.py:128) → unparameterized SQL

BUSINESS IMPACT:
• Authentication system compromise affecting 10,000+ users
• Potential data breach with estimated $2.4M impact
• Compliance violations (SOX, GDPR, HIPAA)

REMEDIATION (Auto-fixable):
• Replace string concatenation with parameterized queries
• Add input sanitization in middleware layer
• Implement query result validation
```
<img width="1175" height="457" alt="crossfile_analysis" src="https://github.com/user-attachments/assets/2765e711-1a1d-4366-8d21-f5222966e356" />

## Reports & Compliance

### Security Reports (Generated in All Modes)

**HTML Reports** (`outputs/report.html`):
- **Executive Dashboard**: Risk assessment with business impact metrics
- **Cross-File Analysis Findings**: Cross-file analysis with attack chain visualization  
- **Detailed Vulnerability Data**: CVE IDs, CVSS scores, CWE classifications
- **Remediation Roadmap**: Prioritized action items with time estimates
- **Compliance Mapping**: OWASP Top 10, NIST Framework, SANS 25 coverage

**GitHub Integration** (CI/CD Mode):
- **PR Comments**: Automated security findings summary on pull requests
- **Status Checks**: Configurable pass/fail criteria based on vulnerability severity
- **Artifact Uploads**: Reports and SBOM files attached to workflow runs

### Automatic SBOM Generation

**Standards Compliance** (No manual configuration required):
- **CycloneDX v1.5**: Industry-standard JSON format with vulnerability data
- **SPDX v2.3**: Linux Foundation standard with license compliance details
- **Dependency Metadata**: Package versions, licenses, known vulnerabilities
- **Supply Chain Security**: SLSA compliance and provenance tracking

**Access Methods:**
- **Web Interface**: Direct download buttons in scan results
- **CLI Mode**: Files saved to `outputs/sbom/` directory  
- **CI/CD Mode**: Uploaded as workflow artifacts with 90-day retention

## Configuration & Customization

### Environment Configuration
```bash
# .env file - API Keys
OPENAI_API_KEY=sk-your-key-here          # OpenAI GPT-4 (recommended)
CLAUDE_API_KEY=claude-key-here           # Anthropic Claude (alternative)
AI_PROVIDER=openai                       # 'openai' or 'claude'

# Scanning Configuration  
APPSEC_SCAN_LEVEL=critical-high          # 'critical-high' or 'all'
APPSEC_DEBUG=false                       # Enable debug logging
APPSEC_LOG_LEVEL=INFO                    # DEBUG/INFO/WARNING/ERROR

# Business Configuration
SECURITY_ENGINEER_HOURLY_RATE=150       # For cost estimation calculations
```

### CI/CD Workflow Configuration
```yaml
# .github/workflows/security-scan.yml
uses: cparnin/AppSecRemediator@main
with:
  openai-api-key: ${{ secrets.OPENAI_API_KEY }}
  auto-fix: 'true'                       # Enable automatic remediation
  auto-fix-mode: '3'                     # 1=SAST+secrets, 2=deps, 3=both, 4=skip
  fail-on-critical: 'false'              # Don't break CI by default
  scan-level: 'critical-high'            # Focus on high-impact vulnerabilities
```

### Advanced Scan Modes

**Auto-Fix Mode Selection:**
- **Mode 1**: SAST vulnerabilities + secret flagging (creates 1 PR)
- **Mode 2**: Dependency updates only (creates 1 PR)  
- **Mode 3**: Both SAST and dependencies (creates 2 separate PRs)
- **Mode 4**: Scan only, no auto-remediation

**Scan Level Options:**
- **critical-high** (default): Focus on actionable, high-impact vulnerabilities
- **all**: Include medium and low severity findings for comprehensive analysis

## Architecture & Technical Details

### System Architecture
```
Input: Repository
        ↓
┌─────────────────────────────────────────────────────┐
│ Parallel Scanner Execution (Async)                  │
├─────────────────┬─────────────────┬─────────────────┤
│ Semgrep (SAST)  │ Gitleaks        │ Trivy           │
│ • Code vulns    │ • Secrets       │ • Dependencies  │
│ • 15+ languages │ • Git history   │ • CVE database  │
└─────────────────┴─────────────────┴─────────────────┘
        ↓
┌─────────────────────────────────────────────────────┐
│ Cross-File Analysis Engine                          │
├─────────────────┬─────────────────┬─────────────────┤
│ Parsing         │ Framework       │ Attack Chain    │
│ • Multi-lang    │ Detection       │ Detection       │
│ • Code flow     │ • Express       │ • Data flow     │
│                 │ • Spring        │ • Entry→Sink    │
└─────────────────┴─────────────────┴─────────────────┘
        ↓
┌─────────────────────────────────────────────────────┐
│ AI Enhancement & Auto-Remediation                   │
├─────────────────┬─────────────────┬─────────────────┤
│ GPT-4.1/Claude  │ Code Generation │ PR Creation     │
│ • Context aware │ • Framework     │ • Separate PRs  │
│ • Business      │ specific        │ • Cross-file    │
│   impact        │ • Tested fixes  │                 │
└─────────────────┴─────────────────┴─────────────────┘
        ↓
┌─────────────────────────────────────────────────────┐
│ Outputs                                             │
├─────────────────┬─────────────────┬─────────────────┤
│ HTML Reports    │ GitHub PRs      │ SBOM Files      │
│ • Executive     │ • Auto-fixes    │ • CycloneDX     │
│ • Technical     │ • Descriptions  │ • SPDX          │
│ • Compliance    │ • Status checks │ • Compliance    │
└─────────────────┴─────────────────┴─────────────────┘
```

### Performance Characteristics
- **Scanning Speed**: 60-70% faster than sequential execution via async/await
- **Memory Usage**: Optimized for large repositories with streaming processing
- **API Efficiency**: Batched AI requests with intelligent rate limiting
- **Scalability**: Handles repositories up to 100,000+ files

## Use Cases & Deployment Scenarios

### Security Consultants → CLI Mode
```bash
cd src && python main.py
# Interactive repository selection and detailed analysis
```
**Benefits**: Deep cross-file analysis, manual control, detailed explanations

### Development Teams → Web Interface  
```bash
cd src && python web_app.py
```
**Benefits**: User-friendly UI, team collaboration, visual reports

### Enterprise CI/CD → GitHub Actions
```bash
cp clients/security-scan.yml .github/workflows/
```
**Benefits**: Automated scanning, PR integration, compliance artifacts

### Security Teams → All Modes
- **Assessment Phase**: CLI for deep analysis
- **Team Training**: Web interface for demonstrations  
- **Production**: CI/CD for continuous monitoring

## Integration & Extensibility

### Enterprise Tool Integration (needs testing, as of July 30)
**Enhances Existing Tools** (doesn't replace):
- **SAST Tools**: Snyk, Veracode, Checkmarx, SonarQube
- **Container Scanning**: Twistlock, Aqua Security
- **SIEM Integration**: Splunk, QRadar via JSON exports
- **Ticketing Systems**: Jira, ServiceNow via API

## Project Structure
```
AppSecRemediator/
├── src/                           # Core application
│   ├── main.py                   # CLI entry point
│   ├── web_app.py               # Web interface (Flask)
│   ├── crossfile_analyzer.py    # Cross-file analysis engine
│   ├── crossfile_integration.py # Cross-file analysis enhancement layer
│   ├── scanners/                # Security scanners
│   │   ├── semgrep.py          # SAST scanning
│   │   ├── gitleaks.py         # Secrets detection
│   │   └── trivy.py            # Dependency scanning
│   ├── auto_remediation/        # AI fix generation
│   │   └── remediation.py      # Auto-fix engine
│   └── reporting/              # Report generation
│       ├── html.py             # HTML reports
│       └── templates/          # Report templates
├── clients/                      # Client integration
│   ├── security-scan.yml       # GitHub Actions workflow
│   └── CLIENT_ENGAGEMENT_TEMPLATE.md
├── outputs/                     # Generated reports
│   ├── report.html             # Security analysis report
│   ├── sbom/                   # Compliance files
│   │   ├── sbom.cyclonedx.json
│   │   └── sbom.spdx.json
│   └── raw/                    # Raw scanner outputs
├── action.yml                   # GitHub Action definition
├── README.md                    # This file
├── CHANGELOG.md                 # Version history
├── main_logic.md               # Technical documentation
└── requirements.txt            # Python dependencies
```

## Security & Privacy

### Data Handling
- **Zero Data Retention**: All analysis performed in your environment
- **Local Processing**: Source code never sent to external services (except AI API calls for fixes)
- **API Security**: Only vulnerability descriptions sent to AI providers, never source code
- **Configurable Privacy**: Disable AI features for air-gapped environments

### Permissions & Access
- **Read-Only Repository Access**: Scanner requires only read permissions
- **Minimal CI/CD Permissions**: `contents: write` only for auto-remediation PRs
- **Audit Trail**: All operations logged with structured logging
- **Compliance Ready**: SOC 2, ISO 27001, FedRAMP compatible deployment

## Documentation

- **[Technical Architecture](TECHNICAL_OVERVIEW.md)**: System design and implementation details
- **[Setup Guide](clients/SETUP.md)**: Quick start for GitHub Actions integration  
- **[Changelog](CHANGELOG.md)**: Version history and upgrade notes

## Support & Troubleshooting

### Common Issues
```bash
# Permission issues
chmod +x start_web.sh

# Python dependency conflicts  
python -m venv .venv && source .venv/bin/activate
pip install --upgrade pip

# Scanner binary missing
# Web interface auto-installs, CLI requires manual installation:
# Semgrep: pip install semgrep
# Gitleaks: https://github.com/zricethezav/gitleaks/releases
# Trivy: https://github.com/aquasecurity/trivy/releases
```

### Debug Configuration
```bash
# Enable detailed logging
export APPSEC_DEBUG=true
export APPSEC_LOG_LEVEL=DEBUG

# Check configuration
grep -r "APPSEC_" src/
```

### Getting Help
- **GitHub Issues**: [Report bugs and request features](https://github.com/cparnin/AppSecRemediator/issues)
- **General**: chadparnin@gmail.com

## Usage Analytics

While this repository is temporarily public for CI/CD testing, usage analytics are automatically collected for IP monitoring and licensing compliance. The scanner tracks:

- Scan frequency and modes used
- Platform and environment information  
- Anonymized user identifiers (no sensitive data)
- Feature usage patterns

Analytics are stored locally in `outputs/analytics/` and help improve the software for all users.

---

## Contributing

Contributions welcome! Please:
- Open an issue first for major changes
- Keep PRs focused and well-tested  
- Follow existing code style

*Note: This is a personal project with limited review capacity. Response times may vary.*

---

**OPEN SOURCE SOFTWARE**

This software is released under the MIT License, allowing free use, modification, and distribution. See [LICENSE](LICENSE) for complete terms and conditions.

*© 2025 Chad Parnin - Released under MIT License*

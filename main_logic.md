# AppSec AI Scanner - Technical Architecture & Implementation Guide

## Executive Summary

Enterprise-grade security scanner combining static analysis (SAST), secrets detection, and dependency scanning with AI-powered auto-remediation. Features advanced Model Context Protocol (MCP) integration for cross-file vulnerability analysis across 15+ programming languages with automatic GitHub PR creation.

**Key Capabilities:**
- **Multi-Scanner Architecture**: Parallel execution of Semgrep, Gitleaks, and Trivy
- **MCP Enhanced Analysis**: Cross-file attack chain detection with AST parsing
- **AI-Powered Remediation**: Context-aware code fixes using OpenAI GPT-4 or Anthropic Claude
- **Three Deployment Modes**: CLI, Web interface, and CI/CD integration
- **Automatic Compliance**: SBOM generation in CycloneDX and SPDX formats

## System Architecture Overview

### High-Level Data Flow
```
Repository Input
        ↓
┌─────────────────────────────────────────────────────┐
│ 1. Parallel Scanner Execution (60-70% faster)       │
├─────────────────┬─────────────────┬─────────────────┤
│ Semgrep (SAST)  │ Gitleaks        │ Trivy           │
│ • Code vulns    │ • Secrets       │ • Dependencies  │
│ • 15+ languages │ • Git history   │ • CVE database  │
└─────────────────┴─────────────────┴─────────────────┘
        ↓
┌─────────────────────────────────────────────────────┐
│ 2. MCP Cross-File Analysis Engine                   │
├─────────────────┬─────────────────┬─────────────────┤
│ AST Parsing     │ Framework       │ Attack Chain    │
│ • Multi-lang    │ Detection       │ Detection       │
│ • Data flow     │ • Express       │ • Entry→Sink    │
│ • Import graph  │ • Spring/Django │ • Cross-file    │
└─────────────────┴─────────────────┴─────────────────┘
        ↓
┌─────────────────────────────────────────────────────┐
│ 3. AI Enhancement & Auto-Remediation                │
├─────────────────┬─────────────────┬─────────────────┤
│ GPT-4/Claude    │ Code Generation │ PR Creation     │
│ • Context aware │ • Framework     │ • Separate PRs  │
│ • Business      │ specific        │ • MCP context   │
│   impact        │ • Tested fixes  │ • Auto-merge    │
└─────────────────┴─────────────────┴─────────────────┘
        ↓
┌─────────────────────────────────────────────────────┐
│ 4. Outputs & Reports                                │
├─────────────────┬─────────────────┬─────────────────┤
│ HTML Reports    │ GitHub PRs      │ SBOM Files      │
│ • Executive     │ • Auto-fixes    │ • CycloneDX     │
│ • Technical     │ • Descriptions  │ • SPDX          │
│ • Compliance    │ • Status checks │ • Compliance    │
└─────────────────┴─────────────────┴─────────────────┘
```

## Core Components & Implementation Details

### 1. Scanner Execution Engine (`src/main.py:300-400`)

**Location**: `run_security_scans_async()` function

```python
# Parallel scanner execution using asyncio
async def run_security_scans_async(repo_path: str, scanners_to_run: List[str], output_dir: Path):
    scanner_tasks = []
    
    # Create async tasks for each scanner
    if "semgrep" in scanners_to_run:
        scanner_tasks.append(asyncio.to_thread(run_semgrep, repo_path, str(output_dir / "raw")))
    if "gitleaks" in scanners_to_run:
        scanner_tasks.append(asyncio.to_thread(run_gitleaks, repo_path, str(output_dir / "raw")))
    if "trivy" in scanners_to_run:
        scanner_tasks.append(asyncio.to_thread(run_trivy_scan, repo_path, str(output_dir / "raw")))
    
    # Execute all scanners in parallel
    results = await asyncio.gather(*scanner_tasks, return_exceptions=True)
```

**Security Scanner Details:**

| Scanner | Purpose | Implementation | Output Format |
|---------|---------|----------------|---------------|
| **Semgrep** | SAST analysis across 15+ languages | `src/scanners/semgrep.py` | JSON with path, line, severity, check_id |
| **Gitleaks** | Secrets detection in code/git history | `src/scanners/gitleaks.py` | JSON with secret type, location, entropy |
| **Trivy** | Dependency vulnerabilities and CVEs | `src/scanners/trivy.py` | JSON with CVE, CVSS, fixed_version |

**Performance Optimization:**
- **Async Execution**: 60-70% performance improvement over sequential scanning
- **Git-Aware Scanning**: Only scans changed files for incremental analysis
- **Resource Management**: Timeout handling and memory optimization for large repositories

### 2. MCP Cross-File Analysis Engine (`src/mcp_server.py:100-200`)

**Location**: `CrossFileAnalyzer` class

```python
class CrossFileAnalyzer:
    """Advanced static analysis with AST parsing for vulnerability detection"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.import_graph = {}          # File dependency mapping
        self.entry_points = []          # User input entry points
        self.sensitive_sinks = []       # Sensitive operations
        self.file_analysis_cache = {}   # Performance optimization
```

**MCP Analysis Capabilities:**

**Multi-Language AST Parsing** (`src/mcp_server.py:250-350`):
- **JavaScript/TypeScript**: Node.js, React, Vue, Angular applications
- **Python**: Django, Flask, FastAPI frameworks
- **Java**: Spring, Spring Boot, traditional Java applications
- **Go**: Gin, Echo, native HTTP applications
- **Rust**: Actix, Rocket web frameworks
- **C#**: ASP.NET, .NET Core applications
- **Ruby**: Rails, Sinatra applications
- **PHP**: Laravel, Symfony, native PHP
- **Swift**: iOS/macOS native applications
- **Kotlin**: Android, server-side applications

**Framework Detection Algorithm** (`src/mcp_server.py:400-500`):
```python
def detect_frameworks(self) -> Dict[str, List[str]]:
    """Automatically detect web frameworks and libraries"""
    frameworks = {
        'web_frameworks': [],
        'frontend_frameworks': [],
        'libraries': []
    }
    
    # Package.json analysis for Node.js
    if (self.repo_path / 'package.json').exists():
        # Detect Express, React, Vue, Angular, etc.
    
    # Requirements.txt analysis for Python  
    if (self.repo_path / 'requirements.txt').exists():
        # Detect Django, Flask, FastAPI, etc.
        
    # Additional framework detection logic...
```

**Attack Chain Detection** (`src/mcp_server.py:600-700`):
```python
def find_attack_chains(self, vulnerability_type: str = None) -> List[AttackChain]:
    """Trace vulnerability paths across multiple files"""
    chains = []
    
    for entry_point in self.entry_points:
        for sink in self.sensitive_sinks:
            # DFS traversal through import graph
            path = self._find_path_between(entry_point, sink)
            if path and self._validates_attack_chain(path, vulnerability_type):
                chains.append(AttackChain(entry_point, sink, path))
    
    return sorted(chains, key=lambda x: x.severity, reverse=True)
```

### 3. AI Enhancement & Auto-Remediation (`src/auto_remediation/remediation.py:150-300`)

**Location**: `AutoRemediator` class

```python
class AutoRemediator:
    """AI-powered automatic vulnerability remediation"""
    
    def __init__(self, ai_provider: str, api_key: str, model: Optional[str] = None):
        self.ai_provider = ai_provider.lower()  # 'openai' or 'claude'
        self.api_key = api_key
        self.model = model
        self._initialize_ai_client()
```

**Remediable Vulnerability Patterns** (`src/auto_remediation/remediation.py:220-260`):
```python
remediable_patterns = [
    # Injection vulnerabilities
    'injection', 'sql-injection', 'nosql', 'command-injection',
    'child-process', 'exec', 'shell-injection',
    
    # XSS vulnerabilities  
    'xss', 'explicit-unescape', 'template-explicit-unescape',
    
    # Path traversal
    'path-traversal', 'directory-traversal',
    
    # JWT and crypto vulnerabilities
    'jwt', 'jwt-none-alg', 'hardcoded-secret', 'weak-crypto',
    
    # Session/cookie security
    'session-hardcoded-secret', 'express-session',
    
    # Transport security
    'http-server', 'insecure-transport',
    
    # Container security
    'dockerfile', 'missing-user', 'docker-user'
]
```

**AI Fix Generation Process** (`src/auto_remediation/remediation.py:280-350`):
```python
def generate_code_fix(self, finding: Dict[str, Any], repo_path: str) -> Optional[Dict[str, Any]]:
    """Generate context-aware code fixes using AI"""
    
    # 1. Extract vulnerability context
    file_path = finding.get('path', '')
    line_number = finding.get('start', {}).get('line', 0)
    
    # 2. Get code context (5 lines before/after)
    context_lines = self._get_code_context(file_path, line_number)
    
    # 3. Generate AI prompt with context
    if self.ai_provider == 'openai':
        prompt = self._get_openai_prompt(check_id, message, file_path, line_number, context_str)
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.1  # Low temperature for consistent fixes
        )
        fix = response.choices[0].message.content.strip()
    elif self.ai_provider == 'claude':
        prompt = self._get_claude_prompt(check_id, message, file_path, line_number, context_str)
        response = self.client.messages.create(
            model=self.model,
            max_tokens=200,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}]
        )
        fix = response.content[0].text.strip()
    
    # 4. Return structured fix
    return {
        'file_path': file_path,
        'line_number': line_number,
        'original_line': problematic_line,
        'fixed_line': fix,
        'vulnerability_type': check_id,
        'description': message
    }
```

**AI Prompt Templates** (`src/auto_remediation/remediation.py:342-397`):

**OpenAI Prompt Template:**
```python
def _get_openai_prompt(self, check_id, message, file_path, line_number, context_str):
    return f"""
You are a security expert. Fix this security vulnerability in the code.

Vulnerability: {check_id}
Description: {message}
File: {file_path}
Line {line_number} needs to be fixed.

Code context:
{context_str}

IMPORTANT: Return ONLY the exact replacement code for line {line_number}. 
Do not include:
- Line numbers
- Markdown formatting
- Code blocks
- Comments
- Extra text

Just return the corrected JavaScript/code line that should replace line {line_number}.

Example:
If line 39 is: User.find({{ username: req.body.username }}, callback)
Return: User.find({{ username: validator.escape(req.body.username) }}, callback)

Corrected line {line_number}:"""
```

**Claude Prompt Template:**
```python
def _get_claude_prompt(self, check_id, message, file_path, line_number, context_str):
    return f"""
You are an expert security engineer. Your task is to provide a single-line code fix for a security vulnerability.

**Vulnerability Details:**
- **Type:** {check_id}
- **Description:** {message}
- **File:** {file_path}
- **Line:** {line_number} (The line to be replaced)

**Code Context:**
```
{context_str}
```

**Instructions:**
Based on the vulnerability and code context, provide the corrected line of code for line {line_number}.

**IMPORTANT:**
- Return **only** the single, corrected line of code.
- Do **not** include the line number, markdown formatting (e.g., ```), code blocks, or any explanatory text.
- The output must be the raw code that will directly replace the original line.

**Example:**
If the original line is `User.find({{ username: req.body.username }})`, the corrected output should be `User.find({{ username: validator.escape(req.body.username) }})`.

**Corrected Code:**
"""
```

**GitHub PR Creation** (`src/auto_remediation/remediation.py:700-800`):
```python
def create_pull_request(self, repo_path: str, branch_name: str, findings: List[Dict], fixes: List[Dict]) -> Optional[str]:
    """Create GitHub PR with MCP-enhanced context"""
    
    # 1. Generate PR title and description with MCP context
    title = f"🔒 Security fixes: {len(fixes)} vulnerabilities addressed"
    description = self._generate_pr_description(findings, fixes)
    
    # 2. Use GitHub API to create PR
    pr_data = {
        "title": title,
        "body": description,
        "head": branch_name,
        "base": "main"  # or detect default branch
    }
    
    # 3. Create PR and return URL
    response = requests.post(f"{github_api_url}/pulls", json=pr_data, headers=headers)
    return response.json().get('html_url')
```

### 4. Report Generation & Compliance (`src/reporting/html.py:50-150`)

**Location**: `generate_html_report()` function

```python
def generate_html_report(findings: List[Dict], ai_summary: str, output_dir: str, repo_path: str):
    """Generate comprehensive HTML security report"""
    
    # 1. Process findings with MCP enhancement
    enhanced_findings = process_mcp_findings(findings)
    
    # 2. Generate executive summary with business impact
    executive_summary = generate_executive_summary(enhanced_findings)
    
    # 3. Create detailed technical sections
    technical_details = generate_technical_details(enhanced_findings)
    
    # 4. Generate compliance mapping
    compliance_data = generate_compliance_mapping(enhanced_findings)
    
    # 5. Render HTML template
    template = env.get_template("report.html")
    html_content = template.render(
        findings=enhanced_findings,
        executive_summary=executive_summary,
        technical_details=technical_details,
        compliance_data=compliance_data,
        ai_summary=ai_summary,
        scan_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        repo_path=repo_path
    )
```

**Automatic SBOM Generation** (`src/sbom_generator.py:100-200`):
```python
async def generate_repository_sbom(repo_path: str, output_dir: str):
    """Generate Software Bill of Materials in multiple formats"""
    
    # 1. Use Syft for dependency extraction
    cyclonedx_result = await run_syft_scan(repo_path, "cyclonedx-json")
    spdx_result = await run_syft_scan(repo_path, "spdx-json")
    
    # 2. Enhance with vulnerability data from Trivy
    enhanced_cyclonedx = enhance_sbom_with_vulnerabilities(cyclonedx_result)
    enhanced_spdx = enhance_sbom_with_vulnerabilities(spdx_result)
    
    # 3. Save both formats
    save_sbom_file(enhanced_cyclonedx, f"{output_dir}/sbom.cyclonedx.json")
    save_sbom_file(enhanced_spdx, f"{output_dir}/sbom.spdx.json")
```

## Deployment Mode Implementations

### 1. CLI Mode (`src/main.py:720-800`)

**Interactive Flow:**
```python
def main():
    """Interactive security analysis for consultants"""
    
    # 1. Show menu and get user choice
    choice = show_interactive_menu()
    
    # 2. Repository selection with smart discovery
    repo_path = select_repository()
    
    # 3. Run comprehensive analysis
    all_findings = run_security_scans(repo_path, ["semgrep", "gitleaks", "trivy"], output_dir)
    
    # 4. MCP enhancement
    enhanced_findings = await enhance_findings_with_mcp(all_findings, repo_path)
    
    # 5. Generate reports and handle remediation
    generate_html_report(enhanced_findings, ai_summary, str(output_dir), repo_path)
    handle_auto_remediation(repo_path, enhanced_findings)
```

### 2. Web Interface (`src/web_app.py:80-150`)

**Flask Application:**
```python
@app.route('/scan', methods=['POST'])
def scan_repository():
    """Web-based scanning with real-time progress"""
    
    # 1. Validate input and extract repo path
    repo_path = request.json.get('repo_path')
    scan_level = request.json.get('scan_level', 'critical-high')
    
    # 2. Run scanners asynchronously
    all_findings = asyncio.run(run_security_scans_async(repo_path, ["semgrep", "gitleaks", "trivy"], output_dir))
    
    # 3. Auto-generate SBOM for compliance
    asyncio.run(generate_repository_sbom(repo_path, str(output_dir / "sbom")))
    
    # 4. Return results with download links
    return jsonify({
        'status': 'success',
        'findings': all_findings,
        'report_url': '/reports/report.html',
        'sbom_cyclonedx_url': '/reports/sbom.cyclonedx.json',
        'sbom_spdx_url': '/reports/sbom.spdx.json'
    })
```

### 3. CI/CD Integration (`action.yml` + `src/main.py:410-500`)

**GitHub Actions Workflow:**
```yaml
# action.yml
runs:
  using: composite
  steps:
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install Dependencies
      shell: bash
      run: |
        cd ${{ github.action_path }}/src
        pip install -r ../requirements.txt
    
    - name: Run AppSec Scanner
      shell: bash
      env:
        AI_PROVIDER: ${{ inputs.ai-provider }}
        OPENAI_API_KEY: ${{ inputs.openai-api-key }}
        CLAUDE_API_KEY: ${{ inputs.claude-api-key }}
        APPSEC_AUTO_FIX: ${{ inputs.auto-fix }}
        APPSEC_AUTO_FIX_MODE: ${{ inputs.auto-fix-mode }}
      run: |
        cd ${{ github.action_path }}/src
        python main.py
```

**Auto Mode Implementation** (`src/main.py:410-500`):
```python
def run_auto_mode() -> List[Dict[str, Any]]:
    """CI/CD optimized scanning with automatic outputs"""
    
    # 1. Detect environment and repo path
    if is_github_actions():
        repo_path = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    
    # 2. Run scanners with CI/CD optimizations
    all_findings = run_security_scans(repo_path, ["semgrep", "gitleaks", "trivy"], output_dir)
    
    # 3. MCP enhancement (same as other modes)
    enhanced_findings = asyncio.run(enhance_findings_with_mcp(all_findings, repo_path))
    
    # 4. Auto-generate reports and SBOM
    generate_html_report(enhanced_findings, ai_summary, str(output_dir), repo_path)
    asyncio.run(generate_repository_sbom(repo_path, str(output_dir / "sbom")))
    
    # 5. Handle auto-remediation based on environment variables
    handle_auto_remediation(repo_path, enhanced_findings)
    
    return enhanced_findings
```

## Configuration & Environment Management

### Environment Variables (`src/config.py`)

```python
# AI Configuration
AI_PROVIDER = os.getenv('AI_PROVIDER', 'openai')          # 'openai' or 'claude'
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')              # OpenAI API key
CLAUDE_API_KEY = os.getenv('CLAUDE_API_KEY')              # Anthropic API key
AI_MODEL = os.getenv('AI_MODEL', 'gpt-4-1106-preview')   # AI model selection

# Scanning Configuration
APPSEC_SCAN_LEVEL = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')  # 'critical-high' or 'all'
APPSEC_DEBUG = os.getenv('APPSEC_DEBUG', 'false')                    # Debug logging
APPSEC_LOG_LEVEL = os.getenv('APPSEC_LOG_LEVEL', 'INFO')            # Log level

# Auto-Remediation Configuration  
APPSEC_AUTO_FIX = os.getenv('APPSEC_AUTO_FIX', 'false')             # Enable auto-fix
APPSEC_AUTO_FIX_MODE = os.getenv('APPSEC_AUTO_FIX_MODE', '')        # 1=SAST+secrets, 2=deps, 3=both, 4=skip

# Business Configuration
SECURITY_ENGINEER_HOURLY_RATE = os.getenv('SECURITY_ENGINEER_HOURLY_RATE', '150')  # Cost calculations

# Performance Configuration
SEMGREP_TIMEOUT = int(os.getenv('SEMGREP_TIMEOUT', '300'))           # Semgrep timeout (seconds)
GITLEAKS_TIMEOUT = int(os.getenv('GITLEAKS_TIMEOUT', '120'))         # Gitleaks timeout (seconds)
TRIVY_TIMEOUT = int(os.getenv('TRIVY_TIMEOUT', '300'))               # Trivy timeout (seconds)
```

### Security Configuration (`src/main.py:80-150`)

```python
def validate_environment_config() -> Dict[str, Any]:
    """Comprehensive environment validation with security checks"""
    
    # 1. Validate timeouts (prevent DoS)
    timeout_vars = {
        'SEMGREP_TIMEOUT': (300, 60, 1800),  # (default, min, max)
        'GITLEAKS_TIMEOUT': (120, 30, 600),
        'TRIVY_TIMEOUT': (300, 60, 1800)
    }
    
    # 2. Validate AI provider and model
    ai_provider = os.getenv('AI_PROVIDER', 'openai').strip().lower()
    if ai_provider not in ['openai', 'claude']:
        raise ValueError(f"Unsupported AI provider: {ai_provider}")
    
    # 3. Validate API keys (format check, no logging)
    api_key = os.getenv('OPENAI_API_KEY' if ai_provider == 'openai' else 'CLAUDE_API_KEY')
    if not api_key or len(api_key) < 10:
        raise ValueError(f"Invalid {ai_provider} API key")
    
    # 4. Validate scan level
    scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high').strip().lower()
    if scan_level not in ['critical-high', 'all']:
        raise ValueError(f"Invalid scan level: {scan_level}")
    
    return validated_config
```

## Error Handling & Logging (`src/logging_config.py`)

### Structured Logging Implementation

```python
def setup_logging(level: str = "INFO", log_file: str = None) -> None:
    """Configure structured logging with security considerations"""
    
    # 1. Create structured formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 2. Console handler with color coding
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # 3. File handler for persistent logs (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
    
    # 4. Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    root_logger.addHandler(console_handler)
```

### Exception Classes (`src/exceptions.py`)

```python
class ScannerError(Exception):
    """Base exception for scanner-related errors"""
    def __init__(self, message: str, scanner: str = None, details: dict = None):
        super().__init__(message)
        self.scanner = scanner
        self.details = details or {}

class ValidationError(ScannerError):
    """Input validation errors"""
    pass

class ScanExecutionError(ScannerError):
    """Scanner execution errors"""
    pass

class BinaryNotFoundError(ScannerError):
    """Required binary not found"""
    pass
```

## Performance Optimization Strategies

### 1. Async/Await Implementation
- **60-70% performance improvement** over sequential execution
- **Parallel scanner execution** using `asyncio.gather()`
- **Resource management** with proper timeout handling

### 2. Caching Mechanisms
- **File analysis caching** in MCP engine to avoid re-parsing
- **Import graph caching** for faster cross-file analysis
- **AST parsing caching** for large files

### 3. Memory Management
- **Streaming processing** for large repositories
- **Lazy loading** of file contents
- **Garbage collection** optimization for long-running scans

### 4. Git-Aware Scanning
- **Incremental scanning** for changed files only
- **Git history optimization** for faster secrets detection
- **Branch-aware analysis** for PR-specific scanning

## Security Implementation Details

### 1. Input Validation (`src/scanners/validation.py`)

```python
def validate_binary_path(binary_path: str, expected_name: str) -> Optional[str]:
    """Secure binary path validation"""
    
    # 1. Input sanitization
    if not binary_path or not isinstance(binary_path, str):
        raise ValidationError("Binary path must be a non-empty string")
    
    # 2. Path traversal protection
    clean_path = os.path.normpath(binary_path)
    if '..' in clean_path or clean_path != binary_path:
        raise ValidationError("Path traversal attempt detected")
    
    # 3. Executable validation
    if not os.path.isfile(clean_path) or not os.access(clean_path, os.X_OK):
        raise BinaryNotFoundError(f"Binary not found or not executable: {clean_path}")
    
    return clean_path
```

### 2. Secure File Operations

```python
def _secure_read_file(file_path: str, max_size: int = 1024*1024) -> Optional[str]:
    """Secure file reading with size limits"""
    
    try:
        # 1. Check file size to prevent memory exhaustion
        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            logger.warning(f"File too large: {file_path} ({file_size} bytes)")
            return None
        
        # 2. Read with encoding detection
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    
    except (IOError, OSError, UnicodeDecodeError) as e:
        logger.error(f"Failed to read file {file_path}: {e}")
        return None
```

### 3. API Security

```python
def _create_ai_prompt(self, vulnerability_data: Dict[str, Any]) -> str:
    """Create AI prompts with data sanitization"""
    
    # 1. Extract only necessary information (never full source code)
    safe_data = {
        'vulnerability_type': vulnerability_data.get('check_id', ''),
        'description': vulnerability_data.get('message', ''),
        'file_extension': Path(vulnerability_data.get('path', '')).suffix,
        'line_context': vulnerability_data.get('context_lines', [])[:5]  # Limit context
    }
    
    # 2. Sanitize sensitive information
    for key, value in safe_data.items():
        if isinstance(value, str):
            # Remove potential API keys, secrets, etc.
            safe_data[key] = re.sub(r'[A-Za-z0-9+/]{20,}', '[REDACTED]', value)
    
    return prompt_template.format(**safe_data)
```

## Deployment Considerations

### 1. Environment Requirements
- **Python 3.9+** with virtual environment
- **Git** for repository operations
- **Scanner binaries**: Semgrep, Gitleaks, Trivy
- **Network access** for AI API calls
- **GitHub token** for PR creation (CI/CD mode)

### 2. Resource Requirements
- **Memory**: 2GB minimum, 4GB recommended for large repositories
- **CPU**: 2 cores minimum for parallel scanning
- **Disk**: 1GB for dependencies, variable for scan outputs
- **Network**: Stable connection for AI API calls

### 3. Security Considerations
- **API key management** using environment variables
- **Minimal permissions** for repository access
- **Audit logging** for all operations
- **Network security** for AI API communications

This technical architecture provides enterprise-grade security analysis with comprehensive vulnerability detection, intelligent remediation, and seamless integration across multiple deployment modes.
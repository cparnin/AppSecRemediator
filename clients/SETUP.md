# AppSec Scanner Setup

AI-powered security scanner that works with any programming language. Finds vulnerabilities and creates GitHub PRs with fixes.

## Quick Setup

### 1. Add Workflow
```bash
cp security-scan.yml .github/workflows/
```

### 2. Add API Key
Go to repository Settings → Secrets → Add:
- Name: `OPENAI_API_KEY` 
- Value: `sk-your-key-here`

### 3. Commit and Push
```bash
git add .github/workflows/security-scan.yml
git commit -m "Add security scanning"
git push
```

## What You Get
- **Automated security scanning** on every PR
- **AI-generated fixes** for vulnerabilities
- **Separate PRs** for code fixes and dependency updates
- **HTML reports** with business impact analysis
- **Automatic SBOM generation** (CycloneDX & SPDX formats) for compliance
- **Downloadable artifacts** including security reports and SBOM files

## Configuration
Add to `.github/workflows/security-scan.yml`:
```yaml
with:
  scan-level: 'critical-high'    # Focus on important issues
  auto-fix: 'true'               # Generate fix PRs
  fail-on-critical: 'false'      # Don't break CI
```

## Features
**Multi-Language Support**:
- JavaScript, Python, Java, Go, Rust, C#, Ruby, PHP, Swift, and more
- Detects frameworks: Express, Spring, Django, Rails, Laravel, ASP.NET
- Finds cross-file vulnerabilities and attack chains

**Compliance & Reporting**:
- **SBOM auto-generation**: No manual configuration required
- **GitHub Actions artifacts**: All reports and SBOM files automatically uploaded  
- **HTML reports**: Business impact analysis with downloadable SBOM links
- **Zero configuration**: Works out-of-the-box with any repository
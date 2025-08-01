#!/usr/bin/env python3
"""
AppSec AI Scanner - Web Interface

🔒 Web wrapper for the AppSec AI Scanner that preserves all existing functionality.

This creates web endpoints that call the exact same functions as the CLI version,
ensuring identical behavior and maintaining all security features.

Usage:
    python web_app.py              # Start web server
    curl -X POST /scan             # API endpoint
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify, send_file, abort, render_template
from flask_cors import CORS
import tempfile
import shutil
import logging

# Add src directory to path so we can import existing modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import ALL existing functionality (no changes to existing code)  
from main import (
    validate_repo_path, 
    validate_environment_config,
    run_security_scans,
    handle_auto_remediation,
    track_usage
)
from reporting.html import generate_html_report

# Configure logging for web app
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app with template directory
app = Flask(__name__, template_folder='templates')
CORS(app)  # Enable CORS for web UI integration

# Global config (same as CLI)
WEB_CONFIG = None

def init_web_config():
    """Initialize configuration using existing validation function."""
    global WEB_CONFIG
    if WEB_CONFIG is None:
        WEB_CONFIG = validate_environment_config()
    return WEB_CONFIG

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for deployment monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'AppSec AI Scanner Web API',
        'version': '1.0.0'
    })

@app.route('/config', methods=['GET'])
def get_config():
    """Get current scanner configuration."""
    try:
        config = init_web_config()
        # Return safe config info (no API keys)
        safe_config = {
            'ai_provider': config.get('ai_provider'),
            'scan_level': config.get('scan_level'),
            'auto_fix_enabled': config.get('auto_fix', False),
            'scanners_available': ['semgrep', 'gitleaks', 'trivy']
        }
        return jsonify(safe_config)
    except Exception as e:
        logger.error(f"Config error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan', methods=['POST'])
def scan_repository():
    """
    Main scanning endpoint that calls existing CLI functions.
    
    Request body:
    {
        "repo_path": "/path/to/repository",
        "scan_level": "critical-high" | "all" (optional),
        "auto_fix": true | false (optional)
    }
    """
    try:
        # Parse request
        data = request.get_json()
        if not data or 'repo_path' not in data:
            return jsonify({'error': 'repo_path is required'}), 400
            
        repo_path = data['repo_path']
        scan_level = data.get('scan_level', 'critical-high')
        auto_fix = data.get('auto_fix', False)
        
        # Validate repository path using existing function
        try:
            validated_path = validate_repo_path(repo_path)
        except (ValueError, PermissionError) as e:
            return jsonify({'error': f'Invalid repository path: {str(e)}'}), 400
            
        # Set environment variables for this scan
        original_scan_level = os.environ.get('APPSEC_SCAN_LEVEL')
        original_auto_fix = os.environ.get('APPSEC_AUTO_FIX')
        
        os.environ['APPSEC_SCAN_LEVEL'] = scan_level
        os.environ['APPSEC_AUTO_FIX'] = str(auto_fix).lower()
        
        try:
            # Track usage for IP monitoring  
            track_usage()
            
            # Initialize config
            config = init_web_config()
            
            # Create clean output directory (same location as CLI)
            script_dir = Path(__file__).parent.parent  # Go up from src/ to root
            # If we're running from src/, go up one more level to reach the project root
            if script_dir.name == 'src':
                script_dir = script_dir / '..'
            script_dir = script_dir.resolve()  # Resolve any .. references
            output_dir = script_dir / "outputs"
            
            # Clean old scan results to prevent showing stale data
            if output_dir.exists():
                import shutil
                try:
                    shutil.rmtree(output_dir)
                except Exception as e:
                    logger.warning(f"Could not clean output directory: {e}")
            
            # Recreate clean directory
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Run scanning logic
            print(f"🔍 Starting scan of {validated_path}")
            
            # Use existing scanning function with default scanners
            scanners_to_run = ['semgrep', 'gitleaks', 'trivy']
            all_findings = run_security_scans(str(validated_path), scanners_to_run, output_dir)
            
            # Add MCP enhancement like CLI mode does
            enhanced_findings = all_findings
            try:
                from mcp_integration import enhance_findings_with_mcp
                if all_findings:
                    print("🧠 Running MCP enhancement analysis...")
                    enhanced_findings = asyncio.run(enhance_findings_with_mcp(all_findings, str(validated_path)))
                    print(f"✅ MCP enhanced {len(enhanced_findings)} findings with context analysis")
            except ImportError:
                print("⚠️ MCP integration not available")
            except Exception as e:
                print(f"⚠️ MCP enhancement failed: {e}")
                enhanced_findings = all_findings
            
            # Generate reports using existing functions
            html_report_path = None
            if enhanced_findings:
                # Generate detailed AI summary like CLI does (use enhanced findings for stats)
                summary_stats = {
                    'total': len(enhanced_findings),
                    'critical': len([f for f in enhanced_findings if f.get('severity', '').lower() == 'critical']),
                    'high': len([f for f in enhanced_findings if f.get('severity', '').lower() in ['high', 'error']]),
                    'sast': len([f for f in enhanced_findings if f.get('tool') == 'semgrep']),
                    'secrets': len([f for f in enhanced_findings if f.get('tool') == 'gitleaks']),
                    'deps': len([f for f in enhanced_findings if f.get('tool') == 'trivy'])
                }
                ai_summary = f"""🛡️ Security Analysis Complete

**Risk Assessment:** {'🔴 High Risk' if summary_stats['critical'] > 0 else '🟡 Medium Risk' if summary_stats['high'] > 0 else '🟢 Low Risk'}

**Key Findings:**
• {summary_stats['total']} total security issues identified
• {summary_stats['critical']} critical vulnerabilities requiring immediate attention
• {summary_stats['high']} high-severity issues needing prompt remediation
• {summary_stats['sast']} code security issues (SAST)
• {summary_stats['secrets']} secrets detected in repository
• {summary_stats['deps']} vulnerable dependencies identified

**Recommended Actions:**
1. Prioritize critical vulnerabilities for immediate patching
2. Review and rotate any exposed secrets
3. Update vulnerable dependencies to latest secure versions
4. Implement security code review practices"""

                html_report_path = generate_html_report(enhanced_findings, ai_summary, str(output_dir), str(validated_path))
                
                # Generate PR summary like CLI does
                try:
                    pr_summary_path = output_dir / "pr-findings.txt"
                    with open(pr_summary_path, 'w') as f:
                        f.write(f"Security Scan Results for {validated_path.name}\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(ai_summary)
                        if summary_stats['total'] > 0:
                            f.write("\n\nDetailed Findings:\n")
                            for i, finding in enumerate(enhanced_findings[:10], 1):  # Limit to top 10
                                f.write(f"{i}. {finding.get('extra', {}).get('message', 'Security issue')} ")
                                f.write(f"({finding.get('severity', 'unknown')} - {finding.get('tool', 'scanner')})\n")
                except Exception as e:
                    logger.warning(f"Could not generate PR summary: {e}")
            else:
                ai_summary = "🎉 Security scan completed successfully with no critical or high-severity issues found."
                html_report_path = generate_html_report([], ai_summary, str(output_dir), str(validated_path))
            
            # Generate SBOM for all web scans (regardless of findings)
            try:
                from sbom_generator import generate_repository_sbom
                print("🔧 Generating SBOM...")
                sbom_result = asyncio.run(generate_repository_sbom(str(validated_path), str(output_dir / "sbom")))
                print("✅ SBOM generated successfully")
                logger.info(f"SBOM generation results: {sbom_result}")
            except ImportError as e:
                logger.error(f"SBOM generator module not found: {e}")
            except Exception as e:
                logger.error(f"SBOM generation failed: {e}")
                # Continue with scan even if SBOM fails
            
            # Handle auto-remediation non-interactively 
            remediation_results = None
            if auto_fix and all_findings:
                # Get auto_fix_mode from request data (sent from frontend form)
                auto_fix_mode = data.get('auto_fix_mode', '3')  # Default to both if not specified
                
                # Set environment variables for non-interactive mode
                os.environ['APPSEC_WEB_MODE'] = 'true'
                os.environ['APPSEC_AUTO_FIX_MODE'] = str(auto_fix_mode)
                try:
                    print(f"🔧 Starting auto-remediation...")
                    remediation_results = handle_auto_remediation(str(validated_path), all_findings)
                    print("✅ Auto-remediation completed")
                except Exception as e:
                    logger.error(f"Auto-remediation failed: {e}")
                    remediation_results = f"Auto-remediation failed: {str(e)}"
                finally:
                    # Clean up environment variables
                    if 'APPSEC_WEB_MODE' in os.environ:
                        del os.environ['APPSEC_WEB_MODE']
                    if 'APPSEC_AUTO_FIX_MODE' in os.environ:
                        del os.environ['APPSEC_AUTO_FIX_MODE']
            
            # Prepare response
            response = {
                'success': True,
                'scan_summary': {
                    'total_findings': len(all_findings),
                    'critical_findings': len([f for f in all_findings if f.get('severity') == 'critical']),
                    'high_findings': len([f for f in all_findings if f.get('severity') == 'high']),
                    'repository_path': str(validated_path),
                    'scan_level': scan_level,
                    'auto_fix_enabled': auto_fix
                },
                'findings': all_findings,
                'html_report_available': html_report_path is not None,
                'remediation_applied': remediation_results is not None
            }
            
            if remediation_results:
                response['remediation_summary'] = remediation_results
                
            logger.info(f"✅ Web scan completed: {len(all_findings)} findings")
            return jsonify(response)
            
        finally:
            # Restore original environment variables
            if original_scan_level:
                os.environ['APPSEC_SCAN_LEVEL'] = original_scan_level
            elif 'APPSEC_SCAN_LEVEL' in os.environ:
                del os.environ['APPSEC_SCAN_LEVEL']
                
            if original_auto_fix:
                os.environ['APPSEC_AUTO_FIX'] = original_auto_fix
            elif 'APPSEC_AUTO_FIX' in os.environ:
                del os.environ['APPSEC_AUTO_FIX']
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/report', methods=['GET'])
def get_html_report():
    """Serve the generated HTML report."""
    try:
        # Calculate script directory - handle both running from root and from src/
        script_dir = Path(__file__).parent.parent
        # If we're running from src/, go up one more level to reach the project root
        if script_dir.name == 'src':
            script_dir = script_dir / '..'
        script_dir = script_dir.resolve()  # Resolve any .. references
        report_path = script_dir / "outputs" / "report.html"
        if not report_path.exists():
            return jsonify({'error': 'No report available. Run a scan first.'}), 404
            
        response = send_file(report_path, as_attachment=False, mimetype='text/html')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logger.error(f"Report error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/reports/<filename>', methods=['GET'])
def get_report_file(filename):
    """Serve specific report files (JSON, SBOM, etc.)."""
    try:
        # Security: Only allow specific file types
        allowed_files = {
            'semgrep.json', 'gitleaks.json', 'trivy-sca.json',
            'sbom.cyclonedx.json', 'sbom.spdx.json', 'pr-findings.txt'
        }
        
        if filename not in allowed_files:
            return jsonify({'error': 'File not allowed'}), 403
            
        # Calculate script directory - handle both running from root and from src/
        script_dir = Path(__file__).parent.parent
        # If we're running from src/, go up one more level to reach the project root
        if script_dir.name == 'src':
            script_dir = script_dir / '..'
        script_dir = script_dir.resolve()  # Resolve any .. references
        
        if filename.endswith('.json') and not filename.startswith('sbom'):
            file_path = script_dir / "outputs" / "raw" / filename
        elif filename.startswith('sbom'):
            file_path = script_dir / "outputs" / "sbom" / filename
        else:
            file_path = script_dir / "outputs" / filename
            
        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404
            
        response = send_file(file_path, as_attachment=True)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logger.error(f"File error: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'API endpoint not found'}), 404

@app.route('/', methods=['GET'])
def index():
    """Main web interface for the scanner."""
    return render_template('index.html')

@app.route('/current-directory', methods=['GET'])
def get_current_directory():
    """Get the current working directory."""
    try:
        current_dir = os.getcwd()
        return jsonify({'path': current_dir})
    except Exception as e:
        logger.error(f"Error getting current directory: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/discover-repos', methods=['GET'])
def discover_repositories():
    """Discover repositories in common locations."""
    try:
        repositories = []
        
        # Common repository locations
        home_dir = Path.home()
        search_paths = [
            home_dir / "repos",
            home_dir / "code", 
            home_dir / "projects",
            home_dir / "Documents",
            home_dir / "Desktop",
            home_dir / "Downloads"
        ]
        
        for search_path in search_paths:
            if search_path.exists() and search_path.is_dir():
                try:
                    # Look for directories with .git folders or package.json files
                    for item in search_path.iterdir():
                        if item.is_dir() and not item.name.startswith('.'):
                            repo_info = {
                                'name': item.name,
                                'path': str(item),
                                'type': 'directory'
                            }
                            
                            # Check if it's a git repository
                            if (item / '.git').exists():
                                repo_info['type'] = 'git'
                            # Check if it's a Node.js project
                            elif (item / 'package.json').exists():
                                repo_info['type'] = 'nodejs'
                            # Check if it's a Python project
                            elif (item / 'requirements.txt').exists() or (item / 'pyproject.toml').exists():
                                repo_info['type'] = 'python'
                            
                            repositories.append(repo_info)
                            
                            # Limit to prevent overwhelming the UI
                            if len(repositories) >= 20:
                                break
                                
                except (PermissionError, OSError):
                    # Skip directories we can't access
                    continue
                    
            if len(repositories) >= 20:
                break
        
        # Sort by name
        repositories.sort(key=lambda x: x['name'].lower())
        
        return jsonify({'repositories': repositories})
        
    except Exception as e:
        logger.error(f"Error discovering repositories: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    import datetime
    
    # Track web interface startup
    track_usage()
    
    print("="*80)
    print("🔒 AppSec AI Scanner Web Interface - © 2025 Chad Parnin")
    print("="*80)
    print(f"🚀 Starting Web API... [{datetime.datetime.now()}]")
    print("🔒 PROPRIETARY SOFTWARE - Licensed Use Only - Chad Parnin")
    print("="*80)
    print()
    print("📖 API Documentation:")
    print("  GET  /health          - Health check")
    print("  GET  /config          - Get scanner configuration") 
    print("  POST /scan            - Run security scan")
    print("  GET  /report          - View HTML report")
    print("  GET  /reports/<file>  - Download specific report files")
    print()
    print("💡 Example scan request:")
    print('  curl -X POST http://localhost:8000/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"repo_path": "/path/to/repo", "scan_level": "critical-high"}\'')
    print()
    print("📊 Usage analytics enabled for IP monitoring while repository is public")
    print("="*80)
    
    # Run Flask development server
    app.run(
        host='0.0.0.0',  # Accept connections from any IP
        port=8000,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
import subprocess
import json
from pathlib import Path
import logging
import os
import shlex
import re

# Import configuration constants
from config import format_subprocess_error, SCAN_EXCLUDE_PATTERNS
from .validation import validate_repo_path
from logging_config import get_logger

logger = get_logger(__name__)

def run_semgrep(repo_path: str, output_dir: str = None) -> list:
    """
    Run Semgrep SAST scanner on the given repository path.
    Returns a list of findings in standardized format.
    
    Args:
        repo_path: Path to repository to scan
        output_dir: Directory for output files (defaults to ../outputs/raw)
    """
    try:
        # Convert to Path objects for proper handling
        if output_dir is None:
            output_path = Path("../outputs/raw")
        else:
            output_path = Path(output_dir)
            
        output_path.mkdir(parents=True, exist_ok=True)
        output_file = output_path / "semgrep.json"
        
        # Validate and sanitize repo path
        repo_path_obj = validate_repo_path(repo_path)
        if not repo_path_obj:
            logger.error(f"Repository path validation failed: {repo_path}")
            return []
        
        logger.debug(f"Starting Semgrep scan of {repo_path_obj}")
        logger.debug(f"Output file: {output_file}")
        
        # Debug: Check if critical files exist
        critical_files = ['routes/index.js', 'app.js', 'Dockerfile']
        for file in critical_files:
            file_path = repo_path_obj / file
            exists = file_path.exists()
            size = file_path.stat().st_size if exists else 0
            logger.debug(f"Critical file check: {file} exists={exists} size={size}")
        
        # Use auto config for consistent rule loading across all environments
        # This downloads the latest available rules and ensures CI/CD vs CLI consistency
        cmd = [
            "semgrep", 
            "--config", "auto", 
            "--json", 
            "--output", str(output_file)
        ]
        
        # Add exclusion patterns
        for pattern in SCAN_EXCLUDE_PATTERNS:
            cmd.extend(["--exclude", pattern])
            
        cmd.append(str(repo_path_obj))
        
        logger.debug(f"Semgrep command: {' '.join(shlex.quote(arg) for arg in cmd)}")
        
        # Use subprocess.run with shell=False for security
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, shell=False)
        
        logger.debug(f"Semgrep completed with return code: {result.returncode}")
        if result.returncode not in (0, 1):
            error_details = format_subprocess_error('semgrep', result.returncode, result.stderr, result.stdout)
            logger.error(error_details)
            # Continue processing if output file exists, as partial results may still be useful
        
        # Parse and return findings from the JSON output
        with open(output_file) as f:
            all_results = json.load(f).get("results", [])
        
        logger.debug(f"Semgrep found {len(all_results)} total findings")
        
        # Filter based on scan level - Semgrep uses: CRITICAL, ERROR, WARNING, INFO
        # CRITICAL = Critical, ERROR = High, WARNING = Medium, INFO = Low
        scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')
        logger.debug(f"Filtering results with scan level: {scan_level}")
        results = []
        for finding in all_results:
            severity = finding.get('extra', {}).get('severity') or finding.get('severity', '')
            severity_lower = severity.lower()
            
            # Map Semgrep severities to standard levels for filtering
            if severity_lower == 'critical':
                normalized_severity = 'critical'
            elif severity_lower == 'error':  
                normalized_severity = 'high'  # ERROR = High severity
            elif severity_lower == 'warning':
                normalized_severity = 'medium'  # WARNING = Medium severity  
            elif severity_lower == 'info':
                normalized_severity = 'low'  # INFO = Low severity
            else:
                logger.debug(f"Skipping finding with unknown severity: {severity}")
                continue  # Skip unknown severities
            
            # Filter based on scan level (use the same variable, don't re-read env)
            if scan_level == 'critical-high' and normalized_severity in ['critical', 'high']:
                finding['severity'] = normalized_severity  # Store normalized severity
                finding['tool'] = 'semgrep'
                results.append(finding)
                logger.debug(f"✅ Including {normalized_severity} finding: {finding.get('check_id', 'unknown')}")
            elif scan_level == 'all':
                finding['severity'] = normalized_severity  # Store normalized severity
                finding['tool'] = 'semgrep'
                results.append(finding)
                logger.debug(f"✅ Including {normalized_severity} finding: {finding.get('check_id', 'unknown')}")
            else:
                logger.debug(f"❌ Filtering out {normalized_severity} finding: {finding.get('check_id', 'unknown')} (scan_level={scan_level})")
        
        logger.debug(f"Semgrep found {len(results)} critical/high vulnerabilities ({len(all_results)} total scanned)")
        return results
            
    except subprocess.TimeoutExpired:
        timeout_msg = format_subprocess_error('semgrep', 124, "Process timed out after 5 minutes")
        logger.error(timeout_msg)
        return []
    except FileNotFoundError:
        not_found_msg = format_subprocess_error('semgrep', 127, "Semgrep command not found in PATH")
        logger.error(not_found_msg)
        return []
    except Exception as e:
        generic_msg = format_subprocess_error('semgrep', 1, str(e))
        logger.error(generic_msg)
        return []
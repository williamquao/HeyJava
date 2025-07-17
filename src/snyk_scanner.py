#!/usr/bin/env python3
"""
Snyk Code Scanner for APK Decompiler
Scans decompiled Java code for security vulnerabilities using Snyk.
"""

import os
import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

class SnykScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def scan_java_code(self, java_dir: str, output_file: str) -> Dict:
        """
        Scan decompiled Java code using Snyk.
        
        Args:
            java_dir: Directory containing decompiled Java code
            output_file: Path to output markdown file
            
        Returns:
            Dictionary containing scan results
        """
        try:
            self.logger.info(f"Starting Snyk code scan of: {java_dir}")
            
            # Check if Snyk is installed
            if not self._check_snyk_installed():
                return {
                    'success': False,
                    'error': 'Snyk is not installed. Please install it first: npm install -g snyk'
                }
            
            # Run Snyk code test with enhanced options
            scan_result = self._run_snyk_scan(java_dir)
            
            if scan_result['success']:
                # Generate markdown report
                self._generate_markdown_report(scan_result, output_file)
                
                return {
                    'success': True,
                    'vulnerabilities': scan_result.get('vulnerabilities', []),
                    'vulnerability_count': len(scan_result.get('vulnerabilities', [])),
                    'output_file': output_file,
                    'scan_data': scan_result
                }
            else:
                return scan_result
                
        except Exception as e:
            self.logger.error(f"Error during Snyk scan: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _check_snyk_installed(self) -> bool:
        """Check if Snyk CLI is installed."""
        try:
            result = subprocess.run(['snyk', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _run_snyk_scan(self, java_dir: str) -> Dict:
        """Run Snyk code test on the Java directory with enhanced options."""
        try:
            # Change to the Java directory for scanning
            original_dir = os.getcwd()
            os.chdir(java_dir)
            
            # Run Snyk code test with more comprehensive options
            cmd = [
                'snyk', 'code', 'test',
                '--json',
                '--severity-threshold=low',  # Include all severities
                '--all-projects',  # Scan all project types
                '--detection-depth=10'  # Increase detection depth
            ]
            
            self.logger.info(f"Running Snyk command: {' '.join(cmd)}")
            self.logger.info(f"Scanning directory: {java_dir}")
            self.logger.info("This may take several minutes for large codebases...")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900  # 15 minutes timeout for large codebases
            )
            
            # Change back to original directory
            os.chdir(original_dir)
            
            # Log the raw output for debugging
            self.logger.debug(f"Snyk stdout: {result.stdout[:1000]}...")
            self.logger.debug(f"Snyk stderr: {result.stderr[:1000]}...")
            
            # Try to parse JSON output regardless of return code
            vulnerabilities = []
            
            try:
                scan_data = json.loads(result.stdout)
                vulnerabilities = scan_data.get('vulnerabilities', [])
                self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities in JSON output")
            except json.JSONDecodeError as e:
                self.logger.warning(f"JSON parsing failed: {e}")
                self.logger.debug(f"Raw stdout: {result.stdout}")
            
            # If no vulnerabilities in JSON, try parsing stderr for issues
            if not vulnerabilities and result.stderr:
                self.logger.info("No vulnerabilities in JSON, parsing stderr...")
                vulnerabilities = self._parse_snyk_stderr(result.stderr)
                self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities in stderr")
            
            # If still no vulnerabilities, try running a simpler scan
            if not vulnerabilities:
                self.logger.info("No vulnerabilities found, trying basic scan...")
                basic_vulns = self._run_basic_snyk_scan(java_dir)
                vulnerabilities.extend(basic_vulns)
                self.logger.info(f"Found {len(basic_vulns)} vulnerabilities in basic scan")
            
            # Add manual vulnerability detection for common patterns
            if not vulnerabilities:
                self.logger.info("Running manual vulnerability detection...")
                manual_vulns = self._detect_manual_vulnerabilities(java_dir)
                vulnerabilities.extend(manual_vulns)
                self.logger.info(f"Found {len(manual_vulns)} vulnerabilities in manual detection")
            
            return {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'scan_data': scan_data if 'scan_data' in locals() else {},
                'raw_stdout': result.stdout,
                'raw_stderr': result.stderr
            }
                    
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Snyk scan timed out after 15 minutes. Try running with fewer files or increase timeout.'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _run_basic_snyk_scan(self, java_dir: str) -> List[Dict]:
        """Run a basic Snyk scan without JSON output."""
        try:
            original_dir = os.getcwd()
            os.chdir(java_dir)
            
            cmd = ['snyk', 'code', 'test', '--severity-threshold=low']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            os.chdir(original_dir)
            
            # Parse the text output
            return self._parse_snyk_text_output(result.stdout, result.stderr)
            
        except Exception as e:
            self.logger.error(f"Basic Snyk scan failed: {e}")
            return []
    
    def _parse_snyk_text_output(self, stdout: str, stderr: str) -> List[Dict]:
        """Parse Snyk text output for vulnerabilities."""
        vulnerabilities = []
        
        # Combine stdout and stderr
        output = stdout + "\n" + stderr
        
        lines = output.split('\n')
        current_vuln = None
        
        for line in lines:
            line = line.strip()
            
            # Look for vulnerability patterns
            if any(pattern in line for pattern in ['✗ [', '✗ ', 'Vulnerability:', 'Issue:']):
                # Extract severity and title
                if '[' in line and ']' in line:
                    severity_start = line.find('[') + 1
                    severity_end = line.find(']')
                    if severity_start > 0 and severity_end > severity_start:
                        severity = line[severity_start:severity_end]
                        title = line[severity_end + 2:] if severity_end + 2 < len(line) else line
                    else:
                        severity = 'medium'
                        title = line
                else:
                    severity = 'medium'
                    title = line
                
                current_vuln = {
                    'title': title,
                    'severity': severity.lower(),
                    'from': ['Unknown'],
                    'lineNumber': 'N/A',
                    'description': '',
                    'message': title
                }
                vulnerabilities.append(current_vuln)
            
            # Look for file paths
            elif current_vuln and any(pattern in line for pattern in ['.java:', 'Path:', 'File:']):
                if '.java:' in line:
                    parts = line.split('.java:')
                    if len(parts) == 2:
                        file_path = parts[0] + '.java'
                        line_num = parts[1].split()[0] if parts[1] else 'N/A'
                        current_vuln['from'] = [file_path]
                        current_vuln['lineNumber'] = line_num
                elif 'Path:' in line:
                    path_info = line.replace('Path:', '').strip()
                    current_vuln['from'] = [path_info]
        
        return vulnerabilities
    
    def _detect_manual_vulnerabilities(self, java_dir: str) -> List[Dict]:
        """Manually detect common security vulnerabilities in Java code."""
        vulnerabilities = []
        
        # Patterns to look for
        patterns = {
            'Resource Leak': [
                'new FileReader(', 'new FileInputStream(', 'new FileOutputStream(',
                'new BufferedReader(', 'new BufferedWriter('
            ],
            'SQL Injection': [
                'executeQuery(', 'executeUpdate(', 'Statement', 'PreparedStatement'
            ],
            'Path Traversal': [
                'File(', 'new File(', 'FileInputStream(', 'FileOutputStream('
            ],
            'Hardcoded Credentials': [
                'password', 'secret', 'key', 'token', 'credential'
            ],
            'Insecure Random': [
                'new Random(', 'Math.random()'
            ]
        }
        
        try:
            for root, dirs, files in os.walk(java_dir):
                for file in files:
                    if file.endswith('.java'):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, java_dir)
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                lines = content.split('\n')
                                
                                for vuln_type, search_patterns in patterns.items():
                                    for pattern in search_patterns:
                                        for line_num, line in enumerate(lines, 1):
                                            if pattern in line:
                                                # Check if this is a potential vulnerability
                                                if self._is_potential_vulnerability(line, pattern, vuln_type):
                                                    vulnerabilities.append({
                                                        'title': f'Potential {vuln_type}',
                                                        'severity': 'medium',
                                                        'from': [relative_path],
                                                        'lineNumber': str(line_num),
                                                        'description': f'Found {pattern} usage that may indicate {vuln_type.lower()}',
                                                        'message': f'Line {line_num}: {line.strip()}'
                                                    })
                        except Exception as e:
                            self.logger.debug(f"Error reading file {file_path}: {e}")
                            
        except Exception as e:
            self.logger.error(f"Error in manual vulnerability detection: {e}")
        
        return vulnerabilities
    
    def _is_potential_vulnerability(self, line: str, pattern: str, vuln_type: str) -> bool:
        """Check if a line contains a potential vulnerability."""
        line = line.strip()
        
        # Skip comments and empty lines
        if line.startswith('//') or line.startswith('/*') or line.startswith('*') or not line:
            return False
        
        # Skip import statements
        if line.startswith('import '):
            return False
        
        # For resource leaks, check if there's no try-with-resources or proper closing
        if vuln_type == 'Resource Leak':
            if 'try (' in line or 'try(' in line:
                return False
            if 'close()' in line:
                return False
        
        # For SQL injection, check if it's using PreparedStatement properly
        if vuln_type == 'SQL Injection':
            if 'PreparedStatement' in line and 'setString(' in line:
                return False
        
        return True
    
    def _parse_snyk_stderr(self, stderr: str) -> List[Dict]:
        """Parse Snyk stderr output to extract vulnerability information."""
        vulnerabilities = []
        
        # Split by lines and look for vulnerability patterns
        lines = stderr.split('\n')
        current_vuln = None
        
        for line in lines:
            line = line.strip()
            
            # Look for vulnerability start pattern
            if '✗ [' in line and '] ' in line:
                # Extract severity and title
                severity_start = line.find('[') + 1
                severity_end = line.find(']')
                if severity_start > 0 and severity_end > severity_start:
                    severity = line[severity_start:severity_end]
                    title = line[severity_end + 2:]  # Skip '] '
                    
                    current_vuln = {
                        'title': title,
                        'severity': severity.lower(),
                        'from': ['Unknown'],
                        'lineNumber': 'N/A',
                        'description': '',
                        'message': ''
                    }
                    vulnerabilities.append(current_vuln)
            
            # Look for file path and line number
            elif current_vuln and 'Path:' in line:
                path_info = line.replace('Path:', '').strip()
                if 'line' in path_info:
                    parts = path_info.split(', line ')
                    if len(parts) == 2:
                        current_vuln['from'] = [parts[0].strip()]
                        current_vuln['lineNumber'] = parts[1].strip()
            
            # Look for info/description
            elif current_vuln and 'Info:' in line:
                info = line.replace('Info:', '').strip()
                current_vuln['description'] = info
                current_vuln['message'] = info
        
        return vulnerabilities
    
    def _generate_markdown_report(self, scan_result: Dict, output_file: str):
        """Generate a markdown report from Snyk scan results."""
        try:
            vulnerabilities = scan_result.get('vulnerabilities', [])
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# Snyk Security Scan Report\n\n")
                f.write(f"**Scan Date:** {self._get_current_timestamp()}\n\n")
                
                # Summary
                f.write("## Summary\n\n")
                f.write(f"- **Total Vulnerabilities:** {len(vulnerabilities)}\n")
                f.write(f"- **High Severity:** {self._count_by_severity(vulnerabilities, 'high')}\n")
                f.write(f"- **Medium Severity:** {self._count_by_severity(vulnerabilities, 'medium')}\n")
                f.write(f"- **Low Severity:** {self._count_by_severity(vulnerabilities, 'low')}\n\n")
                
                if vulnerabilities:
                    f.write("## Vulnerabilities\n\n")
                    
                    # Group by severity
                    for severity in ['high', 'medium', 'low']:
                        sev_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == severity]
                        if sev_vulns:
                            f.write(f"### {severity.title()} Severity ({len(sev_vulns)})\n\n")
                            
                            for vuln in sev_vulns:
                                f.write(f"#### {vuln.get('title', 'Unknown Vulnerability')}\n\n")
                                f.write(f"- **Severity:** {vuln.get('severity', 'Unknown')}\n")
                                f.write(f"- **CVE:** {vuln.get('identifiers', {}).get('CVE', ['N/A'])[0] if vuln.get('identifiers', {}).get('CVE') else 'N/A'}\n")
                                f.write(f"- **File:** {vuln.get('from', ['Unknown'])[0] if vuln.get('from') else 'Unknown'}\n")
                                f.write(f"- **Line:** {vuln.get('lineNumber', 'N/A')}\n\n")
                                
                                if vuln.get('description'):
                                    f.write(f"**Description:** {vuln['description']}\n\n")
                                
                                if vuln.get('message'):
                                    f.write(f"**Message:** {vuln['message']}\n\n")
                                
                                f.write("---\n\n")
                else:
                    f.write("## Vulnerabilities\n\n")
                    f.write("✅ **No vulnerabilities found!**\n\n")
                
                # Recommendations
                f.write("## Recommendations\n\n")
                if vulnerabilities:
                    f.write("1. **Review all high and medium severity vulnerabilities**\n")
                    f.write("2. **Update dependencies** where possible\n")
                    f.write("3. **Implement secure coding practices**\n")
                    f.write("4. **Consider using Snyk monitoring** for continuous security\n")
                else:
                    f.write("✅ **Great job! Your code appears to be secure.**\n")
                    f.write("Continue to follow secure coding practices and keep dependencies updated.\n")
                
                f.write("\n---\n")
                f.write("*Report generated by APK Decompiler with Snyk integration*\n")
            
            self.logger.info(f"Snyk report generated: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error generating markdown report: {str(e)}")
            raise
    
    def _count_by_severity(self, vulnerabilities: List[Dict], severity: str) -> int:
        """Count vulnerabilities by severity."""
        return len([v for v in vulnerabilities if v.get('severity', '').lower() == severity])
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp for the report."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
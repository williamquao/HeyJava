#!/usr/bin/env python3
"""
APK Decompiler CLI Tool
A comprehensive command-line tool for decompiling APK files and extracting Java code.
"""

import os
import sys
import argparse
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

from src.apk_decompiler import APKDecompiler
from src.config import Config

class APKDecompilerCLI:
    def __init__(self):
        self.config = Config()
        self.decompiler = APKDecompiler(self.config)
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('apk_decompiler.log')
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def main(self):
        """Main CLI entry point."""
        parser = self.create_parser()
        args = parser.parse_args()
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        try:
            if args.command == 'decompile':
                self.decompile_command(args)
            elif args.command == 'info':
                self.info_command(args)
            elif args.command == 'extract':
                self.extract_command(args)
            elif args.command == 'analyze':
                self.analyze_command(args)
            elif args.command == 'install-tools':
                self.install_tools_command(args)
            elif args.command == 'snyk-scan':
                self.snyk_scan_command(args)
            else:
                parser.print_help()
                
        except KeyboardInterrupt:
            self.logger.info("Operation cancelled by user")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error: {str(e)}")
            sys.exit(1)
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create command line argument parser."""
        parser = argparse.ArgumentParser(
            description='APK Decompiler CLI Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Decompile APK with all tools
  python cli_decompiler.py decompile app.apk -o output_dir
  
  # Extract only Java code
  python cli_decompiler.py extract app.apk --java-only
  
  # Get APK information only
  python cli_decompiler.py info app.apk
  
  # Analyze existing decompiled code
  python cli_decompiler.py analyze output_dir
  
  # Install required tools
  python cli_decompiler.py install-tools
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Decompile command
        decompile_parser = subparsers.add_parser('decompile', help='Decompile APK file')
        decompile_parser.add_argument('apk_file', help='Path to APK file')
        decompile_parser.add_argument('-o', '--output', required=True, help='Output directory')
        decompile_parser.add_argument('--java-only', action='store_true', help='Extract only Java code')
        decompile_parser.add_argument('--smali-only', action='store_true', help='Extract only Smali code')
        decompile_parser.add_argument('--no-jar', action='store_true', help='Skip JAR conversion')
        decompile_parser.add_argument('--format', choices=['json', 'text'], default='text', help='Output format')
        
        # Info command
        info_parser = subparsers.add_parser('info', help='Extract APK information')
        info_parser.add_argument('apk_file', help='Path to APK file')
        info_parser.add_argument('--format', choices=['json', 'text'], default='text', help='Output format')
        
        # Extract command
        extract_parser = subparsers.add_parser('extract', help='Extract specific components')
        extract_parser.add_argument('apk_file', help='Path to APK file')
        extract_parser.add_argument('-o', '--output', required=True, help='Output directory')
        extract_parser.add_argument('--java-only', action='store_true', help='Extract only Java code')
        extract_parser.add_argument('--smali-only', action='store_true', help='Extract only Smali code')
        extract_parser.add_argument('--resources-only', action='store_true', help='Extract only resources')
        extract_parser.add_argument('--manifest-only', action='store_true', help='Extract only manifest')
        
        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze decompiled code')
        analyze_parser.add_argument('directory', help='Directory with decompiled code')
        analyze_parser.add_argument('--format', choices=['json', 'text'], default='text', help='Output format')
        
        # Install tools command
        install_parser = subparsers.add_parser('install-tools', help='Install required tools')
        install_parser.add_argument('--force', action='store_true', help='Force reinstall tools')
        
        # Snyk scan command
        snyk_parser = subparsers.add_parser('snyk-scan', help='Scan decompiled code with Snyk')
        snyk_parser.add_argument('directory', help='Directory with decompiled code')
        snyk_parser.add_argument('--apk-name', help='Original APK name for report naming')
        snyk_parser.add_argument('--format', choices=['json', 'text'], default='text', help='Output format')
        
        # Global options
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        
        return parser
    
    def decompile_command(self, args):
        """Handle decompile command."""
        apk_path = Path(args.apk_file)
        output_dir = Path(args.output)
        
        if not apk_path.exists():
            self.logger.error(f"APK file not found: {apk_path}")
            sys.exit(1)
        
        if not apk_path.suffix.lower() == '.apk':
            self.logger.error("File must have .apk extension")
            sys.exit(1)
        
        self.logger.info(f"Starting decompilation of: {apk_path}")
        self.logger.info(f"Output directory: {output_dir}")
        
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Perform decompilation
        start_time = time.time()
        result = self.decompiler.decompile_apk(str(apk_path), str(output_dir))
        end_time = time.time()
        
        if result['success']:
            self.logger.info(f"Decompilation completed successfully in {end_time - start_time:.2f} seconds")
            self.print_decompilation_results(result, args.format)
        else:
            self.logger.error(f"Decompilation failed: {result.get('error', 'Unknown error')}")
            sys.exit(1)
    
    def info_command(self, args):
        """Handle info command."""
        apk_path = Path(args.apk_file)
        
        if not apk_path.exists():
            self.logger.error(f"APK file not found: {apk_path}")
            sys.exit(1)
        
        self.logger.info(f"Extracting information from: {apk_path}")
        
        # Extract metadata only
        metadata = self.decompiler._extract_metadata(str(apk_path))
        
        if 'error' not in metadata:
            self.print_apk_info(metadata, args.format)
        else:
            self.logger.error(f"Failed to extract APK info: {metadata['error']}")
            sys.exit(1)
    
    def extract_command(self, args):
        """Handle extract command."""
        apk_path = Path(args.apk_file)
        output_dir = Path(args.output)
        
        if not apk_path.exists():
            self.logger.error(f"APK file not found: {apk_path}")
            sys.exit(1)
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Extracting components from: {apk_path}")
        
        if args.java_only:
            self.extract_java_only(apk_path, output_dir)
        elif args.smali_only:
            self.extract_smali_only(apk_path, output_dir)
        elif args.resources_only:
            self.extract_resources_only(apk_path, output_dir)
        elif args.manifest_only:
            self.extract_manifest_only(apk_path, output_dir)
        else:
            self.logger.error("Please specify what to extract (--java-only, --smali-only, etc.)")
            sys.exit(1)
    
    def analyze_command(self, args):
        """Handle analyze command."""
        directory = Path(args.directory)
        
        if not directory.exists():
            self.logger.error(f"Directory not found: {directory}")
            sys.exit(1)
        
        self.logger.info(f"Analyzing decompiled code in: {directory}")
        
        analysis = self.decompiler._analyze_decompiled_code(str(directory))
        
        if 'error' not in analysis:
            self.print_analysis_results(analysis, args.format)
        else:
            self.logger.error(f"Failed to analyze code: {analysis['error']}")
            sys.exit(1)
    
    def install_tools_command(self, args):
        """Handle install tools command."""
        self.logger.info("Installing required tools...")
        self.install_required_tools(args.force)
    
    def snyk_scan_command(self, args):
        """Handle Snyk scan command."""
        directory = Path(args.directory)
        
        if not directory.exists():
            self.logger.error(f"Directory not found: {directory}")
            sys.exit(1)
        
        self.logger.info(f"Running Snyk security scan on: {directory}")
        
        # Generate output filename
        apk_name = args.apk_name if args.apk_name else directory.name
        snyk_report_file = directory / f"{apk_name}_snyk_scan.md"
        
        # Run Snyk scan
        jadx_dir = directory / 'jadx_output' / 'sources'
        if not jadx_dir.exists():
            self.logger.error("No jadx_output/sources directory found. Please decompile the APK first.")
            sys.exit(1)
        
        result = self.decompiler.snyk_scanner.scan_java_code(str(jadx_dir), str(snyk_report_file))
        
        if result['success']:
            self.logger.info(f"Snyk scan completed successfully!")
            self.print_snyk_results(result, args.format)
        else:
            self.logger.error(f"Snyk scan failed: {result.get('error', 'Unknown error')}")
            sys.exit(1)
    
    def extract_java_only(self, apk_path: Path, output_dir: Path):
        """Extract only Java code using jadx."""
        self.logger.info("Extracting Java code...")
        
        jadx_dir = output_dir / 'java_code'
        cmd = [self.config.JADX_PATH, '-d', str(jadx_dir), str(apk_path)]
        self.logger.info(f"Running command: {' '.join(cmd)}")
        
        try:
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.JOB_TIMEOUT)
            
            # Check if Java files were actually created, regardless of return code
            java_count = self.decompiler._count_java_files(str(jadx_dir))
            
            if java_count > 0:
                self.logger.info(f"Successfully extracted {java_count} Java files to {jadx_dir}")
                if result.returncode != 0:
                    self.logger.warning(f"jadx finished with {result.returncode} errors, but {java_count} Java files were extracted successfully")
                    print(f"\n[WARNING] jadx finished with {result.returncode} errors, but {java_count} Java files were extracted successfully")
                    print(f"Output directory: {jadx_dir}")
            else:
                self.logger.error(f"Failed to extract Java code - no Java files found.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
                print(f"\n[ERROR] jadx failed - no Java files found.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
                sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error extracting Java code: {str(e)}")
            print(f"\n[ERROR] Exception while running jadx: {str(e)}")
            sys.exit(1)
    
    def extract_smali_only(self, apk_path: Path, output_dir: Path):
        """Extract only Smali code using apktool."""
        self.logger.info("Extracting Smali code...")
        
        apktool_dir = output_dir / 'smali_code'
        cmd = [self.config.APKTOOL_PATH, 'd', str(apk_path), '-o', str(apktool_dir), '-f']
        
        try:
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.JOB_TIMEOUT)
            
            if result.returncode == 0:
                smali_dir = apktool_dir / 'smali'
                if smali_dir.exists():
                    smali_files = list(smali_dir.rglob('*.smali'))
                    self.logger.info(f"Successfully extracted {len(smali_files)} Smali files to {apktool_dir}")
                else:
                    self.logger.warning("No Smali files found")
            else:
                self.logger.error(f"Failed to extract Smali code: {result.stderr}")
                sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error extracting Smali code: {str(e)}")
            sys.exit(1)
    
    def extract_resources_only(self, apk_path: Path, output_dir: Path):
        """Extract only resources using apktool."""
        self.logger.info("Extracting resources...")
        
        apktool_dir = output_dir / 'resources'
        cmd = [self.config.APKTOOL_PATH, 'd', str(apk_path), '-o', str(apktool_dir), '-f']
        
        try:
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.JOB_TIMEOUT)
            
            if result.returncode == 0:
                res_dir = apktool_dir / 'res'
                if res_dir.exists():
                    resource_files = list(res_dir.rglob('*'))
                    self.logger.info(f"Successfully extracted {len(resource_files)} resource files to {apktool_dir}")
                else:
                    self.logger.warning("No resource files found")
            else:
                self.logger.error(f"Failed to extract resources: {result.stderr}")
                sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error extracting resources: {str(e)}")
            sys.exit(1)
    
    def extract_manifest_only(self, apk_path: Path, output_dir: Path):
        """Extract only AndroidManifest.xml."""
        self.logger.info("Extracting AndroidManifest.xml...")
        
        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_data = apk_zip.read('AndroidManifest.xml')
                    manifest_path = output_dir / 'AndroidManifest.xml'
                    
                    with open(manifest_path, 'wb') as f:
                        f.write(manifest_data)
                    
                    self.logger.info(f"Successfully extracted AndroidManifest.xml to {manifest_path}")
                else:
                    self.logger.error("AndroidManifest.xml not found in APK")
                    sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error extracting manifest: {str(e)}")
            sys.exit(1)
    
    def install_required_tools(self, force: bool = False):
        """Install required decompilation tools."""
        self.logger.info("Installing required tools...")
        
        try:
            import subprocess
            # Run the separate installation script
            result = subprocess.run([sys.executable, 'src/install_tools.py'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info("Tools installed successfully!")
                self.logger.info("You can now use the APK decompiler.")
            else:
                self.logger.error(f"Tool installation failed: {result.stderr}")
                self.logger.info("Please run 'python src/install_tools.py' manually to install tools.")
        except Exception as e:
            self.logger.error(f"Error during tool installation: {str(e)}")
            self.logger.info("Please run 'python src/install_tools.py' manually to install tools.")
    
    def print_decompilation_results(self, result: Dict, format_type: str):
        """Print decompilation results in specified format."""
        if format_type == 'json':
            print(json.dumps(result, indent=2))
        else:
            print("\n" + "="*60)
            print("DECOMPILATION RESULTS")
            print("="*60)
            
            # Metadata
            if 'metadata' in result:
                metadata = result['metadata']
                print(f"\n📱 APK Information:")
                print(f"   File Size: {metadata.get('file_size', 0) / (1024*1024):.2f} MB")
                print(f"   File Count: {metadata.get('file_count', 0)}")
                
                if 'manifest' in metadata:
                    manifest = metadata['manifest']
                    print(f"   Package: {manifest.get('package_name', 'Unknown')}")
                    print(f"   Version: {manifest.get('version_name', 'Unknown')} ({manifest.get('version_code', 'Unknown')})")
                    print(f"   Permissions: {len(manifest.get('permissions', []))}")
                    print(f"   Activities: {len(manifest.get('activities', []))}")
            
            # Java extraction
            if 'jadx_output' in result and result['jadx_output'].get('success'):
                jadx = result['jadx_output']
                print(f"\n☕ Java Code Extraction:")
                print(f"   Status: ✅ Success")
                print(f"   Java Files: {jadx.get('java_file_count', 0)}")
                print(f"   Output: {jadx.get('output_directory', 'N/A')}")
                if jadx.get('warnings'):
                    print(f"   ⚠️  {jadx.get('warnings')}")
            
            # Smali extraction
            if 'apktool_output' in result and result['apktool_output'].get('success'):
                apktool = result['apktool_output']
                print(f"\n🔧 Smali Code Extraction:")
                print(f"   Status: ✅ Success")
                print(f"   Output: {apktool.get('output_directory', 'N/A')}")
            
            # JAR conversion
            if 'jar_output' in result and result['jar_output'].get('success'):
                jar = result['jar_output']
                print(f"\n📦 JAR Conversion:")
                print(f"   Status: ✅ Success")
                print(f"   JAR Size: {jar.get('jar_size', 0) / (1024*1024):.2f} MB")
                print(f"   Output: {jar.get('jar_path', 'N/A')}")
            
            # Analysis
            if 'analysis' in result:
                analysis = result['analysis']
                print(f"\n📊 Code Analysis:")
                print(f"   Total Java Files: {analysis.get('class_count', 0)}")
                print(f"   Total Lines of Code: {analysis.get('total_java_lines', 0):,}")
                print(f"   Smali Files: {len(analysis.get('smali_files', []))}")
                
                if analysis.get('package_structure'):
                    print(f"   Package Structure:")
                    for package, count in list(analysis['package_structure'].items())[:5]:
                        print(f"     {package}: {count} classes")
                    if len(analysis['package_structure']) > 5:
                        print(f"     ... and {len(analysis['package_structure']) - 5} more packages")
            
            # Snyk Security Scan
            if 'snyk_scan' in result:
                snyk = result['snyk_scan']
                print(f"\n🔒 Security Scan (Snyk):")
                if snyk.get('success'):
                    print(f"   Status: ✅ Completed")
                    print(f"   Vulnerabilities: {snyk.get('vulnerability_count', 0)}")
                    print(f"   Report: {snyk.get('output_file', 'N/A')}")
                else:
                    print(f"   Status: ❌ Failed")
                    print(f"   Error: {snyk.get('error', 'Unknown error')}")
            
            print(f"\n📁 Output Directory: {result.get('output_directory', 'N/A')}")
            print("="*60)
    
    def print_apk_info(self, metadata: Dict, format_type: str):
        """Print APK information in specified format."""
        if format_type == 'json':
            print(json.dumps(metadata, indent=2))
        else:
            print("\n" + "="*50)
            print("APK INFORMATION")
            print("="*50)
            
            print(f"📱 File Size: {metadata.get('file_size', 0) / (1024*1024):.2f} MB")
            print(f"📁 File Count: {metadata.get('file_count', 0)}")
            
            if 'manifest' in metadata:
                manifest = metadata['manifest']
                print(f"\n📋 Manifest Information:")
                print(f"   Package: {manifest.get('package_name', 'Unknown')}")
                print(f"   Version: {manifest.get('version_name', 'Unknown')} ({manifest.get('version_code', 'Unknown')})")
                
                permissions = manifest.get('permissions', [])
                if permissions:
                    print(f"\n🔐 Permissions ({len(permissions)}):")
                    for perm in permissions[:10]:
                        print(f"   • {perm}")
                    if len(permissions) > 10:
                        print(f"   ... and {len(permissions) - 10} more")
                
                activities = manifest.get('activities', [])
                if activities:
                    print(f"\n🎯 Activities ({len(activities)}):")
                    for activity in activities[:10]:
                        print(f"   • {activity}")
                    if len(activities) > 10:
                        print(f"   ... and {len(activities) - 10} more")
            
            print("="*50)
    
    def print_analysis_results(self, analysis: Dict, format_type: str):
        """Print analysis results in specified format."""
        if format_type == 'json':
            print(json.dumps(analysis, indent=2))
        else:
            print("\n" + "="*50)
            print("CODE ANALYSIS")
            print("="*50)
            
            print(f"📊 Java Files: {analysis.get('class_count', 0)}")
            print(f"📝 Total Lines of Code: {analysis.get('total_java_lines', 0):,}")
            print(f"🔧 Smali Files: {len(analysis.get('smali_files', []))}")
            
            if analysis.get('package_structure'):
                print(f"\n📦 Package Structure:")
                sorted_packages = sorted(analysis['package_structure'].items(), key=lambda x: x[1], reverse=True)
                for package, count in sorted_packages[:10]:
                    print(f"   {package}: {count} classes")
                if len(sorted_packages) > 10:
                    print(f"   ... and {len(sorted_packages) - 10} more packages")
            
            if analysis.get('java_files'):
                print(f"\n📄 Largest Java Files:")
                sorted_files = sorted(analysis['java_files'], key=lambda x: x['lines'], reverse=True)
                for file_info in sorted_files[:5]:
                    print(f"   {file_info['path']}: {file_info['lines']} lines")
            
            print("="*50)
    
    def print_snyk_results(self, result: Dict, format_type: str):
        """Print Snyk scan results in specified format."""
        if format_type == 'json':
            print(json.dumps(result, indent=2))
        else:
            print("\n" + "="*50)
            print("SNYK SECURITY SCAN RESULTS")
            print("="*50)
            
            vulnerabilities = result.get('vulnerabilities', [])
            print(f"🔒 Total Vulnerabilities: {len(vulnerabilities)}")
            
            if vulnerabilities:
                high_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'high'])
                medium_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'medium'])
                low_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'low'])
                
                print(f"   🔴 High: {high_count}")
                print(f"   🟡 Medium: {medium_count}")
                print(f"   🟢 Low: {low_count}")
                
                print(f"\n📄 Report saved to: {result.get('output_file', 'N/A')}")
                
                # Show top vulnerabilities
                print(f"\n🚨 Top Vulnerabilities:")
                for i, vuln in enumerate(vulnerabilities[:5], 1):
                    severity = vuln.get('severity', 'Unknown').upper()
                    title = vuln.get('title', 'Unknown')
                    file_path = vuln.get('from', ['Unknown'])[0] if vuln.get('from') else 'Unknown'
                    line = vuln.get('lineNumber', 'N/A')
                    
                    print(f"   {i}. [{severity}] {title}")
                    print(f"      📁 {file_path}:{line}")
                
                if len(vulnerabilities) > 5:
                    print(f"      ... and {len(vulnerabilities) - 5} more vulnerabilities")
            else:
                print("✅ No vulnerabilities found!")
                print(f"\n📄 Report saved to: {result.get('output_file', 'N/A')}")
            
            print("="*50)

def main():
    """Main entry point."""
    cli = APKDecompilerCLI()
    cli.main()

if __name__ == '__main__':
    main() 
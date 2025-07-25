import os
import subprocess
import shutil
import zipfile
import xml.etree.ElementTree as ET
import xmltodict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

from .snyk_scanner import SnykScanner

class APKDecompiler:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.snyk_scanner = SnykScanner()
        
    def decompile_apk(self, apk_path: str, output_dir: str) -> Dict:
        """
        Main method to decompile an APK file and extract Java code.
        
        Args:
            apk_path: Path to the APK file
            output_dir: Directory to store decompiled files
            
        Returns:
            Dictionary containing decompilation results and metadata
        """
        try:
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            
            # Extract APK metadata
            metadata = self._extract_metadata(apk_path)
            
            # Decompile using apktool
            apktool_output = self._decompile_with_apktool(apk_path, output_dir)
            
            # Extract Java code using jadx
            jadx_output = self._extract_java_with_jadx(apk_path, output_dir)
            
            # Convert to JAR using dex2jar (optional)
            jar_output = self._convert_to_jar(apk_path, output_dir)
            
            # Analyze the decompiled code
            analysis = self._analyze_decompiled_code(output_dir)
            
            # Run Snyk security scan on Java code
            snyk_result = self._run_snyk_scan(output_dir, apk_path)
            
            return {
                'success': True,
                'metadata': metadata,
                'apktool_output': apktool_output,
                'jadx_output': jadx_output,
                'jar_output': jar_output,
                'analysis': analysis,
                'snyk_scan': snyk_result,
                'output_directory': output_dir
            }
            
        except Exception as e:
            self.logger.error(f"Error decompiling APK: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _extract_metadata(self, apk_path: str) -> Dict:
        """Extract basic metadata from APK file."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Get file list
                file_list = apk_zip.namelist()
                
                # Try to extract manifest info using apktool for proper decoding
                manifest_info = self._extract_manifest_with_apktool(apk_path)
                
                return {
                    'file_size': os.path.getsize(apk_path),
                    'file_count': len(file_list),
                    'manifest': manifest_info,
                    'files': file_list[:100]  # First 100 files
                }
        except Exception as e:
            self.logger.error(f"Error extracting metadata: {str(e)}")
            return {'error': str(e)}
    
    def _extract_manifest_with_apktool(self, apk_path: str) -> Dict:
        """Extract manifest information using apktool for proper AXML decoding."""
        try:
            # Create temporary directory for apktool output
            import tempfile
            temp_dir = tempfile.mkdtemp()
            
            # Use apktool to decode the APK
            cmd = [
                self.config.APKTOOL_PATH,
                'd',  # decode
                apk_path,
                '-o',  # output
                temp_dir,
                '-f'   # force overwrite
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.JOB_TIMEOUT
            )
            
            if result.returncode == 0:
                # Read the decoded AndroidManifest.xml
                manifest_path = os.path.join(temp_dir, 'AndroidManifest.xml')
                if os.path.exists(manifest_path):
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        manifest_text = f.read()
                    
                    # Parse the decoded manifest
                    manifest_info = self._parse_decoded_manifest(manifest_text)
                    
                    # Cleanup
                    import shutil
                    shutil.rmtree(temp_dir)
                    
                    return manifest_info
            
            # Cleanup on failure
            import shutil
            shutil.rmtree(temp_dir)
            
            # Fallback to basic extraction
            return self._extract_basic_manifest(apk_path)
            
        except Exception as e:
            self.logger.error(f"Error extracting manifest with apktool: {str(e)}")
            # Fallback to basic extraction
            return self._extract_basic_manifest(apk_path)
    
    def _extract_basic_manifest(self, apk_path: str) -> Dict:
        """Fallback method to extract basic manifest info."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_data = apk_zip.read('AndroidManifest.xml')
                    manifest_text = manifest_data.decode('utf-8', errors='ignore')
                    return self._parse_decoded_manifest(manifest_text)
        except Exception as e:
            self.logger.error(f"Error in basic manifest extraction: {str(e)}")
        
        return {
            'package_name': 'Unknown',
            'version_code': 'Unknown',
            'version_name': 'Unknown',
            'permissions': [],
            'activities': []
        }
    
    def _parse_decoded_manifest(self, manifest_text: str) -> Dict:
        """Parse decoded AndroidManifest.xml to extract basic info."""
        try:
            # Extract basic info using string operations
            info = {
                'package_name': self._extract_package_name(manifest_text),
                'version_code': self._extract_version_code(manifest_text),
                'version_name': self._extract_version_name(manifest_text),
                'permissions': self._extract_permissions(manifest_text),
                'activities': self._extract_activities(manifest_text)
            }
            
            return info
        except Exception as e:
            self.logger.error(f"Error parsing decoded manifest: {str(e)}")
            return {
                'package_name': 'Unknown',
                'version_code': 'Unknown',
                'version_name': 'Unknown',
                'permissions': [],
                'activities': []
            }
    
    def _extract_package_name(self, manifest_text: str) -> str:
        """Extract package name from manifest."""
        import re
        match = re.search(r'package="([^"]+)"', manifest_text)
        return match.group(1) if match else "Unknown"
    
    def _extract_version_code(self, manifest_text: str) -> str:
        """Extract version code from manifest."""
        import re
        match = re.search(r'android:versionCode="([^"]+)"', manifest_text)
        return match.group(1) if match else "Unknown"
    
    def _extract_version_name(self, manifest_text: str) -> str:
        """Extract version name from manifest."""
        import re
        match = re.search(r'android:versionName="([^"]+)"', manifest_text)
        return match.group(1) if match else "Unknown"
    
    def _extract_permissions(self, manifest_text: str) -> List[str]:
        """Extract permissions from manifest."""
        import re
        permissions = re.findall(r'<uses-permission[^>]*android:name="([^"]+)"', manifest_text)
        return permissions
    
    def _extract_activities(self, manifest_text: str) -> List[str]:
        """Extract activities from manifest."""
        import re
        activities = re.findall(r'<activity[^>]*android:name="([^"]+)"', manifest_text)
        return activities
    
    def _decompile_with_apktool(self, apk_path: str, output_dir: str) -> Dict:
        """Decompile APK using apktool."""
        try:
            apktool_dir = os.path.join(output_dir, 'apktool_output')
            
            cmd = [
                self.config.APKTOOL_PATH,
                'd',  # decode
                apk_path,
                '-o',  # output
                apktool_dir,
                '-f'   # force overwrite
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.JOB_TIMEOUT
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'output_directory': apktool_dir,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr,
                    'stdout': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'apktool timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _extract_java_with_jadx(self, apk_path: str, output_dir: str) -> Dict:
        """Extract Java code using jadx."""
        try:
            jadx_dir = os.path.join(output_dir, 'jadx_output')
            
            cmd = [
                self.config.JADX_PATH,
                '-d',  # output directory
                jadx_dir,
                apk_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.JOB_TIMEOUT
            )
            
            # Count Java files regardless of return code
            java_files = self._count_java_files(jadx_dir)
            
            if java_files > 0:
                # Success if Java files were created, even if jadx reported errors
                return {
                    'success': True,
                    'output_directory': jadx_dir,
                    'java_file_count': java_files,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'warnings': f"jadx finished with {result.returncode} errors but extracted {java_files} Java files" if result.returncode != 0 else None
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr,
                    'stdout': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'jadx timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _convert_to_jar(self, apk_path: str, output_dir: str) -> Dict:
        """Convert APK to JAR using dex2jar."""
        try:
            jar_path = os.path.join(output_dir, 'output.jar')
            
            cmd = [
                self.config.DEX2JAR_PATH,
                apk_path,
                '-o',
                jar_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.JOB_TIMEOUT
            )
            
            if result.returncode == 0 and os.path.exists(jar_path):
                return {
                    'success': True,
                    'jar_path': jar_path,
                    'jar_size': os.path.getsize(jar_path),
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr,
                    'stdout': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'dex2jar timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _count_java_files(self, directory: str) -> int:
        """Count Java files in a directory recursively."""
        count = 0
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.java'):
                    count += 1
        return count
    
    def _analyze_decompiled_code(self, output_dir: str) -> Dict:
        """Analyze the decompiled code for insights."""
        try:
            jadx_dir = os.path.join(output_dir, 'jadx_output')
            apktool_dir = os.path.join(output_dir, 'apktool_output')
            
            analysis = {
                'java_files': [],
                'smali_files': [],
                'resources': [],
                'total_java_lines': 0,
                'package_structure': {},
                'class_count': 0
            }
            
            # Analyze Java files
            if os.path.exists(jadx_dir):
                analysis.update(self._analyze_java_files(jadx_dir))
            
            # Analyze Smali files
            if os.path.exists(apktool_dir):
                analysis.update(self._analyze_smali_files(apktool_dir))
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing code: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_java_files(self, jadx_dir: str) -> Dict:
        """Analyze Java files for structure and content."""
        java_files = []
        total_lines = 0
        package_structure = {}
        class_count = 0
        
        for root, dirs, files in os.walk(jadx_dir):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, jadx_dir)
                    
                    # Count lines
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            line_count = len(lines)
                            total_lines += line_count
                    except:
                        line_count = 0
                    
                    java_files.append({
                        'path': relative_path,
                        'lines': line_count,
                        'size': os.path.getsize(file_path)
                    })
                    
                    # Extract package info
                    package = os.path.dirname(relative_path).replace('/', '.')
                    if package not in package_structure:
                        package_structure[package] = 0
                    package_structure[package] += 1
                    
                    class_count += 1
        
        return {
            'java_files': java_files,
            'total_java_lines': total_lines,
            'package_structure': package_structure,
            'class_count': class_count
        }
    
    def _analyze_smali_files(self, apktool_dir: str) -> Dict:
        """Analyze Smali files."""
        smali_files = []
        smali_dir = os.path.join(apktool_dir, 'smali')
        
        if os.path.exists(smali_dir):
            for root, dirs, files in os.walk(smali_dir):
                for file in files:
                    if file.endswith('.smali'):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, smali_dir)
                        
                        smali_files.append({
                            'path': relative_path,
                            'size': os.path.getsize(file_path)
                        })
        
        return {'smali_files': smali_files}
    
    def _run_snyk_scan(self, output_dir: str, apk_path: str) -> Dict:
        """Run Snyk security scan on decompiled Java code."""
        try:
            # Use the sources directory for Snyk scan
            jadx_dir = os.path.join(output_dir, 'jadx_output', 'sources')
            
            if not os.path.exists(jadx_dir):
                return {
                    'success': False,
                    'error': 'No Java code found to scan'
                }
            
            # Generate output filename based on APK name
            apk_name = Path(apk_path).stem
            snyk_report_file = os.path.join(output_dir, f"{apk_name}_snyk_scan.md")
            
            # Run Snyk scan
            return self.snyk_scanner.scan_java_code(jadx_dir, snyk_report_file)
            
        except Exception as e:
            self.logger.error(f"Error running Snyk scan: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            } 
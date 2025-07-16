#!/usr/bin/env python3
"""
Tool Installation Script for APK Decompiler
Installs required tools: apktool, jadx, and dex2jar
"""

import os
import sys
import subprocess
import shutil
import tempfile
from pathlib import Path

def check_tool_installed(tool_name: str) -> bool:
    """Check if a tool is already installed."""
    return shutil.which(tool_name) is not None

def download_file(url: str, filename: str) -> str:
    """Download a file from URL."""
    try:
        import requests
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        filepath = Path(filename)
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        return str(filepath)
    except ImportError:
        # Fallback to curl if requests is not available
        result = subprocess.run(['curl', '-L', '-o', filename, url], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            return filename
        else:
            raise Exception(f"Failed to download {url}: {result.stderr}")

def install_apktool():
    """Install apktool."""
    print("Installing apktool...")
    
    if check_tool_installed('apktool'):
        print("apktool is already installed")
        return True
    
    try:
        # Download apktool
        url = "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar"
        jar_path = download_file(url, "apktool.jar")
        
        # Create wrapper script
        wrapper_content = """#!/bin/bash
java -jar "$(dirname "$0")/apktool.jar" "$@"
"""
        
        # Write wrapper script
        with open("apktool", "w") as f:
            f.write(wrapper_content)
        
        # Make executable
        os.chmod("apktool", 0o755)
        
        # Move to /usr/local/bin (requires sudo)
        try:
            subprocess.run(['sudo', 'mv', 'apktool', '/usr/local/bin/'], check=True)
            subprocess.run(['sudo', 'mv', 'apktool.jar', '/usr/local/bin/'], check=True)
            print("apktool installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("Failed to move apktool to /usr/local/bin. You may need to run with sudo.")
            return False
            
    except Exception as e:
        print(f"Failed to install apktool: {e}")
        return False

def install_jadx():
    """Install jadx."""
    print("Installing jadx...")
    
    if check_tool_installed('jadx'):
        print("jadx is already installed")
        return True
    
    try:
        # Download jadx
        url = "https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip"
        zip_path = download_file(url, "jadx.zip")
        
        # Extract
        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(".")
        
        # Move jadx binary
        try:
            subprocess.run(['sudo', 'mv', 'jadx/bin/jadx', '/usr/local/bin/'], check=True)
            subprocess.run(['sudo', 'chmod', '+x', '/usr/local/bin/jadx'], check=True)
            
            # Cleanup
            shutil.rmtree('jadx')
            os.remove(zip_path)
            
            print("jadx installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("Failed to move jadx to /usr/local/bin. You may need to run with sudo.")
            return False
            
    except Exception as e:
        print(f"Failed to install jadx: {e}")
        return False

def install_dex2jar():
    """Install dex2jar."""
    print("Installing dex2jar...")
    
    if check_tool_installed('d2j-dex2jar.sh'):
        print("dex2jar is already installed")
        return True
    
    try:
        # Download dex2jar
        url = "https://github.com/pxb1988/dex2jar/releases/download/v2.1/dex2jar-2.1.zip"
        zip_path = download_file(url, "dex2jar.zip")
        
        # Extract
        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(".")
        
        # Move dex2jar scripts
        try:
            # Check which directory was created
            dex_dir = None
            for item in os.listdir('.'):
                if item.startswith('dex') and os.path.isdir(item):
                    dex_dir = item
                    break
            
            if dex_dir is None:
                raise Exception("dex2jar directory not found after extraction")
            
            subprocess.run(['sudo', 'mv', f'{dex_dir}/d2j-dex2jar.sh', '/usr/local/bin/'], check=True)
            subprocess.run(['sudo', 'mv', f'{dex_dir}/d2j-jar2dex.sh', '/usr/local/bin/'], check=True)
            subprocess.run(['sudo', 'chmod', '+x', '/usr/local/bin/d2j-dex2jar.sh'], check=True)
            subprocess.run(['sudo', 'chmod', '+x', '/usr/local/bin/d2j-jar2dex.sh'], check=True)
            
            # Cleanup
            shutil.rmtree(dex_dir)
            os.remove(zip_path)
            
            print("dex2jar installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("Failed to move dex2jar to /usr/local/bin. You may need to run with sudo.")
            return False
            
    except Exception as e:
        print(f"Failed to install dex2jar: {e}")
        return False

def main():
    """Main installation function."""
    print("APK Decompiler Tool Installer")
    print("=" * 40)
    
    # Check if running as root (needed for /usr/local/bin)
    if os.geteuid() != 0:
        print("Note: This script needs sudo privileges to install tools to /usr/local/bin")
        print("You may be prompted for your password.")
    
    # Check Java installation
    if not check_tool_installed('java'):
        print("Error: Java is required but not installed.")
        print("Please install Java first:")
        print("  macOS: brew install openjdk")
        print("  Ubuntu: sudo apt install openjdk-11-jdk")
        print("  CentOS: sudo yum install java-11-openjdk-devel")
        sys.exit(1)
    
    # Install tools
    success_count = 0
    
    if install_apktool():
        success_count += 1
    
    if install_jadx():
        success_count += 1
    
    if install_dex2jar():
        success_count += 1
    
    print(f"\nInstallation completed: {success_count}/3 tools installed")
    
    if success_count == 3:
        print("\nAll tools installed successfully!")
        print("\nYou can now use the APK decompiler:")
        print("  python cli_decompiler.py --help")
    else:
        print("\nSome tools failed to install. Please check the errors above.")
        sys.exit(1)

if __name__ == '__main__':
    main() 
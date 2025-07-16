#!/usr/bin/env python3
"""
Setup script for APK Decompiler System
Automates the installation process.
"""

import os
import sys
import subprocess
import platform

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_java():
    """Check if Java is installed."""
    try:
        result = subprocess.run(['java', '-version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            # Extract version from stderr (Java prints version to stderr)
            version_line = result.stderr.split('\n')[0]
            print(f"✅ Java found: {version_line}")
            return True
        else:
            print("❌ Java is not working properly")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("❌ Java is not installed")
        print("\nPlease install Java:")
        system = platform.system().lower()
        if system == "darwin":  # macOS
            print("   brew install openjdk")
        elif system == "linux":
            if os.path.exists("/etc/debian_version"):
                print("   sudo apt update && sudo apt install openjdk-11-jdk")
            else:
                print("   sudo yum install java-11-openjdk-devel")
        elif system == "windows":
            print("   Download from: https://adoptium.net/")
        return False

def install_python_dependencies():
    """Install Python dependencies."""
    print("Installing Python dependencies...")
    try:
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'],
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Python dependencies installed successfully")
            return True
        else:
            print(f"❌ Failed to install Python dependencies: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error installing Python dependencies: {e}")
        return False

def install_tools():
    """Install required tools."""
    print("Installing required tools...")
    try:
        result = subprocess.run([sys.executable, 'install_tools.py'],
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Tools installed successfully")
            return True
        else:
            print(f"❌ Failed to install tools: {result.stderr}")
            print("   You may need to run 'python install_tools.py' manually")
            return False
    except Exception as e:
        print(f"❌ Error installing tools: {e}")
        return False

def run_tests():
    """Run system tests."""
    print("Running system tests...")
    try:
        result = subprocess.run([sys.executable, 'test_system.py'],
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ All tests passed")
            return True
        else:
            print(f"❌ Some tests failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return False

def create_directories():
    """Create necessary directories."""
    print("Creating directories...")
    directories = ['uploads', 'decompiled', 'logs']
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✅ Created directory: {directory}")
        except Exception as e:
            print(f"❌ Failed to create directory {directory}: {e}")
            return False
    
    return True

def main():
    """Main setup function."""
    print("APK Decompiler System Setup")
    print("=" * 40)
    
    # Check prerequisites
    if not check_python_version():
        sys.exit(1)
    
    if not check_java():
        print("\nPlease install Java and run this script again.")
        sys.exit(1)
    
    # Install dependencies
    if not install_python_dependencies():
        print("\nFailed to install Python dependencies.")
        sys.exit(1)
    
    # Create directories
    if not create_directories():
        print("\nFailed to create directories.")
        sys.exit(1)
    
    # Install tools
    if not install_tools():
        print("\nFailed to install tools. You may need to run manually:")
        print("  python install_tools.py")
    
    # Run tests
    if not run_tests():
        print("\nSome tests failed. The system may not work properly.")
    
    print("\n" + "=" * 40)
    print("Setup completed!")
    print("\nYou can now use the APK decompiler:")
    print("  python cli_decompiler.py --help")
    print("\nExample usage:")
    print("  python cli_decompiler.py info your_app.apk")
    print("  python cli_decompiler.py decompile your_app.apk -o output_dir")
    print("\nFor more information, see README.md")

if __name__ == '__main__':
    main() 
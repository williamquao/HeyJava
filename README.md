# APK Decompiler CLI System

A comprehensive command-line tool for decompiling APK files and extracting Java code. This system provides multiple decompilation methods and detailed analysis of Android applications.

## Features

- 🔍 **APK Information Extraction**: Extract metadata, permissions, activities, and manifest information
- ☕ **Java Code Extraction**: Decompile APK to readable Java source code using jadx
- 🔧 **Smali Code Extraction**: Extract low-level Smali code using apktool
- 📦 **JAR Conversion**: Convert APK to JAR format using dex2jar
- 📊 **Code Analysis**: Analyze decompiled code structure, package organization, and statistics
- 🔒 **Security Scanning**: Integrated Snyk security scanning for vulnerability detection
- 🛠️ **Multiple Output Formats**: JSON and human-readable text output
- ⚡ **Modular Extraction**: Extract specific components (Java only, Smali only, resources, manifest)

## Prerequisites

- Python 3.7+
- Java 8 or higher (required for decompilation tools)
- Node.js and npm (required for Snyk security scanning)
- Internet connection (for tool installation)

## Installation

### 1. Clone or Download the Project

```bash
git clone <repository-url>
cd HeyJava
```

### 2. Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### 3. Install Required Tools

The system requires three main tools for APK decompilation:

```bash
python3 install_tools.py
```

This will install:

- **apktool**: For extracting resources and Smali code
- **jadx**: For decompiling to Java source code
- **dex2jar**: For converting APK to JAR format

**Note**: The installation script requires sudo privileges to install tools to `/usr/local/bin/`.

### 4. Install Snyk (Optional but Recommended)

For security scanning functionality:

```bash
npm install -g snyk
```

### 4. Verify Installation

```bash
apktool --version
jadx --version
d2j-dex2jar.sh --help
```

## Usage

### Basic Commands

#### 1. Full APK Decompilation

Decompile an APK file with all available tools:

```bash
python3 cli_decompiler.py decompile app.apk -o output_directory
```

#### 2. Extract APK Information Only

Get detailed information about an APK without decompiling:

```bash
python3 cli_decompiler.py info app.apk
```

#### 3. Extract Specific Components

Extract only Java code:

```bash
python3 cli_decompiler.py extract app.apk -o output_dir --java-only
```

Extract only Smali code:

```bash
python3 cli_decompiler.py extract app.apk -o output_dir --smali-only
```

Extract only resources:

```bash
python3 cli_decompiler.py extract app.apk -o output_dir --resources-only
```

Extract only manifest:

```bash
python3 cli_decompiler.py extract app.apk -o output_dir --manifest-only
```

#### 4. Analyze Existing Decompiled Code

Analyze code that was previously decompiled:

```bash
python3 cli_decompiler.py analyze output_directory
```

### Advanced Options

#### Output Format

Get results in JSON format for programmatic processing:

```bash
python3 cli_decompiler.py decompile app.apk -o output_dir --format json
```

#### Verbose Output

Enable detailed logging:

```bash
python3 cli_decompiler.py decompile app.apk -o output_dir -v
```

#### Selective Decompilation

Skip JAR conversion:

```bash
python3 cli_decompiler.py decompile app.apk -o output_dir --no-jar
```

## Examples

### Example 1: Quick APK Analysis

```bash
# Get basic information about an APK
python3 cli_decompiler.py info suspicious_app.apk --format text
```

Output:

```
==================================================
APK INFORMATION
==================================================
📱 File Size: 15.23 MB
📁 File Count: 1,247

📋 Manifest Information:
   Package: com.example.suspiciousapp
   Version: 1.0.0 (1)

🔐 Permissions (8):
   • android.permission.INTERNET
   • android.permission.READ_PHONE_STATE
   • android.permission.ACCESS_FINE_LOCATION
   • ...

🎯 Activities (3):
   • com.example.suspiciousapp.MainActivity
   • com.example.suspiciousapp.SplashActivity
   • ...
==================================================
```

### Example 2: Full Decompilation

```bash
# Decompile with all tools
python3 cli_decompiler.py decompile app.apk -o decompiled_app
```

Output:

```
============================================================
DECOMPILATION RESULTS
============================================================

📱 APK Information:
   File Size: 25.67 MB
   File Count: 2,341
   Package: com.example.myapp
   Version: 2.1.0 (21)
   Permissions: 12
   Activities: 5

☕ Java Code Extraction:
   Status: ✅ Success
   Java Files: 156
   Output: decompiled_app/jadx_output

🔧 Smali Code Extraction:
   Status: ✅ Success
   Output: decompiled_app/apktool_output

📦 JAR Conversion:
   Status: ✅ Success
   JAR Size: 18.45 MB
   Output: decompiled_app/output.jar

📊 Code Analysis:
   Total Java Files: 156
   Total Lines of Code: 45,230
   Smali Files: 189
   Package Structure:
     com.example.myapp.ui: 23 classes
     com.example.myapp.network: 18 classes
     com.example.myapp.utils: 15 classes
     ...

📁 Output Directory: decompiled_app
============================================================
```

### Example 3: Extract Only Java Code

```bash
# Extract only Java source code
python3 cli_decompiler.py extract app.apk -o java_only --java-only
```

## Troubleshooting

### Common Issues

1. **"Command not found" errors**

   - Run `python install_tools.py` to install required tools
   - Ensure Java is installed: `java -version`

2. **Permission denied errors**

   - The installation script needs sudo privileges
   - Run: `sudo python install_tools.py`

3. **APK file not found**

   - Ensure the APK file path is correct
   - Check file permissions

4. **Decompilation fails**
   - Some APKs may be obfuscated or protected
   - Try different extraction methods (Java only vs Smali only)
   - Check the log file: `apk_decompiler.log`

### Logging

The system creates detailed logs in `apk_decompiler.log`. Check this file for detailed error information:

### Batch Processing

For processing multiple APK files:

```bash
for apk in *.apk; do
    python cli_decompiler.py decompile "$apk" -o "decompiled_${apk%.apk}"
done
```

### Integration with Other Tools

The JSON output format allows easy integration with other analysis tools:

```bash
python cli_decompiler.py info app.apk --format json | jq '.manifest.permissions'
``
```

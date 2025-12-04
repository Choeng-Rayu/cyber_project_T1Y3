"""
function2.py - Startup Folder Persistence Detector & Remover
Detects and removes malicious files from Windows Startup folders
"""

import os
import shutil
import hashlib
import re
from datetime import datetime
from pathlib import Path

# ==================== CONFIGURATION ====================

# Known malicious file names (from attacker code)
KNOWN_MALICIOUS_FILES = [
    "WindowsDefender.pyw",
    "WindowsUpdate.pyw",
    "WindowsSecurity.pyw",
    "SystemService.pyw",
    "defender.pyw",
    "service.pyw",
    "update.pyw",
]

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    ".pyw",      # Python script (windowless)
    ".py",       # Python script
    ".vbs",      # VBScript
    ".vbe",      # Encoded VBScript
    ".js",       # JavaScript
    ".jse",      # Encoded JavaScript
    ".wsf",      # Windows Script File
    ".wsh",      # Windows Script Host
    ".ps1",      # PowerShell
    ".bat",      # Batch file
    ".cmd",      # Command file
    ".hta",      # HTML Application
    ".scr",      # Screensaver (executable)
]

# Suspicious content patterns in script files
SUSPICIOUS_CONTENT_PATTERNS = [
    r"import\s+winreg",           # Registry manipulation
    r"import\s+ctypes",           # Low-level Windows API
    r"subprocess\.Popen",         # Process execution
    r"os\.system\(",              # System command execution
    r"eval\(",                    # Dynamic code execution
    r"exec\(",                    # Dynamic code execution
    r"base64\.b64decode",         # Base64 decoding (obfuscation)
    r"\\AppData\\.*\\Security",   # Hidden folders
    r"\\AppData\\.*\\Update",     # Hidden folders
    r"HKEY_CURRENT_USER",         # Registry access
    r"\.encrypt",                 # Encryption methods
    r"\.locked",                  # File locking
    r"ransom",                    # Ransomware keywords
]

# Trusted file patterns (whitelist)
TRUSTED_PATTERNS = [
    r"^desktop\.ini$",
    r"^Microsoft",
    r"^Google",
    r"^Adobe",
    r"^Spotify",
    r"^Discord",
    r"^Steam",
    r"^OneDrive",
    r"^Dropbox",
]

# ==================== CLASSES ====================

class StartupThreat:
    """Represents a detected startup folder threat."""
    
    def __init__(self, filepath, filename, threat_level, reason, file_hash=None, content_preview=None):
        self.filepath = filepath
        self.filename = filename
        self.threat_level = threat_level  # "HIGH", "MEDIUM", "LOW"
        self.reason = reason
        self.file_hash = file_hash
        self.content_preview = content_preview
        self.detected_at = datetime.now()
        self.file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    
    def __str__(self):
        return f"[{self.threat_level}] {self.filename}"
    
    def to_dict(self):
        return {
            "filepath": str(self.filepath),
            "filename": self.filename,
            "threat_level": self.threat_level,
            "reason": self.reason,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "detected_at": self.detected_at.isoformat()
        }

# ==================== HELPER FUNCTIONS ====================

def get_startup_folders():
    """Get all Windows Startup folder paths."""
    folders = []
    
    # Current user startup
    user_startup = os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Start Menu\Programs\Startup"
    )
    if os.path.exists(user_startup):
        folders.append(("User Startup", user_startup))
    
    # All users startup (requires admin)
    all_users_startup = os.path.join(
        os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
        r"Microsoft\Windows\Start Menu\Programs\Startup"
    )
    if os.path.exists(all_users_startup):
        folders.append(("All Users Startup", all_users_startup))
    
    return folders

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except:
        return None

def read_file_content(filepath, max_size=10000):
    """Read file content for analysis."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_size)
    except:
        return None

def is_trusted_file(filename):
    """Check if file matches trusted patterns."""
    for pattern in TRUSTED_PATTERNS:
        if re.search(pattern, filename, re.IGNORECASE):
            return True
    return False

def check_known_malicious(filename):
    """Check if filename matches known malicious files."""
    for malicious in KNOWN_MALICIOUS_FILES:
        if malicious.lower() == filename.lower():
            return True
        if malicious.lower() in filename.lower():
            return True
    return False

def check_suspicious_extension(filename):
    """Check if file has a suspicious extension."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in SUSPICIOUS_EXTENSIONS, ext

def check_suspicious_content(content):
    """Check file content for suspicious patterns."""
    if not content:
        return False, None
    
    for pattern in SUSPICIOUS_CONTENT_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True, pattern
    
    return False, None

# ==================== DETECTION FUNCTIONS ====================

def analyze_startup_file(filepath):
    """Analyze a file in startup folder and determine threat level."""
    filename = os.path.basename(filepath)
    
    # Skip if trusted
    if is_trusted_file(filename):
        return None, None
    
    # Check 1: Known malicious filename
    if check_known_malicious(filename):
        return "HIGH", f"Known malicious filename: {filename}"
    
    # Check 2: Suspicious extension
    is_suspicious_ext, ext = check_suspicious_extension(filename)
    if is_suspicious_ext:
        # Python scripts are especially suspicious
        if ext in [".py", ".pyw"]:
            # Read and analyze content
            content = read_file_content(filepath)
            is_suspicious_content, pattern = check_suspicious_content(content)
            if is_suspicious_content:
                return "HIGH", f"Malicious Python script (pattern: {pattern})"
            return "HIGH", f"Python script in Startup folder: {filename}"
        
        # Other script types
        if ext in [".vbs", ".vbe", ".js", ".jse", ".ps1", ".bat", ".cmd"]:
            return "MEDIUM", f"Script file in Startup: {filename} ({ext})"
        
        return "MEDIUM", f"Suspicious file type: {ext}"
    
    # Check 3: Analyze content of readable files
    content = read_file_content(filepath)
    if content:
        is_suspicious_content, pattern = check_suspicious_content(content)
        if is_suspicious_content:
            return "MEDIUM", f"Suspicious content pattern: {pattern}"
    
    # Check 4: Recently created/modified files
    try:
        stat = os.stat(filepath)
        age_hours = (datetime.now().timestamp() - stat.st_mtime) / 3600
        if age_hours < 24:  # Less than 24 hours old
            if not is_trusted_file(filename):
                return "LOW", f"Recently added file (< 24 hours): {filename}"
    except:
        pass
    
    return None, None

def scan_startup_folder(folder_name, folder_path):
    """Scan a single startup folder for threats."""
    threats = []
    files_scanned = []
    
    print(f"    Scanning: {folder_name}")
    print(f"    Path: {folder_path}")
    
    try:
        for item in os.listdir(folder_path):
            item_path = os.path.join(folder_path, item)
            
            # Skip directories
            if os.path.isdir(item_path):
                continue
            
            files_scanned.append(item)
            
            # Analyze file
            threat_level, reason = analyze_startup_file(item_path)
            
            if threat_level:
                # Get additional info
                file_hash = calculate_file_hash(item_path)
                content = read_file_content(item_path, 500)  # First 500 chars
                
                threat = StartupThreat(
                    filepath=item_path,
                    filename=item,
                    threat_level=threat_level,
                    reason=reason,
                    file_hash=file_hash,
                    content_preview=content[:200] if content else None
                )
                threats.append(threat)
    
    except PermissionError:
        print(f"    [!] Permission denied: {folder_path}")
    except Exception as e:
        print(f"    [!] Error scanning folder: {e}")
    
    return threats, files_scanned

def scan_all_startup_folders():
    """Scan all startup folders for threats."""
    all_threats = []
    all_files = []
    
    print("[*] Scanning Startup Folders...")
    print()
    
    folders = get_startup_folders()
    
    for folder_name, folder_path in folders:
        threats, files = scan_startup_folder(folder_name, folder_path)
        all_threats.extend(threats)
        all_files.extend(files)
        print()
    
    return all_threats, all_files

# ==================== REMOVAL FUNCTIONS ====================

def backup_file(filepath, backup_dir=None):
    """Create a backup of a file before removal."""
    if backup_dir is None:
        backup_dir = os.path.join(os.environ.get("TEMP", ""), "startup_backup")
    
    os.makedirs(backup_dir, exist_ok=True)
    
    filename = os.path.basename(filepath)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"{timestamp}_{filename}")
    
    try:
        shutil.copy2(filepath, backup_path)
        return True, backup_path
    except Exception as e:
        return False, str(e)

def remove_startup_file(filepath, create_backup=True):
    """Remove a file from startup folder."""
    try:
        # Create backup first
        if create_backup:
            backup_success, backup_result = backup_file(filepath)
            if not backup_success:
                print(f"    [!] Backup failed: {backup_result}")
        
        # Remove the file
        os.remove(filepath)
        return True, None
    
    except FileNotFoundError:
        return False, "File not found"
    except PermissionError:
        return False, "Permission denied"
    except Exception as e:
        return False, str(e)

def remove_threat(threat, create_backup=True):
    """Remove a detected threat."""
    success, error = remove_startup_file(threat.filepath, create_backup)
    return success, error

def remove_all_threats(threats, create_backup=True):
    """Remove all detected threats."""
    results = []
    for threat in threats:
        success, error = remove_threat(threat, create_backup)
        results.append({
            "threat": threat,
            "success": success,
            "error": error
        })
    return results

# ==================== REPORTING FUNCTIONS ====================

def print_scan_results(threats, all_files):
    """Print scan results in a formatted way."""
    print()
    print("=" * 60)
    print("    STARTUP FOLDER SCAN RESULTS")
    print("=" * 60)
    print()
    print(f"    Total files scanned: {len(all_files)}")
    print(f"    Threats detected: {len(threats)}")
    print()
    
    if not threats:
        print("    ✅ No threats detected!")
        return
    
    # Group by threat level
    high_threats = [t for t in threats if t.threat_level == "HIGH"]
    medium_threats = [t for t in threats if t.threat_level == "MEDIUM"]
    low_threats = [t for t in threats if t.threat_level == "LOW"]
    
    if high_threats:
        print("    🔴 HIGH RISK THREATS:")
        print("    " + "-" * 50)
        for threat in high_threats:
            print(f"    File: {threat.filename}")
            print(f"    Path: {threat.filepath}")
            print(f"    Size: {threat.file_size} bytes")
            print(f"    Reason: {threat.reason}")
            if threat.file_hash:
                print(f"    SHA256: {threat.file_hash[:32]}...")
            print()
    
    if medium_threats:
        print("    🟡 MEDIUM RISK THREATS:")
        print("    " + "-" * 50)
        for threat in medium_threats:
            print(f"    File: {threat.filename}")
            print(f"    Path: {threat.filepath}")
            print(f"    Reason: {threat.reason}")
            print()
    
    if low_threats:
        print("    🟢 LOW RISK (Review Manually):")
        print("    " + "-" * 50)
        for threat in low_threats:
            print(f"    File: {threat.filename}")
            print(f"    Reason: {threat.reason}")
            print()

def generate_report(threats, all_files):
    """Generate a detailed report dictionary."""
    return {
        "scan_time": datetime.now().isoformat(),
        "total_files": len(all_files),
        "total_threats": len(threats),
        "high_risk": len([t for t in threats if t.threat_level == "HIGH"]),
        "medium_risk": len([t for t in threats if t.threat_level == "MEDIUM"]),
        "low_risk": len([t for t in threats if t.threat_level == "LOW"]),
        "threats": [t.to_dict() for t in threats]
    }

# ==================== MAIN FUNCTIONS ====================

def detect_startup_persistence():
    """Main function to detect startup folder persistence threats."""
    threats, files = scan_all_startup_folders()
    print_scan_results(threats, files)
    return threats

def remove_startup_persistence(threats=None):
    """Remove detected startup folder persistence threats."""
    if threats is None:
        threats, _ = scan_all_startup_folders()
    
    if not threats:
        print("    [*] No threats to remove.")
        return []
    
    high_threats = [t for t in threats if t.threat_level == "HIGH"]
    
    if not high_threats:
        print("    [*] No HIGH risk threats to auto-remove.")
        return []
    
    print(f"    [*] Removing {len(high_threats)} HIGH risk threats...")
    print(f"    [*] Backups will be saved to: %TEMP%\\startup_backup")
    print()
    
    results = remove_all_threats(high_threats)
    
    for result in results:
        if result["success"]:
            print(f"    [+] Removed: {result['threat'].filename}")
        else:
            print(f"    [-] Failed to remove {result['threat'].filename}: {result['error']}")
    
    return results

# ==================== STANDALONE EXECUTION ====================

if __name__ == "__main__":
    print()
    print("=" * 60)
    print("    STARTUP FOLDER PERSISTENCE DETECTOR")
    print("    Function 2: Anti-AutoRun Defense")
    print("=" * 60)
    print()
    
    # Detect threats
    threats = detect_startup_persistence()
    
    if threats:
        print()
        response = input("    Remove HIGH risk threats? (y/n): ")
        if response.lower() == 'y':
            print()
            remove_startup_persistence(threats)
    
    print()
    print("=" * 60)
    print("    Scan Complete!")
    print("=" * 60)
    print()
    input("Press Enter to exit...")
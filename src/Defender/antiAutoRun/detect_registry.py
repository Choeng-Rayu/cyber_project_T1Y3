"""
function1.py - Registry Persistence Detector & Remover
Detects and removes malicious entries from Windows Registry Run keys
"""

import winreg
import os
import re
from datetime import datetime

# ==================== CONFIGURATION ====================

# Known malicious entry names (from attacker code)
KNOWN_MALICIOUS_NAMES = [
    "WindowsSecurityService",
    "EducationalAutoRunTest",
    "WindowsDefender",
    "WindowsUpdate",
    "SystemService",
    "SecurityHealth",
]

# Suspicious patterns in registry values
SUSPICIOUS_PATTERNS = [
    r"pythonw?\.exe.*\.pyw?",      # Python scripts
    r"\.pyw?\s*$",                  # Files ending in .py or .pyw
    r"\\AppData\\.*\\Security\\",   # Hidden security folder
    r"\\AppData\\.*\\Update\\",     # Hidden update folder
    r"wscript\.exe.*\.vbs",         # VBScript execution
    r"cmd\.exe.*/c.*powershell",    # CMD launching PowerShell
    r"powershell.*-enc",            # Encoded PowerShell
    r"powershell.*-w\s+hidden",     # Hidden PowerShell
    r"mshta\.exe",                  # MSHTA execution
    r"regsvr32.*\/s.*\/u",          # Regsvr32 abuse
]

# Trusted publishers/paths (whitelist)
TRUSTED_PATHS = [
    r"C:\\Program Files\\",
    r"C:\\Program Files \(x86\)\\",
    r"C:\\Windows\\System32\\",
    r"C:\\Windows\\SysWOW64\\",
]

# Registry keys to scan
REGISTRY_RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

# ==================== CLASSES ====================

class RegistryThreat:
    """Represents a detected registry threat."""
    
    def __init__(self, hive, key_path, name, value, threat_level, reason):
        self.hive = hive
        self.key_path = key_path
        self.name = name
        self.value = value
        self.threat_level = threat_level  # "HIGH", "MEDIUM", "LOW"
        self.reason = reason
        self.detected_at = datetime.now()
    
    def __str__(self):
        hive_name = "HKCU" if self.hive == winreg.HKEY_CURRENT_USER else "HKLM"
        return f"[{self.threat_level}] {hive_name}\\{self.key_path}\\{self.name}"
    
    def to_dict(self):
        return {
            "hive": "HKCU" if self.hive == winreg.HKEY_CURRENT_USER else "HKLM",
            "key_path": self.key_path,
            "name": self.name,
            "value": self.value,
            "threat_level": self.threat_level,
            "reason": self.reason,
            "detected_at": self.detected_at.isoformat()
        }

# ==================== DETECTION FUNCTIONS ====================

def get_hive_name(hive):
    """Convert registry hive constant to readable name."""
    if hive == winreg.HKEY_CURRENT_USER:
        return "HKEY_CURRENT_USER"
    elif hive == winreg.HKEY_LOCAL_MACHINE:
        return "HKEY_LOCAL_MACHINE"
    return "UNKNOWN"

def is_trusted_path(value):
    """Check if the executable path is from a trusted location."""
    for pattern in TRUSTED_PATHS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False

def check_suspicious_patterns(value):
    """Check if value matches any suspicious patterns."""
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True, pattern
    return False, None

def check_known_malicious(name):
    """Check if entry name matches known malicious names."""
    for malicious_name in KNOWN_MALICIOUS_NAMES:
        if malicious_name.lower() in name.lower():
            return True
    return False

def check_file_exists(value):
    """Extract file path from registry value and check if it exists."""
    # Try to extract file path
    # Handle formats like: "C:\path\file.exe" or "C:\path\file.exe" -args
    match = re.search(r'"([^"]+)"', value)
    if match:
        filepath = match.group(1)
    else:
        # Try without quotes
        parts = value.split()
        if parts:
            filepath = parts[0]
        else:
            return None, False
    
    exists = os.path.exists(filepath)
    return filepath, exists

def analyze_registry_entry(name, value):
    """Analyze a registry entry and determine threat level."""
    threats = []
    
    # Check 1: Known malicious name
    if check_known_malicious(name):
        return "HIGH", f"Known malicious entry name: {name}"
    
    # Check 2: Suspicious patterns
    is_suspicious, pattern = check_suspicious_patterns(value)
    if is_suspicious:
        # If it's a Python script, it's likely malicious
        if "python" in pattern.lower() or ".pyw" in pattern.lower():
            return "HIGH", f"Suspicious Python execution: {pattern}"
        return "MEDIUM", f"Matches suspicious pattern: {pattern}"
    
    # Check 3: Non-trusted path
    if not is_trusted_path(value):
        # Check if file exists
        filepath, exists = check_file_exists(value)
        if filepath and not exists:
            return "MEDIUM", f"Executable not found: {filepath}"
        
        # AppData location is suspicious
        if "AppData" in value and (".py" in value or ".pyw" in value):
            return "HIGH", "Python script in AppData folder"
        
        if "AppData" in value:
            return "LOW", "Executable in AppData folder (verify manually)"
    
    return None, None  # No threat detected

def scan_registry_key(hive, key_path):
    """Scan a single registry key for suspicious entries."""
    threats = []
    entries = []
    
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        
        # Enumerate all values
        index = 0
        while True:
            try:
                name, value, value_type = winreg.EnumValue(key, index)
                entries.append((name, value, value_type))
                index += 1
            except OSError:
                break
        
        winreg.CloseKey(key)
        
        # Analyze each entry
        for name, value, value_type in entries:
            if value_type == winreg.REG_SZ or value_type == winreg.REG_EXPAND_SZ:
                threat_level, reason = analyze_registry_entry(name, str(value))
                if threat_level:
                    threat = RegistryThreat(
                        hive=hive,
                        key_path=key_path,
                        name=name,
                        value=str(value),
                        threat_level=threat_level,
                        reason=reason
                    )
                    threats.append(threat)
        
    except FileNotFoundError:
        pass  # Key doesn't exist
    except PermissionError:
        print(f"    [!] Permission denied: {get_hive_name(hive)}\\{key_path}")
    except Exception as e:
        print(f"    [!] Error scanning {key_path}: {e}")
    
    return threats, entries

def scan_all_registry_keys():
    """Scan all registry run keys for threats."""
    all_threats = []
    all_entries = []
    
    print("[*] Scanning Registry Run Keys...")
    print()
    
    for hive, key_path in REGISTRY_RUN_KEYS:
        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        print(f"    Scanning: {hive_name}\\{key_path}")
        
        threats, entries = scan_registry_key(hive, key_path)
        all_threats.extend(threats)
        all_entries.extend([(hive, key_path, name, value) for name, value, _ in entries])
    
    return all_threats, all_entries

# ==================== REMOVAL FUNCTIONS ====================

def remove_registry_entry(hive, key_path, name):
    """Remove a specific registry entry."""
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)
        return True, None
    except FileNotFoundError:
        return False, "Entry not found"
    except PermissionError:
        return False, "Permission denied (try running as Administrator)"
    except Exception as e:
        return False, str(e)

def remove_threat(threat):
    """Remove a detected threat from registry."""
    success, error = remove_registry_entry(threat.hive, threat.key_path, threat.name)
    return success, error

def remove_all_threats(threats):
    """Remove all detected threats."""
    results = []
    for threat in threats:
        success, error = remove_threat(threat)
        results.append({
            "threat": threat,
            "success": success,
            "error": error
        })
    return results

# ==================== REPORTING FUNCTIONS ====================

def print_scan_results(threats, all_entries):
    """Print scan results in a formatted way."""
    print()
    print("=" * 60)
    print("    REGISTRY SCAN RESULTS")
    print("=" * 60)
    print()
    print(f"    Total entries scanned: {len(all_entries)}")
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
            print(f"    Name: {threat.name}")
            print(f"    Value: {threat.value[:80]}...")
            print(f"    Reason: {threat.reason}")
            print()
    
    if medium_threats:
        print("    🟡 MEDIUM RISK THREATS:")
        print("    " + "-" * 50)
        for threat in medium_threats:
            print(f"    Name: {threat.name}")
            print(f"    Value: {threat.value[:80]}...")
            print(f"    Reason: {threat.reason}")
            print()
    
    if low_threats:
        print("    🟢 LOW RISK (Review Manually):")
        print("    " + "-" * 50)
        for threat in low_threats:
            print(f"    Name: {threat.name}")
            print(f"    Value: {threat.value[:80]}...")
            print(f"    Reason: {threat.reason}")
            print()

def generate_report(threats, all_entries):
    """Generate a detailed report dictionary."""
    return {
        "scan_time": datetime.now().isoformat(),
        "total_entries": len(all_entries),
        "total_threats": len(threats),
        "high_risk": len([t for t in threats if t.threat_level == "HIGH"]),
        "medium_risk": len([t for t in threats if t.threat_level == "MEDIUM"]),
        "low_risk": len([t for t in threats if t.threat_level == "LOW"]),
        "threats": [t.to_dict() for t in threats]
    }

# ==================== MAIN FUNCTIONS ====================

def detect_registry_persistence():
    """Main function to detect registry persistence threats."""
    threats, entries = scan_all_registry_keys()
    print_scan_results(threats, entries)
    return threats

def remove_registry_persistence(threats=None):
    """Remove detected registry persistence threats."""
    if threats is None:
        threats, _ = scan_all_registry_keys()
    
    if not threats:
        print("    [*] No threats to remove.")
        return []
    
    high_threats = [t for t in threats if t.threat_level == "HIGH"]
    
    if not high_threats:
        print("    [*] No HIGH risk threats to auto-remove.")
        return []
    
    print(f"    [*] Removing {len(high_threats)} HIGH risk threats...")
    results = remove_all_threats(high_threats)
    
    for result in results:
        if result["success"]:
            print(f"    [+] Removed: {result['threat'].name}")
        else:
            print(f"    [-] Failed to remove {result['threat'].name}: {result['error']}")
    
    return results

# ==================== STANDALONE EXECUTION ====================

if __name__ == "__main__":
    print()
    print("=" * 60)
    print("    REGISTRY PERSISTENCE DETECTOR")
    print("    Function 1: Anti-AutoRun Defense")
    print("=" * 60)
    print()
    
    # Detect threats
    threats = detect_registry_persistence()
    
    if threats:
        print()
        response = input("    Remove HIGH risk threats? (y/n): ")
        if response.lower() == 'y':
            print()
            remove_registry_persistence(threats)
    
    print()
    print("=" * 60)
    print("    Scan Complete!")
    print("=" * 60)
    print()
    input("Press Enter to exit...")
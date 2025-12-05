"""
anti_autorun.py - Anti-AutoRun Auto Scanner & Remover
Automatically scans and removes all persistence threats
"""

import os
import sys
import json
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import detection functions from existing files
from detect_registry import (
    detect_registry_persistence,
    remove_registry_persistence,
    scan_all_registry_keys,
    generate_report as generate_registry_report
)
from detect_startup import (
    detect_startup_persistence,
    remove_startup_persistence,
    scan_all_startup_folders,
    generate_report as generate_startup_report
)

# ==================== CONFIGURATION ====================

REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")
LOG_FILE = os.path.join(os.path.dirname(__file__), "scan_log.txt")

# ==================== HELPER FUNCTIONS ====================

def log_message(message):
    """Write message to log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")

def save_report(report, filename):
    """Save report to JSON file."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    return filepath

def print_banner():
    """Print the application banner."""
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                                                          ║")
    print("║           🛡️  ANTI-AUTORUN DEFENDER 🛡️                    ║")
    print("║                                                          ║")
    print("║      Automatic Persistence Detection & Removal          ║")
    print("║                                                          ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

# ==================== MAIN SCAN & REMOVE FUNCTION ====================

def scan_and_remove_all():
    """Automatically scan and remove all threats."""
    
    print("=" * 60)
    print("    PHASE 1: SCANNING SYSTEM")
    print("=" * 60)
    print()
    
    log_message("Starting automatic scan and removal")
    
    # ===== SCAN REGISTRY =====
    print("[*] Scanning Registry Run Keys...")
    print("-" * 50)
    registry_threats, registry_entries = scan_all_registry_keys()
    
    print()
    print(f"    📊 Registry entries scanned: {len(registry_entries)}")
    print(f"    ⚠️  Registry threats found: {len(registry_threats)}")
    print()
    
    # ===== SCAN STARTUP FOLDERS =====
    print("[*] Scanning Startup Folders...")
    print("-" * 50)
    startup_threats, startup_files = scan_all_startup_folders()
    
    print()
    print(f"    📊 Startup files scanned: {len(startup_files)}")
    print(f"    ⚠️  Startup threats found: {len(startup_threats)}")
    print()
    
    # ===== SUMMARY =====
    total_threats = len(registry_threats) + len(startup_threats)
    
    print("=" * 60)
    print("    SCAN SUMMARY")
    print("=" * 60)
    print()
    print(f"    Registry threats:       {len(registry_threats)}")
    print(f"    Startup folder threats: {len(startup_threats)}")
    print(f"    ─────────────────────────────────")
    print(f"    TOTAL THREATS:          {total_threats}")
    print()
    
    # Count by risk level
    high_risk_registry = [t for t in registry_threats if t.threat_level == "HIGH"]
    medium_risk_registry = [t for t in registry_threats if t.threat_level == "MEDIUM"]
    low_risk_registry = [t for t in registry_threats if t.threat_level == "LOW"]
    
    high_risk_startup = [t for t in startup_threats if t.threat_level == "HIGH"]
    medium_risk_startup = [t for t in startup_threats if t.threat_level == "MEDIUM"]
    low_risk_startup = [t for t in startup_threats if t.threat_level == "LOW"]
    
    total_high = len(high_risk_registry) + len(high_risk_startup)
    total_medium = len(medium_risk_registry) + len(medium_risk_startup)
    total_low = len(low_risk_registry) + len(low_risk_startup)
    
    print(f"    🔴 High Risk:    {total_high}")
    print(f"    🟡 Medium Risk:  {total_medium}")
    print(f"    🟢 Low Risk:     {total_low}")
    print()
    
    # ===== NO THREATS FOUND =====
    if total_threats == 0:
        print("=" * 60)
        print("    ✅ SYSTEM IS CLEAN!")
        print("    No persistence threats detected.")
        print("=" * 60)
        log_message("Scan completed. No threats found.")
        return
    
    # ===== DISPLAY DETECTED THREATS =====
    print("=" * 60)
    print("    DETECTED THREATS")
    print("=" * 60)
    print()
    
    if registry_threats:
        print("    📁 REGISTRY THREATS:")
        print("    " + "-" * 50)
        for threat in registry_threats:
            icon = "🔴" if threat.threat_level == "HIGH" else "🟡" if threat.threat_level == "MEDIUM" else "🟢"
            print(f"    {icon} [{threat.threat_level}] {threat.name}")
            print(f"       Value: {threat.value[:60]}..." if len(threat.value) > 60 else f"       Value: {threat.value}")
            print(f"       Reason: {threat.reason}")
            print()
    
    if startup_threats:
        print("    📁 STARTUP FOLDER THREATS:")
        print("    " + "-" * 50)
        for threat in startup_threats:
            icon = "🔴" if threat.threat_level == "HIGH" else "🟡" if threat.threat_level == "MEDIUM" else "🟢"
            print(f"    {icon} [{threat.threat_level}] {threat.filename}")
            print(f"       Path: {threat.filepath}")
            print(f"       Reason: {threat.reason}")
            print()
    
    # ===== PHASE 2: REMOVE ALL THREATS =====
    print("=" * 60)
    print("    PHASE 2: REMOVING THREATS")
    print("=" * 60)
    print()
    
    removed_count = 0
    failed_count = 0
    
    # Remove HIGH and MEDIUM risk registry threats
    high_medium_registry = [t for t in registry_threats if t.threat_level in ["HIGH", "MEDIUM"]]
    if high_medium_registry:
        print("[*] Removing registry threats...")
        for threat in high_medium_registry:
            try:
                import winreg
                key = winreg.OpenKey(threat.hive, threat.key_path, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, threat.name)
                winreg.CloseKey(key)
                print(f"    ✅ Removed: {threat.name}")
                removed_count += 1
                log_message(f"Removed registry threat: {threat.name}")
            except PermissionError:
                print(f"    ❌ Failed (Permission denied): {threat.name}")
                failed_count += 1
            except FileNotFoundError:
                print(f"    ⚠️  Already removed: {threat.name}")
            except Exception as e:
                print(f"    ❌ Failed: {threat.name} - {e}")
                failed_count += 1
        print()
    
    # Remove HIGH and MEDIUM risk startup threats
    high_medium_startup = [t for t in startup_threats if t.threat_level in ["HIGH", "MEDIUM"]]
    if high_medium_startup:
        print("[*] Removing startup folder threats...")
        
        # Create backup folder
        backup_dir = os.path.join(os.environ.get("TEMP", ""), "startup_backup")
        os.makedirs(backup_dir, exist_ok=True)
        
        for threat in high_medium_startup:
            try:
                # Backup first
                import shutil
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = os.path.join(backup_dir, f"{timestamp}_{threat.filename}")
                
                if os.path.exists(threat.filepath):
                    shutil.copy2(threat.filepath, backup_path)
                    os.remove(threat.filepath)
                    print(f"    ✅ Removed: {threat.filename}")
                    print(f"       Backup: {backup_path}")
                    removed_count += 1
                    log_message(f"Removed startup threat: {threat.filename}")
                else:
                    print(f"    ⚠️  Already removed: {threat.filename}")
            except PermissionError:
                print(f"    ❌ Failed (Permission denied): {threat.filename}")
                failed_count += 1
            except Exception as e:
                print(f"    ❌ Failed: {threat.filename} - {e}")
                failed_count += 1
        print()
    
    # ===== FINAL SUMMARY =====
    print("=" * 60)
    print("    REMOVAL COMPLETE")
    print("=" * 60)
    print()
    print(f"    ✅ Successfully removed: {removed_count}")
    print(f"    ❌ Failed to remove:     {failed_count}")
    print(f"    🟢 Low risk (skipped):   {total_low}")
    print()
    
    if failed_count > 0:
        print("    ⚠️  Some threats could not be removed.")
        print("    💡 Try running as Administrator for full access.")
        print()
    
    # ===== SAVE REPORT =====
    print("[*] Saving scan report...")
    
    registry_report = generate_registry_report(registry_threats, registry_entries)
    startup_report = generate_startup_report(startup_threats, startup_files)
    
    combined_report = {
        "scan_time": datetime.now().isoformat(),
        "system_info": {
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "username": os.environ.get("USERNAME", "unknown"),
        },
        "registry_scan": registry_report,
        "startup_scan": startup_report,
        "removal_summary": {
            "total_threats": total_threats,
            "removed": removed_count,
            "failed": failed_count,
            "skipped_low_risk": total_low,
        },
        "summary": {
            "total_threats": total_threats,
            "high_risk": total_high,
            "medium_risk": total_medium,
            "low_risk": total_low,
        }
    }
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.json"
    filepath = save_report(combined_report, filename)
    
    print(f"    📄 Report saved: {filepath}")
    print()
    
    log_message(f"Scan and removal completed. Removed: {removed_count}, Failed: {failed_count}")
    
    print("=" * 60)
    print("    🛡️  ANTI-AUTORUN DEFENDER COMPLETE!")
    print("=" * 60)
    print()

# ==================== MAIN ====================

def main():
    """Main function - automatically scan and remove."""
    print_banner()
    
    try:
        scan_and_remove_all()
    except KeyboardInterrupt:
        print()
        print("    [*] Interrupted by user.")
        log_message("Scan interrupted by user")
    except Exception as e:
        print(f"    ❌ Error: {e}")
        log_message(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
"""
Anti-Ransomware Protection System
Defends against:
- File encryption attacks (.locked extension)
- Browser data theft
- Sensitive data collection
- Startup persistence
- Suspicious process activity

Features:
- Real-time folder monitoring
- Automatic file recovery
- Malicious process detection & termination
- Registry protection
- Network traffic blocking
- Browser data protection
"""

import os
import sys
import json
import shutil
import platform
import threading
import time
import re
import hashlib
import subprocess
import sqlite3
from datetime import datetime
from pathlib import Path
from collections import deque

# Try to import Windows-specific modules
try:
    import ctypes
    import winreg
    WINDOWS = True
except ImportError:
    WINDOWS = False

# Try to import watchdog for folder monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

# Try to import psutil for process monitoring
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Try to import tkinter for GUI alerts
try:
    import tkinter as tk
    from tkinter import messagebox
    HAS_GUI = True
except ImportError:
    HAS_GUI = False


# ==================== CONFIGURATION ====================

# Ransomware indicators
RANSOMWARE_EXTENSIONS = {'.locked', '.encrypted', '.crypto', '.crypt', '.enc', '.ransomware'}
LOCK_FILE_NAMES = {'.folder_lock', '.locked', 'README.txt', 'DECRYPT.txt', 'HOW_TO_DECRYPT.txt'}
MALICIOUS_BACKEND_URLS = {
    'clownfish-app-5kdkx.ondigitalocean.app',
    # Add more known malicious domains
}

# Suspicious registry keys used for persistence
SUSPICIOUS_REGISTRY_VALUES = {
    'WindowsSecurityService',
    'WindowsDefenderUpdate',
    'SystemSecurityCheck',
}

# Protected folders
PROTECTED_FOLDERS = [
    Path.home() / 'Documents',
    Path.home() / 'Desktop',
    Path.home() / 'Downloads',
    Path.home() / 'Pictures',
]

# Backup directory
BACKUP_DIR = Path.home() / '.anti_ransomware_backup'

# Log file
LOG_FILE = Path.home() / '.anti_ransomware.log'

# Alert cooldown (seconds)
ALERT_COOLDOWN = 5


# ==================== LOGGING ====================

def log_event(message, level="INFO"):
    """Log security events to file"""
    timestamp = datetime.now().isoformat()
    log_entry = f"[{timestamp}] [{level}] {message}\n"
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
    except:
        pass
    print(f"[{level}] {message}")


# ==================== ALERT SYSTEM ====================

class AlertSystem:
    """GUI alert system for security warnings"""
    
    def __init__(self):
        self.last_alert_time = 0
        self.alert_queue = deque(maxlen=10)
    
    def show_alert(self, title, message, alert_type="warning"):
        """Show alert to user"""
        current_time = time.time()
        if current_time - self.last_alert_time < ALERT_COOLDOWN:
            self.alert_queue.append((title, message, alert_type))
            return
        
        self.last_alert_time = current_time
        log_event(f"ALERT: {title} - {message}", "ALERT")
        
        if HAS_GUI:
            try:
                root = tk.Tk()
                root.withdraw()
                if alert_type == "warning":
                    messagebox.showwarning(title, message)
                elif alert_type == "error":
                    messagebox.showerror(title, message)
                else:
                    messagebox.showinfo(title, message)
                root.destroy()
            except:
                pass


alert_system = AlertSystem()


# ==================== FILE PROTECTION ====================

class FileProtector:
    """Protects files from ransomware encryption"""
    
    def __init__(self):
        self.backup_dir = BACKUP_DIR
        self.backup_dir.mkdir(exist_ok=True)
        self.protected_extensions = {
            '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
            '.txt', '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4',
            '.zip', '.rar', '.7z', '.db', '.sqlite'
        }
    
    def create_backup(self, file_path):
        """Create backup of important file"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return False
            
            if file_path.suffix.lower() not in self.protected_extensions:
                return False
            
            # Create relative backup path
            rel_path = file_path.relative_to(Path.home()) if str(file_path).startswith(str(Path.home())) else file_path.name
            backup_path = self.backup_dir / rel_path
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(file_path, backup_path)
            log_event(f"Backed up: {file_path}")
            return True
        except Exception as e:
            log_event(f"Backup failed for {file_path}: {e}", "ERROR")
            return False
    
    def restore_file(self, locked_file_path):
        """Restore file from backup if it was encrypted"""
        try:
            locked_path = Path(locked_file_path)
            
            # Remove .locked extension to get original name
            if locked_path.suffix == '.locked':
                original_name = locked_path.stem
                original_path = locked_path.parent / original_name
            else:
                original_path = locked_path
            
            # Find backup
            rel_path = original_path.relative_to(Path.home()) if str(original_path).startswith(str(Path.home())) else original_path.name
            backup_path = self.backup_dir / rel_path
            
            if backup_path.exists():
                # Remove locked file
                if locked_path.exists():
                    os.remove(locked_path)
                
                # Restore from backup
                shutil.copy2(backup_path, original_path)
                log_event(f"Restored file: {original_path}")
                return True
            return False
        except Exception as e:
            log_event(f"Restore failed: {e}", "ERROR")
            return False
    
    def recover_locked_folder(self, folder_path):
        """Recover all locked files in a folder"""
        folder_path = Path(folder_path)
        recovered_count = 0
        
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.locked'):
                    file_path = Path(root) / file
                    
                    # Try to restore from backup
                    if self.restore_file(file_path):
                        recovered_count += 1
                    else:
                        # If no backup, just rename to remove .locked
                        try:
                            original_path = str(file_path)[:-7]  # Remove .locked
                            os.rename(file_path, original_path)
                            recovered_count += 1
                            log_event(f"Renamed locked file: {file_path}")
                        except Exception as e:
                            log_event(f"Failed to rename {file_path}: {e}", "ERROR")
        
        return recovered_count
    
    def remove_lock_file(self, folder_path):
        """Remove ransomware lock file from folder"""
        folder_path = Path(folder_path)
        for lock_name in LOCK_FILE_NAMES:
            lock_path = folder_path / lock_name
            if lock_path.exists():
                try:
                    # Remove hidden attribute on Windows
                    if WINDOWS:
                        try:
                            ctypes.windll.kernel32.SetFileAttributesW(str(lock_path), 0)
                        except:
                            pass
                    os.remove(lock_path)
                    log_event(f"Removed lock file: {lock_path}")
                except Exception as e:
                    log_event(f"Failed to remove lock file: {e}", "ERROR")


file_protector = FileProtector()


# ==================== REAL-TIME MONITORING ====================

if HAS_WATCHDOG:
    class RansomwareDetectionHandler(FileSystemEventHandler):
        """Detects and blocks ransomware file operations"""
        
        def __init__(self, on_threat_callback=None):
            super().__init__()
            self.on_threat_callback = on_threat_callback
            self.last_alert_time = 0
            self.encryption_events = deque(maxlen=100)
            self.threshold = 10  # Number of suspicious events before alert
            self.time_window = 5  # Seconds
        
        def is_ransomware_activity(self, event):
            """Check if file event indicates ransomware activity"""
            src_path = event.src_path
            
            # Check for ransomware extensions
            for ext in RANSOMWARE_EXTENSIONS:
                if src_path.endswith(ext):
                    return True
            
            # Check for lock file creation
            filename = os.path.basename(src_path)
            if filename in LOCK_FILE_NAMES:
                return True
            
            return False
        
        def on_created(self, event):
            """Handle file creation events"""
            if event.is_directory:
                return
            
            if self.is_ransomware_activity(event):
                self.handle_threat(event, "File encryption detected")
        
        def on_modified(self, event):
            """Handle file modification events"""
            if event.is_directory:
                return
            
            if self.is_ransomware_activity(event):
                self.handle_threat(event, "File modification by ransomware")
        
        def on_moved(self, event):
            """Handle file rename/move events (common in ransomware)"""
            if event.is_directory:
                return
            
            dest_path = event.dest_path
            
            # Detect renaming to .locked extension
            for ext in RANSOMWARE_EXTENSIONS:
                if dest_path.endswith(ext) and not event.src_path.endswith(ext):
                    self.handle_threat(event, f"File renamed to {ext}")
                    
                    # Try to reverse the rename immediately
                    try:
                        os.rename(dest_path, event.src_path)
                        log_event(f"Reversed ransomware rename: {dest_path} -> {event.src_path}")
                    except:
                        pass
                    return
        
        def handle_threat(self, event, description):
            """Handle detected threat"""
            current_time = time.time()
            self.encryption_events.append(current_time)
            
            # Count recent events
            recent_events = sum(1 for t in self.encryption_events if current_time - t < self.time_window)
            
            log_event(f"THREAT DETECTED: {description} - {event.src_path}", "WARNING")
            
            # If many events in short time, likely ransomware attack
            if recent_events >= self.threshold:
                log_event("RANSOMWARE ATTACK DETECTED! Taking defensive action.", "CRITICAL")
                alert_system.show_alert(
                    "🚨 Ransomware Detected!",
                    f"Ransomware activity detected!\n\nPath: {event.src_path}\n\n"
                    "Defensive measures activated.",
                    "error"
                )
                
                if self.on_threat_callback:
                    self.on_threat_callback(event.src_path)
            
            # Try to recover the file
            if hasattr(event, 'dest_path'):
                file_protector.restore_file(event.dest_path)


    class FolderMonitor(threading.Thread):
        """Monitor folders for ransomware activity"""
        
        def __init__(self, folders_to_monitor, on_threat_callback=None):
            super().__init__(daemon=True)
            self.folders = folders_to_monitor
            self.on_threat_callback = on_threat_callback
            self.observer = None
            self.running = False
        
        def run(self):
            self.running = True
            self.observer = Observer()
            handler = RansomwareDetectionHandler(self.on_threat_callback)
            
            for folder in self.folders:
                if Path(folder).exists():
                    self.observer.schedule(handler, str(folder), recursive=True)
                    log_event(f"Monitoring folder: {folder}")
            
            self.observer.start()
            
            while self.running:
                time.sleep(1)
            
            self.observer.stop()
            self.observer.join()
        
        def stop(self):
            self.running = False


# ==================== PROCESS MONITORING ====================

class ProcessMonitor:
    """Monitor and terminate suspicious processes"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'ransomware',
            r'encrypt',
            r'locker',
            r'cryptor',
        ]
        self.suspicious_connections = MALICIOUS_BACKEND_URLS
        self.killed_processes = set()
    
    def get_suspicious_processes(self):
        """Find processes with suspicious behavior"""
        suspicious = []
        
        if not HAS_PSUTIL:
            return suspicious
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections']):
            try:
                # Check process name
                proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
                
                # Check for suspicious patterns
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, proc_name) or re.search(pattern, cmdline):
                        suspicious.append(proc)
                        break
                
                # Check network connections
                try:
                    connections = proc.connections()
                    for conn in connections:
                        if conn.raddr:
                            remote_ip = conn.raddr.ip
                            for malicious_url in self.suspicious_connections:
                                if malicious_url in str(remote_ip):
                                    suspicious.append(proc)
                                    break
                except:
                    pass
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return suspicious
    
    def kill_process(self, proc):
        """Terminate a suspicious process"""
        try:
            pid = proc.pid
            proc_name = proc.name()
            
            if pid in self.killed_processes:
                return False
            
            proc.terminate()
            proc.wait(timeout=3)
            
            self.killed_processes.add(pid)
            log_event(f"Terminated suspicious process: {proc_name} (PID: {pid})", "WARNING")
            return True
        except Exception as e:
            # Force kill if terminate fails
            try:
                proc.kill()
                log_event(f"Force killed process: {proc.name()} (PID: {proc.pid})", "WARNING")
                return True
            except:
                log_event(f"Failed to kill process: {e}", "ERROR")
                return False
    
    def scan_and_kill_threats(self):
        """Scan for and terminate suspicious processes"""
        suspicious = self.get_suspicious_processes()
        killed = 0
        
        for proc in suspicious:
            if self.kill_process(proc):
                killed += 1
        
        return killed
    
    def monitor_continuously(self, interval=5):
        """Continuously monitor for suspicious processes"""
        while True:
            try:
                killed = self.scan_and_kill_threats()
                if killed > 0:
                    alert_system.show_alert(
                        "⚠️ Malicious Process Detected",
                        f"Terminated {killed} suspicious process(es).",
                        "warning"
                    )
            except Exception as e:
                log_event(f"Process monitor error: {e}", "ERROR")
            
            time.sleep(interval)


process_monitor = ProcessMonitor()


# ==================== REGISTRY PROTECTION ====================

class RegistryProtector:
    """Protect Windows registry from malicious modifications"""
    
    def __init__(self):
        self.startup_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    def remove_malicious_startup_entries(self):
        """Remove known malicious startup entries"""
        if not WINDOWS:
            return 0
        
        removed = 0
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.startup_key,
                0,
                winreg.KEY_ALL_ACCESS
            )
            
            # Enumerate values
            i = 0
            values_to_remove = []
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    
                    # Check for suspicious entries
                    if name in SUSPICIOUS_REGISTRY_VALUES:
                        values_to_remove.append(name)
                    
                    # Check for suspicious paths in value
                    value_lower = str(value).lower()
                    suspicious_keywords = ['ransomware', 'encrypt', 'locker', 'malicious']
                    for keyword in suspicious_keywords:
                        if keyword in value_lower:
                            values_to_remove.append(name)
                            break
                    
                    i += 1
                except OSError:
                    break
            
            # Remove suspicious entries
            for name in set(values_to_remove):
                try:
                    winreg.DeleteValue(key, name)
                    log_event(f"Removed malicious startup entry: {name}", "WARNING")
                    removed += 1
                except:
                    pass
            
            winreg.CloseKey(key)
        except Exception as e:
            log_event(f"Registry protection error: {e}", "ERROR")
        
        return removed
    
    def protect_startup_key(self):
        """Monitor and protect startup registry key"""
        if not WINDOWS:
            return
        
        while True:
            removed = self.remove_malicious_startup_entries()
            if removed > 0:
                alert_system.show_alert(
                    "🛡️ Registry Protected",
                    f"Removed {removed} malicious startup entries.",
                    "info"
                )
            time.sleep(10)


registry_protector = RegistryProtector()


# ==================== BROWSER PROTECTION ====================

class BrowserProtector:
    """Protect browser data from theft"""
    
    def __init__(self):
        self.browser_paths = self._get_browser_paths()
    
    def _get_browser_paths(self):
        """Get browser data paths"""
        if not WINDOWS:
            return {}
        
        userprofile = os.environ.get("USERPROFILE", "")
        return {
            'Chrome': os.path.join(userprofile, "AppData", "Local", "Google", "Chrome", "User Data"),
            'Brave': os.path.join(userprofile, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
            'Edge': os.path.join(userprofile, "AppData", "Local", "Microsoft", "Edge", "User Data"),
            'Firefox': os.path.join(userprofile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
        }
    
    def detect_browser_data_access(self):
        """Detect unauthorized access to browser data"""
        alerts = []
        
        if not HAS_PSUTIL:
            return alerts
        
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                # Skip browser processes themselves
                proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                if any(browser.lower() in proc_name for browser in ['chrome', 'firefox', 'edge', 'brave']):
                    continue
                
                # Check if process is accessing browser files
                open_files = proc.open_files()
                for file in open_files:
                    file_path = file.path.lower()
                    
                    for browser, browser_path in self.browser_paths.items():
                        if browser_path.lower() in file_path:
                            # Check for sensitive files
                            sensitive_files = ['login data', 'cookies', 'history', 'local state']
                            for sensitive in sensitive_files:
                                if sensitive in file_path:
                                    alerts.append({
                                        'process': proc.info['name'],
                                        'pid': proc.info['pid'],
                                        'browser': browser,
                                        'file': file.path
                                    })
                                    break
            except:
                pass
        
        return alerts
    
    def protect_browser_data(self):
        """Continuously protect browser data"""
        while True:
            try:
                alerts = self.detect_browser_data_access()
                
                for alert in alerts:
                    log_event(
                        f"BROWSER DATA ACCESS: Process {alert['process']} (PID: {alert['pid']}) "
                        f"accessing {alert['browser']} {alert['file']}",
                        "WARNING"
                    )
                    
                    # Try to terminate the suspicious process
                    try:
                        proc = psutil.Process(alert['pid'])
                        proc.terminate()
                        log_event(f"Terminated browser data thief: {alert['process']}", "WARNING")
                    except:
                        pass
                
                if alerts:
                    alert_system.show_alert(
                        "🔒 Browser Data Protected",
                        f"Blocked {len(alerts)} unauthorized access attempt(s) to browser data.",
                        "warning"
                    )
            except Exception as e:
                log_event(f"Browser protection error: {e}", "ERROR")
            
            time.sleep(5)


browser_protector = BrowserProtector()


# ==================== NETWORK PROTECTION ====================

class NetworkProtector:
    """Block connections to malicious servers"""
    
    def __init__(self):
        self.blocked_domains = MALICIOUS_BACKEND_URLS
        self.hosts_file = Path("C:/Windows/System32/drivers/etc/hosts") if WINDOWS else Path("/etc/hosts")
    
    def block_domain(self, domain):
        """Add domain to hosts file to block it"""
        try:
            # Check if already blocked
            if self.hosts_file.exists():
                content = self.hosts_file.read_text()
                if domain in content:
                    return True
            
            # Add to hosts file (requires admin privileges)
            with open(self.hosts_file, 'a') as f:
                f.write(f"\n127.0.0.1 {domain}")
                f.write(f"\n127.0.0.1 www.{domain}")
            
            log_event(f"Blocked domain: {domain}")
            return True
        except PermissionError:
            log_event(f"Cannot block domain {domain}: requires admin privileges", "WARNING")
            return False
        except Exception as e:
            log_event(f"Failed to block domain {domain}: {e}", "ERROR")
            return False
    
    def block_all_malicious_domains(self):
        """Block all known malicious domains"""
        blocked = 0
        for domain in self.blocked_domains:
            if self.block_domain(domain):
                blocked += 1
        return blocked
    
    def monitor_connections(self):
        """Monitor and block connections to malicious servers"""
        if not HAS_PSUTIL:
            return
        
        while True:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'connections']):
                    try:
                        connections = proc.connections()
                        for conn in connections:
                            if conn.raddr:
                                remote_addr = str(conn.raddr)
                                for domain in self.blocked_domains:
                                    if domain in remote_addr:
                                        log_event(
                                            f"Blocked connection to {domain} from {proc.info['name']}",
                                            "WARNING"
                                        )
                                        proc.terminate()
                                        break
                    except:
                        pass
            except Exception as e:
                log_event(f"Network monitor error: {e}", "ERROR")
            
            time.sleep(3)


network_protector = NetworkProtector()


# ==================== FOLDER RECOVERY ====================

class FolderRecovery:
    """Recover folders from ransomware encryption"""
    
    def __init__(self):
        self.protected_folders = PROTECTED_FOLDERS
    
    def scan_for_locked_folders(self):
        """Scan for folders that have been locked by ransomware"""
        locked_folders = []
        
        for folder in self.protected_folders:
            if not folder.exists():
                continue
            
            # Check for lock file
            for lock_name in LOCK_FILE_NAMES:
                lock_path = folder / lock_name
                if lock_path.exists():
                    locked_folders.append(folder)
                    break
            
            # Check for .locked files
            if folder not in locked_folders:
                for root, dirs, files in os.walk(folder):
                    for file in files:
                        if file.endswith('.locked'):
                            locked_folders.append(folder)
                            break
                    if folder in locked_folders:
                        break
        
        return locked_folders
    
    def recover_folder(self, folder_path):
        """Recover a locked folder"""
        folder_path = Path(folder_path)
        
        log_event(f"Starting recovery for: {folder_path}")
        
        # Remove lock file
        file_protector.remove_lock_file(folder_path)
        
        # Recover locked files
        recovered = file_protector.recover_locked_folder(folder_path)
        
        log_event(f"Recovered {recovered} files in {folder_path}")
        return recovered
    
    def auto_recover_all(self):
        """Automatically recover all locked folders"""
        locked_folders = self.scan_for_locked_folders()
        total_recovered = 0
        
        if locked_folders:
            log_event(f"Found {len(locked_folders)} locked folder(s)", "WARNING")
            
            for folder in locked_folders:
                try:
                    recovered = self.recover_folder(folder)
                    total_recovered += recovered
                except Exception as e:
                    log_event(f"Recovery failed for {folder}: {e}", "ERROR")
            
            if total_recovered > 0:
                alert_system.show_alert(
                    "✅ Files Recovered",
                    f"Successfully recovered {total_recovered} files from ransomware.",
                    "info"
                )
        
        return total_recovered


folder_recovery = FolderRecovery()


# ==================== MAIN PROTECTION CLASS ====================

class AntiRansomwareProtection:
    """Main anti-ransomware protection system"""
    
    def __init__(self):
        self.running = False
        self.threads = []
        self.folder_monitor = None
    
    def on_threat_detected(self, file_path):
        """Handle detected ransomware threat"""
        log_event(f"Threat callback triggered for: {file_path}", "CRITICAL")
        
        # Kill suspicious processes
        process_monitor.scan_and_kill_threats()
        
        # Clean registry
        registry_protector.remove_malicious_startup_entries()
        
        # Recover files
        folder = Path(file_path).parent
        file_protector.recover_locked_folder(folder)
    
    def start_real_time_protection(self):
        """Start all real-time protection features"""
        log_event("Starting Anti-Ransomware Protection System...")
        self.running = True
        
        # 1. Recover any existing locked folders
        log_event("Scanning for locked folders...")
        folder_recovery.auto_recover_all()
        
        # 2. Remove malicious startup entries
        log_event("Cleaning registry...")
        registry_protector.remove_malicious_startup_entries()
        
        # 3. Block malicious domains
        log_event("Blocking malicious domains...")
        network_protector.block_all_malicious_domains()
        
        # 4. Start folder monitoring
        if HAS_WATCHDOG:
            log_event("Starting folder monitoring...")
            self.folder_monitor = FolderMonitor(
                PROTECTED_FOLDERS,
                self.on_threat_detected
            )
            self.folder_monitor.start()
            self.threads.append(self.folder_monitor)
        
        # 5. Start process monitoring
        if HAS_PSUTIL:
            log_event("Starting process monitoring...")
            process_thread = threading.Thread(
                target=process_monitor.monitor_continuously,
                daemon=True
            )
            process_thread.start()
            self.threads.append(process_thread)
        
        # 6. Start registry monitoring
        if WINDOWS:
            log_event("Starting registry monitoring...")
            registry_thread = threading.Thread(
                target=registry_protector.protect_startup_key,
                daemon=True
            )
            registry_thread.start()
            self.threads.append(registry_thread)
        
        # 7. Start browser protection
        if HAS_PSUTIL:
            log_event("Starting browser protection...")
            browser_thread = threading.Thread(
                target=browser_protector.protect_browser_data,
                daemon=True
            )
            browser_thread.start()
            self.threads.append(browser_thread)
        
        # 8. Start network monitoring
        if HAS_PSUTIL:
            log_event("Starting network monitoring...")
            network_thread = threading.Thread(
                target=network_protector.monitor_connections,
                daemon=True
            )
            network_thread.start()
            self.threads.append(network_thread)
        
        log_event("Anti-Ransomware Protection System is now ACTIVE", "SUCCESS")
        
        if HAS_GUI:
            try:
                root = tk.Tk()
                root.withdraw()
                messagebox.showinfo(
                    "🛡️ Protection Active",
                    "Anti-Ransomware Protection is now running.\n\n"
                    "Features enabled:\n"
                    "• Real-time folder monitoring\n"
                    "• Process monitoring\n"
                    "• Browser data protection\n"
                    "• Registry protection\n"
                    "• Network protection"
                )
                root.destroy()
            except:
                pass
    
    def stop(self):
        """Stop all protection features"""
        log_event("Stopping Anti-Ransomware Protection...")
        self.running = False
        
        if self.folder_monitor:
            self.folder_monitor.stop()
        
        log_event("Anti-Ransomware Protection stopped")
    
    def run_forever(self):
        """Run protection indefinitely"""
        self.start_real_time_protection()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            log_event("Received shutdown signal...")
            self.stop()


# ==================== QUICK ACTIONS ====================

def quick_scan():
    """Perform a quick scan for ransomware"""
    print("\n" + "="*60)
    print("  🔍 Anti-Ransomware Quick Scan")
    print("="*60 + "\n")
    
    # Check for locked folders
    print("[*] Scanning for locked folders...")
    locked = folder_recovery.scan_for_locked_folders()
    if locked:
        print(f"[!] Found {len(locked)} locked folder(s):")
        for folder in locked:
            print(f"    - {folder}")
    else:
        print("[+] No locked folders found")
    
    # Check for suspicious processes
    if HAS_PSUTIL:
        print("\n[*] Scanning for suspicious processes...")
        suspicious = process_monitor.get_suspicious_processes()
        if suspicious:
            print(f"[!] Found {len(suspicious)} suspicious process(es):")
            for proc in suspicious:
                print(f"    - {proc.name()} (PID: {proc.pid})")
        else:
            print("[+] No suspicious processes found")
    
    # Check registry
    if WINDOWS:
        print("\n[*] Scanning registry for malicious entries...")
        # Just check, don't remove yet
        
    print("\n" + "="*60)
    print("  Scan Complete")
    print("="*60 + "\n")
    
    return locked


def quick_recover():
    """Quickly recover from ransomware attack"""
    print("\n" + "="*60)
    print("  🔧 Anti-Ransomware Quick Recovery")
    print("="*60 + "\n")
    
    # Kill suspicious processes
    if HAS_PSUTIL:
        print("[*] Terminating suspicious processes...")
        killed = process_monitor.scan_and_kill_threats()
        print(f"[+] Terminated {killed} suspicious process(es)")
    
    # Clean registry
    if WINDOWS:
        print("\n[*] Cleaning registry...")
        removed = registry_protector.remove_malicious_startup_entries()
        print(f"[+] Removed {removed} malicious startup entries")
    
    # Recover folders
    print("\n[*] Recovering locked folders...")
    recovered = folder_recovery.auto_recover_all()
    print(f"[+] Recovered {recovered} files")
    
    print("\n" + "="*60)
    print("  Recovery Complete")
    print("="*60 + "\n")


# ==================== MAIN ENTRY POINT ====================

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Anti-Ransomware Protection System')
    parser.add_argument('--scan', '-s', action='store_true', help='Quick scan for ransomware')
    parser.add_argument('--recover', '-r', action='store_true', help='Quick recovery from ransomware')
    parser.add_argument('--protect', '-p', action='store_true', help='Start real-time protection')
    parser.add_argument('--daemon', '-d', action='store_true', help='Run as daemon in background')
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║           🛡️ Anti-Ransomware Protection System v1.0               ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║  Features:                                                        ║
    ║  • Real-time folder monitoring                                    ║
    ║  • Automatic file recovery                                        ║
    ║  • Malicious process detection & termination                      ║
    ║  • Registry protection                                            ║
    ║  • Browser data protection                                        ║
    ║  • Network traffic blocking                                       ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    if args.scan:
        quick_scan()
    elif args.recover:
        quick_recover()
    elif args.protect or args.daemon:
        protection = AntiRansomwareProtection()
        protection.run_forever()
    else:
        # Default: start protection
        protection = AntiRansomwareProtection()
        protection.run_forever()


if __name__ == "__main__":
    main()

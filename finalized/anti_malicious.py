"""
Anti-Malicious Defender - Complete Protection Suite
Defends against: Photoshop_Setup.py malware
- Browser data theft protection
- Discord token theft protection
- Ransomware encryption protection
- Registry/startup persistence protection
- Credential capture protection
- Network exfiltration protection

WARNING: For EDUCATIONAL/RESEARCH purposes only.
"""

import os
import sys
import json
import hashlib
import shutil
import platform
import threading
import time
import re
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from collections import deque
import queue

# Try to import Windows-specific modules
try:
    import ctypes
    import winreg
    WINDOWS = True
except ImportError:
    WINDOWS = False

# Try to import tkinter for GUI
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext, filedialog
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

# Try to import psutil for process monitoring
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Try to import watchdog for folder monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False


# ==================== CONFIGURATION ====================

# Known malicious indicators from Photoshop_Setup.py
MALICIOUS_BACKEND_URLS = [
    "clownfish-app-5kdkx.ondigitalocean.app",
    "api/browser-data",
    "api/receive",
    "api/credentials",
]

MALICIOUS_EMAIL = "choengrayu307@gmail.com"

# Ransomware signature
RANSOMWARE_LOCK_FILE = ".G2T4_Khmer_tver_ban"
RANSOMWARE_EXTENSION = ".G2T4_Khmer_tver_ban"

# Known malicious code patterns
MALICIOUS_PATTERNS = [
    # Browser data theft patterns
    r"get_chromium_passwords",
    r"get_chromium_cookies",
    r"decrypt_password",
    r"get_encryption_key",
    r"Login Data",
    r"CryptUnprotectData",
    # Discord token theft
    r"get_discord_tokens",
    r"leveldb",
    r"mfa\.[\w-]{84}",
    # Ransomware patterns
    r"encrypt_folder",
    r"\.G2T4_Khmer_tver_ban",
    r"FolderEncryptor",
    # Persistence patterns
    r"add_to_startup",
    r"add_scheduled_task",
    r"WindowsSecurityService",
    r"WindowsSecurityUpdate",
    # Security bypass patterns
    r"disable_firewall",
    r"disable_defender",
    r"disable_windows_security",
    r"Set-MpPreference.*DisableRealtimeMonitoring",
    # Data exfiltration
    r"send_to_backend",
    r"send_credentials_to_backend",
    r"SensitiveDataCollector",
    # Credential capture
    r"capture_login_credentials",
    r"credential_capture_loop",
    # Obfuscation
    r"decode_ascii_to_text",
    r"rayu_mae_ah_nang",
]

# Suspicious process names
SUSPICIOUS_PROCESS_NAMES = [
    "photoshop_setup",
    "adobe_setup",
    "crack",
    "keygen",
    "patch",
    "activator",
]

# Protected registry keys
PROTECTED_REGISTRY_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
]

# Browser paths to protect
BROWSER_PATHS = {
    "Chrome": ["Google", "Chrome", "User Data"],
    "Edge": ["Microsoft", "Edge", "User Data"],
    "Brave": ["BraveSoftware", "Brave-Browser", "User Data"],
    "Opera": ["Opera Software", "Opera Stable"],
    "Firefox": ["Mozilla", "Firefox", "Profiles"],
    "Discord": ["Discord", "Local Storage"],
}

# Quarantine directory
QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), "quarantine")
LOG_FILE = os.path.join(os.path.dirname(__file__), "antimalware.log")


# ==================== LOGGING SETUP ====================

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()


# ==================== UTILITY FUNCTIONS ====================

def ensure_quarantine():
    """Ensure quarantine directory exists"""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

def sha256_file(file_path):
    """Calculate SHA256 hash of a file"""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def quarantine_file(file_path, reason="suspicious"):
    """Move suspicious file to quarantine"""
    ensure_quarantine()
    try:
        base = os.path.basename(file_path)
        file_hash = sha256_file(file_path) or "nohash"
        dest = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{file_hash[:8]}_{base}")
        shutil.move(file_path, dest)
        # Make read-only
        try:
            os.chmod(dest, 0o444)
        except:
            pass
        logger.info(f"[QUARANTINE] Moved {file_path} -> {dest} (reason={reason})")
        return dest
    except Exception as e:
        logger.error(f"[QUARANTINE-FAILED] {file_path} -> {e}")
        return None


# ==================== MALWARE SIGNATURE SCANNER ====================

class MalwareSignatureScanner:
    """Scans files for malicious patterns from Photoshop_Setup.py"""

    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in MALICIOUS_PATTERNS]
        self.scan_results = []

    def scan_file(self, file_path):
        """Scan a single file for malicious patterns"""
        if not os.path.exists(file_path):
            return None

        # Only scan text-based files
        text_extensions = {'.py', '.js', '.vbs', '.bat', '.ps1', '.txt', '.cmd', '.sh'}
        if Path(file_path).suffix.lower() not in text_extensions:
            return None

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            detected_patterns = []
            for pattern in self.patterns:
                matches = pattern.findall(content)
                if matches:
                    detected_patterns.extend(matches[:3])  # Limit to 3 matches per pattern

            # Check for specific malware identifiers
            if "rayu_mae_ah_nang" in content.lower() or "g2t4_khmer" in content.lower():
                detected_patterns.append("KNOWN_MALWARE_SIGNATURE")

            if MALICIOUS_EMAIL in content:
                detected_patterns.append("MALICIOUS_EMAIL_FOUND")

            for url in MALICIOUS_BACKEND_URLS:
                if url in content:
                    detected_patterns.append(f"MALICIOUS_URL: {url}")

            if detected_patterns:
                result = {
                    'file': file_path,
                    'patterns': detected_patterns,
                    'hash': sha256_file(file_path),
                    'timestamp': datetime.now().isoformat()
                }
                self.scan_results.append(result)
                return result

            return None

        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            return None

    def scan_directory(self, directory, recursive=True):
        """Scan directory for malware"""
        malware_found = []

        try:
            if recursive:
                for root, dirs, files in os.walk(directory):
                    # Skip protected directories
                    dirs[:] = [d for d in dirs if d not in {'node_modules', '__pycache__', '.git', 'venv'}]
                    for file in files:
                        file_path = os.path.join(root, file)
                        result = self.scan_file(file_path)
                        if result:
                            malware_found.append(result)
            else:
                for file in os.listdir(directory):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        result = self.scan_file(file_path)
                        if result:
                            malware_found.append(result)
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")

        return malware_found

    def get_threat_level(self, patterns):
        """Determine threat level based on detected patterns"""
        critical_patterns = ['KNOWN_MALWARE_SIGNATURE', 'MALICIOUS_EMAIL_FOUND', 'MALICIOUS_URL']
        high_patterns = ['encrypt_folder', 'disable_defender', 'add_to_startup', 'send_to_backend']

        for p in patterns:
            if any(cp in str(p) for cp in critical_patterns):
                return "CRITICAL"

        for p in patterns:
            if any(hp in str(p) for hp in high_patterns):
                return "HIGH"

        return "MEDIUM"


# ==================== BROWSER PROTECTION ====================

class BrowserProtector:
    """Protects browser databases from unauthorized access"""

    def __init__(self):
        self.user_home = Path.home()
        self.local_appdata = os.getenv('LOCALAPPDATA', '')
        self.roaming_appdata = os.getenv('APPDATA', '')
        self.protected_files = []
        self.original_permissions = {}

    def get_browser_db_paths(self):
        """Get paths to sensitive browser database files"""
        db_paths = []

        browser_locations = {
            'Chrome': os.path.join(self.local_appdata, 'Google', 'Chrome', 'User Data'),
            'Edge': os.path.join(self.local_appdata, 'Microsoft', 'Edge', 'User Data'),
            'Brave': os.path.join(self.local_appdata, 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Opera': os.path.join(self.roaming_appdata, 'Opera Software', 'Opera Stable'),
            'Vivaldi': os.path.join(self.local_appdata, 'Vivaldi', 'User Data'),
        }

        sensitive_files = ['Login Data', 'Cookies', 'History', 'Local State', 'Web Data']

        for browser, base_path in browser_locations.items():
            if os.path.exists(base_path):
                # Check Default profile
                default_profile = os.path.join(base_path, 'Default')
                if os.path.exists(default_profile):
                    for file in sensitive_files:
                        file_path = os.path.join(default_profile, file)
                        if os.path.exists(file_path):
                            db_paths.append({'browser': browser, 'path': file_path, 'type': file})
                        # Also check Network subfolder for Cookies
                        network_path = os.path.join(default_profile, 'Network', file)
                        if os.path.exists(network_path):
                            db_paths.append({'browser': browser, 'path': network_path, 'type': file})

                # Check Local State
                local_state = os.path.join(base_path, 'Local State')
                if os.path.exists(local_state):
                    db_paths.append({'browser': browser, 'path': local_state, 'type': 'Local State'})

        return db_paths

    def get_discord_paths(self):
        """Get paths to Discord token storage"""
        discord_paths = []
        discord_locations = [
            os.path.join(self.roaming_appdata, 'Discord', 'Local Storage', 'leveldb'),
            os.path.join(self.roaming_appdata, 'discordcanary', 'Local Storage', 'leveldb'),
            os.path.join(self.roaming_appdata, 'discordptb', 'Local Storage', 'leveldb'),
        ]

        for path in discord_locations:
            if os.path.exists(path):
                discord_paths.append({'app': 'Discord', 'path': path, 'type': 'Token Storage'})

        return discord_paths

    def check_browser_access_attempts(self):
        """Monitor for suspicious access to browser databases"""
        if not HAS_PSUTIL:
            return []

        suspicious_access = []
        browser_db_patterns = ['Login Data', 'Cookies', 'Local State', 'leveldb']

        try:
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    proc_info = proc.info
                    if proc_info['open_files']:
                        for open_file in proc_info['open_files']:
                            file_path = open_file.path
                            for pattern in browser_db_patterns:
                                if pattern in file_path:
                                    # Check if it's a browser process (legitimate access)
                                    if not self._is_legitimate_browser_process(proc_info['name']):
                                        suspicious_access.append({
                                            'pid': proc_info['pid'],
                                            'process_name': proc_info['name'],
                                            'file_accessed': file_path,
                                            'timestamp': datetime.now().isoformat()
                                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error(f"Error checking browser access: {e}")

        return suspicious_access

    def _is_legitimate_browser_process(self, process_name):
        """Check if process is a legitimate browser"""
        legitimate_browsers = [
            'chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi',
            'discord', 'slack', 'teams'
        ]
        if process_name:
            process_lower = process_name.lower()
            return any(browser in process_lower for browser in legitimate_browsers)
        return False


# ==================== REGISTRY PROTECTION ====================

class RegistryProtector:
    """Monitors and protects Windows registry from malicious modifications"""

    def __init__(self):
        self.baseline_startup_entries = {}
        self.suspicious_entries = []

    def get_startup_entries(self):
        """Get current startup registry entries"""
        if not WINDOWS:
            return {}

        startup_entries = {}

        try:
            # HKEY_CURRENT_USER Run
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        startup_entries[f"HKCU\\{key_path}\\{name}"] = value
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(key)
            except WindowsError:
                pass

            # HKEY_LOCAL_MACHINE Run
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        startup_entries[f"HKLM\\{key_path}\\{name}"] = value
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(key)
            except WindowsError:
                pass

        except Exception as e:
            logger.error(f"Error reading registry: {e}")

        return startup_entries

    def create_baseline(self):
        """Create baseline of legitimate startup entries"""
        self.baseline_startup_entries = self.get_startup_entries()
        logger.info(f"[REGISTRY] Baseline created with {len(self.baseline_startup_entries)} entries")
        return self.baseline_startup_entries

    def detect_new_entries(self):
        """Detect new startup entries added since baseline"""
        current_entries = self.get_startup_entries()
        new_entries = {}

        for key, value in current_entries.items():
            if key not in self.baseline_startup_entries:
                new_entries[key] = value
                # Check for malware-specific entries
                if 'WindowsSecurityService' in key or 'WindowsSecurityUpdate' in key:
                    self.suspicious_entries.append({
                        'key': key,
                        'value': value,
                        'reason': 'KNOWN_MALWARE_PERSISTENCE',
                        'timestamp': datetime.now().isoformat()
                    })

        return new_entries

    def remove_malicious_entry(self, key_path):
        """Remove a malicious registry entry"""
        if not WINDOWS:
            return False

        try:
            # Parse the key path
            if key_path.startswith("HKCU\\"):
                hive = winreg.HKEY_CURRENT_USER
                subkey = key_path[5:]
            elif key_path.startswith("HKLM\\"):
                hive = winreg.HKEY_LOCAL_MACHINE
                subkey = key_path[5:]
            else:
                return False

            # Split subkey and value name
            parts = subkey.rsplit('\\', 1)
            if len(parts) != 2:
                return False

            subkey_path, value_name = parts

            key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)

            logger.info(f"[REGISTRY] Removed malicious entry: {key_path}")
            return True

        except Exception as e:
            logger.error(f"Error removing registry entry {key_path}: {e}")
            return False


# ==================== RANSOMWARE PROTECTION ====================

class RansomwareProtector:
    """Protects against ransomware encryption attacks"""

    def __init__(self):
        self.user_home = Path.home()
        self.protected_folders = [
            self.user_home / 'Documents',
            self.user_home / 'Desktop',
            self.user_home / 'Downloads',
            self.user_home / 'Pictures',
        ]
        self.file_baseline = {}
        self.encryption_detected = False

    def check_for_ransomware_lock_files(self):
        """Check for known ransomware lock files"""
        lock_files_found = []

        for folder in self.protected_folders:
            if folder.exists():
                lock_file = folder / RANSOMWARE_LOCK_FILE
                if lock_file.exists():
                    lock_files_found.append({
                        'folder': str(folder),
                        'lock_file': str(lock_file),
                        'type': 'G2T4_RANSOMWARE',
                        'timestamp': datetime.now().isoformat()
                    })

        return lock_files_found

    def check_for_encrypted_files(self):
        """Check for files with ransomware extension"""
        encrypted_files = []

        for folder in self.protected_folders:
            if folder.exists():
                try:
                    for root, dirs, files in os.walk(folder):
                        for file in files:
                            if file.endswith(RANSOMWARE_EXTENSION):
                                encrypted_files.append({
                                    'file': os.path.join(root, file),
                                    'extension': RANSOMWARE_EXTENSION,
                                    'timestamp': datetime.now().isoformat()
                                })
                except Exception:
                    pass

        return encrypted_files

    def decrypt_file(self, file_path):
        """Restore encrypted file by removing ransomware extension"""
        try:
            if file_path.endswith(RANSOMWARE_EXTENSION):
                original_path = file_path[:-len(RANSOMWARE_EXTENSION)]
                os.rename(file_path, original_path)
                logger.info(f"[RANSOMWARE] Restored file: {original_path}")
                return True
        except Exception as e:
            logger.error(f"Error restoring file {file_path}: {e}")
        return False

    def decrypt_folder(self, folder_path):
        """Restore all encrypted files in a folder"""
        restored_count = 0
        folder = Path(folder_path)

        if not folder.exists():
            return 0

        try:
            # Remove lock file if exists
            lock_file = folder / RANSOMWARE_LOCK_FILE
            if lock_file.exists():
                try:
                    # Remove hidden attribute on Windows
                    if WINDOWS:
                        ctypes.windll.kernel32.SetFileAttributesW(str(lock_file), 0)
                    os.remove(lock_file)
                    logger.info(f"[RANSOMWARE] Removed lock file: {lock_file}")
                except Exception as e:
                    logger.error(f"Error removing lock file: {e}")

            # Restore all encrypted files
            for root, dirs, files in os.walk(folder):
                for file in files:
                    if file.endswith(RANSOMWARE_EXTENSION):
                        file_path = os.path.join(root, file)
                        if self.decrypt_file(file_path):
                            restored_count += 1

        except Exception as e:
            logger.error(f"Error decrypting folder {folder_path}: {e}")

        return restored_count

    def create_file_baseline(self):
        """Create baseline of file hashes for monitoring"""
        self.file_baseline = {}

        for folder in self.protected_folders:
            if folder.exists():
                try:
                    for root, dirs, files in os.walk(folder):
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        for file in files[:100]:  # Limit to 100 files per folder
                            file_path = os.path.join(root, file)
                            try:
                                stat = os.stat(file_path)
                                self.file_baseline[file_path] = {
                                    'size': stat.st_size,
                                    'mtime': stat.st_mtime
                                }
                            except:
                                pass
                except Exception:
                    pass

        return len(self.file_baseline)

    def detect_mass_encryption(self):
        """Detect rapid file modifications indicating encryption"""
        changes_detected = 0

        for file_path, baseline in self.file_baseline.items():
            try:
                if os.path.exists(file_path):
                    stat = os.stat(file_path)
                    if stat.st_mtime != baseline['mtime'] or stat.st_size != baseline['size']:
                        changes_detected += 1
            except:
                pass

        # If more than 20% of files changed, likely encryption attack
        if len(self.file_baseline) > 0:
            change_ratio = changes_detected / len(self.file_baseline)
            if change_ratio > 0.2:
                self.encryption_detected = True
                return True

        return False


# ==================== NETWORK PROTECTION ====================

class NetworkProtector:
    """Blocks suspicious network connections"""

    def __init__(self):
        self.blocked_domains = MALICIOUS_BACKEND_URLS.copy()
        self.blocked_connections = []

    def check_suspicious_connections(self):
        """Check for connections to known malicious endpoints"""
        if not HAS_PSUTIL:
            return []

        suspicious = []

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port

                    # Get process info
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except:
                        proc_name = "Unknown"

                    # Check for suspicious HTTP/HTTPS connections
                    if remote_port in [80, 443, 8080]:
                        suspicious.append({
                            'pid': conn.pid,
                            'process': proc_name,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'timestamp': datetime.now().isoformat()
                        })
        except Exception as e:
            logger.error(f"Error checking network connections: {e}")

        return suspicious

    def block_malicious_domains(self):
        """Add entries to hosts file to block malicious domains"""
        if not WINDOWS:
            return False

        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

        try:
            # Read current hosts file
            with open(hosts_path, 'r') as f:
                hosts_content = f.read()

            # Add blocks for malicious domains
            new_entries = []
            for domain in self.blocked_domains:
                if domain not in hosts_content:
                    new_entries.append(f"127.0.0.1 {domain}")

            if new_entries:
                with open(hosts_path, 'a') as f:
                    f.write("\n# Blocked by Anti-Malicious Defender\n")
                    f.write("\n".join(new_entries) + "\n")

                logger.info(f"[NETWORK] Blocked {len(new_entries)} malicious domains")
                return True

        except PermissionError:
            logger.warning("[NETWORK] Need administrator rights to modify hosts file")
        except Exception as e:
            logger.error(f"Error blocking domains: {e}")

        return False

    def kill_suspicious_process(self, pid):
        """Kill a suspicious process by PID"""
        if not HAS_PSUTIL:
            return False

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            logger.info(f"[NETWORK] Terminated suspicious process: PID {pid}")
            return True
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {e}")
            return False


# ==================== USB AUTORUN PROTECTOR ====================

class USBAutorunProtector:
    """Prevents malware from auto-running via USB drives and removable media"""

    def __init__(self):
        self.autorun_files = ['autorun.inf', 'autorun.bat', 'autorun.cmd', 'autorun.exe', 'autorun.vbs']
        self.suspicious_usb_files = [
            'setup.exe', 'install.exe', 'run.exe', 'start.exe',
            'photoshop_setup.py', 'photoshop_setup.exe',
            'open.exe', 'driver.exe', 'recycler.exe'
        ]

    def get_removable_drives(self):
        """Get list of removable drives"""
        drives = []

        if not HAS_PSUTIL:
            # Fallback: check common drive letters on Windows
            if WINDOWS:
                for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
                    drive = f"{letter}:\\"
                    if os.path.exists(drive):
                        try:
                            # Check if it's a removable drive
                            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                            if drive_type == 2:  # DRIVE_REMOVABLE
                                drives.append(drive)
                        except:
                            pass
            return drives

        try:
            for partition in psutil.disk_partitions(all=True):
                # Check for removable drives
                if 'removable' in partition.opts.lower() or partition.fstype == '':
                    drives.append(partition.mountpoint)
                # On Windows, also check drive type
                elif WINDOWS:
                    try:
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(partition.mountpoint)
                        if drive_type == 2:  # DRIVE_REMOVABLE
                            drives.append(partition.mountpoint)
                    except:
                        pass
        except Exception as e:
            logger.error(f"Error getting removable drives: {e}")

        return drives

    def disable_autorun_registry(self):
        """Disable Windows autorun via registry"""
        if not WINDOWS:
            return False

        try:
            # Disable autorun for all drives
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            except WindowsError:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)

            # NoDriveTypeAutoRun = 0xFF disables autorun for all drive types
            winreg.SetValueEx(key, "NoDriveTypeAutoRun", 0, winreg.REG_DWORD, 0xFF)
            winreg.CloseKey(key)

            logger.info("[USB] Disabled autorun via registry (NoDriveTypeAutoRun = 0xFF)")
            return True

        except Exception as e:
            logger.error(f"Error disabling autorun in registry: {e}")
            return False

    def disable_autoplay_registry(self):
        """Disable Windows autoplay via registry"""
        if not WINDOWS:
            return False

        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"

            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            except WindowsError:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)

            # DisableAutoplay = 1 disables autoplay
            winreg.SetValueEx(key, "DisableAutoplay", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)

            logger.info("[USB] Disabled autoplay via registry")
            return True

        except Exception as e:
            logger.error(f"Error disabling autoplay: {e}")
            return False

    def scan_drive_for_autorun(self, drive_path):
        """Scan a drive for autorun files and suspicious executables"""
        threats = []

        try:
            # Check root for autorun files
            for filename in self.autorun_files:
                file_path = os.path.join(drive_path, filename)
                if os.path.exists(file_path):
                    threats.append({
                        'file': file_path,
                        'type': 'AUTORUN_FILE',
                        'risk': 'HIGH',
                        'description': f'Autorun file detected: {filename}'
                    })
                    logger.warning(f"[USB] Found autorun file: {file_path}")

            # Check for suspicious executables in root
            for filename in self.suspicious_usb_files:
                file_path = os.path.join(drive_path, filename)
                if os.path.exists(file_path):
                    threats.append({
                        'file': file_path,
                        'type': 'SUSPICIOUS_USB_FILE',
                        'risk': 'HIGH',
                        'description': f'Suspicious USB file: {filename}'
                    })
                    logger.warning(f"[USB] Found suspicious USB file: {file_path}")

            # Check for hidden executables in root
            try:
                for item in os.listdir(drive_path):
                    item_path = os.path.join(drive_path, item)
                    if os.path.isfile(item_path):
                        # Check for hidden files with executable extensions
                        if item.lower().endswith(('.exe', '.bat', '.cmd', '.vbs', '.ps1', '.py')):
                            if WINDOWS:
                                try:
                                    attrs = ctypes.windll.kernel32.GetFileAttributesW(item_path)
                                    if attrs & 2:  # FILE_ATTRIBUTE_HIDDEN
                                        threats.append({
                                            'file': item_path,
                                            'type': 'HIDDEN_EXECUTABLE',
                                            'risk': 'MEDIUM',
                                            'description': f'Hidden executable: {item}'
                                        })
                                        logger.warning(f"[USB] Found hidden executable: {item_path}")
                                except:
                                    pass
            except PermissionError:
                pass

        except Exception as e:
            logger.error(f"Error scanning drive {drive_path}: {e}")

        return threats

    def remove_autorun_file(self, file_path):
        """Remove an autorun file and quarantine it"""
        try:
            if os.path.exists(file_path):
                result = quarantine_file(file_path, reason="autorun_threat")
                if result:
                    logger.info(f"[USB] Quarantined autorun file: {file_path}")
                    return True
        except Exception as e:
            logger.error(f"Error removing autorun file {file_path}: {e}")
        return False

    def protect_all_drives(self):
        """Scan and protect all removable drives"""
        all_threats = []

        # First, disable autorun at system level
        self.disable_autorun_registry()
        self.disable_autoplay_registry()

        # Scan all removable drives
        drives = self.get_removable_drives()
        for drive in drives:
            logger.info(f"[USB] Scanning removable drive: {drive}")
            threats = self.scan_drive_for_autorun(drive)
            all_threats.extend(threats)

        return all_threats

    def create_autorun_immunization(self, drive_path):
        """Create immunization folder to prevent autorun.inf creation"""
        try:
            autorun_folder = os.path.join(drive_path, "autorun.inf")
            if not os.path.exists(autorun_folder):
                os.makedirs(autorun_folder)
                # Make it read-only and hidden on Windows
                if WINDOWS:
                    ctypes.windll.kernel32.SetFileAttributesW(
                        autorun_folder,
                        0x01 | 0x02 | 0x04  # READ_ONLY | HIDDEN | SYSTEM
                    )
                logger.info(f"[USB] Created immunization folder: {autorun_folder}")
                return True
        except Exception as e:
            logger.error(f"Error creating immunization: {e}")
        return False


# ==================== NETWORK SPREADING PROTECTOR ====================

class NetworkSpreadingProtector:
    """Prevents malware from spreading via network shares and connections"""

    def __init__(self):
        self.network_share_paths = []
        self.suspicious_share_files = [
            'photoshop_setup.py', 'photoshop_setup.exe',
            'setup.exe', 'install.exe', 'update.exe',
            '*.g2t4_khmer_tver_ban'  # Ransomware encrypted files
        ]
        self.blocked_ports = [445, 139, 135]  # SMB and NetBIOS ports

    def get_network_shares(self):
        """Get list of network share connections"""
        shares = []

        if WINDOWS:
            try:
                # Use net use command to get network shares
                result = subprocess.run(
                    ['net', 'use'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                for line in result.stdout.split('\n'):
                    if '\\\\' in line:
                        parts = line.split()
                        for part in parts:
                            if part.startswith('\\\\'):
                                shares.append(part)
            except Exception as e:
                logger.error(f"Error getting network shares: {e}")

        return shares

    def scan_network_share(self, share_path):
        """Scan a network share for spreading malware"""
        threats = []

        try:
            if not os.path.exists(share_path):
                return threats

            for root, dirs, files in os.walk(share_path):
                for filename in files:
                    file_lower = filename.lower()
                    file_path = os.path.join(root, filename)

                    # Check for malware files
                    if file_lower in [f.lower() for f in self.suspicious_share_files if not f.startswith('*')]:
                        threats.append({
                            'file': file_path,
                            'type': 'NETWORK_MALWARE',
                            'risk': 'HIGH',
                            'description': f'Suspicious file on network share: {filename}'
                        })
                        logger.warning(f"[NETWORK] Found suspicious file on share: {file_path}")

                    # Check for ransomware encrypted files
                    if file_lower.endswith('.g2t4_khmer_tver_ban'):
                        threats.append({
                            'file': file_path,
                            'type': 'RANSOMWARE_ENCRYPTED',
                            'risk': 'CRITICAL',
                            'description': f'Ransomware encrypted file on share: {filename}'
                        })
                        logger.warning(f"[NETWORK] Found encrypted file on share: {file_path}")

                # Limit depth to prevent excessive scanning
                if root.count(os.sep) - share_path.count(os.sep) >= 3:
                    break

        except PermissionError:
            logger.warning(f"[NETWORK] Permission denied accessing: {share_path}")
        except Exception as e:
            logger.error(f"Error scanning network share {share_path}: {e}")

        return threats

    def disable_admin_shares(self):
        """Disable administrative shares (C$, ADMIN$, etc.) via registry"""
        if not WINDOWS:
            return False

        try:
            key_path = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                # AutoShareWks = 0 disables admin shares on workstations
                winreg.SetValueEx(key, "AutoShareWks", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                logger.info("[NETWORK] Disabled administrative shares via registry")
                return True
            except PermissionError:
                logger.warning("[NETWORK] Need admin rights to disable admin shares")
                return False

        except Exception as e:
            logger.error(f"Error disabling admin shares: {e}")
            return False

    def check_smb_connections(self):
        """Check for suspicious SMB connections"""
        suspicious = []

        if not HAS_PSUTIL:
            return suspicious

        try:
            connections = psutil.net_connections(kind='inet')

            for conn in connections:
                # Check for SMB ports
                if conn.raddr and conn.raddr.port in self.blocked_ports:
                    suspicious.append({
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status,
                        'pid': conn.pid,
                        'type': 'SMB_CONNECTION'
                    })

        except Exception as e:
            logger.error(f"Error checking SMB connections: {e}")

        return suspicious

    def block_network_spreading_firewall(self):
        """Create firewall rules to block network spreading"""
        if not WINDOWS:
            return False

        rules_created = 0

        try:
            # Block outbound SMB
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=AntiMalware_Block_SMB_Out', 'dir=out', 'action=block',
                'protocol=tcp', 'remoteport=445'
            ], capture_output=True, timeout=10)
            rules_created += 1

            # Block outbound NetBIOS
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=AntiMalware_Block_NetBIOS_Out', 'dir=out', 'action=block',
                'protocol=tcp', 'remoteport=139'
            ], capture_output=True, timeout=10)
            rules_created += 1

            logger.info(f"[NETWORK] Created {rules_created} firewall rules to block spreading")
            return True

        except Exception as e:
            logger.error(f"Error creating firewall rules: {e}")
            return False

    def remove_firewall_rules(self):
        """Remove the firewall rules created by this protector"""
        if not WINDOWS:
            return False

        try:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=AntiMalware_Block_SMB_Out'
            ], capture_output=True, timeout=10)

            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=AntiMalware_Block_NetBIOS_Out'
            ], capture_output=True, timeout=10)

            logger.info("[NETWORK] Removed spreading protection firewall rules")
            return True

        except Exception as e:
            logger.error(f"Error removing firewall rules: {e}")
            return False

    def protect_shared_folders(self):
        """Scan and protect shared folders from malware spreading"""
        all_threats = []

        shares = self.get_network_shares()
        for share in shares:
            logger.info(f"[NETWORK] Scanning network share: {share}")
            threats = self.scan_network_share(share)
            all_threats.extend(threats)

        return all_threats

    def get_local_shared_folders(self):
        """Get locally shared folders"""
        shared = []

        if WINDOWS:
            try:
                result = subprocess.run(
                    ['net', 'share'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                for line in result.stdout.split('\n')[4:]:  # Skip header
                    if line.strip() and not line.startswith('The command'):
                        parts = line.split()
                        if len(parts) >= 2 and ':' in parts[1]:
                            shared.append({
                                'name': parts[0],
                                'path': parts[1]
                            })
            except Exception as e:
                logger.error(f"Error getting local shares: {e}")

        return shared


# ==================== PROCESS MONITOR ====================

class ProcessMonitor:
    """Monitors running processes for suspicious activity"""

    def __init__(self):
        self.suspicious_patterns = SUSPICIOUS_PROCESS_NAMES.copy()
        self.monitored_pids = set()

    def scan_processes(self):
        """Scan all running processes for suspicious activity"""
        if not HAS_PSUTIL:
            return []

        suspicious_processes = []

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    info = proc.info
                    proc_name = (info['name'] or '').lower()
                    cmdline = ' '.join(info['cmdline'] or []).lower()
                    exe_path = info['exe'] or ''

                    # Check for suspicious process names
                    for pattern in self.suspicious_patterns:
                        if pattern in proc_name or pattern in cmdline:
                            suspicious_processes.append({
                                'pid': info['pid'],
                                'name': info['name'],
                                'cmdline': cmdline[:200],
                                'exe': exe_path,
                                'reason': f'Suspicious pattern: {pattern}',
                                'timestamp': datetime.now().isoformat()
                            })
                            break

                    # Check for malware-specific indicators in command line
                    malware_indicators = [
                        'g2t4_khmer', 'rayu_mae_ah_nang', 'choengrayu',
                        'encrypt_folder', 'disable_defender', 'add_to_startup'
                    ]

                    for indicator in malware_indicators:
                        if indicator in cmdline:
                            suspicious_processes.append({
                                'pid': info['pid'],
                                'name': info['name'],
                                'cmdline': cmdline[:200],
                                'exe': exe_path,
                                'reason': f'Malware indicator: {indicator}',
                                'timestamp': datetime.now().isoformat()
                            })
                            break

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            logger.error(f"Error scanning processes: {e}")

        return suspicious_processes

    def kill_process(self, pid):
        """Terminate a process by PID"""
        if not HAS_PSUTIL:
            return False

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=5)
            logger.info(f"[PROCESS] Terminated suspicious process: PID {pid}")
            return True
        except psutil.TimeoutExpired:
            proc.kill()
            logger.info(f"[PROCESS] Force killed process: PID {pid}")
            return True
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False


# ==================== MAIN ANTI-MALWARE ENGINE ====================

class AntiMalwareEngine:
    """Main anti-malware engine that coordinates all protection modules"""

    def __init__(self):
        self.scanner = MalwareSignatureScanner()
        self.browser_protector = BrowserProtector()
        self.registry_protector = RegistryProtector()
        self.ransomware_protector = RansomwareProtector()
        self.network_protector = NetworkProtector()
        self.process_monitor = ProcessMonitor()
        self.usb_protector = USBAutorunProtector()
        self.network_spreading_protector = NetworkSpreadingProtector()

        self.is_running = False
        self.protection_active = False
        self.scan_results = []
        self.alerts = []
        self.log_queue = queue.Queue()

    def log(self, message, level="INFO"):
        """Thread-safe logging"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.log_queue.put(log_entry)

        if level == "ERROR":
            logger.error(message)
        elif level == "WARNING":
            logger.warning(message)
        else:
            logger.info(message)

    def quick_scan(self, directory=None):
        """Perform a quick scan of common locations"""
        self.log("Starting quick scan...")
        results = []

        # Scan user directories
        scan_dirs = [
            Path.home() / 'Downloads',
            Path.home() / 'Desktop',
            Path.home() / 'Documents',
        ]

        if directory:
            scan_dirs = [Path(directory)]

        for scan_dir in scan_dirs:
            if scan_dir.exists():
                self.log(f"Scanning: {scan_dir}")
                dir_results = self.scanner.scan_directory(str(scan_dir), recursive=False)
                results.extend(dir_results)

        self.scan_results = results
        self.log(f"Quick scan complete. Found {len(results)} threats.")
        return results

    def full_scan(self, directory=None):
        """Perform a full recursive scan"""
        self.log("Starting full system scan...")
        results = []

        if directory:
            scan_dirs = [Path(directory)]
        else:
            scan_dirs = [
                Path.home(),
            ]

        for scan_dir in scan_dirs:
            if scan_dir.exists():
                self.log(f"Deep scanning: {scan_dir}")
                dir_results = self.scanner.scan_directory(str(scan_dir), recursive=True)
                results.extend(dir_results)

        self.scan_results = results
        self.log(f"Full scan complete. Found {len(results)} threats.")
        return results

    def check_system_health(self):
        """Perform comprehensive system health check"""
        health_report = {
            'timestamp': datetime.now().isoformat(),
            'threats': [],
            'warnings': [],
            'status': 'HEALTHY'
        }

        # Check for ransomware
        self.log("Checking for ransomware...")
        lock_files = self.ransomware_protector.check_for_ransomware_lock_files()
        if lock_files:
            health_report['threats'].extend(lock_files)
            health_report['status'] = 'CRITICAL'
            self.log(f"WARNING: Found {len(lock_files)} ransomware lock files!", "WARNING")

        encrypted_files = self.ransomware_protector.check_for_encrypted_files()
        if encrypted_files:
            health_report['threats'].append({
                'type': 'ENCRYPTED_FILES',
                'count': len(encrypted_files),
                'files': encrypted_files[:10]
            })
            health_report['status'] = 'CRITICAL'
            self.log(f"WARNING: Found {len(encrypted_files)} encrypted files!", "WARNING")

        # Check registry for persistence
        self.log("Checking registry for malicious persistence...")
        self.registry_protector.create_baseline()
        if self.registry_protector.suspicious_entries:
            health_report['threats'].extend(self.registry_protector.suspicious_entries)
            health_report['status'] = 'INFECTED'
            self.log(f"WARNING: Found {len(self.registry_protector.suspicious_entries)} suspicious registry entries!", "WARNING")

        # Check for suspicious processes
        self.log("Scanning running processes...")
        suspicious_procs = self.process_monitor.scan_processes()
        if suspicious_procs:
            health_report['threats'].extend(suspicious_procs)
            health_report['status'] = 'INFECTED'
            self.log(f"WARNING: Found {len(suspicious_procs)} suspicious processes!", "WARNING")

        # Check browser protection
        self.log("Checking browser data protection...")
        browser_access = self.browser_protector.check_browser_access_attempts()
        if browser_access:
            health_report['warnings'].extend(browser_access)
            self.log(f"Alert: {len(browser_access)} suspicious browser access attempts detected", "WARNING")

        # Check USB autorun threats
        self.log("Checking USB drives for autorun threats...")
        usb_threats = self.usb_protector.protect_all_drives()
        if usb_threats:
            health_report['threats'].extend(usb_threats)
            health_report['status'] = 'INFECTED'
            self.log(f"WARNING: Found {len(usb_threats)} USB autorun threats!", "WARNING")

        # Check network spreading
        self.log("Checking for network spreading threats...")
        network_threats = self.network_spreading_protector.protect_shared_folders()
        if network_threats:
            health_report['threats'].extend(network_threats)
            health_report['status'] = 'INFECTED'
            self.log(f"WARNING: Found {len(network_threats)} network spreading threats!", "WARNING")

        # Check SMB connections
        smb_connections = self.network_spreading_protector.check_smb_connections()
        if smb_connections:
            health_report['warnings'].extend(smb_connections)
            self.log(f"Alert: Found {len(smb_connections)} active SMB connections", "WARNING")

        # Final status
        if health_report['status'] == 'HEALTHY':
            self.log("System health check complete: No threats detected")
        else:
            self.log(f"System health check complete: Status = {health_report['status']}", "WARNING")

        return health_report

    def remove_threats(self, threats=None):
        """Remove detected threats"""
        if threats is None:
            threats = self.scan_results

        removed_count = 0

        for threat in threats:
            if 'file' in threat:
                file_path = threat['file']
                if os.path.exists(file_path):
                    result = quarantine_file(file_path, reason="malware_detected")
                    if result:
                        removed_count += 1
                        self.log(f"Quarantined: {file_path}")

        self.log(f"Removed {removed_count} threats")
        return removed_count

    def restore_encrypted_files(self):
        """Restore files encrypted by ransomware"""
        total_restored = 0

        for folder in self.ransomware_protector.protected_folders:
            if folder.exists():
                restored = self.ransomware_protector.decrypt_folder(str(folder))
                total_restored += restored
                self.log(f"Restored {restored} files in {folder}")

        return total_restored


# ==================== GUI APPLICATION ====================

if HAS_GUI:
    class AntiMalwareGUI:
        """Modern GUI for Anti-Malware Defender"""

        def __init__(self):
            self.engine = AntiMalwareEngine()
            self.root = tk.Tk()
            self.root.title("🛡️ Anti-Malicious Defender v1.0")
            self.root.geometry("900x700")
            self.root.minsize(800, 600)

            # Colors
            self.bg_color = "#1a1a2e"
            self.card_bg = "#16213e"
            self.accent = "#0f3460"
            self.highlight = "#e94560"
            self.success = "#00d26a"
            self.warning = "#ffc107"
            self.text_color = "#eaeaea"
            self.text_secondary = "#a0a0a0"

            self.root.configure(bg=self.bg_color)

            # Scanning state
            self.is_scanning = False
            self.scan_thread = None

            self.setup_styles()
            self.build_ui()
            self.start_log_updater()

        def setup_styles(self):
            """Setup ttk styles"""
            style = ttk.Style()
            style.theme_use('clam')

            style.configure('Card.TFrame', background=self.card_bg)
            style.configure('Dark.TLabel', background=self.bg_color, foreground=self.text_color)
            style.configure('Card.TLabel', background=self.card_bg, foreground=self.text_color)
            style.configure('Title.TLabel', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 24, 'bold'))
            style.configure('Subtitle.TLabel', background=self.bg_color, foreground=self.text_secondary, font=('Segoe UI', 10))
            style.configure('Status.TLabel', background=self.card_bg, foreground=self.success, font=('Segoe UI', 12, 'bold'))

            style.configure('Accent.TButton', background=self.highlight, foreground='white', font=('Segoe UI', 11, 'bold'), padding=10)
            style.map('Accent.TButton', background=[('active', '#ff6b6b')])

            style.configure('Secondary.TButton', background=self.accent, foreground='white', font=('Segoe UI', 10), padding=8)
            style.map('Secondary.TButton', background=[('active', '#1a4a7a')])

        def build_ui(self):
            """Build the main user interface"""
            # Main container
            main_frame = tk.Frame(self.root, bg=self.bg_color)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

            # Header
            header_frame = tk.Frame(main_frame, bg=self.bg_color)
            header_frame.pack(fill=tk.X, pady=(0, 20))

            tk.Label(header_frame, text="🛡️ Anti-Malicious Defender",
                    font=("Segoe UI", 24, "bold"), bg=self.bg_color, fg=self.text_color).pack(side=tk.LEFT)

            tk.Label(header_frame, text="G2 Team 4 - Cyber Project T1Y3",
                    font=("Segoe UI", 10), bg=self.bg_color, fg=self.text_secondary).pack(side=tk.LEFT, padx=20)

            # Status card
            status_card = tk.Frame(main_frame, bg=self.card_bg, padx=20, pady=15)
            status_card.pack(fill=tk.X, pady=(0, 15))

            self.status_var = tk.StringVar(value="🟢 Protected")
            self.status_label = tk.Label(status_card, textvariable=self.status_var,
                                        font=("Segoe UI", 14, "bold"), bg=self.card_bg, fg=self.success)
            self.status_label.pack(side=tk.LEFT)

            self.last_scan_var = tk.StringVar(value="Last scan: Never")
            tk.Label(status_card, textvariable=self.last_scan_var,
                    font=("Segoe UI", 10), bg=self.card_bg, fg=self.text_secondary).pack(side=tk.RIGHT)

            # Control buttons frame
            control_frame = tk.Frame(main_frame, bg=self.bg_color)
            control_frame.pack(fill=tk.X, pady=(0, 15))

            # Quick Scan button
            self.quick_scan_btn = tk.Button(control_frame, text="⚡ Quick Scan",
                                           font=("Segoe UI", 11, "bold"), bg=self.highlight, fg="white",
                                           relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
                                           command=self.start_quick_scan)
            self.quick_scan_btn.pack(side=tk.LEFT, padx=(0, 10))

            # Full Scan button
            self.full_scan_btn = tk.Button(control_frame, text="🔍 Full Scan",
                                          font=("Segoe UI", 11, "bold"), bg=self.accent, fg="white",
                                          relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
                                          command=self.start_full_scan)
            self.full_scan_btn.pack(side=tk.LEFT, padx=(0, 10))

            # Health Check button
            self.health_btn = tk.Button(control_frame, text="💊 Health Check",
                                       font=("Segoe UI", 11), bg=self.accent, fg="white",
                                       relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
                                       command=self.run_health_check)
            self.health_btn.pack(side=tk.LEFT, padx=(0, 10))

            # Restore Files button
            self.restore_btn = tk.Button(control_frame, text="🔓 Restore Files",
                                        font=("Segoe UI", 11), bg="#2d6a4f", fg="white",
                                        relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
                                        command=self.restore_files)
            self.restore_btn.pack(side=tk.LEFT, padx=(0, 10))

            # Custom Scan button
            self.custom_btn = tk.Button(control_frame, text="📁 Custom Scan",
                                       font=("Segoe UI", 11), bg=self.accent, fg="white",
                                       relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
                                       command=self.custom_scan)
            self.custom_btn.pack(side=tk.LEFT)

            # Progress bar
            self.progress_var = tk.DoubleVar()
            self.progress = ttk.Progressbar(main_frame, variable=self.progress_var,
                                           mode='indeterminate', length=400)
            self.progress.pack(fill=tk.X, pady=(0, 15))

            # Notebook for tabs
            notebook_frame = tk.Frame(main_frame, bg=self.bg_color)
            notebook_frame.pack(fill=tk.BOTH, expand=True)

            notebook = ttk.Notebook(notebook_frame)
            notebook.pack(fill=tk.BOTH, expand=True)

            # Activity Log tab
            log_frame = tk.Frame(notebook, bg=self.card_bg)
            notebook.add(log_frame, text="📋 Activity Log")

            self.log_text = scrolledtext.ScrolledText(log_frame, bg="#0d1117", fg="#58a6ff",
                                                     font=("Consolas", 10), relief=tk.FLAT,
                                                     insertbackground="#58a6ff")
            self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Anti-Malicious Defender initialized\n")
            self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Target: Photoshop_Setup.py malware\n")
            self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Protection modules loaded:\n")
            self.log_text.insert(tk.END, "  - Malware Signature Scanner\n")
            self.log_text.insert(tk.END, "  - Browser Data Protector\n")
            self.log_text.insert(tk.END, "  - Registry Protector\n")
            self.log_text.insert(tk.END, "  - Ransomware Protector\n")
            self.log_text.insert(tk.END, "  - Network Protector\n")
            self.log_text.insert(tk.END, "  - Process Monitor\n")
            self.log_text.insert(tk.END, "  - USB Autorun Protector\n")
            self.log_text.insert(tk.END, "  - Network Spreading Protector\n")
            self.log_text.see(tk.END)

            # Threats tab
            threats_frame = tk.Frame(notebook, bg=self.card_bg)
            notebook.add(threats_frame, text="🚨 Detected Threats")

            self.threats_tree = ttk.Treeview(threats_frame, columns=("File", "Threat", "Level"), show="headings")
            self.threats_tree.heading("File", text="File Path")
            self.threats_tree.heading("Threat", text="Threat Type")
            self.threats_tree.heading("Level", text="Level")
            self.threats_tree.column("File", width=400)
            self.threats_tree.column("Threat", width=200)
            self.threats_tree.column("Level", width=100)
            self.threats_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Threat action buttons
            threat_actions = tk.Frame(threats_frame, bg=self.card_bg)
            threat_actions.pack(fill=tk.X, padx=10, pady=(0, 10))

            tk.Button(threat_actions, text="🗑️ Quarantine Selected",
                     font=("Segoe UI", 10), bg=self.highlight, fg="white",
                     relief=tk.FLAT, padx=15, pady=5, cursor="hand2",
                     command=self.quarantine_selected).pack(side=tk.LEFT, padx=(0, 10))

            tk.Button(threat_actions, text="🗑️ Quarantine All",
                     font=("Segoe UI", 10), bg="#b91c1c", fg="white",
                     relief=tk.FLAT, padx=15, pady=5, cursor="hand2",
                     command=self.quarantine_all).pack(side=tk.LEFT)

            # Protection Status tab
            protection_frame = tk.Frame(notebook, bg=self.card_bg)
            notebook.add(protection_frame, text="🔒 Protection Status")

            self.build_protection_status(protection_frame)

            # Footer
            footer = tk.Frame(main_frame, bg=self.bg_color)
            footer.pack(fill=tk.X, pady=(15, 0))

            tk.Label(footer, text="Protects against: Browser theft, Discord tokens, Ransomware, Registry persistence, USB autorun, Network spreading",
                    font=("Segoe UI", 9), bg=self.bg_color, fg=self.text_secondary).pack(side=tk.LEFT)

        def build_protection_status(self, parent):
            """Build protection status display"""
            modules = [
                ("🔍 Malware Scanner", "Active", self.success),
                ("🌐 Browser Protection", "Active", self.success),
                ("📝 Registry Monitor", "Active", self.success),
                ("🔐 Ransomware Shield", "Active", self.success),
                ("🌍 Network Guard", "Active", self.success),
                ("⚙️ Process Monitor", "Active", self.success),
                ("💾 USB Autorun Protection", "Active", self.success),
                ("🔗 Network Spreading Protection", "Active", self.success),
            ]

            for i, (name, status, color) in enumerate(modules):
                row = tk.Frame(parent, bg=self.card_bg)
                row.pack(fill=tk.X, padx=20, pady=10)

                tk.Label(row, text=name, font=("Segoe UI", 12),
                        bg=self.card_bg, fg=self.text_color).pack(side=tk.LEFT)

                status_label = tk.Label(row, text=f"● {status}", font=("Segoe UI", 12, "bold"),
                                        bg=self.card_bg, fg=color)
                status_label.pack(side=tk.RIGHT)


        def log_message(self, message):
            """Add message to log"""
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)

        def start_log_updater(self):
            """Start periodic log update from engine"""
            def update():
                try:
                    while True:
                        message = self.engine.log_queue.get_nowait()
                        self.log_message(message)
                except queue.Empty:
                    pass
                self.root.after(100, update)

            self.root.after(100, update)

        def set_scanning(self, scanning):
            """Set scanning state and update UI"""
            self.is_scanning = scanning
            state = tk.DISABLED if scanning else tk.NORMAL

            self.quick_scan_btn.config(state=state)
            self.full_scan_btn.config(state=state)
            self.health_btn.config(state=state)
            self.custom_btn.config(state=state)

            if scanning:
                self.progress.start(10)
                self.status_var.set("🔵 Scanning...")
                self.status_label.config(fg="#3b82f6")
            else:
                self.progress.stop()

        def start_quick_scan(self):
            """Start quick scan in background thread"""
            if self.is_scanning:
                return

            self.set_scanning(True)
            self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] Starting quick scan...")

            def scan():
                results = self.engine.quick_scan()
                self.root.after(0, lambda: self.scan_complete(results))

            self.scan_thread = threading.Thread(target=scan, daemon=True)
            self.scan_thread.start()

        def start_full_scan(self):
            """Start full scan in background thread"""
            if self.is_scanning:
                return

            self.set_scanning(True)
            self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] Starting full system scan...")

            def scan():
                results = self.engine.full_scan()
                self.root.after(0, lambda: self.scan_complete(results))

            self.scan_thread = threading.Thread(target=scan, daemon=True)
            self.scan_thread.start()

        def custom_scan(self):
            """Scan a custom directory"""
            if self.is_scanning:
                return

            directory = filedialog.askdirectory(title="Select Directory to Scan")
            if not directory:
                return

            self.set_scanning(True)
            self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning: {directory}")

            def scan():
                results = self.engine.full_scan(directory)
                self.root.after(0, lambda: self.scan_complete(results))

            self.scan_thread = threading.Thread(target=scan, daemon=True)
            self.scan_thread.start()

        def scan_complete(self, results):
            """Handle scan completion"""
            self.set_scanning(False)

            # Update last scan time
            self.last_scan_var.set(f"Last scan: {datetime.now().strftime('%Y-%m-%d %H:%M')}")

            # Clear and populate threats tree
            for item in self.threats_tree.get_children():
                self.threats_tree.delete(item)

            if results:
                self.status_var.set(f"🔴 {len(results)} Threats Found!")
                self.status_label.config(fg=self.highlight)

                for threat in results:
                    threat_type = threat['patterns'][0] if threat['patterns'] else "Unknown"
                    level = self.engine.scanner.get_threat_level(threat['patterns'])
                    self.threats_tree.insert("", tk.END, values=(
                        threat['file'],
                        threat_type[:50],
                        level
                    ))

                messagebox.showwarning("Threats Detected",
                    f"Found {len(results)} potential threats!\n\nCheck the 'Detected Threats' tab for details.")
            else:
                self.status_var.set("🟢 Protected - No Threats")
                self.status_label.config(fg=self.success)
                messagebox.showinfo("Scan Complete", "No threats detected. Your system is clean!")

        def run_health_check(self):
            """Run system health check"""
            if self.is_scanning:
                return

            self.set_scanning(True)
            self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] Running health check...")

            def check():
                report = self.engine.check_system_health()
                self.root.after(0, lambda: self.health_check_complete(report))

            thread = threading.Thread(target=check, daemon=True)
            thread.start()

        def health_check_complete(self, report):
            """Handle health check completion"""
            self.set_scanning(False)

            status = report['status']
            threats_count = len(report['threats'])
            warnings_count = len(report['warnings'])

            if status == 'HEALTHY':
                self.status_var.set("🟢 System Healthy")
                self.status_label.config(fg=self.success)
                messagebox.showinfo("Health Check", "Your system is healthy!\nNo threats detected.")
            elif status == 'CRITICAL':
                self.status_var.set("🔴 CRITICAL - Ransomware Detected!")
                self.status_label.config(fg=self.highlight)
                messagebox.showerror("Critical Alert",
                    f"RANSOMWARE DETECTED!\n\n{threats_count} critical threats found.\n\n"
                    "Use 'Restore Files' to recover encrypted files.")
            else:
                self.status_var.set(f"🟠 {threats_count} Issues Found")
                self.status_label.config(fg=self.warning)
                messagebox.showwarning("Health Check",
                    f"Found {threats_count} threats and {warnings_count} warnings.\n\n"
                    "Review the Activity Log for details.")

        def restore_files(self):
            """Restore files encrypted by ransomware"""
            result = messagebox.askyesno("Restore Files",
                "This will attempt to restore files encrypted by the G2T4 ransomware.\n\n"
                "Continue?")

            if not result:
                return

            self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] Starting file restoration...")

            restored = self.engine.restore_encrypted_files()

            if restored > 0:
                self.status_var.set("🟢 Files Restored")
                self.status_label.config(fg=self.success)
                messagebox.showinfo("Restoration Complete",
                    f"Successfully restored {restored} files!")
            else:
                messagebox.showinfo("Restoration Complete",
                    "No encrypted files found to restore.")

        def quarantine_selected(self):
            """Quarantine selected threats"""
            selected = self.threats_tree.selection()
            if not selected:
                messagebox.showinfo("No Selection", "Please select threats to quarantine.")
                return

            count = 0
            for item in selected:
                values = self.threats_tree.item(item, 'values')
                file_path = values[0]
                if os.path.exists(file_path):
                    result = quarantine_file(file_path, reason="user_quarantine")
                    if result:
                        count += 1
                        self.threats_tree.delete(item)
                        self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] Quarantined: {file_path}")

            if count > 0:
                messagebox.showinfo("Quarantine Complete", f"Quarantined {count} files.")

        def quarantine_all(self):
            """Quarantine all detected threats"""
            items = self.threats_tree.get_children()
            if not items:
                messagebox.showinfo("No Threats", "No threats to quarantine.")
                return

            result = messagebox.askyesno("Confirm",
                f"Quarantine all {len(items)} detected threats?")

            if not result:
                return

            count = self.engine.remove_threats()

            # Clear threats tree
            for item in items:
                self.threats_tree.delete(item)

            self.status_var.set("🟢 Threats Removed")
            self.status_label.config(fg=self.success)

            messagebox.showinfo("Quarantine Complete",
                f"Quarantined {count} threats.\n\nFiles moved to: {QUARANTINE_DIR}")

        def run(self):
            """Run the GUI application"""
            self.root.mainloop()


# ==================== BACKGROUND SERVICE ====================

class BackgroundProtectionService:
    """Background service that runs protection continuously"""

    def __init__(self):
        self.engine = AntiMalwareEngine()
        self.running = False
        self.scan_interval = 300  # Scan every 5 minutes
        self.log_file = os.path.join(os.path.expanduser("~"), ".anti_malicious", "service.log")

        # Ensure log directory exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def log(self, message):
        """Log message to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except:
            pass

    def run_protection_cycle(self):
        """Run a single protection cycle"""
        self.log("Starting protection cycle...")

        try:
            # Quick scan
            threats = self.engine.quick_scan()
            if threats:
                self.log(f"Found {len(threats)} threats!")
                removed = self.engine.remove_threats(threats)
                self.log(f"Removed {removed} threats")

            # Check system health
            health = self.engine.check_system_health()
            self.log(f"Health check: {health['status']}")

            # Check for ransomware
            encrypted = self.engine.ransomware_protector.check_for_encrypted_files()
            if encrypted:
                self.log(f"Found {len(encrypted)} encrypted files - attempting restoration")
                restored = self.engine.restore_encrypted_files()
                self.log(f"Restored {restored} files")

            self.log("Protection cycle complete")

        except Exception as e:
            self.log(f"Error in protection cycle: {e}")

    def start(self):
        """Start the background service"""
        self.running = True
        self.log("Background protection service started")

        # Initial protection setup
        if WINDOWS:
            # Disable autorun
            self.engine.usb_protector.disable_autorun_registry()
            self.engine.usb_protector.disable_autoplay_registry()
            self.log("USB autorun protection enabled")

        # Main service loop
        while self.running:
            self.run_protection_cycle()

            # Wait for next cycle
            for _ in range(self.scan_interval):
                if not self.running:
                    break
                time.sleep(1)

        self.log("Background protection service stopped")

    def stop(self):
        """Stop the background service"""
        self.running = False


# ==================== INSTALLATION & SHORTCUTS ====================

def get_script_path():
    """Get the path to this script or executable"""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return sys.executable
    else:
        # Running as script
        return os.path.abspath(__file__)


def create_scheduled_task():
    """Create a Windows scheduled task to run at startup"""
    if not WINDOWS:
        print("Scheduled tasks are only supported on Windows")
        return False

    script_path = get_script_path()
    task_name = "AntiMaliciousDefender"

    try:
        # Delete existing task if any
        subprocess.run(
            ['schtasks', '/delete', '/tn', task_name, '/f'],
            capture_output=True,
            timeout=10
        )

        # Create new task that runs at logon
        if script_path.endswith('.py'):
            # Running as Python script
            python_exe = sys.executable
            command = f'"{python_exe}" "{script_path}" --background'
        else:
            # Running as executable
            command = f'"{script_path}" --background'

        result = subprocess.run([
            'schtasks', '/create',
            '/tn', task_name,
            '/tr', command,
            '/sc', 'ONLOGON',
            '/rl', 'HIGHEST',
            '/f'
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            print(f"✅ Scheduled task '{task_name}' created successfully!")
            print("   The defender will run automatically when you log in.")
            return True
        else:
            print(f"❌ Failed to create scheduled task: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ Error creating scheduled task: {e}")
        return False


def remove_scheduled_task():
    """Remove the scheduled task"""
    if not WINDOWS:
        return False

    task_name = "AntiMaliciousDefender"

    try:
        result = subprocess.run(
            ['schtasks', '/delete', '/tn', task_name, '/f'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            print(f"✅ Scheduled task '{task_name}' removed successfully!")
            return True
        else:
            print(f"❌ Task not found or already removed")
            return False

    except Exception as e:
        print(f"❌ Error removing scheduled task: {e}")
        return False


def create_desktop_shortcut():
    """Create a desktop shortcut to run the GUI with logo icon"""
    if not WINDOWS:
        print("Desktop shortcuts are only supported on Windows")
        return False

    try:
        # Get desktop path
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        shortcut_path = os.path.join(desktop, "Anti-Malicious Defender.lnk")

        script_path = get_script_path()

        # Get icon path
        icon_path = get_icon_path()

        # Use PowerShell to create shortcut
        if script_path.endswith('.py'):
            python_exe = sys.executable
            target = python_exe
            # Escape for PowerShell - use single quotes for inner path
            arguments = f"'{script_path}' --gui"
        else:
            target = script_path
            arguments = '--gui'

        # Escape backslashes for PowerShell
        shortcut_path_escaped = shortcut_path.replace('\\', '\\\\')
        target_escaped = target.replace('\\', '\\\\')
        arguments_escaped = arguments.replace('\\', '\\\\').replace("'", "''")
        working_dir_escaped = os.path.dirname(script_path).replace('\\', '\\\\')

        # Build icon line if icon exists
        icon_line = ""
        if icon_path and os.path.exists(icon_path):
            icon_escaped = icon_path.replace('\\', '\\\\')
            icon_line = f'$Shortcut.IconLocation = "{icon_escaped},0"'

        # PowerShell script to create shortcut
        ps_script = f'''
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{shortcut_path_escaped}")
$Shortcut.TargetPath = "{target_escaped}"
$Shortcut.Arguments = '{arguments_escaped}'
$Shortcut.WorkingDirectory = "{working_dir_escaped}"
$Shortcut.Description = "Anti-Malicious Defender - G2 Team 4"
{icon_line}
$Shortcut.Save()
'''

        result = subprocess.run(
            ['powershell', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            print(f"✅ Desktop shortcut created: {shortcut_path}")
            return True
        else:
            print(f"❌ Failed to create shortcut: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ Error creating shortcut: {e}")
        return False


def create_start_menu_shortcut():
    """Create a Start Menu shortcut with logo icon"""
    if not WINDOWS:
        return False

    try:
        # Get Start Menu path
        start_menu = os.path.join(
            os.environ.get('APPDATA', ''),
            'Microsoft', 'Windows', 'Start Menu', 'Programs'
        )
        shortcut_path = os.path.join(start_menu, "Anti-Malicious Defender.lnk")

        script_path = get_script_path()

        # Get icon path
        icon_path = get_icon_path()

        if script_path.endswith('.py'):
            python_exe = sys.executable
            target = python_exe
            arguments = f"'{script_path}' --gui"
        else:
            target = script_path
            arguments = '--gui'

        # Escape backslashes for PowerShell
        shortcut_path_escaped = shortcut_path.replace('\\', '\\\\')
        target_escaped = target.replace('\\', '\\\\')
        arguments_escaped = arguments.replace('\\', '\\\\').replace("'", "''")
        working_dir_escaped = os.path.dirname(script_path).replace('\\', '\\\\')

        # Build icon line if icon exists
        icon_line = ""
        if icon_path and os.path.exists(icon_path):
            icon_escaped = icon_path.replace('\\', '\\\\')
            icon_line = f'$Shortcut.IconLocation = "{icon_escaped},0"'

        ps_script = f'''
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{shortcut_path_escaped}")
$Shortcut.TargetPath = "{target_escaped}"
$Shortcut.Arguments = '{arguments_escaped}'
$Shortcut.WorkingDirectory = "{working_dir_escaped}"
$Shortcut.Description = "Anti-Malicious Defender - G2 Team 4"
{icon_line}
$Shortcut.Save()
'''

        result = subprocess.run(
            ['powershell', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            print(f"✅ Start Menu shortcut created")
            return True
        else:
            return False

    except Exception as e:
        return False


def add_to_startup_registry():
    """Add to Windows startup via registry"""
    if not WINDOWS:
        return False

    try:
        script_path = get_script_path()

        if script_path.endswith('.py'):
            python_exe = sys.executable
            command = f'"{python_exe}" "{script_path}" --background'
        else:
            command = f'"{script_path}" --background'

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "AntiMaliciousDefender", 0, winreg.REG_SZ, command)
        winreg.CloseKey(key)

        print("✅ Added to Windows startup (Registry)")
        return True

    except Exception as e:
        print(f"❌ Error adding to startup: {e}")
        return False


def remove_from_startup_registry():
    """Remove from Windows startup registry"""
    if not WINDOWS:
        return False

    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "AntiMaliciousDefender")
        winreg.CloseKey(key)

        print("✅ Removed from Windows startup")
        return True

    except FileNotFoundError:
        print("ℹ️ Entry not found in startup")
        return True
    except Exception as e:
        print(f"❌ Error removing from startup: {e}")
        return False


def install_service():
    """Install the defender as a background service with shortcuts"""
    print("\n🛡️ Installing Anti-Malicious Defender...")
    print("=" * 50)

    # Create scheduled task
    print("\n[1/4] Creating scheduled task...")
    create_scheduled_task()

    # Add to startup registry as backup
    print("\n[2/4] Adding to startup registry...")
    add_to_startup_registry()

    # Create desktop shortcut
    print("\n[3/4] Creating desktop shortcut...")
    create_desktop_shortcut()

    # Create Start Menu shortcut
    print("\n[4/4] Creating Start Menu shortcut...")
    create_start_menu_shortcut()

    print("\n" + "=" * 50)
    print("✅ Installation complete!")
    print("\nThe defender will:")
    print("  • Run automatically when you log in (background)")
    print("  • Scan for threats every 5 minutes")
    print("  • Protect against USB autorun")
    print("  • Monitor for ransomware")
    print("\nTo open the GUI, use the desktop shortcut or run:")
    print(f"  python {os.path.basename(__file__)} --gui")


def uninstall_service():
    """Remove the defender service and shortcuts"""
    print("\n🗑️ Uninstalling Anti-Malicious Defender...")
    print("=" * 50)

    # Remove scheduled task
    print("\n[1/3] Removing scheduled task...")
    remove_scheduled_task()

    # Remove from startup registry
    print("\n[2/3] Removing from startup...")
    remove_from_startup_registry()

    # Remove shortcuts
    print("\n[3/3] Removing shortcuts...")
    try:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        shortcut_path = os.path.join(desktop, "Anti-Malicious Defender.lnk")
        if os.path.exists(shortcut_path):
            os.remove(shortcut_path)
            print("✅ Desktop shortcut removed")
    except:
        pass

    try:
        start_menu = os.path.join(
            os.environ.get('APPDATA', ''),
            'Microsoft', 'Windows', 'Start Menu', 'Programs'
        )
        shortcut_path = os.path.join(start_menu, "Anti-Malicious Defender.lnk")
        if os.path.exists(shortcut_path):
            os.remove(shortcut_path)
            print("✅ Start Menu shortcut removed")
    except:
        pass

    print("\n" + "=" * 50)
    print("✅ Uninstallation complete!")


def run_background_service():
    """Run as background service (no GUI)"""
    # Hide console window on Windows
    if WINDOWS:
        try:
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0
            )
        except:
            pass

    service = BackgroundProtectionService()

    try:
        service.start()
    except KeyboardInterrupt:
        service.stop()


def show_help():
    """Show command-line help"""
    print("""
🛡️ Anti-Malicious Defender - G2 Team 4
========================================

Usage: anti_malicious.exe [option]
   or: python anti_malicious.py [option]

Options:
  --gui           Launch the graphical user interface
  --background    Run as background service (no GUI)
  --install       Install as startup service + create shortcuts
  --uninstall     Remove service and shortcuts
  --scan          Run a quick scan (CLI mode)
  --help          Show this help message

When running as EXE (no arguments):
  - First run: Creates desktop shortcut + adds to startup
  - Runs silently in background protecting your system
  - Use the desktop shortcut to open GUI

When running as Python script (no arguments):
  - Opens GUI directly
""")


# ==================== AUTO SETUP FOR EXE ====================

def is_first_run():
    """Check if this is the first time running the application"""
    marker_file = os.path.join(os.path.expanduser("~"), ".anti_malicious", ".installed")
    return not os.path.exists(marker_file)


def mark_as_installed():
    """Mark that the application has been installed"""
    marker_dir = os.path.join(os.path.expanduser("~"), ".anti_malicious")
    os.makedirs(marker_dir, exist_ok=True)
    marker_file = os.path.join(marker_dir, ".installed")
    with open(marker_file, "w") as f:
        f.write(datetime.now().isoformat())


def auto_setup_exe():
    """Automatically setup when running as exe for the first time"""
    if not is_first_run():
        return

    # Create desktop shortcut for GUI
    create_desktop_shortcut_for_gui()

    # Add to startup registry for background service
    add_to_startup_registry()

    # Mark as installed
    mark_as_installed()


def get_icon_path():
    """Get or create the icon file for shortcuts"""
    script_dir = os.path.dirname(get_script_path())

    # Check for existing ICO file (antiLogo.ico)
    ico_path = os.path.join(script_dir, "antiLogo.ico")
    if os.path.exists(ico_path):
        return ico_path

    # Check for PNG and try to convert
    png_path = os.path.join(script_dir, "antiLogo.png")
    if os.path.exists(png_path):
        try:
            from PIL import Image
            img = Image.open(png_path)
            # Resize to standard icon sizes
            img = img.resize((256, 256), Image.Resampling.LANCZOS)
            img.save(ico_path, format='ICO', sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
            return ico_path
        except ImportError:
            # Pillow not available, use exe itself as icon
            pass
        except Exception:
            pass

    # Fallback: use the exe itself as icon source
    exe_path = get_script_path()
    if exe_path.endswith('.exe'):
        return exe_path

    return None


def create_desktop_shortcut_for_gui():
    """Create desktop shortcut that opens GUI with logo icon"""
    if not WINDOWS:
        return False

    try:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        shortcut_path = os.path.join(desktop, "Anti-Malicious Defender.lnk")

        # Get the exe path
        exe_path = get_script_path()

        # Get icon path
        icon_path = get_icon_path()

        # Escape for PowerShell
        sp = shortcut_path.replace('\\', '\\\\')
        tg = exe_path.replace('\\', '\\\\')
        wd = os.path.dirname(exe_path).replace('\\', '\\\\')

        # Build icon line if icon exists
        icon_line = ""
        if icon_path and os.path.exists(icon_path):
            ic = icon_path.replace('\\', '\\\\')
            icon_line = f'$Shortcut.IconLocation = "{ic},0"'

        ps_script = f'''
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{sp}")
$Shortcut.TargetPath = "{tg}"
$Shortcut.Arguments = "--gui"
$Shortcut.WorkingDirectory = "{wd}"
$Shortcut.Description = "Anti-Malicious Defender - G2 Team 4"
{icon_line}
$Shortcut.Save()
'''
        subprocess.run(['powershell', '-Command', ps_script],
                      capture_output=True, timeout=30,
                      creationflags=subprocess.CREATE_NO_WINDOW if WINDOWS else 0)
        return True
    except:
        return False


def hide_console():
    """Hide the console window"""
    if WINDOWS:
        try:
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0
            )
        except:
            pass


# ==================== MAIN ENTRY POINT ====================

def main():
    """Main entry point - auto runs as background service when exe"""

    # Parse command-line arguments
    args = sys.argv[1:] if len(sys.argv) > 1 else []

    # Check if running as compiled exe
    is_exe = getattr(sys, 'frozen', False)

    # Handle command line arguments
    if '--help' in args or '-h' in args:
        show_help()
        return

    if '--install' in args:
        install_service()
        return

    if '--uninstall' in args:
        uninstall_service()
        return

    if '--gui' in args:
        # Explicitly requested GUI mode
        if HAS_GUI:
            app = AntiMalwareGUI()
            app.run()
        else:
            print("GUI not available")
        return

    if '--background' in args:
        # Explicitly requested background mode
        hide_console()
        run_background_service()
        return

    if '--scan' in args:
        # CLI scan mode
        print("🛡️ Anti-Malicious Defender - Quick Scan")
        engine = AntiMalwareEngine()
        health = engine.check_system_health()
        print(f"Status: {health['status']}")
        results = engine.quick_scan()
        print(f"Threats: {len(results)}")
        if results:
            engine.remove_threats(results)
        print("✅ Scan complete!")
        return

    # DEFAULT BEHAVIOR (no arguments):
    # If running as EXE: auto-setup + run silently in background
    # If running as Python script: show GUI

    if is_exe:
        # Running as compiled EXE
        # First run: create shortcut and add to startup
        auto_setup_exe()

        # Hide console window
        hide_console()

        # Run background protection service silently
        run_background_service()
    else:
        # Running as Python script - show GUI
        if HAS_GUI:
            app = AntiMalwareGUI()
            app.run()
        else:
            print("🛡️ Anti-Malicious Defender")
            print("Run with --help for options")
            engine = AntiMalwareEngine()
            health = engine.check_system_health()
            print(f"Status: {health['status']}")


if __name__ == "__main__":
    main()
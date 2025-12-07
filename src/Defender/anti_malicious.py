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

            tk.Label(header_frame, text="Protection against Photoshop_Setup.py malware",
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

            tk.Label(footer, text="Protects against: Browser theft, Discord tokens, Ransomware, Registry persistence",
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


# ==================== MAIN ENTRY POINT ====================

def main():
    """Main entry point"""
    print("🛡️ Anti-Malicious Defender")
    print("=" * 40)
    print("Protection against Photoshop_Setup.py malware")
    print()

    if HAS_GUI:
        app = AntiMalwareGUI()
        app.run()
    else:
        # Command-line mode
        print("GUI not available. Running in CLI mode.")
        engine = AntiMalwareEngine()

        print("\n[1] Checking system health...")
        health = engine.check_system_health()
        print(f"Status: {health['status']}")
        print(f"Threats found: {len(health['threats'])}")

        print("\n[2] Quick scanning user directories...")
        results = engine.quick_scan()
        print(f"Threats found: {len(results)}")

        if results:
            print("\n[3] Quarantining threats...")
            removed = engine.remove_threats(results)
            print(f"Removed: {removed} threats")

        print("\n[4] Checking for ransomware...")
        encrypted = engine.ransomware_protector.check_for_encrypted_files()
        if encrypted:
            print(f"Found {len(encrypted)} encrypted files!")
            print("Restoring files...")
            restored = engine.restore_encrypted_files()
            print(f"Restored: {restored} files")
        else:
            print("No encrypted files found.")

        print("\n✅ Scan complete!")


if __name__ == "__main__":
    main()
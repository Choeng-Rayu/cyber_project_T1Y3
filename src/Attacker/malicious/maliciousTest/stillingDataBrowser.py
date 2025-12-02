import os
import json
import sqlite3
import base64
import shutil
from pathlib import Path

class BrowserDataAnalyzer:
    def __init__(self):
        self.browser_paths = {
            'chrome_win': os.path.expanduser('~') + '/AppData/Local/Google/Chrome/User Data/Default',
            'chrome_linux': os.path.expanduser('~') + '/.config/google-chrome/Default',
            'firefox': os.path.expanduser('~') + '/.mozilla/firefox'
        }
    
    def get_browser_storage_locations(self):
        """Show where browsers store sensitive data"""
        locations = {}
        
        for browser, path in self.browser_paths.items():
            full_path = Path(path)
            if full_path.exists():
                locations[browser] = {
                    'cookies': str(full_path / 'Cookies'),
                    'local_storage': str(full_path / 'Local Storage'),
                    'session_storage': str(full_path / 'Session Storage'),
                    'login_data': str(full_path / 'Login Data'),
                    'web_data': str(full_path / 'Web Data')
                }
        
        return locations
    
    def demonstrate_cookie_structure(self):
        """Show how browser cookies are structured (educational)"""
        # This is what a typical browser cookie database looks like
        cookie_structure = {
            "database_format": "SQLite",
            "common_tables": ["cookies", "meta"],
            "cookie_columns": [
                "host_key", "name", "value", "path", 
                "expires_utc", "is_secure", "is_httponly"
            ],
            "encryption": "May use AES encryption or DPAPI protection"
        }
        return cookie_structure

# Example usage for educational purposes
if __name__ == "__main__":
    analyzer = BrowserDataAnalyzer()
    
    print("=== BROWSER DATA STORAGE LOCATIONS ===")
    locations = analyzer.get_browser_storage_locations()
    for browser, paths in locations.items():
        print(f"\n{browser.upper()}:")
        for data_type, path in paths.items():
            exists = "✓ EXISTS" if Path(path).exists() else "✗ NOT FOUND"
            print(f"  {data_type}: {path} {exists}")
    
    print("\n=== COOKIE DATABASE STRUCTURE ===")
    structure = analyzer.demonstrate_cookie_structure()
    print(json.dumps(structure, indent=2))
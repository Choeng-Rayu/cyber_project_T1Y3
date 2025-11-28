"""
Windows Executable Security Checker
A security workflow for checking .exe files before downloading.

Features:
- File hash verification (SHA256)
- VirusTotal API integration
- Filename analysis for suspicious patterns
- Safety assessment with color-coded output
"""

import os
import re
import sys
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Tuple, List

try:
    import requests
except ImportError:
    print("Error: 'requests' library not installed. Run: pip install requests")
    sys.exit(1)


# ==================== CONFIGURATION ====================

class Config:
    """Configuration management for the security checker."""
    
    # VirusTotal API settings
    VT_API_URL = "https://www.virustotal.com/api/v3/files/"
    
    # Try to load API key from environment variable or config file
    @staticmethod
    def get_api_key() -> Optional[str]:
        """Get VirusTotal API key from environment or config file."""
        # First, try environment variable
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if api_key:
            return api_key
        
        # Try config file in same directory
        config_path = Path(__file__).parent / 'vt_config.json'
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    return config.get('api_key')
            except (json.JSONDecodeError, IOError):
                pass
        
        # Try config file in user home
        home_config = Path.home() / '.virustotal_config.json'
        if home_config.exists():
            try:
                with open(home_config, 'r') as f:
                    config = json.load(f)
                    return config.get('api_key')
            except (json.JSONDecodeError, IOError):
                pass
        
        return None


# ==================== COLOR OUTPUT ====================

class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def enable_windows_colors():
        """Enable ANSI colors on Windows."""
        if sys.platform == 'win32':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                pass


def print_colored(text: str, color: str = Colors.WHITE, bold: bool = False):
    """Print text with color."""
    prefix = Colors.BOLD if bold else ""
    print(f"{prefix}{color}{text}{Colors.RESET}")


def print_safe():
    """Print SAFE status."""
    print_colored("✓ SAFE", Colors.GREEN, bold=True)


def print_caution():
    """Print CAUTION status."""
    print_colored("⚠ CAUTION", Colors.YELLOW, bold=True)


def print_unsafe():
    """Print UNSAFE status."""
    print_colored("✗ UNSAFE", Colors.RED, bold=True)


# ==================== HASH VERIFICATION ====================

class HashVerifier:
    """Calculate and verify file hashes."""
    
    @staticmethod
    def calculate_sha256(file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of a file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read in chunks for large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            print_colored(f"Error: File not found: {file_path}", Colors.RED)
            return None
        except PermissionError:
            print_colored(f"Error: Permission denied: {file_path}", Colors.RED)
            return None
        except IOError as e:
            print_colored(f"Error reading file: {e}", Colors.RED)
            return None
    
    @staticmethod
    def verify_hash(file_path: str, expected_hash: str) -> Tuple[bool, str]:
        """
        Verify file hash matches expected hash.
        Returns (match_result, calculated_hash)
        """
        calculated = HashVerifier.calculate_sha256(file_path)
        if calculated is None:
            return False, ""
        
        # Normalize both hashes to lowercase for comparison
        match = calculated.lower() == expected_hash.lower()
        return match, calculated
    
    @staticmethod
    def is_valid_sha256(hash_string: str) -> bool:
        """Check if a string is a valid SHA256 hash."""
        if len(hash_string) != 64:
            return False
        try:
            int(hash_string, 16)
            return True
        except ValueError:
            return False


# ==================== VIRUSTOTAL INTEGRATION ====================

class VirusTotalChecker:
    """Interface with VirusTotal API."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or Config.get_api_key()
        self.base_url = Config.VT_API_URL
    
    def check_hash(self, file_hash: str) -> Dict:
        """
        Check a file hash against VirusTotal database.
        Returns a dictionary with results.
        """
        result = {
            'success': False,
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0,
            'total': 0,
            'status': 'unknown',
            'vendors': [],
            'error': None
        }
        
        if not self.api_key:
            result['error'] = "VirusTotal API key not configured"
            return result
        
        if not HashVerifier.is_valid_sha256(file_hash):
            result['error'] = "Invalid SHA256 hash format"
            return result
        
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        
        try:
            response = requests.get(
                f"{self.base_url}{file_hash}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                
                result['malicious'] = stats.get('malicious', 0)
                result['suspicious'] = stats.get('suspicious', 0)
                result['harmless'] = stats.get('harmless', 0)
                result['undetected'] = stats.get('undetected', 0)
                result['total'] = sum([
                    result['malicious'],
                    result['suspicious'],
                    result['harmless'],
                    result['undetected']
                ])
                
                # Collect vendor detections
                for vendor, info in results.items():
                    if info.get('category') in ['malicious', 'suspicious']:
                        result['vendors'].append({
                            'name': vendor,
                            'result': info.get('result', 'Unknown'),
                            'category': info.get('category')
                        })
                
                # Determine overall status
                if result['malicious'] > 0 or result['suspicious'] > 3:
                    result['status'] = 'malicious'
                elif result['suspicious'] > 0:
                    result['status'] = 'suspicious'
                elif result['harmless'] > 0 or result['undetected'] > 0:
                    result['status'] = 'clean'
                
                result['success'] = True
                
            elif response.status_code == 404:
                result['status'] = 'not_found'
                result['error'] = "Hash not found in VirusTotal database"
                result['success'] = True  # API worked, just no data
                
            elif response.status_code == 401:
                result['error'] = "Invalid VirusTotal API key"
                
            elif response.status_code == 429:
                result['error'] = "VirusTotal API rate limit exceeded. Please wait and try again."
                
            else:
                result['error'] = f"VirusTotal API error: HTTP {response.status_code}"
                
        except requests.exceptions.Timeout:
            result['error'] = "Connection to VirusTotal timed out"
        except requests.exceptions.ConnectionError:
            result['error'] = "Could not connect to VirusTotal (check internet connection)"
        except requests.exceptions.RequestException as e:
            result['error'] = f"Network error: {str(e)}"
        except json.JSONDecodeError:
            result['error'] = "Invalid response from VirusTotal"
        
        return result


# ==================== FILENAME ANALYSIS ====================

class FilenameAnalyzer:
    """Analyze filenames for suspicious patterns."""
    
    # Suspicious patterns
    DOUBLE_EXTENSIONS = [
        r'\.pdf\.exe$', r'\.doc\.exe$', r'\.docx\.exe$', r'\.xls\.exe$',
        r'\.xlsx\.exe$', r'\.jpg\.exe$', r'\.png\.exe$', r'\.txt\.exe$',
        r'\.mp3\.exe$', r'\.mp4\.exe$', r'\.avi\.exe$', r'\.zip\.exe$',
        r'\.rar\.exe$', r'\.pdf\.scr$', r'\.doc\.scr$', r'\.jpg\.scr$'
    ]
    
    SUSPICIOUS_NAMES = [
        r'^invoice', r'^receipt', r'^payment', r'^document',
        r'^order', r'^delivery', r'^shipping', r'^tracking',
        r'^resume', r'^cv', r'^urgent', r'^important',
        r'^confirm', r'^verify', r'^update', r'^security',
        r'^account', r'^password', r'^login', r'^bank',
        r'^tax', r'^refund', r'^prize', r'^winner',
        r'^free', r'^download', r'^setup', r'^install',
        r'^crack', r'^keygen', r'^patch', r'^serial',
        r'^activat', r'^loader', r'^cheat', r'^hack'
    ]
    
    DECEPTIVE_EXTENSIONS = [
        '.scr',  # Screen saver (executable)
        '.pif',  # Program Information File (executable)
        '.com',  # DOS executable
        '.bat',  # Batch file
        '.cmd',  # Command script
        '.vbs',  # VBScript
        '.js',   # JavaScript (can be executable)
        '.jse',  # JScript encoded
        '.ws',   # Windows Script
        '.wsf',  # Windows Script File
        '.msi',  # Windows Installer
        '.msp',  # Windows Installer Patch
        '.hta',  # HTML Application
        '.cpl',  # Control Panel applet
    ]
    
    UNICODE_TRICKS = [
        '\u202e',  # Right-to-Left Override
        '\u202d',  # Left-to-Right Override
        '\u200e',  # Left-to-Right Mark
        '\u200f',  # Right-to-Left Mark
    ]
    
    @classmethod
    def analyze(cls, filename: str) -> Dict:
        """
        Analyze a filename for suspicious patterns.
        Returns analysis results dictionary.
        """
        result = {
            'suspicious': False,
            'risk_level': 'low',
            'warnings': [],
            'details': []
        }
        
        filename_lower = filename.lower()
        basename = os.path.basename(filename)
        basename_lower = basename.lower()
        
        # Check for double extensions
        for pattern in cls.DOUBLE_EXTENSIONS:
            if re.search(pattern, basename_lower):
                result['suspicious'] = True
                result['warnings'].append("Double extension detected (common malware trick)")
                result['details'].append(f"Pattern: {pattern}")
        
        # Check for suspicious names
        for pattern in cls.SUSPICIOUS_NAMES:
            if re.search(pattern, basename_lower):
                result['warnings'].append(f"Suspicious keyword in filename: {pattern.replace('^', '')}")
                result['details'].append(f"Social engineering keyword detected")
        
        # Check for deceptive extensions
        for ext in cls.DECEPTIVE_EXTENSIONS:
            if basename_lower.endswith(ext):
                result['warnings'].append(f"Potentially dangerous extension: {ext}")
                result['details'].append("This extension can execute code")
        
        # Check for Unicode tricks
        for char in cls.UNICODE_TRICKS:
            if char in filename:
                result['suspicious'] = True
                result['warnings'].append("Unicode direction override detected (filename spoofing)")
                result['details'].append("File may appear different than it is")
        
        # Check for excessive spaces or dots
        if '   ' in basename or '...' in basename:
            result['warnings'].append("Unusual spacing or dots in filename")
            result['details'].append("May be hiding true extension")
        
        # Check for very long filenames (may hide extension)
        if len(basename) > 100:
            result['warnings'].append("Unusually long filename")
            result['details'].append("May be attempting to hide file extension")
        
        # Calculate risk level
        warning_count = len(result['warnings'])
        if result['suspicious'] or warning_count >= 3:
            result['risk_level'] = 'high'
        elif warning_count >= 1:
            result['risk_level'] = 'medium'
        
        return result


# ==================== SAFETY ASSESSMENT ====================

class SafetyAssessor:
    """Combine all checks into a final safety assessment."""
    
    @staticmethod
    def assess(vt_result: Optional[Dict], filename_result: Dict, hash_verified: Optional[bool] = None) -> Dict:
        """
        Combine results and provide final assessment.
        Returns assessment dictionary.
        """
        assessment = {
            'status': 'unknown',
            'recommendation': '',
            'confidence': 'low',
            'factors': []
        }
        
        # Factor 1: VirusTotal results
        if vt_result and vt_result.get('success'):
            if vt_result['status'] == 'malicious':
                assessment['factors'].append(('negative', 'VirusTotal detections found'))
                assessment['status'] = 'unsafe'
            elif vt_result['status'] == 'suspicious':
                assessment['factors'].append(('caution', 'Suspicious activity flagged by some vendors'))
            elif vt_result['status'] == 'clean':
                assessment['factors'].append(('positive', 'No VirusTotal detections'))
            elif vt_result['status'] == 'not_found':
                assessment['factors'].append(('caution', 'File unknown to VirusTotal'))
        
        # Factor 2: Filename analysis
        if filename_result['risk_level'] == 'high':
            assessment['factors'].append(('negative', 'High-risk filename patterns detected'))
            if assessment['status'] != 'unsafe':
                assessment['status'] = 'caution'
        elif filename_result['risk_level'] == 'medium':
            assessment['factors'].append(('caution', 'Suspicious filename patterns'))
        else:
            assessment['factors'].append(('positive', 'Filename appears normal'))
        
        # Factor 3: Hash verification
        if hash_verified is not None:
            if hash_verified:
                assessment['factors'].append(('positive', 'Hash verification passed'))
            else:
                assessment['factors'].append(('negative', 'Hash verification FAILED'))
                assessment['status'] = 'unsafe'
        
        # Final status determination
        negative_count = sum(1 for f in assessment['factors'] if f[0] == 'negative')
        caution_count = sum(1 for f in assessment['factors'] if f[0] == 'caution')
        positive_count = sum(1 for f in assessment['factors'] if f[0] == 'positive')
        
        if assessment['status'] == 'unknown':
            if negative_count > 0:
                assessment['status'] = 'unsafe'
            elif caution_count > 0:
                assessment['status'] = 'caution'
            elif positive_count > 0:
                assessment['status'] = 'safe'
        
        # Set recommendation
        if assessment['status'] == 'unsafe':
            assessment['recommendation'] = "DO NOT run this file. It appears to be malicious."
            assessment['confidence'] = 'high' if negative_count > 1 else 'medium'
        elif assessment['status'] == 'caution':
            assessment['recommendation'] = "Proceed with caution. Additional verification recommended."
            assessment['confidence'] = 'medium'
        elif assessment['status'] == 'safe':
            assessment['recommendation'] = "File appears safe based on available data."
            assessment['confidence'] = 'high' if positive_count > 1 else 'medium'
        else:
            assessment['recommendation'] = "Unable to determine safety. Exercise caution."
            assessment['confidence'] = 'low'
        
        return assessment


# ==================== USER INTERFACE ====================

class SecurityCheckerUI:
    """Command-line interface for the security checker."""
    
    def __init__(self):
        Colors.enable_windows_colors()
        self.vt_checker = VirusTotalChecker()
    
    def print_banner(self):
        """Print application banner."""
        print()
        print_colored("=" * 60, Colors.CYAN)
        print_colored("       Windows Executable Security Checker", Colors.CYAN, bold=True)
        print_colored("=" * 60, Colors.CYAN)
        print()
    
    def print_menu(self):
        """Print main menu."""
        print_colored("\nSelect an option:", Colors.WHITE, bold=True)
        print_colored("  [1] Check local file", Colors.WHITE)
        print_colored("  [2] Check by hash only", Colors.WHITE)
        print_colored("  [3] Verify sender-provided hash", Colors.WHITE)
        print_colored("  [4] Configure API key", Colors.WHITE)
        print_colored("  [5] Exit", Colors.WHITE)
        print()
    
    def get_input(self, prompt: str) -> str:
        """Get user input with prompt."""
        print_colored(prompt, Colors.CYAN, bold=False)
        try:
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return ""
    
    def display_vt_results(self, result: Dict):
        """Display VirusTotal results."""
        print()
        print_colored("─" * 50, Colors.BLUE)
        print_colored("VirusTotal Results", Colors.BLUE, bold=True)
        print_colored("─" * 50, Colors.BLUE)
        
        if result.get('error'):
            print_colored(f"  Error: {result['error']}", Colors.YELLOW)
            return
        
        if result['status'] == 'not_found':
            print_colored("  Status: File not found in VirusTotal database", Colors.YELLOW)
            print_colored("  Note: This could be a new or rare file", Colors.WHITE)
            return
        
        # Detection ratio
        total = result['total']
        malicious = result['malicious']
        suspicious = result['suspicious']
        
        if malicious > 0:
            color = Colors.RED
        elif suspicious > 0:
            color = Colors.YELLOW
        else:
            color = Colors.GREEN
        
        print_colored(f"  Detection Ratio: {malicious}/{total} malicious, {suspicious}/{total} suspicious", color)
        
        # Status
        status_colors = {
            'clean': Colors.GREEN,
            'suspicious': Colors.YELLOW,
            'malicious': Colors.RED
        }
        print_colored(f"  Status: {result['status'].upper()}", status_colors.get(result['status'], Colors.WHITE))
        
        # Vendor detections
        if result['vendors']:
            print_colored("\n  Detections by vendor:", Colors.RED)
            for vendor in result['vendors'][:10]:  # Limit to 10
                print_colored(f"    • {vendor['name']}: {vendor['result']}", Colors.RED)
            if len(result['vendors']) > 10:
                print_colored(f"    ... and {len(result['vendors']) - 10} more", Colors.RED)
    
    def display_filename_analysis(self, result: Dict, filename: str):
        """Display filename analysis results."""
        print()
        print_colored("─" * 50, Colors.BLUE)
        print_colored("Filename Analysis", Colors.BLUE, bold=True)
        print_colored("─" * 50, Colors.BLUE)
        print_colored(f"  File: {os.path.basename(filename)}", Colors.WHITE)
        
        risk_colors = {
            'low': Colors.GREEN,
            'medium': Colors.YELLOW,
            'high': Colors.RED
        }
        print_colored(f"  Risk Level: {result['risk_level'].upper()}", 
                     risk_colors.get(result['risk_level'], Colors.WHITE))
        
        if result['warnings']:
            print_colored("\n  Warnings:", Colors.YELLOW)
            for warning in result['warnings']:
                print_colored(f"    ⚠ {warning}", Colors.YELLOW)
    
    def display_assessment(self, assessment: Dict):
        """Display final safety assessment."""
        print()
        print_colored("═" * 50, Colors.MAGENTA)
        print_colored("FINAL SAFETY ASSESSMENT", Colors.MAGENTA, bold=True)
        print_colored("═" * 50, Colors.MAGENTA)
        
        # Status with appropriate color
        print("\n  Overall Status: ", end="")
        if assessment['status'] == 'safe':
            print_safe()
        elif assessment['status'] == 'caution':
            print_caution()
        elif assessment['status'] == 'unsafe':
            print_unsafe()
        else:
            print_colored("UNKNOWN", Colors.YELLOW)
        
        print_colored(f"\n  Confidence: {assessment['confidence'].upper()}", Colors.WHITE)
        print_colored(f"\n  Recommendation: {assessment['recommendation']}", Colors.WHITE, bold=True)
        
        print_colored("\n  Assessment Factors:", Colors.WHITE)
        for factor_type, description in assessment['factors']:
            if factor_type == 'positive':
                print_colored(f"    ✓ {description}", Colors.GREEN)
            elif factor_type == 'negative':
                print_colored(f"    ✗ {description}", Colors.RED)
            else:
                print_colored(f"    ⚠ {description}", Colors.YELLOW)
        
        print()
    
    def check_local_file(self):
        """Option 1: Check a local file."""
        file_path = self.get_input("\nEnter file path: ")
        if not file_path:
            print_colored("No file path provided.", Colors.YELLOW)
            return
        
        # Handle quoted paths
        file_path = file_path.strip('"\'')
        
        if not os.path.exists(file_path):
            print_colored(f"File not found: {file_path}", Colors.RED)
            return
        
        print_colored(f"\nAnalyzing: {file_path}", Colors.CYAN)
        print_colored("Please wait...", Colors.WHITE)
        
        # Calculate hash
        file_hash = HashVerifier.calculate_sha256(file_path)
        if file_hash:
            print_colored(f"\nSHA256: {file_hash}", Colors.WHITE)
        
        # Check VirusTotal
        vt_result = None
        if file_hash:
            vt_result = self.vt_checker.check_hash(file_hash)
            self.display_vt_results(vt_result)
        
        # Analyze filename
        filename_result = FilenameAnalyzer.analyze(file_path)
        self.display_filename_analysis(filename_result, file_path)
        
        # Final assessment
        assessment = SafetyAssessor.assess(vt_result, filename_result)
        self.display_assessment(assessment)
    
    def check_by_hash(self):
        """Option 2: Check by hash only."""
        file_hash = self.get_input("\nEnter SHA256 hash: ")
        if not file_hash:
            print_colored("No hash provided.", Colors.YELLOW)
            return
        
        file_hash = file_hash.strip()
        
        if not HashVerifier.is_valid_sha256(file_hash):
            print_colored("Invalid SHA256 hash format. Must be 64 hexadecimal characters.", Colors.RED)
            return
        
        print_colored(f"\nChecking hash: {file_hash}", Colors.CYAN)
        print_colored("Please wait...", Colors.WHITE)
        
        # Check VirusTotal
        vt_result = self.vt_checker.check_hash(file_hash)
        self.display_vt_results(vt_result)
        
        # Get optional filename for analysis
        filename = self.get_input("\nEnter filename for analysis (optional, press Enter to skip): ")
        
        filename_result = {'risk_level': 'low', 'warnings': [], 'suspicious': False}
        if filename:
            filename_result = FilenameAnalyzer.analyze(filename)
            self.display_filename_analysis(filename_result, filename)
        
        # Final assessment
        assessment = SafetyAssessor.assess(vt_result, filename_result)
        self.display_assessment(assessment)
    
    def verify_sender_hash(self):
        """Option 3: Verify a sender-provided hash against a local file."""
        file_path = self.get_input("\nEnter local file path: ")
        if not file_path:
            print_colored("No file path provided.", Colors.YELLOW)
            return
        
        file_path = file_path.strip('"\'')
        
        if not os.path.exists(file_path):
            print_colored(f"File not found: {file_path}", Colors.RED)
            return
        
        expected_hash = self.get_input("Enter expected SHA256 hash (provided by sender): ")
        if not expected_hash:
            print_colored("No hash provided.", Colors.YELLOW)
            return
        
        expected_hash = expected_hash.strip()
        
        if not HashVerifier.is_valid_sha256(expected_hash):
            print_colored("Invalid SHA256 hash format. Must be 64 hexadecimal characters.", Colors.RED)
            return
        
        print_colored(f"\nVerifying: {file_path}", Colors.CYAN)
        print_colored("Please wait...", Colors.WHITE)
        
        # Verify hash
        match, calculated_hash = HashVerifier.verify_hash(file_path, expected_hash)
        
        print()
        print_colored("─" * 50, Colors.BLUE)
        print_colored("Hash Verification", Colors.BLUE, bold=True)
        print_colored("─" * 50, Colors.BLUE)
        print_colored(f"  Expected:   {expected_hash.lower()}", Colors.WHITE)
        print_colored(f"  Calculated: {calculated_hash.lower()}", Colors.WHITE)
        
        if match:
            print_colored("\n  Result: MATCH ✓", Colors.GREEN, bold=True)
            print_colored("  File integrity verified successfully!", Colors.GREEN)
        else:
            print_colored("\n  Result: MISMATCH ✗", Colors.RED, bold=True)
            print_colored("  WARNING: File may have been tampered with!", Colors.RED)
        
        # Check VirusTotal
        if calculated_hash:
            vt_result = self.vt_checker.check_hash(calculated_hash)
            self.display_vt_results(vt_result)
        else:
            vt_result = None
        
        # Analyze filename
        filename_result = FilenameAnalyzer.analyze(file_path)
        self.display_filename_analysis(filename_result, file_path)
        
        # Final assessment
        assessment = SafetyAssessor.assess(vt_result, filename_result, hash_verified=match)
        self.display_assessment(assessment)
    
    def configure_api_key(self):
        """Option 4: Configure VirusTotal API key."""
        print()
        print_colored("─" * 50, Colors.BLUE)
        print_colored("VirusTotal API Configuration", Colors.BLUE, bold=True)
        print_colored("─" * 50, Colors.BLUE)
        
        current_key = Config.get_api_key()
        if current_key:
            masked = current_key[:8] + "..." + current_key[-4:] if len(current_key) > 12 else "***"
            print_colored(f"  Current API key: {masked}", Colors.GREEN)
        else:
            print_colored("  No API key configured", Colors.YELLOW)
        
        print_colored("\n  Options for setting API key:", Colors.WHITE)
        print_colored("  1. Set environment variable: VIRUSTOTAL_API_KEY", Colors.WHITE)
        print_colored("  2. Create config file: vt_config.json", Colors.WHITE)
        print_colored("  3. Create config in home: ~/.virustotal_config.json", Colors.WHITE)
        
        save_now = self.get_input("\nSave a new API key now? (y/n): ")
        if save_now.lower() == 'y':
            new_key = self.get_input("Enter your VirusTotal API key: ")
            if new_key:
                config_path = Path(__file__).parent / 'vt_config.json'
                try:
                    with open(config_path, 'w') as f:
                        json.dump({'api_key': new_key}, f, indent=2)
                    print_colored(f"\n  API key saved to: {config_path}", Colors.GREEN)
                    self.vt_checker = VirusTotalChecker(new_key)
                except IOError as e:
                    print_colored(f"\n  Error saving config: {e}", Colors.RED)
    
    def run(self):
        """Main application loop."""
        self.print_banner()
        
        # Check API key status
        if not Config.get_api_key():
            print_colored("⚠ Warning: VirusTotal API key not configured.", Colors.YELLOW)
            print_colored("  Some features will be limited. Use option 4 to configure.", Colors.YELLOW)
        
        while True:
            self.print_menu()
            choice = self.get_input("Enter choice (1-5): ")
            
            if choice == '1':
                self.check_local_file()
            elif choice == '2':
                self.check_by_hash()
            elif choice == '3':
                self.verify_sender_hash()
            elif choice == '4':
                self.configure_api_key()
            elif choice == '5':
                print_colored("\nGoodbye! Stay safe online.", Colors.CYAN)
                break
            else:
                print_colored("Invalid option. Please enter 1-5.", Colors.RED)


# ==================== MAIN ENTRY POINT ====================

def main():
    """Main entry point."""
    try:
        ui = SecurityCheckerUI()
        ui.run()
    except KeyboardInterrupt:
        print_colored("\n\nOperation cancelled by user.", Colors.YELLOW)
        sys.exit(0)


if __name__ == "__main__":
    main()

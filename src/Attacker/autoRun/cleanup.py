"""
Cleanup - Removes ALL persistence and ransomware files
Run this to clean up after testing.
"""

import os
import winreg
import shutil
from pathlib import Path

# Names used in the attack
MALWARE_NAMES = [
    "EducationalAutoRunTest",
    "WindowsSecurityService",
]

def cleanup():
    print()
    print("=" * 60)
    print("    COMPLETE CLEANUP")
    print("    Removes all persistence and malware files")
    print("=" * 60)
    print()
    
    # 1. Remove Registry entries
    print("[1/5] Removing Registry entries...")
    for name in MALWARE_NAMES:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE
            )
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            print(f"    [+] Removed: {name}")
        except FileNotFoundError:
            print(f"    [*] Not found: {name}")
        except Exception as e:
            print(f"    [-] Error: {e}")
    print()
    
    # 2. Remove Startup folder files
    print("[2/5] Removing Startup folder files...")
    startup_folder = os.path.join(
        os.environ["APPDATA"],
        r"Microsoft\Windows\Start Menu\Programs\Startup"
    )
    startup_files = [
        "WindowsUpdate.pyw",
        "WindowsDefender.pyw",
    ]
    for filename in startup_files:
        filepath = os.path.join(startup_folder, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            print(f"    [+] Removed: {filename}")
        else:
            print(f"    [*] Not found: {filename}")
    print()
    
    # 3. Remove hidden payload files
    print("[3/5] Removing hidden payload files...")
    hidden_files = [
        os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Update", "service.pyw"),
        os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Security", "defender.pyw"),
    ]
    for filepath in hidden_files:
        if os.path.exists(filepath):
            os.remove(filepath)
            print(f"    [+] Removed: {filepath}")
        else:
            print(f"    [*] Not found: {os.path.basename(filepath)}")
    print()
    
    # 4. Remove hidden folders
    print("[4/5] Removing hidden folders...")
    hidden_folders = [
        os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Update"),
        os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Security"),
    ]
    for folder in hidden_folders:
        if os.path.exists(folder):
            try:
                shutil.rmtree(folder)
                print(f"    [+] Removed: {folder}")
            except Exception as e:
                print(f"    [-] Failed: {e}")
        else:
            print(f"    [*] Not found: {os.path.basename(folder)}")
    print()
    
    # 5. Decrypt locked folders
    print("[5/5] Decrypting locked folders...")
    user_home = Path.home()
    target_folders = [
        user_home / "Documents",
        user_home / "Desktop",
        user_home / "Downloads",
        user_home / "Pictures",
    ]
    
    LOCK_FILE = ".folder_lock"
    ENCRYPTED_EXTENSION = ".locked"
    
    for folder in target_folders:
        if not folder.exists():
            continue
        
        lock_path = folder / LOCK_FILE
        if lock_path.exists():
            print(f"    [*] Decrypting: {folder.name}")
            
            # Decrypt files
            decrypted = 0
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith(ENCRYPTED_EXTENSION):
                        try:
                            locked_path = os.path.join(root, file)
                            original_path = locked_path[:-len(ENCRYPTED_EXTENSION)]
                            os.rename(locked_path, original_path)
                            decrypted += 1
                        except:
                            pass
            
            # Remove lock file
            try:
                # Unhide file first
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(lock_path), 0)
            except:
                pass
            
            if lock_path.exists():
                os.remove(lock_path)
            
            print(f"    [+] Decrypted {decrypted} files in {folder.name}")
        else:
            print(f"    [*] Not locked: {folder.name}")
    
    print()
    print("=" * 60)
    print("    CLEANUP COMPLETE")
    print("=" * 60)
    print()
    print("  All persistence mechanisms removed!")
    print("  All encrypted files restored!")
    print()
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    cleanup()
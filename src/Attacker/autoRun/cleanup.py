"""
Cleanup - Removes all persistence
"""

import os
import winreg
import shutil

MALWARE_NAME = "HelloWorldMalware"

def cleanup():
    print("=" * 50)
    print("    REMOVING ALL PERSISTENCE")
    print("=" * 50)
    print()
    
    # Remove Registry
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, MALWARE_NAME)
        winreg.CloseKey(key)
        print("[+] Registry entry removed")
    except:
        print("[*] Registry entry not found")
    
    # Remove Startup folder
    startup = os.path.join(
        os.environ["APPDATA"],
        r"Microsoft\Windows\Start Menu\Programs\Startup",
        "helloWorld.exe"
    )
    if os.path.exists(startup):
        os.remove(startup)
        print("[+] Startup file removed")
    else:
        print("[*] Startup file not found")
    
    # Remove hidden copy
    hidden = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "helloWorld.exe")
    if os.path.exists(hidden):
        os.remove(hidden)
        print("[+] Hidden malware removed")
    
    print()
    print("[+] Cleanup complete!")
    input("Press Enter to exit...")

if __name__ == "__main__":
    cleanup()
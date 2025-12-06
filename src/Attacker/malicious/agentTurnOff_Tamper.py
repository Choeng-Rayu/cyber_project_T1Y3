"""
Simple script to turn off Tamper Protection
Retries until successful
"""
import pyautogui
import subprocess
import time

pyautogui.FAILSAFE = False
pyautogui.PAUSE = 0.3

def check_tamper_status():
    """Check if Tamper Protection is disabled"""
    try:
        result = subprocess.run(
            ['powershell', '-Command', '(Get-MpComputerStatus).IsTamperProtected'],
            capture_output=True, text=True, timeout=10
        )
        status = result.stdout.strip().lower()
        print(f"[DEBUG] Tamper Protection status: {status}")
        return status == "false"  # True means it's OFF
    except:
        return False

def check_realtime_status():
    """Check if Real-time Protection is disabled"""
    try:
        result = subprocess.run(
            ['powershell', '-Command', '(Get-MpComputerStatus).RealTimeProtectionEnabled'],
            capture_output=True, text=True, timeout=10
        )
        status = result.stdout.strip().lower()
        print(f"[DEBUG] Real-time Protection status: {status}")
        return status == "false"  # True means it's OFF
    except:
        return False

def close_windows_security():
    """Close Windows Security window"""
    print("[*] Closing Windows Security...")
    pyautogui.hotkey("alt", "f4")
    time.sleep(1)

def turn_off_protections():
    """Step by step to turn off protections"""

    # Step 1: Open Windows Security
    print("\n[Step 1] Opening Windows Security...")
    subprocess.Popen('start windowsdefender://threatsettings', shell=True)
    time.sleep(3)

    # Step 2: Click "Manage settings"
    print("[Step 2] Pressing TAB to navigate to 'Manage settings'...")
    for _ in range(5):
        pyautogui.press("tab")
        time.sleep(0.2)
    pyautogui.press("enter")
    time.sleep(2)

    # Step 3: Navigate to Real-time protection toggle
    print("[Step 3] Navigating to Real-time protection toggle...")
    for _ in range(3):
        pyautogui.press("tab")
        time.sleep(0.2)

    # Step 4: Turn OFF Real-time protection
    print("[Step 4] Turning OFF Real-time protection...")
    pyautogui.press("space")
    time.sleep(2)

    # Step 5: Accept UAC
    print("[Step 5] Accepting UAC (Alt+Y)...")
    pyautogui.hotkey("alt", "y")
    time.sleep(2)

    # Step 6: Navigate to Tamper Protection toggle
    print("[Step 6] Navigating to Tamper Protection toggle...")
    for _ in range(4):
        pyautogui.press("tab")
        time.sleep(0.2)

    # Step 7: Turn OFF Tamper Protection
    print("[Step 7] Turning OFF Tamper Protection...")
    pyautogui.press("space")
    time.sleep(2)

    # Step 8: Accept UAC
    print("[Step 8] Accepting UAC (Alt+Y)...")
    pyautogui.hotkey("alt", "y")
    time.sleep(2)

def main():
    """Main function - retry until Tamper Protection is OFF"""
    print("=" * 50)
    print("  DISABLE TAMPER PROTECTION")
    print("=" * 50)

    max_attempts = 5
    attempt = 0

    while attempt < max_attempts:
        attempt += 1
        print(f"\n>>> ATTEMPT {attempt}/{max_attempts}")

        # Check if already disabled
        if check_tamper_status() and check_realtime_status():
            print("\n[+] SUCCESS! Both protections are already OFF!")
            return True

        # Try to disable
        turn_off_protections()

        # Close and verify
        close_windows_security()
        time.sleep(1)

        # Check result
        tamper_off = check_tamper_status()
        realtime_off = check_realtime_status()

        if tamper_off and realtime_off:
            print("\n" + "=" * 50)
            print("[+] SUCCESS! Both protections are now OFF!")
            print("=" * 50)
            return True
        else:
            print(f"\n[-] Attempt {attempt} failed. Retrying...")
            time.sleep(2)

    print("\n[-] FAILED after maximum attempts.")
    print("[-] Please try manually or check Windows Security settings.")
    return False

if __name__ == "__main__":
    print("\n[!] Starting in 3 seconds...")
    print("[!] DO NOT touch keyboard/mouse!\n")
    time.sleep(3)
    main()
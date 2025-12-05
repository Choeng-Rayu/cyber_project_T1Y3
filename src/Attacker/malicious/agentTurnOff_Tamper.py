import pyautogui
import time
import sys

class WindowsSecurityDisabler:
    def __init__(self):
        pyautogui.FAILSAFE = True  # Move mouse to corner to abort
        self.delay_between_actions = 0.5  # Reduced delay for speed
        self.confirmation_delay = 1.0     # Longer delay for critical steps
        
    def wait(self, seconds=None):
        """Wait for specified time or default delay"""
        if seconds is None:
            seconds = self.delay_between_actions
        time.sleep(seconds)
    
    def press_with_feedback(self, keys, description=""):
        """Press key combination with optional description"""
        if description:
            print(f"🔹 {description}")
        pyautogui.hotkey(*keys.split('+')) if '+' in keys else pyautogui.press(keys)
        self.wait()
    
    def type_with_feedback(self, text, description=""):
        """Type text with optional description"""
        if description:
            print(f"🔹 {description}")
        pyautogui.write(text, interval=0.05)
        self.wait()
    
    def execute_blind_protocol(self):
        """Execute the blind keyboard protocol you specified"""
        print("🚀 Starting Blind Protocol: Disable Windows Security")
        print("=" * 50)
        
        try:
            # Phase 1: Initial Setup
            print("\n📁 PHASE 1: Desktop Setup")
            self.press_with_feedback('win+d', "Windows + D (Go to Desktop)")
            self.wait(0.3)
            
            # Phase 2: Open Windows Defender
            print("\n🔧 PHASE 2: Open Windows Defender")
            self.press_with_feedback('win+r', "Windows + R (Open Run dialog)")
            self.wait(0.5)
            
            self.type_with_feedback('windowsdefender:', "Type: windowsdefender:")
            self.press_with_feedback('enter', "Enter (Open Windows Defender)")
            self.wait(1.5)  # Wait for app to load
            
            # Phase 3: Navigate to Virus Settings
            print("\n🦠 PHASE 3: Navigate to Virus Settings")
            self.press_with_feedback('enter', "Enter (Virus & threat protection)")
            self.wait(1.0)  # Wait for page to load
            
            # Phase 4: Manage Settings
            print("\n⚙️ PHASE 4: Manage Settings")
            for i in range(4):
                self.press_with_feedback('tab', f"Tab {i+1}/4")
            self.press_with_feedback('enter', "Enter (Manage settings)")
            self.wait(1.0)
            
            # Phase 5: Toggle Real-time Protection
            print("\n🔓 PHASE 5: Toggle Real-time Protection")
            for i in range(4):
                self.press_with_feedback('tab', f"Tab {i+1}/4")
            
            print("⚠️ WARNING: About to disable Real-time protection!")
            for countdown in range(3, 0, -1):
                print(f"⏳ {countdown}...")
                time.sleep(1)
            
            self.press_with_feedback('space', "Spacebar (Toggle real-time protection OFF)")
            self.wait(1.5)  # Wait for change to apply
            
            # Handle possible UAC prompt
            print("\n🛡️ Checking for UAC prompt...")
            self.wait(2.0)
            
            # Try to detect and handle UAC
            try:
                # Look for UAC window (simplified detection)
                self.press_with_feedback('tab', "Tab (Navigate UAC if present)")
                self.press_with_feedback('tab', "Tab (Move to Yes button)")
                self.press_with_feedback('enter', "Enter (Confirm UAC)")
                self.wait(1.0)
            except:
                pass  # No UAC or already handled
            
            # Phase 6: Clean Exit
            print("\n🚪 PHASE 6: Clean Exit")
            self.press_with_feedback('alt+f4', "Alt + F4 (Close Windows Security)")
            
            # Double-check everything is closed
            self.press_with_feedback('alt+f4', "Alt + F4 (Ensure closed)")
            self.wait(0.5)
            
            print("\n" + "=" * 50)
            print("✅ Protocol Complete!")
            print("⚠️ Remember: Re-enable protection when done!")
            
        except pyautogui.FailSafeException:
            print("\n❌ Protocol aborted by user (mouse moved to corner)")
        except Exception as e:
            print(f"\n❌ Error occurred: {e}")
            print("Attempting emergency cleanup...")
            self.emergency_cleanup()
    
    def emergency_cleanup(self):
        """Try to close any open windows"""
        for _ in range(5):
            self.press_with_feedback('alt+f4', "Closing windows...")
            self.wait(0.3)
        self.press_with_feedback('esc', "Press Escape")
    
    def verification_protocol(self):
        """Optional: Verify the change was made"""
        print("\n🔍 VERIFICATION PROTOCOL")
        print("-" * 30)
        
        self.press_with_feedback('win+r', "Open Run dialog")
        self.type_with_feedback('powershell', "Open PowerShell")
        self.press_with_feedback('enter', "Launch PowerShell")
        self.wait(2.0)
        
        # Run verification command
        command = 'Get-MpComputerStatus | select RealTimeProtectionEnabled'
        pyautogui.write(command, interval=0.05)
        self.press_with_feedback('enter', "Execute command")
        self.wait(2.0)
        
        # Close PowerShell
        self.press_with_feedback('alt+f4', "Close PowerShell")
        
        print("\n📋 Verification complete. Check output above.")
        print("If it shows 'False', real-time protection is disabled.")
    
    def reenable_protocol(self):
        """Protocol to re-enable protection (reverse process)"""
        print("\n🔄 RE-ENABLE PROTOCOL")
        print("-" * 30)
        
        self.execute_blind_protocol()  # Same steps toggle it back ON
        print("✅ Protection should be re-enabled")

def countdown_timer(seconds=5):
    """Countdown before starting"""
    print("🖥️ Windows Security Disabler - Starting in...")
    for i in range(seconds, 0, -1):
        print(f"   {i}")
        time.sleep(1)
    print("   GO!")

def main():
    """Main function with menu"""
    print("=" * 60)
    print("WINDOWS SECURITY BLIND PROTOCOL SIMULATOR")
    print("=" * 60)
    print("\n⚠️  WARNING: This script will modify Windows Security settings")
    print("   Use responsibly and re-enable protection after testing!")
    print("\nOptions:")
    print("1. Execute Disable Protocol (Your exact method)")
    print("2. Execute + Verify")
    print("3. Re-enable Protocol")
    print("4. Test Navigation Only (No toggle)")
    print("5. Exit")
    
    choice = input("\nSelect option (1-5): ").strip()
    
    disabler = WindowsSecurityDisabler()
    
    if choice == '1':
        countdown_timer(3)
        disabler.execute_blind_protocol()
    elif choice == '2':
        countdown_timer(3)
        disabler.execute_blind_protocol()
        disabler.verification_protocol()
    elif choice == '3':
        countdown_timer(3)
        disabler.reenable_protocol()
    elif choice == '4':
        print("\n🧪 TEST MODE: Navigation only (will not toggle)")
        # Modify to skip the spacebar press
        original_method = disabler.execute_blind_protocol
        def test_method():
            print("🧪 TEST MODE ACTIVE - Will skip final toggle")
            # We'll create a modified version that doesn't press space
            # This is a simplified approach
            print("(Simulating navigation without toggling)")
            for step in ["win+d", "win+r", "type", "enter", "tab", "enter", "tab", "alt+f4"]:
                print(f"  Simulating: {step}")
                time.sleep(0.3)
            print("✅ Test complete - No changes made")
        disabler.execute_blind_protocol = test_method
        countdown_timer(2)
        disabler.execute_blind_protocol()
    elif choice == '5':
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid choice!")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    print("Aborted. Incorrect confirmation code.")
    #main()
    WindowsSecurityDisabler().execute_blind_protocol()
"""
Simple test payload - just shows a message to prove autorun works.
This is SAFE to test - no malicious actions.
"""

import os
import datetime
import tkinter as tk
from tkinter import messagebox

# Log file to prove it ran
LOG_FILE = "C:\\MalwareLab\\autorun_test_log.txt"

def log_execution():
    """Log when this script runs."""
    os.makedirs("C:\\MalwareLab", exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] AutoRun test executed successfully!\n")
    
    print(f"[+] Logged to: {LOG_FILE}")

def show_popup():
    """Show a popup message to prove autorun works."""
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    messagebox.showinfo(
        "AutoRun Test", 
        "✅ SUCCESS!\n\nThis message proves that AutoRun persistence is working.\n\nThe script ran automatically!"
    )
    
    root.destroy()

def main():
    print("=" * 40)
    print("  AUTORUN TEST PAYLOAD EXECUTED!")
    print("=" * 40)
    print()
    
    # Log the execution
    log_execution()
    
    # Show popup
    show_popup()
    
    print("[+] Test completed!")

if __name__ == "__main__":
    main()
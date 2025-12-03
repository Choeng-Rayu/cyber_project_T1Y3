"""
HelloWorld.exe - Simulates malware behavior
Shows a popup message and logs execution to prove it ran.
"""

import tkinter as tk
from tkinter import messagebox
import datetime
import os

def main():
    # Create log folder
    os.makedirs("C:\\MalwareLab", exist_ok=True)
    
    # Log execution
    log_file = "C:\\MalwareLab\\malware_log.txt"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] HelloWorld.exe executed!\n")
    
    # Show popup
    root = tk.Tk()
    root.withdraw()
    
    messagebox.showinfo(
        "HelloWorld - Malware Simulation",
        f"🔴 HELLO WORLD!\n\n"
        f"This EXE ran automatically!\n\n"
        f"In a real attack, this could:\n"
        f"• Encrypt your files\n"
        f"• Steal your data\n"
        f"• Install backdoors\n\n"
        f"Time: {timestamp}\n\n"
        f"Check: C:\\MalwareLab\\malware_log.txt"
    )
    
    root.destroy()

if __name__ == "__main__":
    main()
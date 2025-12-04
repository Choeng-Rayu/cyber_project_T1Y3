"""
USB Spreading Main Execution Script
Professional Red Team USB Worm Testing
"""

import os
import sys
from pathlib import Path

# Import the professional framework
from usbSpreading import USBWormFramework, logger


def setup_test_environment(usb_path: str = "./test_usb"):
    """Setup a test USB environment with dummy malware"""
    logger.info(f"Setting up test environment at: {usb_path}")
    
    try:
        # Create test USB directory
        os.makedirs(usb_path, exist_ok=True)
        
        # Create dummy malware on the "USB"
        malware_path = f"{usb_path}/main.py"
        if not os.path.exists(malware_path):
            with open(malware_path, 'w') as f:
                f.write("""#!/usr/bin/env python3
# Simulated USB Worm Payload
import os
print("[*] This is simulated malware")
print("[*] In real scenario, this would encrypt files")
""")
            logger.info(f"✓ Created dummy malware: {malware_path}")
        
        return usb_path
    except Exception as e:
        logger.error(f"Error setting up test environment: {e}")
        return None


def main():
    """Main execution point"""
    print("""
╔═══════════════════════════════════════════════════════╗
║  🔴 USB WORM FRAMEWORK - PROFESSIONAL EDITION        ║
║  For Authorized Penetration Testing Only             ║
╚═══════════════════════════════════════════════════════╝
    """)
    
    # Get USB path from command line or use default
    usb_path = sys.argv[1] if len(sys.argv) > 1 else "./test_usb"
    
    # Setup test environment if it doesn't exist
    if not os.path.exists(usb_path):
        logger.info("Test USB directory not found, creating it...")
        usb_path = setup_test_environment(usb_path)
        if usb_path is None:
            logger.error("Failed to setup test environment")
            return
    
    # Initialize the framework
    engagement_id = f"ENGAGEMENT_{os.path.basename(usb_path).upper()}"
    framework = USBWormFramework(engagement_id)
    
    logger.info(f"🎯 Starting USB insertion simulation...")
    logger.info(f"📍 USB Path: {usb_path}")
    
    # Execute USB insertion handling
    result = framework.handle_usb_insert(usb_path)
    
    # Print summary
    framework.print_summary()
    
    # Save report
    report_path = framework.save_report()
    logger.info(f"📄 Detailed report saved: {report_path}")
    
    logger.info("✓ Engagement complete!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
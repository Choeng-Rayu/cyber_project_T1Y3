# USB Spreading Framework - Professional Edition

## Overview

This is a **professional-grade USB worm simulation framework** for authorized penetration testing and cybersecurity education. It demonstrates how USB-based lateral movement attacks work in three distinct phases.

## ✨ Improvements Made

### 1. **Object-Oriented Architecture**
- Converted from procedural code to class-based design (`USBWormFramework`)
- Better code organization and maintainability
- Easier to extend with new features

### 2. **Professional Logging**
- Comprehensive logging system with file and console output
- Debug, info, warning, and error levels
- All operations logged to `usb_spreading.log`
- Easy to track execution flow

### 3. **Engagement Tracking**
- Unique engagement IDs for each test
- Operation-level logging with timestamps
- Track metrics: infections, USB spreads, data stolen
- Detailed operation history

### 4. **Reporting System**
- Generate JSON reports with all engagement details
- Summary statistics
- Success/failure rates
- Detailed operation logs
- Reports saved to `reports/` directory

### 5. **Enhanced Metadata**
- Infection markers now include timestamps and engagement IDs
- Better tracking of what happened and when
- Useful for post-exploitation analysis

### 6. **Cross-Platform Support**
- Windows: Registry-based autostart
- Linux: .desktop file autostart
- macOS: LaunchAgent support (prepared)
- Platform detection and logging

### 7. **Type Hints & Documentation**
- Full type annotations for better IDE support
- Comprehensive docstrings
- Better code clarity and maintainability

### 8. **Backward Compatibility**
- Legacy functions preserved for existing code
- Can use old API while new framework is optional
- Smooth migration path

### 9. **Better Error Handling**
- Detailed error messages
- All operations wrapped in try-except
- Graceful failure modes
- Operation status tracking

### 10. **Data Organization**
- Separate data folder for stolen documents on USB
- Better folder structure for real-world scenarios
- More realistic attack simulation

## Architecture

```
USBWormFramework
├── __init__()                    # Initialize framework
├── computer_is_infected()        # Check computer infection status
├── usb_is_infected()            # Check USB infection status
├── mark_computer_infected()     # Mark computer as infected
├── mark_usb_infected()          # Mark USB as infected
├── add_to_autostart()           # Add to system autostart
├── create_autorun_file()        # Create autorun.inf
├── steal_documents_to_usb()     # Exfiltrate documents
├── handle_usb_insert()          # Main USB insertion handler
├── _log_operation()             # Log operations
├── generate_report()            # Generate engagement report
├── save_report()                # Save report to JSON
└── print_summary()              # Print summary stats
```

## Usage

### Basic Usage

```python
from usbSpreading import USBWormFramework

# Create framework instance
framework = USBWormFramework()

# Simulate USB insertion
result = framework.handle_usb_insert("/media/usb")

# Generate and save report
framework.print_summary()
framework.save_report()
```

### Command Line Usage

```bash
# Test with default directory
python main.py

# Test with specific USB path
python main.py /path/to/usb

# Test with local folder
python main.py ./test_usb
```

### Running the Test

```bash
cd src/Attacker/spreading/

# Setup test environment
mkdir test_usb
echo "test malware" > test_usb/main.py

# Run the framework
python main.py test_usb
```

## Three-Phase Attack Flow

### Phase 1: Computer Infection (USB → Computer)
1. Check if computer is already infected
2. Copy malware from USB to computer
3. Add malware to system autostart
4. Mark computer as infected
5. **Result:** Computer infected and persistent

### Phase 2: USB Replication (Computer → USB)
1. Check if USB is already infected
2. Copy malware from computer to USB
3. Create `autorun.inf` for auto-execution on next computer
4. Mark USB as infected
5. **Result:** USB ready to infect next victim

### Phase 3: Data Exfiltration
1. Scan user's Documents folder
2. Copy all documents to USB's Data folder
3. Log files stolen
4. **Result:** Sensitive data on attacker's USB

## Output Files Generated

### Logs
- `usb_spreading.log` - Detailed operation log

### Reports
- `reports/ENGAGEMENT_XXXXX_report.json` - Engagement report with:
  - Computers infected count
  - USBs compromised count
  - Documents stolen count
  - All operations with timestamps
  - Success/failure rates

### Data
- `test_usb/main.py` - Malware payload
- `test_usb/autorun.inf` - Auto-execution configuration
- `test_usb/Data/` - Stolen documents
- `~/.infected` - Computer infection marker
- `test_usb/.usb_infected` - USB infection marker

## Report Example

```json
{
  "engagement_id": "USB_WORM_20231203_120000",
  "timestamp": "2023-12-03T12:00:00.000000",
  "summary": {
    "computers_infected": 1,
    "usbs_compromised": 1,
    "documents_stolen": 5,
    "total_operations": 12,
    "successful_operations": 11,
    "failed_operations": 0
  },
  "operations": [
    {
      "operation": "ADD_TO_AUTOSTART",
      "status": "SUCCESS",
      "timestamp": "2023-12-03T12:00:01.234567",
      "details": "Linux"
    }
  ]
}
```

## Configuration

Edit `usbSpreading.py` constants to customize:

```python
INFECTION_MARKER_FILE = ".infected"      # Marker file name
USB_MARKER_FILE = ".usb_infected"        # USB marker file name
MALWARE_NAME = "malware_hello.py"        # Computer malware name
PAYLOAD_NAME = "main.py"                 # USB payload name
ENGAGEMENT_LOG_FILE = "usb_operations.json"  # Log file
```

## Improvements Summary

| Feature | Before | After |
|---------|--------|-------|
| Code Structure | Procedural | Object-Oriented |
| Logging | print() statements | Professional logging |
| Reporting | None | JSON reports |
| Error Tracking | Silent failures | Detailed tracking |
| Metadata | Minimal | Rich with timestamps |
| Documentation | Basic | Comprehensive |
| Type Hints | None | Full typing |
| Cross-Platform | Limited | Full Windows/Linux/macOS |
| Engagement Tracking | None | Complete history |
| Reusability | Low | High |

## Professional Features

✅ **Engagement ID Tracking** - Each test has unique ID
✅ **Operation Logging** - Every action logged with timestamp
✅ **Success/Failure Metrics** - Track what worked and what didn't
✅ **JSON Reporting** - Machine-readable reports
✅ **Platform Detection** - Detects and adapts to OS
✅ **Data Organization** - Stolen data in separate folder
✅ **Error Recovery** - Graceful failure handling
✅ **Audit Trail** - Complete operation history
✅ **Summary Statistics** - Quick overview of engagement
✅ **Backward Compatible** - Legacy API still works

## Safety & Legal Notice

⚠️ **For Authorized Testing Only**
- Only use in authorized penetration tests
- Obtain proper authorization before testing
- Follow all applicable laws and regulations
- This is educational code for cybersecurity courses
- Unauthorized access to systems is illegal

## Files Modified

1. `usbSpreading.py` - Complete rewrite with framework
2. `main.py` - Updated to use new framework

## Learning Outcomes

This improved version teaches:
- Professional Python code structure
- Logging and monitoring best practices
- Report generation and metrics
- Cross-platform development
- Error handling patterns
- Type hints and documentation
- Engagement tracking concepts
- Penetration testing workflows

---

**Last Updated:** December 3, 2025
**Framework Version:** 2.0 (Professional Edition)

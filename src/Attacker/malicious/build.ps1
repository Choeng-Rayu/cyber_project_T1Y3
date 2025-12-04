# Safe build script for this folder
# This script is intentionally conservative and will refuse to build "main.py" because it contains malicious behavior.
# Usage: .\build.ps1 -File <filename> [-Force]
param(
    [string]$File = "safe_test.py",
    [switch]$Force
)

$cwd = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
Set-Location $cwd

Write-Output "Building in folder: $cwd"

# Ensure Python is available
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Error "Python is not found in PATH. Please install Python and try again."; exit 1
}

# Create a venv if not exists
if (-not (Test-Path .venv)) {
    Write-Output "Creating virtual environment (.venv)..."
    python -m venv .venv
}

# Set execution policy for venv script activation for this session
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

# Activate venv
. .\.venv\Scripts\Activate.ps1

# Upgrade pip and install pyinstaller if not installed
Write-Output "Ensuring pip and PyInstaller are installed in the venv..."
python -m pip install --upgrade pip | Out-Null
python -m pip install pyinstaller --no-warn-script-location | Out-Null

# Prevent packaging of dangerous/malicious files
if ($File -eq 'main.py' -and -not $Force) {
    Write-Warning "This script will not build 'main.py' because it contains potentially harmful behavior."
    Write-Warning "If you are doing legitimate research and have explicit permission, re-run with -Force to override this check."
    exit 2
}

# Ensure file exists
if (-not (Test-Path $File)) {
    Write-Error "File $File not found."; exit 1
}

# Build
Write-Output "Building $File with PyInstaller (onefile, noconsole)..."
python -m PyInstaller --onefile --noconsole $File

if (Test-Path dist) {
    Write-Output "Build completed. Output in the 'dist' folder:"
    Get-ChildItem -Path .\dist -File | ForEach-Object { Write-Output " - $($_.Name)" }
} else {
    Write-Warning "Build didn't produce a dist folder. Check PyInstaller logs in the build folder.";
}

Write-Output "Finished."
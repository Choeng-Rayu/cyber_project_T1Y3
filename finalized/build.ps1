# Build script for Anti-Malicious Defender
# Creates a standalone .exe with icon support

Write-Host "Building Anti-Malicious Defender .exe" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check if PyInstaller is installed
Write-Host "[1/5] Checking PyInstaller..." -ForegroundColor Yellow
try {
    $pyinstallerCheck = python -m PyInstaller --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] PyInstaller installed: $pyinstallerCheck" -ForegroundColor Green
    } else {
        throw "PyInstaller not found"
    }
} catch {
    Write-Host "  [WARN] PyInstaller not installed. Installing now..." -ForegroundColor Yellow
    python -m pip install pyinstaller
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [ERROR] Failed to install PyInstaller" -ForegroundColor Red
        exit 1
    }
    Write-Host "  [OK] PyInstaller installed successfully" -ForegroundColor Green
}

# Check for icon files
Write-Host ""
Write-Host "[2/5] Checking icon files..." -ForegroundColor Yellow
if (Test-Path "antiLogo.ico") {
    Write-Host "  [OK] antiLogo.ico found" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] antiLogo.ico not found!" -ForegroundColor Red
    Write-Host "  Please ensure antiLogo.ico is in the current directory" -ForegroundColor Red
    exit 1
}

# Clean previous build
Write-Host ""
Write-Host "[3/5] Cleaning previous build..." -ForegroundColor Yellow
if (Test-Path "build") {
    Remove-Item -Recurse -Force "build"
    Write-Host "  [OK] Removed build folder" -ForegroundColor Green
}
if (Test-Path "dist") {
    Remove-Item -Recurse -Force "dist"
    Write-Host "  [OK] Removed dist folder" -ForegroundColor Green
}
if (Test-Path "anti_malicious.exe") {
    Remove-Item -Force "anti_malicious.exe"
    Write-Host "  [OK] Removed old exe" -ForegroundColor Green
}

# Build the executable
Write-Host ""
Write-Host "[4/5] Building executable with PyInstaller..." -ForegroundColor Yellow
Write-Host "  This may take a few minutes..." -ForegroundColor Gray

python -m PyInstaller anti_malicious.spec --clean

if ($LASTEXITCODE -ne 0) {
    Write-Host "  [ERROR] Build failed!" -ForegroundColor Red
    exit 1
}

# Move exe to current directory
Write-Host ""
Write-Host "[5/5] Finalizing..." -ForegroundColor Yellow
if (Test-Path "dist\anti_malicious.exe") {
    Copy-Item "dist\anti_malicious.exe" "anti_malicious.exe" -Force
    Write-Host "  [OK] Executable created: anti_malicious.exe" -ForegroundColor Green
    
    # Get file size
    $fileSize = (Get-Item "anti_malicious.exe").Length
    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
    Write-Host "  [INFO] Size: $fileSizeMB MB" -ForegroundColor Gray
} else {
    Write-Host "  [ERROR] Executable not found in dist folder!" -ForegroundColor Red
    exit 1
}

# Clean up build artifacts (optional)
Write-Host ""
Write-Host "Cleaning up build artifacts..." -ForegroundColor Gray
Remove-Item -Recurse -Force "build" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "dist" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Build Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Output: anti_malicious.exe" -ForegroundColor Cyan
Write-Host ""
Write-Host "How to use:" -ForegroundColor Yellow
Write-Host "  1. Run: .\anti_malicious.exe" -ForegroundColor White
Write-Host "     - First run creates desktop shortcut with icon" -ForegroundColor Gray
Write-Host "     - Adds to startup and runs in background" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Click desktop shortcut: 'Anti-Malicious Defender'" -ForegroundColor White
Write-Host "     - Opens GUI interface" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Or run: .\anti_malicious.exe --gui" -ForegroundColor White
Write-Host "     - Directly opens GUI" -ForegroundColor Gray
Write-Host ""

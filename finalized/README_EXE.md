# Anti-Malicious Defender - Executable Guide

## 🎯 Overview

This guide explains how to use the **anti_malicious.exe** standalone executable.

---

## 🛠️ Building from Source

To rebuild the executable from the Python script:

```powershell
.\build.ps1
```

This will create `anti_malicious.exe` (approximately 17 MB).

---

## 🚀 First Run

### When you run `anti_malicious.exe` for the first time:

```powershell
.\anti_malicious.exe
```

**What happens:**
1. ✅ Creates desktop shortcut with logo icon: "Anti-Malicious Defender"
2. ✅ Adds to Windows startup registry (runs on boot)
3. ✅ Marks installation as complete
4. ✅ Runs silently in background protecting your system

**You won't see any window** - the executable runs in the background as a protection service.

---

## 💻 Opening the GUI

There are **3 ways** to open the graphical interface:

### Method 1: Desktop Shortcut (Recommended)
- Double-click the **"Anti-Malicious Defender"** icon on your desktop
- The icon will show the `antiLogo.ico` logo

### Method 2: Command Line with --gui flag
```powershell
.\anti_malicious.exe --gui
```

### Method 3: From Start Menu
- Press Windows key
- Type "Anti-Malicious Defender"
- Click the shortcut

---

## 🔄 Subsequent Runs

When you run `anti_malicious.exe` again (without --gui flag):
- It runs silently in the background
- No setup steps (already installed)
- Provides continuous protection

---

## 📋 Command-Line Options

```powershell
# Show help
.\anti_malicious.exe --help

# Open GUI
.\anti_malicious.exe --gui

# Run in background (default)
.\anti_malicious.exe --background

# Quick scan (CLI mode)
.\anti_malicious.exe --scan

# Install service + create shortcuts
.\anti_malicious.exe --install

# Uninstall service + remove shortcuts
.\anti_malicious.exe --uninstall
```

---

## 🛡️ How It Works

### Background Service Mode (Default)
When you run the exe without arguments:
- Runs silently in background (no console window)
- Scans every 5 minutes for threats
- Monitors:
  - Browser data theft attempts
  - Discord token theft
  - Ransomware encryption
  - Registry persistence
  - USB autorun threats
  - Network spreading

### GUI Mode (--gui flag)
- Opens interactive graphical interface
- Real-time protection status
- Manual scan controls
- Threat detection log
- One-click threat removal

---

## 📁 Files Created

On first run, the executable creates:

```
Desktop/
  └── Anti-Malicious Defender.lnk  (Desktop shortcut with icon)

Start Menu/
  └── Anti-Malicious Defender.lnk  (Start menu shortcut with icon)

%USERPROFILE%/.anti_malicious/
  ├── .installed                    (Installation marker)
  └── service.log                   (Background service logs)

%APPDATA%/Microsoft/Windows/Start Menu/Programs/
  └── Anti-Malicious Defender.lnk  (Start menu entry)

Registry:
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    └── AntiMaliciousDefender        (Startup entry)
```

---

## 🧪 Testing Flow

### Test 1: First Run (Background Service)
```powershell
# Remove previous installation
Remove-Item "$env:USERPROFILE\.anti_malicious\.installed" -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Desktop\Anti-Malicious Defender.lnk" -ErrorAction SilentlyContinue

# Run exe
.\anti_malicious.exe

# Verify shortcut created
Test-Path "$env:USERPROFILE\Desktop\Anti-Malicious Defender.lnk"

# Verify process running
Get-Process anti_malicious
```

### Test 2: Open GUI via Shortcut
```powershell
# Launch GUI
Start-Process "$env:USERPROFILE\Desktop\Anti-Malicious Defender.lnk"
```

### Test 3: Direct GUI Launch
```powershell
.\anti_malicious.exe --gui
```

---

## 🔧 Uninstallation

To completely remove the defender:

```powershell
.\anti_malicious.exe --uninstall
```

This will:
- Remove scheduled task
- Remove startup registry entry
- Remove desktop shortcut
- Remove Start Menu shortcut

---

## 🎨 Icon Information

- **Icon file**: `antiLogo.ico`
- **Format**: Windows ICO (256x256, 128x128, 64x64, 48x48, 32x32, 16x16)
- **Location**: Same directory as `anti_malicious.exe`
- **Usage**: 
  - Executable icon
  - Desktop shortcut icon
  - Start Menu shortcut icon

---

## 🐛 Troubleshooting

### Shortcut not created
- Ensure `antiLogo.ico` is in the same folder as the exe
- Run with administrator privileges
- Check `%USERPROFILE%\.anti_malicious\service.log` for errors

### Process not running in background
- Check Task Manager for `anti_malicious.exe`
- Check startup registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

### GUI not opening
- Run: `.\anti_malicious.exe --gui`
- Check if tkinter is included (should be bundled in exe)

---

## ✅ Success Indicators

After first run, you should see:
- ✅ Desktop shortcut with logo icon exists
- ✅ Process running in Task Manager
- ✅ Registry entry in Windows startup
- ✅ No error messages in console

---

## 📊 File Size

- **anti_malicious.exe**: ~17 MB
- **antiLogo.ico**: ~100 KB
- Includes all dependencies (Python, tkinter, psutil, PIL, etc.)

---

## 🔐 Security Notes

- Runs with current user privileges (no elevation needed)
- Background service monitors system continuously
- Logs stored in `%USERPROFILE%\.anti_malicious\`
- Quarantined files stored in `.\quarantine\`

---

## 🎓 Educational Purpose

**WARNING**: This software is for EDUCATIONAL and RESEARCH purposes only.
- Demonstrates anti-malware techniques
- Protects against `Photoshop_Setup.py` malware
- G2 Team 4 - Cyber Project T1Y3

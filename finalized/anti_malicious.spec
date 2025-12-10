# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for Anti-Malicious Defender
# Builds a Windows executable with icon support

block_cipher = None

a = Analysis(
    ['anti_malicious.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('antiLogo.ico', '.'),  # Include the icon file in the bundle
        ('antiLogo.png', '.'),  # Include PNG as backup
    ],
    hiddenimports=['tkinter', 'tkinter.ttk', 'tkinter.messagebox', 'tkinter.scrolledtext', 'tkinter.filedialog'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='anti_malicious',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window - runs silently in background
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='antiLogo.ico',  # Set the executable icon
)

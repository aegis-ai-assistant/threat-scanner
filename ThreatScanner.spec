# -*- mode: python ; coding: utf-8 -*-
# Windows PyInstaller spec. Used by Wine and Docker cross-compilers on Linux.
# Equivalent CLI flags: --onefile --noconsole --name ThreatScanner --add-data "config.example.json;."

from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [("config.example.json", ".")]
binaries = []
hiddenimports = collect_submodules("aegis") + [
    "tkinter",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "tkinter.ttk",
    "py7zr",
    "rarfile",
]

for package in ("py7zr", "rarfile", "tkinter"):
    try:
        pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
        datas += pkg_datas
        binaries += pkg_binaries
        hiddenimports += pkg_hidden
    except Exception:
        pass

a = Analysis(
    ["threat_scanner.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[".venv", "venv"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ThreatScanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

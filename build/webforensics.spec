# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for WebForensics.

Produces a single-folder distribution (``--onedir``) rather than a single
file because PyQt5 + pytsk3 + pyewf push the binary north of 100 MB and the
folder layout starts up noticeably faster.

Run from the project root::

    pyinstaller build/webforensics.spec --noconfirm
"""

import os, sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Spec lives at <project>/build/webforensics.spec — but PyInstaller runs it
# from CWD, so we resolve everything relative to the spec file itself.
SPEC_DIR    = os.path.dirname(os.path.abspath(SPEC))  # noqa: F821 — set by PyInstaller
PROJECT_DIR = os.path.normpath(os.path.join(SPEC_DIR, ".."))
sys.path.insert(0, PROJECT_DIR)

block_cipher = None

hidden = []
hidden += collect_submodules("PyQt5")
hidden += collect_submodules("Crypto")
# Our own top-level packages — listed explicitly so PyInstaller's static
# analyser keeps them, even though main.py imports them statically.
for pkg in ("ui", "data", "browsers", "exporters", "forensics", "utils"):
    hidden += collect_submodules(pkg)
# pytsk3 / pyewf are imported lazily inside ``forensics`` — make sure they
# get bundled even though PyInstaller won't see static imports.
hidden += ["pytsk3", "pyewf"]

datas = []
datas += collect_data_files("PyQt5", subdir="Qt5/plugins")

a = Analysis(
    [os.path.join(PROJECT_DIR, "main.py")],
    pathex=[PROJECT_DIR],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # Trim things we never use; keeps the dist folder under control.
        "tkinter",
        "test",
        "unittest",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WebForensics",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # drop a build/icon.ico in here once you have one
    # Embed a requireAdministrator manifest so double-clicking the .exe
    # always triggers UAC. Needed for manage-bde, Arsenal Image Mounter,
    # OSFMount and vssadmin paths inside the app.
    uac_admin=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="WebForensics",
)

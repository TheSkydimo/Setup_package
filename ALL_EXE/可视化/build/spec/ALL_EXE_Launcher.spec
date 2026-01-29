# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules('selenium')
hiddenimports += collect_submodules('webdriver_manager')


a = Analysis(
    ['C:\\Users\\Skydimo\\Desktop\\Setup_package\\ALL_EXE\\可视化\\launcher_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\Skydimo\\Desktop\\Setup_package\\ALL_EXE\\可视化\\assets\\Unified.iss', 'assets'), ('C:\\Users\\Skydimo\\Desktop\\Setup_package\\ALL_EXE\\360_auto_upload.py', 'assets')],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='ALL_EXE_Launcher',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

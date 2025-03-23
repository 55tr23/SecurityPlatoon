# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['gui.py'],
    pathex=[],
    binaries=[],
    datas=[('agents', 'agents'), ('.env.example', '.')],
    hiddenimports=['pydantic.deprecated.decorator', 'pydantic_core', 'pydantic_migration', 'pydantic_internal_validators', 'langchain_core', 'langchain_core.tools', 'langchain_core.tools.base', 'langgraph.prebuilt', 'langgraph.prebuilt.chat_agent_executor', 'langgraph.graph', 'langgraph.prebuilt.tool_executor'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CybersecuritySystem',
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
    icon=['icon.ico'],
)

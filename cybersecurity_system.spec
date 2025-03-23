# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('agents', 'agents'),  # Include the agents directory
        ('.env.example', '.'),  # Include the example environment file
    ],
    hiddenimports=[
        'langgraph',
        'langchain',
        'langchain_openai',
        'rich',
        'pydantic',
        'pydantic.deprecated.decorator',
        'pydantic_core',
        'pydantic_migration',
        'pydantic_internal_validators',
        'asyncio',
        'tkinter',
        'json',
        'threading',
        'PIL',
        'PIL._tkinter_finder',
        'dotenv',
        'requests',
        'bs4',
        'rich.console',
        'rich.text',
        'rich.panel',
        'rich.table',
        'langchain_core',
        'langchain_core.tools',
        'langchain_core.tools.base',
        'langgraph.prebuilt',
        'langgraph.prebuilt.chat_agent_executor',
        'langgraph.graph',
        'langgraph.prebuilt.tool_executor'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Add additional data files
a.datas += [
    ('langgraph', 'langgraph'),
    ('langchain', 'langchain'),
    ('langchain_core', 'langchain_core'),
    ('pydantic', 'pydantic'),
    ('pydantic_core', 'pydantic_core'),
]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CybersecuritySystem',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Changed to True for debugging
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico'  # You'll need to add an icon file
) 
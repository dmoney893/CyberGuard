# Build on macOS: .venv-agent/bin/python -m PyInstaller --distpath dist/mac --workpath build/mac CyberGuardAgent-mac.spec
from PyInstaller.utils.hooks import collect_submodules
from pathlib import Path
import os

clamav = Path(os.environ['CYBERGUARD_CLAMAV_STAGE'])
engine_binaries = [(str(p), 'clamav/bin') for p in (clamav / 'bin').iterdir()]
engine_binaries += [(str(p), 'clamav/lib') for p in (clamav / 'lib').iterdir()]

a = Analysis(
    ['src/local_scanner/cyberguard_agent.py'],
    pathex=['src/local_scanner'],
    binaries=engine_binaries,
    datas=[(str(clamav / 'seed'), 'clamav/seed'), (str(clamav / 'licenses'), 'clamav/licenses'), (str(clamav / 'certs'), 'clamav/certs')],
    hiddenimports=collect_submodules('uvicorn'),
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name='CyberGuardAgent',
    console=False,
    argv_emulation=False,
    target_arch='arm64',
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(exe, a.binaries, a.datas, name='CyberGuardAgent')
app = BUNDLE(
    coll,
    name='CyberGuard Agent.app',
    bundle_identifier='com.cyberguard.agent',
    info_plist={
        'CFBundleShortVersionString': '1.2.0',
        'CFBundleVersion': '1.2.0',
        'NSHighResolutionCapable': True,
    },
)

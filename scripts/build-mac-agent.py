"""Build an Apple Silicon test app and stage its ZIP for the website."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
import runpy

root = Path(__file__).resolve().parents[1]
if sys.platform != "darwin":
    raise SystemExit("Build the Mac app on macOS with a Tk-enabled Python.")

def run(*args):
    subprocess.run(args, cwd=root, check=True)

with tempfile.TemporaryDirectory(prefix="cyberguard-mac-") as temporary:
    stage = Path(temporary)
    runtime = runpy.run_path(str(root / 'scripts' / 'prepare-mac-clamav.py'))['prepare']()
    os.environ['CYBERGUARD_CLAMAV_STAGE'] = str(runtime)
    os.environ["PYINSTALLER_CONFIG_DIR"] = str(stage / "cache")
    run(sys.executable, "-m", "PyInstaller", "--noconfirm",
        "--distpath", str(stage / "dist"), "--workpath", str(stage / "build"),
        "CyberGuardAgent-mac.spec")
    app = stage / "dist" / "CyberGuard Agent.app"
    # Build outside Desktop/iCloud to avoid Finder metadata invalidating signatures.
    run("xattr", "-cr", str(app))
    run("codesign", "--force", "--deep", "--sign", "-", str(app))
    run("codesign", "--verify", "--deep", "--strict", str(app))
    output = root / "dist" / "mac"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "CyberGuard-Agent-mac-arm64.zip"
    package = stage / "CyberGuard Mac"
    package.mkdir()
    run("ditto", "--norsrc", str(app), str(package / app.name))
    shutil.copyfile(root / "installer" / "Mac-Testing-Instructions.txt", package / "Read Me.txt")
    shutil.copyfile(root / "build" / "clamav" / "clamav-1.5.5.tar.gz", package / "ClamAV-1.5.5-source.tar.gz")
    run("ditto", "-c", "-k", "--norsrc", "--keepParent", str(package), str(archive))
    run("ditto", "--norsrc", str(app), str(output / app.name))
    if archive.stat().st_size < 95 * 1024 * 1024:
        downloads = root / "public" / "downloads"
        downloads.mkdir(parents=True, exist_ok=True)
        run("ditto", str(archive), str(downloads / archive.name))
    else:
        print("Full scanner archive exceeds GitHub's per-file limit. Upload as a GitHub Release asset, not a Git commit.")
    print(f"Created {archive}\nTest build only; not notarized.")

"""Build an Apple Silicon test app and stage its ZIP for the website."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil

root = Path(__file__).resolve().parents[1]
if sys.platform != "darwin":
    raise SystemExit("Build the Mac app on macOS with a Tk-enabled Python.")

def run(*args):
    subprocess.run(args, cwd=root, check=True)

with tempfile.TemporaryDirectory(prefix="cyberguard-mac-") as temporary:
    stage = Path(temporary)
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
    run("ditto", "-c", "-k", "--norsrc", "--keepParent", str(package), str(archive))
    run("ditto", "--norsrc", str(app), str(output / app.name))
    downloads = root / "public" / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    run("ditto", str(archive), str(downloads / archive.name))
    print(f"Created {archive}\nStaged website download. Test build only; not notarized.")

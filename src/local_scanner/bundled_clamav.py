"""Private, per-user ClamAV runtime for the packaged Mac agent."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

_lock = threading.Lock()
_started = False
_status = {"ready": False, "message": "Preparing malware scanner…"}


def bundle_root():
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    root = base / "clamav"
    return root if (root / "bin" / "clamscan").is_file() else None


def data_root():
    return Path.home() / "Library" / "Application Support" / "CyberGuard" / "ClamAV"


def process_environment():
    env = dict(os.environ)
    root = bundle_root()
    if root:
        env["CVD_CERTS_DIR"] = str(root / "certs")
    return env


def status():
    with _lock:
        return dict(_status)


def _set(**values):
    with _lock:
        _status.update(values)


def prepare():
    root = bundle_root()
    if root is None:
        return None
    directory = data_root()
    directory.mkdir(parents=True, exist_ok=True)
    # Serialize first-launch copies and updater runs across multiple app windows.
    import fcntl
    with (directory / "runtime.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        database = directory / "db"
        database.mkdir(exist_ok=True)
        for source in (root / "seed").iterdir():
            if source.suffix not in (".cvd", ".cld", ".sign"):
                continue
            target = database / source.name
            # FreshClam may convert CVD to CLD; never replace newer user definitions.
            if (database / (source.stem + ".cvd")).exists() or (database / (source.stem + ".cld")).exists():
                continue
            if not target.exists():
                temporary = directory / (source.name + ".tmp")
                shutil.copyfile(source, temporary)
                os.replace(temporary, target)
        if not any(database.glob("main.*")) or not any(database.glob("daily.*")):
            raise RuntimeError("The app's malware definitions are incomplete. Download the latest CyberGuard Agent.")
    _set(ready=True, message="Malware scanner ready")
    return root / "bin" / "clamscan", database


def _update():
    try:
        paths = prepare()
        if not paths:
            return
        root = bundle_root()
        directory = data_root()
        import fcntl
        with (directory / "runtime.lock").open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            stamp = directory / "last-update-attempt.json"
            try:
                last = json.loads(stamp.read_text())["time"]
            except (OSError, ValueError, KeyError):
                last = 0
            if time.time() - last < 6 * 60 * 60:
                return
            stamp.write_text(json.dumps({"time": time.time()}))
            config = directory / "freshclam.conf"
            config.write_text(
                f'DatabaseDirectory "{paths[1]}"\n'
                f'CVDCertsDirectory "{root / "certs"}"\n'
                "DatabaseMirror database.clamav.net\n"
                "DNSDatabaseInfo current.cvd.clamav.net\n"
                "ConnectTimeout 15\nReceiveTimeout 60\nMaxAttempts 2\n"
                "ScriptedUpdates yes\nTestDatabases yes\n"
            )
            result = subprocess.run(
                [str(root / "bin" / "freshclam"), f"--config-file={config}", "--stdout"],
                capture_output=True, text=True, timeout=300, env=process_environment(),
            )
            (directory / "update.log").write_text((result.stdout + result.stderr)[-12000:])
            if result.returncode:
                _set(message="Scanner ready; definition update unavailable. Will retry automatically.")
            else:
                _set(message="Malware scanner ready — definitions updated")
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        _set(message=f"Malware scanner: {exc}")


def start():
    global _started
    if bundle_root() is None:
        return
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_update, daemon=True).start()

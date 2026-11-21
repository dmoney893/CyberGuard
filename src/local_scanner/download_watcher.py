"""Poll the user's Downloads folder for new or changed files.

Uses only the Python stdlib plus existing project modules. Permission
errors are swallowed so a missing or locked Downloads folder never
affects the rest of the scanner.
"""

from __future__ import annotations

import logging
import os
import plistlib
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from event_store import hash_file, record_file_downloaded

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 3.0
INCOMPLETE_SUFFIXES = (
    ".crdownload",
    ".part",
    ".partial",
    ".download",
    ".tmp",
    ".temp",
)
INCOMPLETE_PREFIXES = (".com.google.Chrome", ".com.apple.Safari", "~$")

_stop = threading.Event()
_thread: Optional[threading.Thread] = None
_seen: dict[str, tuple[float, int]] = {}
_recorded: set[str] = set()


def downloads_dir() -> Path:
    return Path.home() / "Downloads"


def _is_incomplete(path: Path) -> bool:
    name = path.name
    lower = name.lower()

    if any(lower.endswith(suffix) for suffix in INCOMPLETE_SUFFIXES):
        return True

    if any(name.startswith(prefix) for prefix in INCOMPLETE_PREFIXES):
        return True

    return False


def _read_macos_where_froms(path: Path) -> list[str]:
    urls: list[str] = []

    try:
        result = subprocess.run(
            [
                "xattr",
                "-px",
                "com.apple.metadata:kMDItemWhereFroms",
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            hex_text = re.sub(r"\s+", "", result.stdout)
            raw = bytes.fromhex(hex_text)
            parsed = plistlib.loads(raw)
            urls.extend(_coerce_url_list(parsed))
    except Exception:
        logger.debug("xattr where-froms failed for %s", path, exc_info=True)

    if urls:
        return urls

    try:
        result = subprocess.run(
            ["mdls", "-raw", "-name", "kMDItemWhereFroms", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            urls.extend(_parse_mdls_where_froms(result.stdout))
    except Exception:
        logger.debug("mdls where-froms failed for %s", path, exc_info=True)

    return urls


def _coerce_url_list(value) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        text = value.strip()
        return [text] if text.startswith(("http://", "https://")) else []

    if isinstance(value, (list, tuple)):
        found = []
        for item in value:
            found.extend(_coerce_url_list(item))
        return found

    return []


def _parse_mdls_where_froms(stdout: str) -> list[str]:
    text = (stdout or "").strip()
    if not text or text == "(null)":
        return []

    urls = re.findall(r'https?://[^\s",]+', text)
    return urls


def _read_windows_zone_identifier(path: Path) -> list[str]:
    urls: list[str] = []
    ads_path = f"{path}:Zone.Identifier"

    try:
        with open(ads_path, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
    except OSError:
        return []

    host_url = None
    referrer_url = None

    for line in content.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "hosturl":
            host_url = value
        elif key == "referrerurl":
            referrer_url = value

    for candidate in (host_url, referrer_url):
        if candidate and candidate.startswith(("http://", "https://")):
            urls.append(candidate)

    return urls


def read_download_source_urls(path: Path) -> list[str]:
    try:
        if os.name == "nt":
            return _read_windows_zone_identifier(path)

        # Prefer macOS metadata APIs on Darwin (and typical mac home layouts).
        is_darwin = False
        try:
            import platform

            is_darwin = platform.system() == "Darwin"
        except Exception:
            is_darwin = Path.home().joinpath("Library").is_dir()

        if is_darwin:
            return _read_macos_where_froms(path)
    except Exception:
        logger.debug("source URL lookup failed for %s", path, exc_info=True)

    return []


def _observe_file(path: Path) -> None:
    try:
        if not path.is_file() or _is_incomplete(path):
            return

        stat = path.stat()
        key = str(path.resolve())
        signature = (float(stat.st_mtime), int(stat.st_size))

        previous = _seen.get(key)

        # Require one stable poll interval before hashing / emitting.
        if previous is None or previous != signature:
            _seen[key] = signature
            _recorded.discard(key)
            return

        if key in _recorded:
            return

        sha256 = hash_file(path)
        if not sha256:
            # Too large or unreadable — don't retry every poll.
            _recorded.add(key)
            return

        source_urls = read_download_source_urls(path)
        record_file_downloaded(
            path=str(path),
            sha256=sha256,
            source_urls=source_urls,
            ts=stat.st_mtime,
            size=stat.st_size,
        )
        _recorded.add(key)
    except (OSError, PermissionError):
        return
    except Exception:
        logger.exception("download observe failed for %s", path)


def _scan_once(directory: Path) -> None:
    try:
        if not directory.is_dir():
            return

        for entry in directory.iterdir():
            if entry.is_file():
                _observe_file(entry)
    except (OSError, PermissionError):
        return
    except Exception:
        logger.exception("Downloads scan failed")


def _run_loop() -> None:
    directory = downloads_dir()
    logger.info("Downloads watcher started for %s", directory)

    # Prime so existing Downloads are not emitted as new on startup.
    # Files that later change mtime/size will be observed normally.
    try:
        if directory.is_dir():
            for entry in directory.iterdir():
                try:
                    if entry.is_file() and not _is_incomplete(entry):
                        key = str(entry.resolve())
                        stat = entry.stat()
                        _seen[key] = (
                            float(stat.st_mtime),
                            int(stat.st_size),
                        )
                        _recorded.add(key)
                except (OSError, PermissionError):
                    continue
    except Exception:
        logger.debug("Downloads prime failed", exc_info=True)

    while not _stop.is_set():
        _scan_once(directory)
        _stop.wait(POLL_INTERVAL_SECONDS)


def start_download_watcher() -> bool:
    """Start the background Downloads poller. Idempotent and fail-silent."""

    global _thread

    try:
        if _thread is not None and _thread.is_alive():
            return True

        _stop.clear()
        _thread = threading.Thread(
            target=_run_loop,
            name="cyberguard-download-watcher",
            daemon=True,
        )
        _thread.start()
        return True
    except Exception:
        logger.exception("Failed to start Downloads watcher")
        return False


def stop_download_watcher() -> None:
    global _thread

    _stop.set()
    thread = _thread
    if thread is not None and thread.is_alive():
        thread.join(timeout=2)
    _thread = None

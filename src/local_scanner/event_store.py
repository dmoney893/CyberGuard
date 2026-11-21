"""Local SQLite event store for CyberGuard incident correlation.

Device-local only. Failures are logged and never raised to callers.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

RETENTION_SECONDS = 30 * 24 * 60 * 60
MAX_HASH_BYTES = 200 * 1024 * 1024
CMDLINE_MAX_CHARS = 500

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None
_db_path: Optional[Path] = None
_hash_cache: dict[tuple[str, float], Optional[str]] = {}
_seen_ips: set[str] = set()
_seen_process_ips: set[tuple[str, str]] = set()
_initialized = False


def app_data_dir() -> Path:
    system = os.name
    if system == "nt":
        base = os.environ.get("APPDATA") or str(
            Path.home() / "AppData" / "Roaming"
        )
        return Path(base) / "CyberGuard"

    if Path.home().joinpath("Library").is_dir():
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "CyberGuard"
        )

    return Path.home() / ".cyberguard"


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path),
        check_same_thread=False,
        timeout=30,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            ts REAL NOT NULL,
            source TEXT NOT NULL,
            type TEXT NOT NULL,
            risk REAL NOT NULL DEFAULT 0,
            payload TEXT NOT NULL DEFAULT '{}',
            entities TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS entities (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            label TEXT NOT NULL,
            base_risk REAL NOT NULL DEFAULT 0,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            attrs TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS edges (
            src TEXT NOT NULL,
            dst TEXT NOT NULL,
            kind TEXT NOT NULL,
            ts REAL NOT NULL,
            event_id TEXT,
            PRIMARY KEY (src, dst, kind)
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            severity TEXT NOT NULL,
            score REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'open',
            title TEXT NOT NULL,
            node_ids TEXT NOT NULL DEFAULT '[]',
            rule_hits TEXT NOT NULL DEFAULT '[]',
            storyline TEXT NOT NULL DEFAULT '[]'
        );

        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_edges_ts ON edges(ts);
        CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind);
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        """
    )
    conn.commit()


def init_store(db_path: Optional[Path] = None) -> bool:
    """Open (or create) the SQLite database. Safe to call multiple times."""

    global _conn, _db_path, _initialized, _seen_ips, _seen_process_ips

    with _lock:
        if _initialized and _conn is not None:
            return True

        try:
            path = Path(db_path) if db_path else app_data_dir() / "events.db"
            conn = _connect(path)
            _ensure_schema(conn)
            _conn = conn
            _db_path = path
            _load_seen_network_state(conn)
            prune_old(conn=conn, commit=True)
            _initialized = True
            logger.info("CyberGuard event store ready at %s", path)
            return True
        except Exception:
            logger.exception("Failed to initialize event store")
            _conn = None
            _initialized = False
            return False


def _load_seen_network_state(conn: sqlite3.Connection) -> None:
    global _seen_ips, _seen_process_ips

    _seen_ips = set()
    _seen_process_ips = set()

    try:
        rows = conn.execute(
            "SELECT id FROM entities WHERE kind = 'ip'"
        ).fetchall()
        _seen_ips = {row["id"].removeprefix("ip:") for row in rows}

        edge_rows = conn.execute(
            """
            SELECT src, dst FROM edges
            WHERE kind = 'connected_to'
              AND src LIKE 'process:%'
              AND dst LIKE 'ip:%'
            """
        ).fetchall()
        _seen_process_ips = {
            (row["src"], row["dst"].removeprefix("ip:"))
            for row in edge_rows
        }
    except Exception:
        logger.exception("Failed to load network seen-state")


def _get_conn() -> Optional[sqlite3.Connection]:
    if _conn is None and not _initialized:
        init_store()
    return _conn


def _json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)


def _json_loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


# ---------------------------------------------------------------------------
# Entity id helpers
# ---------------------------------------------------------------------------

def normalize_domain(host: str) -> str:
    host = (host or "").strip().lower()
    if host.startswith("www."):
        host = host[4:]
    return host.rstrip(".")


def normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""

    try:
        parsed = urlparse(raw)
    except Exception:
        return raw.lower()

    scheme = (parsed.scheme or "https").lower()
    netloc = normalize_domain(parsed.netloc or parsed.path.split("/")[0])
    path = parsed.path if parsed.netloc else "/"
    if not path:
        path = "/"

    # Drop fragment; keep query (can distinguish tracking links).
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


def domain_entity_id(host: str) -> str:
    return f"domain:{normalize_domain(host)}"


def url_entity_id(url: str) -> str:
    return f"url:{normalize_url(url)}"


def file_entity_id(sha256: str) -> str:
    return f"file:{(sha256 or '').lower()}"


def process_entity_id(pid: Any, create_time: Any) -> str:
    return f"process:{pid}:{create_time}"


def ip_entity_id(address: str) -> str:
    return f"ip:{(address or '').strip()}"


def email_entity_id(
    message_id: Optional[str] = None,
    *,
    sender: str = "",
    subject: str = "",
    ts: Optional[float] = None,
) -> str:
    if message_id:
        return f"email:{message_id.strip()}"

    material = f"{sender}|{subject}|{ts or 0}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
    return f"email:{digest}"


def is_private_or_loopback(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def hash_file(path: str | Path, *, max_bytes: int = MAX_HASH_BYTES) -> Optional[str]:
    """SHA-256 a file. Returns None if missing, too large, or unreadable."""

    try:
        file_path = Path(path)
        if not file_path.is_file():
            return None

        size = file_path.stat().st_size
        if size > max_bytes:
            return None

        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError, ValueError):
        return None


def hash_executable(path: Optional[str]) -> Optional[str]:
    """Hash an executable once per path+mtime (skip files > 200 MB)."""

    if not path:
        return None

    try:
        file_path = Path(path)
        stat = file_path.stat()
        cache_key = (str(file_path), float(stat.st_mtime))
    except (OSError, PermissionError, ValueError, TypeError):
        return None

    with _lock:
        if cache_key in _hash_cache:
            return _hash_cache[cache_key]

    digest = hash_file(file_path)
    with _lock:
        _hash_cache[cache_key] = digest
        # Bound cache growth roughly.
        if len(_hash_cache) > 2048:
            for key in list(_hash_cache)[:512]:
                _hash_cache.pop(key, None)

    return digest


def truncate_cmdline(cmdline: Any) -> Optional[str]:
    if cmdline is None:
        return None

    if isinstance(cmdline, (list, tuple)):
        text = " ".join(str(part) for part in cmdline)
    else:
        text = str(cmdline)

    text = text.strip()
    if not text:
        return None

    if len(text) > CMDLINE_MAX_CHARS:
        return text[: CMDLINE_MAX_CHARS - 1] + "…"
    return text


# ---------------------------------------------------------------------------
# Write API
# ---------------------------------------------------------------------------

def upsert_entity(
    entity_id: str,
    kind: str,
    label: str,
    *,
    base_risk: float = 0.0,
    ts: Optional[float] = None,
    attrs: Optional[dict] = None,
    conn: Optional[sqlite3.Connection] = None,
    commit: bool = True,
) -> None:
    if not entity_id:
        return

    own_conn = conn is None
    connection = conn or _get_conn()
    if connection is None:
        return

    now = float(ts if ts is not None else time.time())
    attrs = attrs or {}

    try:
        with _lock if own_conn else _nullcontext():
            existing = connection.execute(
                "SELECT base_risk, first_seen, attrs FROM entities WHERE id = ?",
                (entity_id,),
            ).fetchone()

            if existing is None:
                connection.execute(
                    """
                    INSERT INTO entities
                        (id, kind, label, base_risk, first_seen, last_seen, attrs)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entity_id,
                        kind,
                        label or entity_id,
                        float(base_risk),
                        now,
                        now,
                        _json_dumps(attrs),
                    ),
                )
            else:
                merged_attrs = _json_loads(existing["attrs"], {})
                if isinstance(merged_attrs, dict):
                    merged_attrs.update(attrs)
                else:
                    merged_attrs = attrs

                connection.execute(
                    """
                    UPDATE entities
                    SET label = ?,
                        base_risk = MAX(base_risk, ?),
                        last_seen = MAX(last_seen, ?),
                        attrs = ?
                    WHERE id = ?
                    """,
                    (
                        label or entity_id,
                        float(base_risk),
                        now,
                        _json_dumps(merged_attrs),
                        entity_id,
                    ),
                )

            if commit and own_conn:
                connection.commit()
    except Exception:
        logger.exception("upsert_entity failed for %s", entity_id)
        if own_conn and connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass


def upsert_edge(
    src: str,
    dst: str,
    kind: str,
    *,
    ts: Optional[float] = None,
    event_id: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None,
    commit: bool = True,
) -> None:
    if not src or not dst or not kind:
        return

    own_conn = conn is None
    connection = conn or _get_conn()
    if connection is None:
        return

    now = float(ts if ts is not None else time.time())

    try:
        with _lock if own_conn else _nullcontext():
            connection.execute(
                """
                INSERT INTO edges (src, dst, kind, ts, event_id)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(src, dst, kind) DO UPDATE SET
                    ts = excluded.ts,
                    event_id = COALESCE(excluded.event_id, edges.event_id)
                """,
                (src, dst, kind, now, event_id),
            )
            if commit and own_conn:
                connection.commit()
    except Exception:
        logger.exception("upsert_edge failed for %s -[%s]-> %s", src, kind, dst)
        if own_conn and connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass


def record_event(
    *,
    event_id: str,
    source: str,
    event_type: str,
    risk: float = 0.0,
    ts: Optional[float] = None,
    payload: Optional[dict] = None,
    entities: Optional[list[str]] = None,
    entity_rows: Optional[Iterable[dict]] = None,
    edges: Optional[Iterable[dict]] = None,
) -> bool:
    """Insert an event and optional related entities/edges. Dedupes by id."""

    connection = _get_conn()
    if connection is None or not event_id:
        return False

    now = float(ts if ts is not None else time.time())
    payload = payload or {}
    entities = list(entities or [])

    try:
        with _lock:
            existing = connection.execute(
                "SELECT id FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()
            if existing is not None:
                return False

            for row in entity_rows or []:
                upsert_entity(
                    row["id"],
                    row.get("kind") or "unknown",
                    row.get("label") or row["id"],
                    base_risk=float(row.get("base_risk") or 0),
                    ts=now,
                    attrs=row.get("attrs") or {},
                    conn=connection,
                    commit=False,
                )
                if row["id"] not in entities:
                    entities.append(row["id"])

            connection.execute(
                """
                INSERT INTO events (id, ts, source, type, risk, payload, entities)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    now,
                    source,
                    event_type,
                    float(risk),
                    _json_dumps(payload),
                    _json_dumps(entities),
                ),
            )

            for edge in edges or []:
                upsert_edge(
                    edge["src"],
                    edge["dst"],
                    edge["kind"],
                    ts=now,
                    event_id=event_id,
                    conn=connection,
                    commit=False,
                )

            connection.commit()
        return True
    except Exception:
        logger.exception("record_event failed for %s", event_id)
        try:
            connection.rollback()
        except Exception:
            pass
        return False


def prune_old(
    *,
    older_than_seconds: float = RETENTION_SECONDS,
    conn: Optional[sqlite3.Connection] = None,
    commit: bool = True,
) -> None:
    connection = conn or _get_conn()
    if connection is None:
        return

    cutoff = time.time() - older_than_seconds

    try:
        own = conn is None
        with _lock if own else _nullcontext():
            connection.execute(
                "DELETE FROM events WHERE ts < ?",
                (cutoff,),
            )
            connection.execute(
                "DELETE FROM edges WHERE ts < ?",
                (cutoff,),
            )
            # Drop entities not touched recently and not on any remaining edge.
            connection.execute(
                """
                DELETE FROM entities
                WHERE last_seen < ?
                  AND id NOT IN (SELECT src FROM edges)
                  AND id NOT IN (SELECT dst FROM edges)
                """,
                (cutoff,),
            )
            if commit:
                connection.commit()
    except Exception:
        logger.exception("prune_old failed")
        try:
            connection.rollback()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Domain helpers used by timeline / network / downloads
# ---------------------------------------------------------------------------

def record_process_event(
    *,
    event_type: str,
    severity: str,
    message: str,
    process: Optional[dict],
    ts: Optional[float] = None,
    timeline_id: Optional[Any] = None,
) -> None:
    """Persist a process-timeline event. Never raises."""

    try:
        if not init_store() and _get_conn() is None:
            return

        now = float(ts if ts is not None else time.time())
        process = process or {}
        pid = process.get("pid")
        create_time = process.get("create_time")

        if pid is None or create_time is None:
            # Still record monitoring_started-style events without a process.
            record_event(
                event_id=f"local:{event_type}:{timeline_id or now}",
                source="process",
                event_type=event_type,
                risk=_severity_to_risk(severity),
                ts=now,
                payload={
                    "message": message,
                    "severity": severity,
                    "timeline_id": timeline_id,
                },
                entities=[],
            )
            return

        proc_id = process_entity_id(pid, create_time)
        exe = process.get("executable") or process.get("exe")
        cmdline = truncate_cmdline(
            process.get("cmdline") or process.get("command_line")
        )
        name = process.get("name") or f"PID {pid}"
        ppid = process.get("parent_pid") or process.get("ppid")
        parent_create_time = process.get("parent_create_time")
        sha256 = hash_executable(exe) if event_type == "process_started" else None

        attrs = {
            "pid": pid,
            "ppid": ppid,
            "exe": exe,
            "cmdline": cmdline,
            "create_time": create_time,
            "name": name,
        }
        if sha256:
            attrs["sha256"] = sha256

        entity_rows = [
            {
                "id": proc_id,
                "kind": "process",
                "label": name,
                "base_risk": _severity_to_risk(severity),
                "attrs": attrs,
            }
        ]
        edges = []
        entity_ids = [proc_id]

        if event_type == "process_started" and ppid not in (None, 0):
            parent_id = None
            if parent_create_time is not None:
                parent_id = process_entity_id(ppid, parent_create_time)
                entity_rows.append(
                    {
                        "id": parent_id,
                        "kind": "process",
                        "label": process.get("parent_name") or f"PID {ppid}",
                        "base_risk": 0.0,
                        "attrs": {
                            "pid": ppid,
                            "create_time": parent_create_time,
                            "name": process.get("parent_name"),
                        },
                    }
                )
            else:
                # Best-effort parent node when create_time is unknown.
                parent_id = f"process:{ppid}:unknown"
                entity_rows.append(
                    {
                        "id": parent_id,
                        "kind": "process",
                        "label": process.get("parent_name") or f"PID {ppid}",
                        "base_risk": 0.0,
                        "attrs": {
                            "pid": ppid,
                            "create_time": None,
                            "name": process.get("parent_name"),
                            "unresolved": True,
                        },
                    }
                )

            edges.append(
                {"src": parent_id, "dst": proc_id, "kind": "spawned"}
            )
            entity_ids.append(parent_id)

        if event_type == "process_started" and sha256:
            file_id = file_entity_id(sha256)
            entity_rows.append(
                {
                    "id": file_id,
                    "kind": "file",
                    "label": Path(exe).name if exe else sha256[:12],
                    "base_risk": 0.0,
                    "attrs": {
                        "sha256": sha256,
                        "path": exe,
                    },
                }
            )
            edges.append(
                {"src": file_id, "dst": proc_id, "kind": "ran_as"}
            )
            entity_ids.append(file_id)

        record_event(
            event_id=f"process:{event_type}:{pid}:{create_time}:{timeline_id or now}",
            source="process",
            event_type=event_type,
            risk=_severity_to_risk(severity),
            ts=now,
            payload={
                "message": message,
                "severity": severity,
                "timeline_id": timeline_id,
                "pid": pid,
                "ppid": ppid,
                "exe": exe,
                "cmdline": cmdline,
                "create_time": create_time,
                "sha256": sha256,
                "name": name,
            },
            entities=entity_ids,
            entity_rows=entity_rows,
            edges=edges,
        )
    except Exception:
        logger.exception("record_process_event failed")


def record_connection_first_seen(
    *,
    pid: int,
    create_time: Optional[float],
    process_name: Optional[str],
    remote_ip: str,
    remote_port: Optional[int] = None,
    protocol: Optional[str] = None,
    ts: Optional[float] = None,
) -> bool:
    """Record the first (process, remote_ip) pair. Returns True if new."""

    try:
        if not remote_ip or create_time is None:
            return False

        if not init_store() and _get_conn() is None:
            return False

        now = float(ts if ts is not None else time.time())
        proc_id = process_entity_id(pid, create_time)
        pair = (proc_id, remote_ip)

        with _lock:
            if pair in _seen_process_ips:
                return False
            _seen_process_ips.add(pair)
            first_seen_device = remote_ip not in _seen_ips
            _seen_ips.add(remote_ip)

        private = is_private_or_loopback(remote_ip)
        ip_id = ip_entity_id(remote_ip)

        entity_rows = [
            {
                "id": proc_id,
                "kind": "process",
                "label": process_name or f"PID {pid}",
                "base_risk": 0.0,
                "attrs": {
                    "pid": pid,
                    "create_time": create_time,
                    "name": process_name,
                },
            },
            {
                "id": ip_id,
                "kind": "ip",
                "label": remote_ip,
                "base_risk": 0.0,
                "attrs": {
                    "address": remote_ip,
                    "private": private,
                    "first_seen_device": first_seen_device,
                },
            },
        ]

        record_event(
            event_id=f"net:{proc_id}:{remote_ip}",
            source="network",
            event_type="process_connected",
            risk=0.0,
            ts=now,
            payload={
                "pid": pid,
                "create_time": create_time,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": protocol,
                "private": private,
                "first_seen_device": first_seen_device,
            },
            entities=[proc_id, ip_id],
            entity_rows=entity_rows,
            edges=[
                {"src": proc_id, "dst": ip_id, "kind": "connected_to"},
            ],
        )
        return True
    except Exception:
        logger.exception("record_connection_first_seen failed")
        return False


def record_file_downloaded(
    *,
    path: str,
    sha256: str,
    source_urls: Optional[list[str]] = None,
    ts: Optional[float] = None,
    size: Optional[int] = None,
) -> bool:
    """Persist a Downloads-folder observation. Never raises."""

    try:
        if not sha256 or not path:
            return False

        if not init_store() and _get_conn() is None:
            return False

        now = float(ts if ts is not None else time.time())
        file_id = file_entity_id(sha256)
        name = Path(path).name
        source_urls = [u for u in (source_urls or []) if u]

        entity_rows = [
            {
                "id": file_id,
                "kind": "file",
                "label": name,
                "base_risk": 0.0,
                "attrs": {
                    "sha256": sha256,
                    "path": path,
                    "size": size,
                    "source_urls": source_urls,
                },
            }
        ]
        edges = []
        entity_ids = [file_id]

        for url in source_urls:
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
            except Exception:
                host = ""

            if host:
                domain_id = domain_entity_id(host)
                entity_rows.append(
                    {
                        "id": domain_id,
                        "kind": "domain",
                        "label": normalize_domain(host),
                        "base_risk": 0.0,
                        "attrs": {"host": normalize_domain(host)},
                    }
                )
                edges.append(
                    {"src": domain_id, "dst": file_id, "kind": "served"}
                )
                entity_ids.append(domain_id)

            normalized = normalize_url(url)
            if normalized:
                url_id = url_entity_id(normalized)
                entity_rows.append(
                    {
                        "id": url_id,
                        "kind": "url",
                        "label": normalized,
                        "base_risk": 0.0,
                        "attrs": {"url": normalized},
                    }
                )
                edges.append(
                    {"src": url_id, "dst": file_id, "kind": "served"}
                )
                entity_ids.append(url_id)

        return record_event(
            event_id=f"download:{sha256}:{int(now)}",
            source="download",
            event_type="file_downloaded",
            risk=0.0,
            ts=now,
            payload={
                "path": path,
                "filename": name,
                "sha256": sha256,
                "size": size,
                "source_urls": source_urls,
            },
            entities=entity_ids,
            entity_rows=entity_rows,
            edges=edges,
        )
    except Exception:
        logger.exception("record_file_downloaded failed")
        return False


def _severity_to_risk(severity: str) -> float:
    mapping = {
        "high": 0.8,
        "warning": 0.5,
        "info": 0.05,
        "low": 0.05,
    }
    return mapping.get((severity or "").lower(), 0.05)


def ingest_normalized_event(event: dict) -> bool:
    """Persist one web-app / extension event. Dedupes by event id.

    Expected keys: id, source, type, ts, risk, payload, entities, edges.
    ``entities`` may be a list of ids or dict rows with id/kind/label/...
    """

    try:
        if not init_store() and _get_conn() is None:
            return False

        event_id = str(event.get("id") or "").strip()
        if not event_id:
            return False

        source = str(event.get("source") or "unknown")
        event_type = str(event.get("type") or "unknown")
        ts = float(event.get("ts") if event.get("ts") is not None else time.time())
        risk = max(0.0, min(1.0, float(event.get("risk") or 0)))
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}

        raw_entities = event.get("entities") or []
        entity_rows = []
        entity_ids = []

        for item in raw_entities:
            if isinstance(item, str):
                if item:
                    entity_ids.append(item)
                continue
            if not isinstance(item, dict) or not item.get("id"):
                continue
            entity_rows.append(
                {
                    "id": str(item["id"]),
                    "kind": str(item.get("kind") or "unknown"),
                    "label": str(item.get("label") or item["id"]),
                    "base_risk": float(item.get("base_risk") or 0),
                    "attrs": item.get("attrs")
                    if isinstance(item.get("attrs"), dict)
                    else {},
                }
            )
            entity_ids.append(str(item["id"]))

        edges = []
        for edge in event.get("edges") or []:
            if not isinstance(edge, dict):
                continue
            src = edge.get("src")
            dst = edge.get("dst")
            kind = edge.get("kind")
            if src and dst and kind:
                edges.append(
                    {
                        "src": str(src),
                        "dst": str(dst),
                        "kind": str(kind),
                    }
                )

        return record_event(
            event_id=event_id,
            source=source,
            event_type=event_type,
            risk=risk,
            ts=ts,
            payload=payload,
            entities=entity_ids,
            entity_rows=entity_rows,
            edges=edges,
        )
    except Exception:
        logger.exception("ingest_normalized_event failed")
        return False


def ingest_normalized_batch(events: Iterable[dict]) -> dict:
    """Ingest a batch of normalized events. Returns accepted/duplicate/error counts."""

    accepted = 0
    duplicates = 0
    errors = 0

    for event in events:
        try:
            event_id = str((event or {}).get("id") or "").strip()
            if not event_id:
                errors += 1
                continue

            connection = _get_conn()
            if connection is None:
                if not init_store():
                    errors += 1
                    continue
                connection = _get_conn()

            with _lock:
                exists = connection.execute(
                    "SELECT 1 FROM events WHERE id = ?",
                    (event_id,),
                ).fetchone()

            if exists is not None:
                duplicates += 1
                continue

            if ingest_normalized_event(event):
                accepted += 1
            else:
                # record_event returns False for dupes or failures; re-check.
                with _lock:
                    exists_after = connection.execute(
                        "SELECT 1 FROM events WHERE id = ?",
                        (event_id,),
                    ).fetchone()
                if exists_after is not None:
                    duplicates += 1
                else:
                    errors += 1
        except Exception:
            logger.exception("batch ingest item failed")
            errors += 1

    try:
        prune_old()
    except Exception:
        pass

    return {
        "accepted": accepted,
        "duplicates": duplicates,
        "errors": errors,
    }


def _row_to_entity(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "label": row["label"],
        "base_risk": float(row["base_risk"] or 0),
        "first_seen": float(row["first_seen"] or 0),
        "last_seen": float(row["last_seen"] or 0),
        "attrs": _json_loads(row["attrs"], {}),
    }


def _row_to_edge(row: sqlite3.Row) -> dict:
    return {
        "src": row["src"],
        "dst": row["dst"],
        "kind": row["kind"],
        "ts": float(row["ts"] or 0),
        "event_id": row["event_id"],
    }


def _row_to_incident(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "created_at": float(row["created_at"] or 0),
        "updated_at": float(row["updated_at"] or 0),
        "severity": row["severity"],
        "score": float(row["score"] or 0),
        "status": row["status"],
        "title": row["title"],
        "node_ids": _json_loads(row["node_ids"], []),
        "rule_hits": _json_loads(row["rule_hits"], []),
        "storyline": _json_loads(row["storyline"], []),
    }


def load_entities_since(since_ts: float) -> list[dict]:
    connection = _get_conn()
    if connection is None:
        return []

    try:
        with _lock:
            rows = connection.execute(
                """
                SELECT * FROM entities
                WHERE last_seen >= ?
                ORDER BY first_seen ASC
                """,
                (float(since_ts),),
            ).fetchall()
        return [_row_to_entity(row) for row in rows]
    except Exception:
        logger.exception("load_entities_since failed")
        return []


def load_edges_since(since_ts: float) -> list[dict]:
    connection = _get_conn()
    if connection is None:
        return []

    try:
        with _lock:
            rows = connection.execute(
                """
                SELECT * FROM edges
                WHERE ts >= ?
                ORDER BY ts ASC
                """,
                (float(since_ts),),
            ).fetchall()
        return [_row_to_edge(row) for row in rows]
    except Exception:
        logger.exception("load_edges_since failed")
        return []


def load_events_since(since_ts: float) -> list[dict]:
    connection = _get_conn()
    if connection is None:
        return []

    try:
        with _lock:
            rows = connection.execute(
                """
                SELECT id, ts, source, type, risk, payload, entities
                FROM events
                WHERE ts >= ?
                ORDER BY ts ASC
                """,
                (float(since_ts),),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "ts": float(row["ts"] or 0),
                "source": row["source"],
                "type": row["type"],
                "risk": float(row["risk"] or 0),
                "payload": _json_loads(row["payload"], {}),
                "entities": _json_loads(row["entities"], []),
            }
            for row in rows
        ]
    except Exception:
        logger.exception("load_events_since failed")
        return []


def get_entities_by_ids(entity_ids: Iterable[str]) -> list[dict]:
    ids = [eid for eid in entity_ids if eid]
    if not ids:
        return []

    connection = _get_conn()
    if connection is None:
        return []

    try:
        placeholders = ",".join("?" for _ in ids)
        with _lock:
            rows = connection.execute(
                f"SELECT * FROM entities WHERE id IN ({placeholders})",
                ids,
            ).fetchall()
        return [_row_to_entity(row) for row in rows]
    except Exception:
        logger.exception("get_entities_by_ids failed")
        return []


def list_incidents(status: Optional[str] = "open") -> list[dict]:
    connection = _get_conn()
    if connection is None:
        return []

    try:
        with _lock:
            if status:
                rows = connection.execute(
                    """
                    SELECT * FROM incidents
                    WHERE status = ?
                    ORDER BY updated_at DESC
                    """,
                    (status,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM incidents
                    ORDER BY updated_at DESC
                    """
                ).fetchall()
        return [_row_to_incident(row) for row in rows]
    except Exception:
        logger.exception("list_incidents failed")
        return []


def get_incident(incident_id: str) -> Optional[dict]:
    connection = _get_conn()
    if connection is None or not incident_id:
        return None

    try:
        with _lock:
            row = connection.execute(
                "SELECT * FROM incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()
        return _row_to_incident(row) if row else None
    except Exception:
        logger.exception("get_incident failed")
        return None


def upsert_incident(incident: dict) -> bool:
    connection = _get_conn()
    if connection is None or not incident.get("id"):
        return False

    try:
        with _lock:
            connection.execute(
                """
                INSERT INTO incidents (
                    id, created_at, updated_at, severity, score, status,
                    title, node_ids, rule_hits, storyline
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    severity = excluded.severity,
                    score = excluded.score,
                    status = excluded.status,
                    title = excluded.title,
                    node_ids = excluded.node_ids,
                    rule_hits = excluded.rule_hits,
                    storyline = excluded.storyline
                """,
                (
                    incident["id"],
                    float(incident.get("created_at") or time.time()),
                    float(incident.get("updated_at") or time.time()),
                    incident.get("severity") or "LOW",
                    float(incident.get("score") or 0),
                    incident.get("status") or "open",
                    incident.get("title") or "Incident",
                    _json_dumps(incident.get("node_ids") or []),
                    _json_dumps(incident.get("rule_hits") or []),
                    _json_dumps(incident.get("storyline") or []),
                ),
            )
            connection.commit()
        return True
    except Exception:
        logger.exception("upsert_incident failed")
        try:
            connection.rollback()
        except Exception:
            pass
        return False


def update_incident_status(incident_id: str, status: str) -> bool:
    if status not in {"open", "resolved", "dismissed"}:
        return False

    connection = _get_conn()
    if connection is None or not incident_id:
        return False

    try:
        with _lock:
            cursor = connection.execute(
                """
                UPDATE incidents
                SET status = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, time.time(), incident_id),
            )
            connection.commit()
            return cursor.rowcount > 0
    except Exception:
        logger.exception("update_incident_status failed")
        try:
            connection.rollback()
        except Exception:
            pass
        return False


class _nullcontext:
    def __enter__(self):
        return None

    def __exit__(self, *args):
        return False

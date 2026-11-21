import logging
import socket
import time

import psutil

logger = logging.getLogger(__name__)

# pid -> create_time cache so connection rows can resolve process identity
# without an extra full process scan on every poll.
_process_create_times: dict[int, float] = {}
_process_names: dict[int, str] = {}


def format_address(address):
    if not address:
        return None, None

    try:
        return address.ip, address.port
    except AttributeError:
        try:
            return address[0], address[1]
        except (IndexError, TypeError):
            return None, None


def _refresh_process_identity_cache():
    global _process_create_times, _process_names

    create_times = {}
    names = {}

    try:
        for proc in psutil.process_iter(["pid", "create_time", "name"]):
            try:
                info = proc.info
                pid = info.get("pid")
                if pid is None:
                    continue
                created = info.get("create_time")
                if created is not None:
                    create_times[pid] = created
                names[pid] = info.get("name") or f"PID {pid}"
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
                OSError,
            ):
                continue
    except Exception:
        logger.debug("process identity cache refresh failed", exc_info=True)
        return

    _process_create_times = create_times
    _process_names = names


def _persist_first_seen_connections(connections):
    """Write first-seen (process, remote_ip) pairs to the event store."""

    try:
        from event_store import record_connection_first_seen
    except Exception:
        return

    if not connections:
        return

    try:
        _refresh_process_identity_cache()
    except Exception:
        pass

    for connection in connections:
        remote_ip = connection.get("remote_ip")
        pid = connection.get("pid")

        if not remote_ip or pid is None:
            continue

        create_time = _process_create_times.get(pid)
        if create_time is None:
            continue

        try:
            record_connection_first_seen(
                pid=pid,
                create_time=create_time,
                process_name=_process_names.get(pid),
                remote_ip=remote_ip,
                remote_port=connection.get("remote_port"),
                protocol=connection.get("protocol"),
            )
        except Exception:
            logger.debug(
                "first-seen connection persist failed",
                exc_info=True,
            )


def get_process_network_connections(persist_first_seen=True):
    """Collect accessible TCP and UDP connections."""

    connections = []
    restricted = False

    try:
        raw_connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError):
        raw_connections = []
        restricted = True

    for connection in raw_connections:
        pid = connection.pid

        if pid is None:
            continue

        local_ip, local_port = format_address(
            connection.laddr
        )

        remote_ip, remote_port = format_address(
            connection.raddr
        )

        protocol = (
            "TCP"
            if connection.type == socket.SOCK_STREAM
            else "UDP"
        )

        connections.append({
            "pid": pid,
            "protocol": protocol,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": connection.status,
        })

    if persist_first_seen:
        try:
            _persist_first_seen_connections(connections)
        except Exception:
            logger.debug(
                "connection first-seen tracking failed",
                exc_info=True,
            )

    return {
        "connections": connections,
        "total": len(connections),
        "restricted": restricted,
        "last_updated": time.time(),
    }


def poll_network_first_seen():
    """Background-safe poll used by the scanner startup thread."""

    try:
        get_process_network_connections(persist_first_seen=True)
    except Exception:
        logger.debug("network first-seen poll failed", exc_info=True)

"""Background correlation runner with debounce after ingest."""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from .config import DEFAULT_WINDOW_SECONDS, ENGINE_DEBOUNCE_SECONDS, ENGINE_INTERVAL_SECONDS
from .graph import load_graph
from .incidents import build_incidents, incident_detail
from .propagation import propagate_risk
from .rules import run_rules

logger = logging.getLogger(__name__)

_stop = threading.Event()
_wake = threading.Event()
_thread: Optional[threading.Thread] = None
_lock = threading.Lock()
_last_run = 0.0
_last_graph: Optional[dict] = None
_last_propagated: Optional[dict] = None


def run_correlation_once(window_seconds: float = DEFAULT_WINDOW_SECONDS) -> dict:
    """Run one correlation pass and persist incidents."""

    global _last_run, _last_graph, _last_propagated

    try:
        graph = load_graph(window_seconds=window_seconds)
        propagated = propagate_risk(graph)
        hits = run_rules(graph, propagated)
        incidents = build_incidents(graph, propagated, hits)

        with _lock:
            _last_run = time.time()
            _last_graph = graph
            _last_propagated = propagated

        return {
            "nodes": len(graph["nodes"]),
            "edges": len(graph["edges"]),
            "rule_hits": len(hits),
            "incidents": len(incidents),
            "incident_ids": [item["id"] for item in incidents],
        }
    except Exception:
        logger.exception("Correlation run failed")
        return {
            "nodes": 0,
            "edges": 0,
            "rule_hits": 0,
            "incidents": 0,
            "incident_ids": [],
            "error": True,
        }


def get_cached_state() -> tuple[Optional[dict], Optional[dict]]:
    with _lock:
        return _last_graph, _last_propagated


def request_correlation_run() -> None:
    """Debounced wake-up after ingest batches."""

    _wake.set()


def _loop() -> None:
    while not _stop.is_set():
        triggered = _wake.wait(timeout=ENGINE_INTERVAL_SECONDS)
        _wake.clear()

        if triggered:
            # Debounce rapid ingest bursts.
            time.sleep(ENGINE_DEBOUNCE_SECONDS)
            _wake.clear()

        run_correlation_once()


def start_correlation_engine() -> bool:
    """Start the background correlation thread. Idempotent."""

    global _thread

    try:
        if _thread is not None and _thread.is_alive():
            return True

        _stop.clear()
        _thread = threading.Thread(
            target=_loop,
            name="cyberguard-correlation",
            daemon=True,
        )
        _thread.start()
        # Kick an initial pass shortly after startup.
        request_correlation_run()
        return True
    except Exception:
        logger.exception("Failed to start correlation engine")
        return False


def stop_correlation_engine() -> None:
    global _thread
    _stop.set()
    _wake.set()
    thread = _thread
    if thread is not None and thread.is_alive():
        thread.join(timeout=2)
    _thread = None


def get_incident_with_graph(incident_id: str) -> Optional[dict]:
    graph, propagated = get_cached_state()
    if graph is None or propagated is None:
        run_correlation_once()
        graph, propagated = get_cached_state()
    if graph is None or propagated is None:
        return None
    return incident_detail(incident_id, graph, propagated)

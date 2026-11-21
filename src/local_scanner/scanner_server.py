import os
import subprocess
import threading
from pathlib import Path
import platform
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, Literal

from pydantic import BaseModel, Field
from windows_scanner import scan_windows
from mac_scanner import scan_mac
from malware_scanner import start_scan, scan_status, cancel_scan
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from system_guardian import (
    get_system_stats,
    get_running_processes,
    get_process_details,
)
from process_analysis import analyze_processes

from process_termination import (
    check_termination_eligibility,
    terminate_eligible_process,
    check_application_termination,
    terminate_application,
)
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

from security_timeline import (
    update_process_timeline,
    get_security_events,
    record_process_termination,
)

from process_network import (
    get_process_network_connections,
    poll_network_first_seen,
)

app = FastAPI(title="CyberGuard Local Scanner")

process_executor = ThreadPoolExecutor(max_workers=1)
process_cache_lock = Lock()
process_cache = {
    "data": None,
    "scanning": False,
    "last_updated": None,
}

NETWORK_POLL_SECONDS = 5.0
_network_poll_stop = threading.Event()
_network_poll_thread = None


def _start_local_telemetry():
    """Initialize device-local event store and background watchers.

    Failures are swallowed so the existing scanner API still starts.
    """

    global _network_poll_thread

    try:
        from event_store import init_store

        init_store()
    except Exception:
        import logging

        logging.exception("Event store startup failed")

    try:
        from download_watcher import start_download_watcher

        start_download_watcher()
    except Exception:
        import logging

        logging.exception("Downloads watcher startup failed")

    try:
        if _network_poll_thread is None or not _network_poll_thread.is_alive():
            _network_poll_stop.clear()

            def _network_loop():
                while not _network_poll_stop.is_set():
                    poll_network_first_seen()
                    _network_poll_stop.wait(NETWORK_POLL_SECONDS)

            _network_poll_thread = threading.Thread(
                target=_network_loop,
                name="cyberguard-network-poll",
                daemon=True,
            )
            _network_poll_thread.start()
    except Exception:
        import logging

        logging.exception("Network first-seen poller startup failed")

    try:
        from correlation import start_correlation_engine

        start_correlation_engine()
    except Exception:
        import logging

        logging.exception("Correlation engine startup failed")


_start_local_telemetry()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost"],
)

ALLOWED_ORIGINS = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
}


class ScanRequest(BaseModel):
    mode: str = "quick"
    folder: str = "downloads"


class FolderRequest(BaseModel):
    path: str


class IngestEntity(BaseModel):
    id: str = Field(..., min_length=1, max_length=512)
    kind: str = Field(..., min_length=1, max_length=64)
    label: str = Field(..., min_length=1, max_length=1024)
    base_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    attrs: dict[str, Any] = Field(default_factory=dict)


class IngestEdge(BaseModel):
    src: str = Field(..., min_length=1, max_length=512)
    dst: str = Field(..., min_length=1, max_length=512)
    kind: str = Field(..., min_length=1, max_length=64)


class IngestEvent(BaseModel):
    id: str = Field(..., min_length=1, max_length=512)
    source: Literal["email", "website", "file_check", "gmail_attachment"]
    type: str = Field(..., min_length=1, max_length=64)
    ts: float
    risk: float = Field(default=0.0, ge=0.0, le=1.0)
    payload: dict[str, Any] = Field(default_factory=dict)
    entities: list[IngestEntity] = Field(default_factory=list)
    edges: list[IngestEdge] = Field(default_factory=list)


class IngestBatch(BaseModel):
    events: list[IngestEvent] = Field(..., min_length=1, max_length=200)


def require_local_frontend(
    origin: str | None = Header(default=None),
):
    if origin not in ALLOWED_ORIGINS:
        raise HTTPException(
            status_code=403,
            detail="Request must come from the CyberGuard frontend."
        )

@app.get("/health")
def health(_=Depends(require_local_frontend)):
    system = platform.system()
    print("Detected operating system:", repr(system))
    return {"status": "ready", "operating_system": system,
            "supported": system in ("Windows", "Darwin")}


@app.post("/events/ingest")
def ingest_events(
    batch: IngestBatch,
    _=Depends(require_local_frontend),
):
    """Accept normalized correlation events from the CyberGuard web app."""

    try:
        from event_store import ingest_normalized_batch

        result = ingest_normalized_batch(
            [event.model_dump() for event in batch.events]
        )
        if result.get("accepted", 0) > 0:
            try:
                from correlation import request_correlation_run

                request_correlation_run()
            except Exception:
                pass
        return {"status": "ok", **result}
    except Exception:
        import logging

        logging.exception("Event ingest failed")
        raise HTTPException(
            status_code=500,
            detail="Unable to ingest events.",
        )


class IncidentStatusRequest(BaseModel):
    status: Literal["open", "resolved", "dismissed"]


@app.get("/incidents")
def get_incidents(
    status: str = "open",
    _=Depends(require_local_frontend),
):
    try:
        from event_store import list_incidents

        allowed = {"open", "resolved", "dismissed", "all"}
        if status not in allowed:
            raise HTTPException(status_code=400, detail="Invalid status filter.")
        incidents = list_incidents(None if status == "all" else status)
        return {"incidents": incidents, "total": len(incidents)}
    except HTTPException:
        raise
    except Exception:
        import logging

        logging.exception("List incidents failed")
        raise HTTPException(status_code=500, detail="Unable to list incidents.")


@app.get("/incidents/{incident_id}")
def get_incident_detail(
    incident_id: str,
    _=Depends(require_local_frontend),
):
    try:
        from correlation.engine import get_incident_with_graph

        detail = get_incident_with_graph(incident_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
        return detail
    except HTTPException:
        raise
    except Exception:
        import logging

        logging.exception("Get incident failed")
        raise HTTPException(status_code=500, detail="Unable to load incident.")


@app.post("/incidents/{incident_id}/status")
def set_incident_status(
    incident_id: str,
    request: IncidentStatusRequest,
    _=Depends(require_local_frontend),
):
    try:
        from event_store import update_incident_status

        ok = update_incident_status(incident_id, request.status)
        if not ok:
            raise HTTPException(status_code=404, detail="Incident not found.")
        return {"id": incident_id, "status": request.status}
    except HTTPException:
        raise
    except Exception:
        import logging

        logging.exception("Update incident status failed")
        raise HTTPException(status_code=500, detail="Unable to update incident.")


@app.get("/graph")
def get_graph(
    since: float | None = None,
    _=Depends(require_local_frontend),
):
    try:
        import time

        from correlation.config import DEFAULT_WINDOW_SECONDS
        from correlation.graph import load_graph
        from correlation.propagation import propagate_risk

        if since is None:
            window = DEFAULT_WINDOW_SECONDS
        else:
            window = max(60.0, time.time() - float(since))

        graph = load_graph(window_seconds=window)
        propagated = propagate_risk(graph)
        nodes = []
        for node_id, node in graph["nodes"].items():
            nodes.append(
                {
                    **node,
                    "propagated_risk": propagated["risk"].get(node_id, 0.0),
                    "max_parent": propagated["max_parent"].get(node_id),
                }
            )
        return {
            "since": graph["since"],
            "nodes": nodes,
            "edges": graph["edges"],
            "total_nodes": len(nodes),
            "total_edges": len(graph["edges"]),
        }
    except Exception:
        import logging

        logging.exception("Graph debug endpoint failed")
        raise HTTPException(status_code=500, detail="Unable to load graph.")


@app.post("/events/demo")
def seed_demo_events(_=Depends(require_local_frontend)):
    """Dev-only synthetic phish chain. Requires CYBERGUARD_DEMO_EVENTS=1."""

    if os.environ.get("CYBERGUARD_DEMO_EVENTS", "").strip() not in {"1", "true", "yes"}:
        raise HTTPException(
            status_code=403,
            detail="Demo seeding disabled. Set CYBERGUARD_DEMO_EVENTS=1 to enable.",
        )

    try:
        from correlation.demo import seed_demo_chain
        from correlation.engine import request_correlation_run, run_correlation_once

        seeded = seed_demo_chain()
        summary = run_correlation_once()
        request_correlation_run()
        return {
            "status": "ok",
            "seed": seeded,
            "correlation": summary,
        }
    except Exception:
        import logging

        logging.exception("Demo seed failed")
        raise HTTPException(status_code=500, detail="Unable to seed demo events.")

@app.get("/status")
def security_status(_=Depends(require_local_frontend)):
    system = platform.system()
    if system == "Windows":
        return scan_windows()
    if system == "Darwin":
        return scan_mac()
    raise HTTPException(status_code=501, detail=f"Unsupported operating system: {system}")


@app.post("/choose-folder")
def choose_folder(_=Depends(require_local_frontend)):

    system = platform.system()

    if system == "Windows":
        script = """
        Add-Type -AssemblyName System.Windows.Forms

        $form = New-Object System.Windows.Forms.Form
        $form.TopMost = $true
        $form.ShowInTaskbar = $false
        $form.StartPosition = 'CenterScreen'
        $form.Size = New-Object System.Drawing.Size(1,1)
        $form.Opacity = 0

        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = 'Select a folder to scan with CyberGuard'
        $dialog.ShowNewFolderButton = $false

        try {
            $form.Show()
            $form.Activate()

            if ($dialog.ShowDialog($form) -eq 'OK') {
                Write-Output $dialog.SelectedPath
            }
        }
        finally {
            $form.Close()
            $form.Dispose()
            $dialog.Dispose()
        }
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-STA", "-Command", script],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail="Unable to open folder picker."
            )

        selected = result.stdout.strip()

    elif system == "Darwin":
        result = subprocess.run(
            [
                "osascript",
                "-e",
                'POSIX path of (choose folder with prompt "Select a folder to scan with CyberGuard")'
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        selected = result.stdout.strip() if result.returncode == 0 else ""

    else:
        raise HTTPException(
            status_code=501,
            detail="Unsupported operating system."
        )

    if not selected:
        return {"status": "cancelled", "path": None}

    path = Path(selected).resolve()

    if not path.is_dir():
        raise HTTPException(
            status_code=400,
            detail="Selected folder does not exist."
        )

    return {
        "status": "selected",
        "path": str(path)
    }

@app.post("/scan-malware")
def start_malware_scan(
    request: ScanRequest,
    _=Depends(require_local_frontend),
):
    return start_scan(
        mode=request.mode,
        folder=request.folder,
    )

@app.get("/scan-malware/status")
def malware_scan_status(_=Depends(require_local_frontend)):
    return scan_status()


@app.post("/scan-malware/cancel")
def cancel_malware_scan(_=Depends(require_local_frontend)):
    return cancel_scan()

@app.get("/system/stats")
def system_stats(_=Depends(require_local_frontend)):
    try:
        return get_system_stats()
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve system performance information."
        )

def refresh_process_cache():
    try:
        start = time.perf_counter()

        result = get_running_processes()
        analyzed = analyze_processes(result["processes"])
        
        update_process_timeline(analyzed["processes"])

        with process_cache_lock:
            process_cache["data"] = analyzed
            process_cache["last_updated"] = time.time()

        print(
            f"[CyberGuard] Process cache refreshed in "
            f"{time.perf_counter() - start:.2f} seconds",
            flush=True,
        )

    except Exception:
        import logging
        logging.exception("Process cache refresh failed")

    finally:
        with process_cache_lock:
            process_cache["scanning"] = False

@app.get("/system/processes")
def system_processes(_=Depends(require_local_frontend)):
    with process_cache_lock:
        cached = process_cache["data"]
        last_updated = process_cache["last_updated"]

        if not process_cache["scanning"]:
            process_cache["scanning"] = True

            try:
                process_executor.submit(refresh_process_cache)
            except RuntimeError:
                process_cache["scanning"] = False

        scanning = process_cache["scanning"]

    if cached is None:
        return {
            "processes": [],
            "summary": {
                "total": 0,
                "high_resource": 0,
                "review_recommended": 0,
                "security_concerns": 0,
                "high_risk": 0,
                "moderate_risk": 0,
            },
            "scanning": scanning,
            "last_updated": None,
        }

    return {
        **cached,
        "scanning": scanning,
        "last_updated": last_updated,
    }

@app.get("/system/security-events")
def system_security_events(
    _=Depends(require_local_frontend),
):
    return get_security_events(limit=100)


@app.get("/system/network-connections")
def system_network_connections(
    _=Depends(require_local_frontend),
):
    try:
        return get_process_network_connections()
    except Exception:
        import logging
        logging.exception("Network collection failed")

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve network connections.",
        )

@app.get("/system/processes/{pid}")
def system_process_details(
    pid: int,
    _=Depends(require_local_frontend)
):
    result = get_process_details(pid)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Process not found or access denied."
        )

    return result

class TerminationRequest(BaseModel):
    pid: int
    create_time: float

@app.post("/system/processes/termination-check")
def system_check_process_termination(
    request: TerminationRequest,
    _=Depends(require_local_frontend),
):
    return check_termination_eligibility(
        request.pid,
        request.create_time,
    )


@app.post("/system/processes/terminate")
def system_terminate_process(
    request: TerminationRequest,
    _=Depends(require_local_frontend),
):
    result = terminate_eligible_process(
        request.pid,
        request.create_time,
    )

    if result.get("success") and result.get("terminated"):
        record_process_termination(
            request.pid,
            result.get("name") or f"PID {request.pid}",
        )

    return result

@app.post("/system/processes/application-check")
def system_check_application_termination(
    request: TerminationRequest,
    _=Depends(require_local_frontend),
):
    return check_application_termination(
        request.pid,
        request.create_time,
    )


@app.post("/system/processes/terminate-application")
def system_terminate_application(
    request: TerminationRequest,
    _=Depends(require_local_frontend),
):
    result = terminate_application(
        request.pid,
        request.create_time,
    )

    for item in result.get("results", []):
        if item.get("success"):
            record_process_termination(
                item["pid"],
                item["name"],
            )

    return result

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)
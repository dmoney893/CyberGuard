"""Sigma-style time-window correlation rules."""

from __future__ import annotations

import time
from typing import Callable

from .config import (
    R1_EMAIL_RISK,
    R1_EXEC_WINDOW,
    R1_VISIT_WINDOW,
    R2_DOMAIN_RISK,
    R3_FILE_RISK,
    R4_FIRST_SEEN_WINDOW,
)
from .lookalike import is_brand_lookalike

RuleFn = Callable[[dict, dict], list[dict]]


def _edges_by_kind(graph: dict, kind: str) -> list[dict]:
    return [edge for edge in graph["edges"] if edge["kind"] == kind]


def _node(graph: dict, node_id: str) -> dict:
    return graph["nodes"].get(node_id) or {}


def rule_phish_to_execution(graph: dict, propagated: dict) -> list[dict]:
    """R1: phishing email → visit → download → execute."""

    matches = []
    links = _edges_by_kind(graph, "links_to")
    visits = _edges_by_kind(graph, "visited")
    served = _edges_by_kind(graph, "served")
    ran_as = _edges_by_kind(graph, "ran_as")

    for link in links:
        email_id, domain_id = link["src"], link["dst"]
        if not email_id.startswith("email:"):
            continue
        if not domain_id.startswith("domain:"):
            # email may also link to url:; resolve domain via url host later
            continue

        email = _node(graph, email_id)
        if float(email.get("base_risk") or 0) < R1_EMAIL_RISK and float(
            propagated["risk"].get(email_id, 0)
        ) < R1_EMAIL_RISK:
            continue

        # Prefer visit events where domain is touched; also accept domain/url visited edges.
        candidate_visits = []
        for edge in visits:
            if edge["src"] == domain_id or edge["dst"] == domain_id:
                candidate_visits.append(edge)
            elif edge["src"].startswith("url:") and domain_id.removeprefix("domain:") in edge["src"]:
                candidate_visits.append(edge)
            elif edge["dst"].startswith("url:") and domain_id.removeprefix("domain:") in edge["dst"]:
                candidate_visits.append(edge)

        # Also treat a "visited" event touching the domain entity via entity list:
        # fall back to any edge into/out of domain with kind visited, else use
        # domain last_seen after email if a website event exists.
        if not candidate_visits:
            # Synthetic: domain first_seen after email counts if domain has elevated risk
            # from a visit ingest (base_risk set on visit).
            domain = _node(graph, domain_id)
            if float(domain.get("base_risk") or 0) < 0.05:
                continue
            visit_ts = float(domain.get("first_seen") or 0)
            if visit_ts - float(link["ts"]) < 0 or visit_ts - float(link["ts"]) > R1_VISIT_WINDOW:
                # Allow domain last_seen as visit proxy
                visit_ts = float(domain.get("last_seen") or 0)
            if visit_ts - float(link["ts"]) < 0 or visit_ts - float(link["ts"]) > R1_VISIT_WINDOW:
                continue
            candidate_visits = [{"src": domain_id, "dst": domain_id, "ts": visit_ts, "kind": "visited"}]

        for visit in candidate_visits:
            if visit["ts"] < link["ts"] or visit["ts"] - link["ts"] > R1_VISIT_WINDOW:
                continue

            for serve in served:
                if serve["src"] != domain_id and not (
                    serve["src"].startswith("url:")
                    and domain_id.removeprefix("domain:") in serve["src"]
                ):
                    continue
                file_id = serve["dst"]
                if not file_id.startswith("file:"):
                    continue
                if serve["ts"] < visit["ts"]:
                    continue

                for run in ran_as:
                    if run["src"] != file_id:
                        continue
                    process_id = run["dst"]
                    if run["ts"] < serve["ts"] or run["ts"] - serve["ts"] > R1_EXEC_WINDOW:
                        continue

                    matches.append(
                        {
                            "rule_id": "R1",
                            "name": "Phish-to-execution",
                            "severity": "HIGH",
                            "node_ids": [email_id, domain_id, file_id, process_id],
                            "detail": "Phishing email linked to a domain that was visited, downloaded a file, and executed it.",
                        }
                    )
    return matches


def rule_risky_download_executed(graph: dict, propagated: dict) -> list[dict]:
    """R2: file served by risky domain, later executed."""

    matches = []
    served = _edges_by_kind(graph, "served")
    ran_as = _edges_by_kind(graph, "ran_as")

    for serve in served:
        if not serve["src"].startswith("domain:"):
            continue
        domain_id = serve["src"]
        file_id = serve["dst"]
        domain_risk = max(
            float(_node(graph, domain_id).get("base_risk") or 0),
            float(propagated["risk"].get(domain_id, 0)),
        )
        if domain_risk < R2_DOMAIN_RISK:
            continue

        for run in ran_as:
            if run["src"] != file_id:
                continue
            if run["ts"] < serve["ts"]:
                continue
            matches.append(
                {
                    "rule_id": "R2",
                    "name": "Risky download executed",
                    "severity": "HIGH",
                    "node_ids": [domain_id, file_id, run["dst"]],
                    "detail": "A file from a risky domain was later executed.",
                }
            )
    return matches


def rule_flagged_attachment_executed(graph: dict, propagated: dict) -> list[dict]:
    """R3: risky attachment hash matches an executed process hash."""

    matches = []
    attached = _edges_by_kind(graph, "attached")
    ran_as = _edges_by_kind(graph, "ran_as")

    for attach in attached:
        email_id, file_id = attach["src"], attach["dst"]
        if not file_id.startswith("file:"):
            continue
        file_node = _node(graph, file_id)
        file_risk = max(
            float(file_node.get("base_risk") or 0),
            float(propagated["risk"].get(file_id, 0)),
        )
        if file_risk < R3_FILE_RISK:
            continue

        for run in ran_as:
            if run["src"] != file_id:
                continue
            matches.append(
                {
                    "rule_id": "R3",
                    "name": "Flagged attachment executed",
                    "severity": "HIGH",
                    "node_ids": [email_id, file_id, run["dst"]],
                    "detail": "A flagged email attachment matches an executed program.",
                }
            )
    return matches


def rule_new_binary_beaconing(graph: dict, propagated: dict) -> list[dict]:
    """R4: new Downloads/temp binary connects to a first-seen device IP."""

    matches = []
    now = time.time()
    connected = _edges_by_kind(graph, "connected_to")
    ran_as = _edges_by_kind(graph, "ran_as")

    file_by_process = {
        edge["dst"]: edge["src"]
        for edge in ran_as
        if edge["dst"].startswith("process:") and edge["src"].startswith("file:")
    }

    for edge in connected:
        process_id, ip_id = edge["src"], edge["dst"]
        process = _node(graph, process_id)
        ip = _node(graph, ip_id)
        attrs = ip.get("attrs") or {}
        if attrs.get("private"):
            continue
        if not attrs.get("first_seen_device"):
            continue

        first_seen = float(process.get("first_seen") or 0)
        if first_seen and now - first_seen > R4_FIRST_SEEN_WINDOW:
            continue

        exe = (process.get("attrs") or {}).get("exe") or ""
        path_lower = str(exe).lower()
        in_risky_dir = any(
            marker in path_lower
            for marker in (
                "/downloads/",
                "\\downloads\\",
                "/tmp/",
                "\\temp\\",
                "/temp/",
                "\\appdata\\local\\temp",
            )
        )

        file_id = file_by_process.get(process_id)
        if file_id:
            file_path = str((_node(graph, file_id).get("attrs") or {}).get("path") or "").lower()
            in_risky_dir = in_risky_dir or any(
                marker in file_path
                for marker in ("/downloads/", "\\downloads\\", "/tmp/", "\\temp\\")
            )

        if not in_risky_dir and not file_id:
            # Still flag if process cmdline/name suggests downloads binary.
            label = (process.get("label") or "").lower()
            if "invoice" not in label and "setup" not in label:
                continue

        nodes = [process_id, ip_id]
        if file_id:
            nodes.insert(0, file_id)

        matches.append(
            {
                "rule_id": "R4",
                "name": "New binary beaconing",
                "severity": "MEDIUM",
                "node_ids": nodes,
                "detail": "A newly seen program from Downloads/temp connected to a new remote IP.",
            }
        )
    return matches


def rule_email_to_lookalike_visit(graph: dict, propagated: dict) -> list[dict]:
    """R5: email links to a lookalike domain that the user later visits."""

    matches = []
    links = _edges_by_kind(graph, "links_to")
    visits = _edges_by_kind(graph, "visited")

    for link in links:
        email_id, domain_id = link["src"], link["dst"]
        if not email_id.startswith("email:") or not domain_id.startswith("domain:"):
            continue
        domain = domain_id.removeprefix("domain:")
        lookalike, brand = is_brand_lookalike(domain)
        if not lookalike:
            continue

        visited = False
        for visit in visits:
            if visit["src"] == domain_id or visit["dst"] == domain_id:
                visited = True
                break
            if domain in visit["src"] or domain in visit["dst"]:
                visited = True
                break

        domain_node = _node(graph, domain_id)
        if not visited and float(domain_node.get("base_risk") or 0) < 0.05:
            continue

        matches.append(
            {
                "rule_id": "R5",
                "name": "Email to lookalike visit",
                "severity": "MEDIUM",
                "node_ids": [email_id, domain_id],
                "detail": (
                    f"An email linked to a lookalike of {brand or 'a known brand'} "
                    "and that domain was visited."
                ),
            }
        )
    return matches


RULE_REGISTRY: list[tuple[str, RuleFn]] = [
    ("R1", rule_phish_to_execution),
    ("R2", rule_risky_download_executed),
    ("R3", rule_flagged_attachment_executed),
    ("R4", rule_new_binary_beaconing),
    ("R5", rule_email_to_lookalike_visit),
]


def run_rules(graph: dict, propagated: dict) -> list[dict]:
    hits: list[dict] = []
    for _rule_id, fn in RULE_REGISTRY:
        try:
            hits.extend(fn(graph, propagated))
        except Exception:
            continue
    return hits

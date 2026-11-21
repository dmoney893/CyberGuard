"""Build, score, merge, and persist incidents from correlated activity."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Optional

from event_store import get_incident, list_incidents, upsert_incident

from .config import (
    INCIDENT_RISK_THRESHOLD,
    RULE_HIT_BOOST,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from .graph import connected_components
from .propagation import reconstruct_path


def severity_for_score(score: float) -> str:
    if score >= SEVERITY_HIGH:
        return "HIGH"
    if score >= SEVERITY_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _story_text(node: dict, edge_kind: Optional[str] = None) -> str:
    kind = node.get("kind") or "unknown"
    label = node.get("label") or node.get("id")
    attrs = node.get("attrs") or {}

    if kind == "email":
        subject = attrs.get("subject") or label
        return f'You opened an email that looked suspicious (“{subject}”).'

    if kind == "domain":
        if edge_kind == "links_to":
            return f"The email contained a link to {label}."
        if edge_kind == "visited":
            return f"You visited {label}."
        if edge_kind == "served":
            return f"{label} provided a file download."
        return f"Activity involved the website {label}."

    if kind == "url":
        if edge_kind == "visited":
            return f"You opened a page at {label}."
        return f"A web address was involved: {label}."

    if kind == "file":
        name = attrs.get("filename") or attrs.get("path") or label
        if isinstance(name, str) and "/" in name:
            name = name.rsplit("/", 1)[-1]
        if isinstance(name, str) and "\\" in name:
            name = name.rsplit("\\", 1)[-1]
        if edge_kind == "served":
            return f"A file named {name} was downloaded."
        if edge_kind == "attached":
            return f"The email had an attachment named {name}."
        if edge_kind == "ran_as":
            return f"The downloaded file {name} was used to start a program."
        return f"A file named {name} was involved."

    if kind == "process":
        name = attrs.get("name") or label
        if edge_kind == "spawned":
            return f"A program ({name}) started another process."
        if edge_kind == "connected_to":
            return f"{name} connected to a remote computer."
        return f"A program started: {name}."

    if kind == "ip":
        private = attrs.get("private")
        if private:
            return f"A local network address was contacted ({label})."
        if attrs.get("first_seen_device"):
            return f"The program reached out to a new internet address ({label})."
        return f"A remote address was contacted ({label})."

    return f"Related activity on {label}."


def build_storyline(
    node_ids: list[str],
    graph: dict,
    propagated: dict,
    rule_hits: Optional[list[dict]] = None,
) -> list[dict]:
    """Ordered plain-English steps following the causal max-parent path."""

    if not node_ids:
        return []

    risk = propagated["risk"]
    max_parent = propagated["max_parent"]
    node_set = set(node_ids)

    ordered: list[str] = []
    # Prefer an explicit multi-step rule path when available (R1/R2/R3).
    for preferred_rule in ("R1", "R2", "R3", "R4", "R5"):
        hit = next(
            (
                item
                for item in (rule_hits or [])
                if item.get("rule_id") == preferred_rule
            ),
            None,
        )
        if not hit:
            continue
        ordered = [nid for nid in (hit.get("node_ids") or []) if nid in node_set]
        if ordered:
            break

    if not ordered:
        candidates = sorted(
            node_ids,
            key=lambda nid: (
                0 if max_parent.get(nid) else 1,
                -risk.get(nid, 0.0),
                nid,
            ),
        )
        ordered = reconstruct_path(candidates[0], max_parent)

    # Keep causal order. Append missing high-signal kinds once.
    path_set = set(ordered)
    preferred_kinds = ("email", "domain", "file", "process", "ip")
    extras = [
        node_id
        for node_id in sorted(
            node_ids,
            key=lambda nid: float(graph["nodes"].get(nid, {}).get("first_seen") or 0),
        )
        if node_id not in path_set
        and (graph["nodes"].get(node_id) or {}).get("kind") in preferred_kinds
    ]
    seen_kinds = {
        (graph["nodes"].get(node_id) or {}).get("kind") for node_id in ordered
    }
    for node_id in extras:
        kind = (graph["nodes"].get(node_id) or {}).get("kind")
        if kind in seen_kinds:
            continue
        ordered.append(node_id)
        seen_kinds.add(kind)

    steps = []
    prev = None
    for node_id in ordered:
        if node_id not in graph["nodes"]:
            continue
        node = graph["nodes"][node_id]
        edge_kind = None
        parent_info = max_parent.get(node_id)
        if parent_info and parent_info.get("parent") == prev:
            edge_kind = parent_info.get("edge_kind")
        elif prev is not None:
            for edge in graph["adjacency"].get(prev, []):
                if edge["dst"] == node_id:
                    edge_kind = edge["kind"]
                    break

        steps.append(
            {
                "ts": float(node.get("first_seen") or 0),
                "node_id": node_id,
                "kind": node.get("kind"),
                "text": _story_text(node, edge_kind),
            }
        )
        prev = node_id

    return steps


def _title_for(rule_hits: list[dict], storyline: list[dict], score: float) -> str:
    if rule_hits:
        priority = {"R1": 0, "R2": 1, "R3": 2, "R4": 3, "R5": 4}
        ranked = sorted(
            rule_hits,
            key=lambda hit: (
                0 if hit.get("severity") == "HIGH" else 1,
                priority.get(hit.get("rule_id"), 99),
            ),
        )
        names = []
        for hit in ranked:
            name = hit.get("name")
            if name and name not in names:
                names.append(name)
        if names:
            return names[0] if len(names) == 1 else f"{names[0]} (+{len(names) - 1} more)"

    if storyline:
        return storyline[0]["text"].rstrip(".")

    severity = severity_for_score(score)
    return f"{severity.title()} correlated activity"


def _incident_id_for(node_ids: set[str]) -> str:
    material = "|".join(sorted(node_ids))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"inc_{digest}"


def _merge_open_incidents(node_ids: set[str]) -> Optional[dict]:
    open_incidents = list_incidents(status="open")
    overlapping = []
    for incident in open_incidents:
        existing = set(incident.get("node_ids") or [])
        if existing & node_ids:
            overlapping.append(incident)

    if not overlapping:
        return None

    # Prefer the highest-score open incident as the merge target.
    overlapping.sort(key=lambda item: float(item.get("score") or 0), reverse=True)
    return overlapping[0]


def build_incidents(graph: dict, propagated: dict, rule_hits: list[dict]) -> list[dict]:
    """Create/update incidents for risky connected components."""

    risk = propagated["risk"]
    nodes_with_hits: dict[str, list[dict]] = {}
    for hit in rule_hits:
        for node_id in hit.get("node_ids") or []:
            nodes_with_hits.setdefault(node_id, []).append(hit)

    interesting = {
        node_id
        for node_id, value in risk.items()
        if value >= INCIDENT_RISK_THRESHOLD or node_id in nodes_with_hits
    }
    if not interesting:
        return []

    components = connected_components(graph, interesting)
    # Expand each component to full undirected closure within interesting∪neighbors
    # already handled by connected_components over interesting subset.

    built: list[dict] = []
    now = time.time()

    for component in components:
        if not component:
            continue

        component_hits = []
        seen_rules = set()
        for node_id in component:
            for hit in nodes_with_hits.get(node_id, []):
                key = (hit.get("rule_id"), tuple(sorted(hit.get("node_ids") or [])))
                if key in seen_rules:
                    continue
                seen_rules.add(key)
                component_hits.append(hit)

        # Skip components that only have low risk and no rule hits.
        max_risk = max((risk.get(node_id, 0.0) for node_id in component), default=0.0)
        if max_risk < INCIDENT_RISK_THRESHOLD and not component_hits:
            continue

        score = min(1.0, max_risk + RULE_HIT_BOOST * len({h.get("rule_id") for h in component_hits}))
        severity = severity_for_score(score)
        storyline = build_storyline(
            sorted(component), graph, propagated, rule_hits=component_hits
        )
        title = _title_for(component_hits, storyline, score)

        existing = _merge_open_incidents(component)
        if existing:
            merged_nodes = sorted(set(existing.get("node_ids") or []) | component)
            merged_hits = list(existing.get("rule_hits") or [])
            existing_keys = {
                (h.get("rule_id"), tuple(sorted(h.get("node_ids") or [])))
                for h in merged_hits
                if isinstance(h, dict)
            }
            for hit in component_hits:
                key = (hit.get("rule_id"), tuple(sorted(hit.get("node_ids") or [])))
                if key not in existing_keys:
                    merged_hits.append(hit)
            score = min(
                1.0,
                max(float(existing.get("score") or 0), max_risk)
                + RULE_HIT_BOOST * len({h.get("rule_id") for h in merged_hits}),
            )
            severity = severity_for_score(score)
            storyline = build_storyline(
                merged_nodes, graph, propagated, rule_hits=merged_hits
            )
            title = _title_for(merged_hits, storyline, score)
            incident = {
                "id": existing["id"],
                "created_at": existing.get("created_at") or now,
                "updated_at": now,
                "severity": severity,
                "score": score,
                "status": "open",
                "title": title,
                "node_ids": merged_nodes,
                "rule_hits": merged_hits,
                "storyline": storyline,
            }
        else:
            incident = {
                "id": _incident_id_for(component),
                "created_at": now,
                "updated_at": now,
                "severity": severity,
                "score": score,
                "status": "open",
                "title": title,
                "node_ids": sorted(component),
                "rule_hits": component_hits,
                "storyline": storyline,
            }

        upsert_incident(incident)
        built.append(incident)

    return built


def incident_detail(incident_id: str, graph: dict, propagated: dict) -> Optional[dict]:
    incident = get_incident(incident_id)
    if not incident:
        return None

    node_ids = list(incident.get("node_ids") or [])
    nodes = []
    for node_id in node_ids:
        node = graph["nodes"].get(node_id)
        if not node:
            continue
        nodes.append(
            {
                **node,
                "base_risk": float(node.get("base_risk") or 0),
                "propagated_risk": float(propagated["risk"].get(node_id, 0)),
                "max_parent": propagated["max_parent"].get(node_id),
            }
        )

    node_set = set(node_ids)
    edges = [
        edge
        for edge in graph["edges"]
        if edge["src"] in node_set and edge["dst"] in node_set
    ]

    return {
        **incident,
        "nodes": nodes,
        "edges": edges,
    }

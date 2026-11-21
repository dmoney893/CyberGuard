"""Load entities + edges into a plain in-memory directed graph."""

from __future__ import annotations

import time
from typing import Optional

from event_store import load_edges_since, load_entities_since, load_events_since

from .config import DEFAULT_WINDOW_SECONDS


def load_graph(window_seconds: float = DEFAULT_WINDOW_SECONDS) -> dict:
    """Return `{nodes, edges, events, since}` for the recent time window."""

    since = time.time() - float(window_seconds)
    entities = load_entities_since(since)
    edges = load_edges_since(since)
    events = load_events_since(since)

    nodes = {entity["id"]: dict(entity) for entity in entities}

    # Ensure edge endpoints exist even if last_seen drifted out of prune quirks.
    for edge in edges:
        for endpoint in (edge["src"], edge["dst"]):
            if endpoint not in nodes:
                kind = endpoint.split(":", 1)[0] if ":" in endpoint else "unknown"
                nodes[endpoint] = {
                    "id": endpoint,
                    "kind": kind,
                    "label": endpoint,
                    "base_risk": 0.0,
                    "first_seen": edge["ts"],
                    "last_seen": edge["ts"],
                    "attrs": {},
                }

    adjacency: dict[str, list[dict]] = {node_id: [] for node_id in nodes}
    reverse: dict[str, list[dict]] = {node_id: [] for node_id in nodes}

    for edge in edges:
        if edge["src"] not in nodes or edge["dst"] not in nodes:
            continue
        adjacency[edge["src"]].append(edge)
        reverse[edge["dst"]].append(edge)

    return {
        "since": since,
        "nodes": nodes,
        "edges": edges,
        "events": events,
        "adjacency": adjacency,
        "reverse": reverse,
    }


def connected_components(graph: dict, node_ids: Optional[set[str]] = None) -> list[set[str]]:
    """Undirected connected components over the graph edges."""

    nodes = set(node_ids) if node_ids is not None else set(graph["nodes"])
    if not nodes:
        return []

    undirected: dict[str, set[str]] = {node_id: set() for node_id in nodes}
    for edge in graph["edges"]:
        src, dst = edge["src"], edge["dst"]
        if src in undirected and dst in undirected:
            undirected[src].add(dst)
            undirected[dst].add(src)

    seen: set[str] = set()
    components: list[set[str]] = []

    for start in nodes:
        if start in seen:
            continue
        stack = [start]
        component: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            component.add(current)
            stack.extend(undirected.get(current, ()))
        if component:
            components.append(component)

    return components

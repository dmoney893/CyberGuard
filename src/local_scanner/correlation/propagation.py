"""Time-decayed risk propagation across the incident graph."""

from __future__ import annotations

import math
from typing import Optional

from .config import EDGE_WEIGHTS, MAX_PATH_DEPTH, TAU_SECONDS


def propagate_risk(
    graph: dict,
    *,
    tau_seconds: float = TAU_SECONDS,
    weights: Optional[dict[str, float]] = None,
    max_depth: int = MAX_PATH_DEPTH,
) -> dict:
    """Compute propagated risk and max-parent contributors for each node.

    For each node in timestamp order:
      risk(n) = max(
          base_risk(n),
          max over parents p of risk(p) * w(edge_kind) * exp(-Δt / τ)
      )

    Returns:
      {
        risk: {node_id: float},
        max_parent: {node_id: {parent, edge_kind, edge_ts, contribution} | None},
        depth: {node_id: int},
      }
    """

    edge_weights = weights or EDGE_WEIGHTS
    nodes = graph["nodes"]
    reverse = graph["reverse"]

    ordered = sorted(
        nodes.values(),
        key=lambda node: (float(node.get("first_seen") or 0), node["id"]),
    )

    risk: dict[str, float] = {}
    max_parent: dict[str, Optional[dict]] = {}
    depth: dict[str, int] = {}

    for node in ordered:
        node_id = node["id"]
        base = float(node.get("base_risk") or 0)
        # Private / loopback IPs never carry risk.
        attrs = node.get("attrs") or {}
        if node.get("kind") == "ip" and attrs.get("private"):
            base = 0.0

        best = base
        best_parent = None
        best_depth = 0

        for edge in reverse.get(node_id, []):
            parent_id = edge["src"]
            if parent_id not in risk:
                continue

            parent_depth = depth.get(parent_id, 0)
            if parent_depth >= max_depth:
                continue

            weight = float(edge_weights.get(edge["kind"], 0.5))
            dest_ts = float(node.get("first_seen") or edge["ts"])
            parent_ts = float(nodes.get(parent_id, {}).get("first_seen") or edge["ts"])
            delta_t = max(0.0, dest_ts - parent_ts)

            contribution = risk[parent_id] * weight * math.exp(-delta_t / tau_seconds)
            if contribution > best:
                best = contribution
                best_parent = {
                    "parent": parent_id,
                    "edge_kind": edge["kind"],
                    "edge_ts": float(edge["ts"]),
                    "contribution": contribution,
                }
                best_depth = parent_depth + 1

        risk[node_id] = min(1.0, float(best))
        max_parent[node_id] = best_parent
        depth[node_id] = best_depth

    return {
        "risk": risk,
        "max_parent": max_parent,
        "depth": depth,
    }


def reconstruct_path(
    node_id: str,
    max_parent: dict[str, Optional[dict]],
    *,
    limit: int = MAX_PATH_DEPTH + 1,
) -> list[str]:
    """Follow max-parent links backward, then return chronological node ids."""

    path = [node_id]
    seen = {node_id}
    current = node_id

    while len(path) < limit:
        parent_info = max_parent.get(current)
        if not parent_info:
            break
        parent = parent_info.get("parent")
        if not parent or parent in seen:
            break
        path.append(parent)
        seen.add(parent)
        current = parent

    path.reverse()
    return path

"""Configurable thresholds and edge weights for correlation."""

from __future__ import annotations

# Risk propagation
TAU_SECONDS = 30 * 60  # 30 minutes
MAX_PATH_DEPTH = 6

EDGE_WEIGHTS = {
    "links_to": 0.8,
    "visited": 0.9,
    "served": 0.9,
    "attached": 0.9,
    "ran_as": 0.95,
    "spawned": 0.85,
    "connected_to": 0.6,
}

DEFAULT_WINDOW_SECONDS = 24 * 60 * 60

# Incident scoring
INCIDENT_RISK_THRESHOLD = 0.6
SEVERITY_HIGH = 0.8
SEVERITY_MEDIUM = 0.6
RULE_HIT_BOOST = 0.1

# Rule thresholds
R1_EMAIL_RISK = 0.6
R1_VISIT_WINDOW = 30 * 60
R1_EXEC_WINDOW = 60 * 60

R2_DOMAIN_RISK = 0.6

R3_FILE_RISK = 0.6

R4_FIRST_SEEN_WINDOW = 24 * 60 * 60

# Engine scheduling
ENGINE_INTERVAL_SECONDS = 15.0
ENGINE_DEBOUNCE_SECONDS = 1.5

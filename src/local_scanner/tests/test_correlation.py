import math
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import event_store as es
from correlation.demo import seed_demo_chain
from correlation.engine import run_correlation_once
from correlation.graph import load_graph
from correlation.incidents import build_incidents, severity_for_score
from correlation.propagation import propagate_risk, reconstruct_path
from correlation.rules import (
    rule_email_to_lookalike_visit,
    rule_flagged_attachment_executed,
    rule_new_binary_beaconing,
    rule_phish_to_execution,
    rule_risky_download_executed,
    run_rules,
)


class CorrelationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "events.db"
        # Reset module globals so each test gets a fresh DB.
        es._conn = None
        es._db_path = None
        es._initialized = False
        es._hash_cache.clear()
        es._seen_ips.clear()
        es._seen_process_ips.clear()
        self.assertTrue(es.init_store(self.db))

    def tearDown(self):
        if es._conn is not None:
            es._conn.close()
        es._conn = None
        es._initialized = False
        self.tmp.cleanup()


class PropagationTests(CorrelationTestCase):
    def test_decay_weights_and_max_parent(self):
        now = time.time()
        es.ingest_normalized_batch(
            [
                {
                    "id": "e1",
                    "source": "email",
                    "type": "email_scanned",
                    "ts": now,
                    "risk": 1.0,
                    "payload": {},
                    "entities": [
                        {
                            "id": "email:a",
                            "kind": "email",
                            "label": "a",
                            "base_risk": 1.0,
                        },
                        {
                            "id": "domain:b",
                            "kind": "domain",
                            "label": "b",
                            "base_risk": 0.0,
                        },
                    ],
                    "edges": [
                        {"src": "email:a", "dst": "domain:b", "kind": "links_to"},
                    ],
                }
            ]
        )
        # Force destination first_seen later for decay.
        with es._lock:
            es._conn.execute(
                "UPDATE entities SET first_seen = ?, last_seen = ? WHERE id = ?",
                (now + 1800, now + 1800, "domain:b"),
            )
            es._conn.commit()

        graph = load_graph(window_seconds=7200)
        result = propagate_risk(graph, tau_seconds=1800, weights={"links_to": 0.8})
        expected = 1.0 * 0.8 * math.exp(-1800 / 1800)
        self.assertAlmostEqual(result["risk"]["domain:b"], expected, places=5)
        self.assertEqual(result["max_parent"]["domain:b"]["parent"], "email:a")
        self.assertEqual(result["max_parent"]["domain:b"]["edge_kind"], "links_to")
        self.assertEqual(reconstruct_path("domain:b", result["max_parent"]), ["email:a", "domain:b"])

    def test_base_risk_wins_over_weaker_parent(self):
        now = time.time()
        es.ingest_normalized_batch(
            [
                {
                    "id": "e2",
                    "source": "email",
                    "type": "email_scanned",
                    "ts": now,
                    "risk": 0.1,
                    "payload": {},
                    "entities": [
                        {
                            "id": "email:low",
                            "kind": "email",
                            "label": "low",
                            "base_risk": 0.1,
                        },
                        {
                            "id": "domain:hot",
                            "kind": "domain",
                            "label": "hot",
                            "base_risk": 0.9,
                        },
                    ],
                    "edges": [
                        {"src": "email:low", "dst": "domain:hot", "kind": "links_to"},
                    ],
                }
            ]
        )
        graph = load_graph()
        result = propagate_risk(graph)
        self.assertAlmostEqual(result["risk"]["domain:hot"], 0.9)
        self.assertIsNone(result["max_parent"]["domain:hot"])


class RuleTests(CorrelationTestCase):
    def _seed_minimal_chain(self, now=None):
        return seed_demo_chain(now=now or time.time())

    def test_r1_phish_to_execution(self):
        self._seed_minimal_chain()
        graph = load_graph()
        propagated = propagate_risk(graph)
        hits = rule_phish_to_execution(graph, propagated)
        self.assertTrue(hits)
        self.assertEqual(hits[0]["rule_id"], "R1")
        self.assertEqual(hits[0]["severity"], "HIGH")

    def test_r2_risky_download_executed(self):
        self._seed_minimal_chain()
        graph = load_graph()
        propagated = propagate_risk(graph)
        hits = rule_risky_download_executed(graph, propagated)
        self.assertTrue(any(hit["rule_id"] == "R2" for hit in hits))

    def test_r3_flagged_attachment_executed(self):
        now = time.time()
        file_id = "file:" + ("a" * 64)
        es.ingest_normalized_batch(
            [
                {
                    "id": "att1",
                    "source": "gmail_attachment",
                    "type": "gmail_attachment_scanned",
                    "ts": now,
                    "risk": 0.9,
                    "payload": {},
                    "entities": [
                        {
                            "id": "email:m1",
                            "kind": "email",
                            "label": "Invoice",
                            "base_risk": 0.4,
                        },
                        {
                            "id": file_id,
                            "kind": "file",
                            "label": "invoice.exe",
                            "base_risk": 0.9,
                        },
                        {
                            "id": "process:9:1",
                            "kind": "process",
                            "label": "invoice.exe",
                            "base_risk": 0.2,
                        },
                    ],
                    "edges": [
                        {"src": "email:m1", "dst": file_id, "kind": "attached"},
                        {"src": file_id, "dst": "process:9:1", "kind": "ran_as"},
                    ],
                }
            ]
        )
        graph = load_graph()
        propagated = propagate_risk(graph)
        hits = rule_flagged_attachment_executed(graph, propagated)
        self.assertTrue(hits)
        self.assertEqual(hits[0]["rule_id"], "R3")

    def test_r4_new_binary_beaconing(self):
        self._seed_minimal_chain()
        graph = load_graph()
        propagated = propagate_risk(graph)
        hits = rule_new_binary_beaconing(graph, propagated)
        self.assertTrue(any(hit["rule_id"] == "R4" for hit in hits))

    def test_r5_email_to_lookalike_visit(self):
        self._seed_minimal_chain()
        graph = load_graph()
        propagated = propagate_risk(graph)
        hits = rule_email_to_lookalike_visit(graph, propagated)
        self.assertTrue(any(hit["rule_id"] == "R5" for hit in hits))


class IncidentTests(CorrelationTestCase):
    def test_severity_thresholds(self):
        self.assertEqual(severity_for_score(0.85), "HIGH")
        self.assertEqual(severity_for_score(0.65), "MEDIUM")
        self.assertEqual(severity_for_score(0.2), "LOW")

    def test_incident_merging_shared_nodes(self):
        seed_demo_chain()
        graph = load_graph()
        propagated = propagate_risk(graph)
        hits = run_rules(graph, propagated)
        first = build_incidents(graph, propagated, hits)
        self.assertTrue(first)
        first_id = first[0]["id"]

        # Second pass with same nodes should merge into the open incident.
        second = build_incidents(graph, propagated, hits)
        self.assertTrue(second)
        self.assertEqual(second[0]["id"], first_id)
        open_incidents = es.list_incidents(status="open")
        matching = [item for item in open_incidents if item["id"] == first_id]
        self.assertEqual(len(matching), 1)

    def test_full_demo_chain_high_storyline(self):
        seeded = seed_demo_chain()
        summary = run_correlation_once()
        self.assertGreaterEqual(summary["incidents"], 1)

        incidents = es.list_incidents(status="open")
        high = [item for item in incidents if item["severity"] == "HIGH"]
        self.assertTrue(high, msg=f"expected HIGH incident, got {incidents}")

        incident = high[0]
        story = incident.get("storyline") or []
        self.assertGreaterEqual(len(story), 5, msg=story)

        kinds = [step.get("kind") for step in story]
        self.assertIn("email", kinds)
        self.assertIn("domain", kinds)
        self.assertIn("file", kinds)
        self.assertIn("process", kinds)
        self.assertIn("ip", kinds)

        # Causal path should include the demo nodes.
        node_ids = set(incident.get("node_ids") or [])
        for node_id in seeded["node_ids"]:
            if node_id.startswith("url:"):
                continue
            self.assertIn(node_id, node_ids)

        texts = " ".join(step["text"].lower() for step in story)
        self.assertIn("email", texts)
        self.assertTrue(
            "download" in texts or "file" in texts or "invoice" in texts
        )


if __name__ == "__main__":
    unittest.main()

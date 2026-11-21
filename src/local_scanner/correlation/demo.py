"""Dev-only synthetic phish → visit → download → exec → connect chain."""

from __future__ import annotations

import time

from event_store import (
    domain_entity_id,
    file_entity_id,
    ingest_normalized_batch,
    ip_entity_id,
    process_entity_id,
    url_entity_id,
)


def seed_demo_chain(now: float | None = None) -> dict:
    """Insert the demo attack chain with fresh timestamps."""

    now = float(now if now is not None else time.time())
    email_id = "email:demo-fedex-phish"
    domain = "fedex-track-parcel.co"
    domain_id = domain_entity_id(domain)
    url = f"https://{domain}/invoice.zip"
    url_id = url_entity_id(url)
    file_hash = "d" * 64
    file_id = file_entity_id(file_hash)
    process_id = process_entity_id(4242, now - 10)
    remote_ip = "203.0.113.77"
    ip_id = ip_entity_id(remote_ip)

    t0 = now - 120
    t1 = t0 + 40
    t2 = t1 + 15
    t3 = t2 + 20
    t4 = t3 + 10

    events = [
        {
            "id": f"demo:email:{int(now)}",
            "source": "email",
            "type": "email_scanned",
            "ts": t0,
            "risk": 0.82,
            "payload": {
                "subject": "FedEx: Your parcel is waiting",
                "sender": "delivery@fedex-track-parcel.co",
                "classification": "PHISHING",
                "demo": True,
            },
            "entities": [
                {
                    "id": email_id,
                    "kind": "email",
                    "label": "FedEx: Your parcel is waiting",
                    "base_risk": 0.82,
                    "attrs": {
                        "subject": "FedEx: Your parcel is waiting",
                        "sender": "delivery@fedex-track-parcel.co",
                        "classification": "PHISHING",
                    },
                },
                {
                    "id": domain_id,
                    "kind": "domain",
                    "label": domain,
                    "base_risk": 0.0,
                    "attrs": {"host": domain},
                },
            ],
            "edges": [
                {"src": email_id, "dst": domain_id, "kind": "links_to"},
            ],
        },
        {
            "id": f"demo:visit:{int(now)}",
            "source": "website",
            "type": "visited",
            "ts": t1,
            "risk": 0.9,
            "payload": {
                "domain": domain,
                "url": url,
                "risk_level": "HIGH_RISK",
                "demo": True,
            },
            "entities": [
                {
                    "id": domain_id,
                    "kind": "domain",
                    "label": domain,
                    "base_risk": 0.9,
                    "attrs": {"host": domain, "risk_level": "HIGH_RISK"},
                },
                {
                    "id": url_id,
                    "kind": "url",
                    "label": url,
                    "base_risk": 0.9,
                    "attrs": {"url": url},
                },
            ],
            "edges": [
                {"src": domain_id, "dst": url_id, "kind": "visited"},
            ],
        },
        {
            "id": f"demo:download:{int(now)}",
            "source": "file_check",
            "type": "file_downloaded",
            "ts": t2,
            "risk": 0.7,
            "payload": {
                "filename": "invoice.zip",
                "sha256": file_hash,
                "path": "/Users/demo/Downloads/invoice.zip",
                "demo": True,
            },
            "entities": [
                {
                    "id": file_id,
                    "kind": "file",
                    "label": "invoice.zip",
                    "base_risk": 0.7,
                    "attrs": {
                        "filename": "invoice.zip",
                        "sha256": file_hash,
                        "path": "/Users/demo/Downloads/invoice.zip",
                    },
                },
                {
                    "id": domain_id,
                    "kind": "domain",
                    "label": domain,
                    "base_risk": 0.9,
                    "attrs": {"host": domain},
                },
            ],
            "edges": [
                {"src": domain_id, "dst": file_id, "kind": "served"},
                {"src": url_id, "dst": file_id, "kind": "served"},
            ],
        },
        {
            "id": f"demo:exec:{int(now)}",
            "source": "file_check",
            "type": "process_started",
            "ts": t3,
            "risk": 0.6,
            "payload": {
                "name": "invoice.exe",
                "pid": 4242,
                "demo": True,
            },
            "entities": [
                {
                    "id": process_id,
                    "kind": "process",
                    "label": "invoice.exe",
                    "base_risk": 0.5,
                    "attrs": {
                        "name": "invoice.exe",
                        "pid": 4242,
                        "create_time": now - 10,
                        "exe": "/Users/demo/Downloads/invoice.exe",
                        "sha256": file_hash,
                    },
                },
                {
                    "id": file_id,
                    "kind": "file",
                    "label": "invoice.zip",
                    "base_risk": 0.7,
                    "attrs": {
                        "filename": "invoice.exe",
                        "sha256": file_hash,
                        "path": "/Users/demo/Downloads/invoice.exe",
                    },
                },
            ],
            "edges": [
                {"src": file_id, "dst": process_id, "kind": "ran_as"},
            ],
        },
        {
            "id": f"demo:connect:{int(now)}",
            "source": "file_check",
            "type": "process_connected",
            "ts": t4,
            "risk": 0.4,
            "payload": {
                "remote_ip": remote_ip,
                "demo": True,
            },
            "entities": [
                {
                    "id": process_id,
                    "kind": "process",
                    "label": "invoice.exe",
                    "base_risk": 0.5,
                    "attrs": {
                        "name": "invoice.exe",
                        "pid": 4242,
                        "exe": "/Users/demo/Downloads/invoice.exe",
                    },
                },
                {
                    "id": ip_id,
                    "kind": "ip",
                    "label": remote_ip,
                    "base_risk": 0.0,
                    "attrs": {
                        "address": remote_ip,
                        "private": False,
                        "first_seen_device": True,
                    },
                },
            ],
            "edges": [
                {"src": process_id, "dst": ip_id, "kind": "connected_to"},
            ],
        },
    ]

    # Source literals for ingest validation only allow email|website|file_check|gmail_attachment.
    # Map process/network demo events through file_check/email sources already set.
    result = ingest_normalized_batch(events)
    return {
        "seed": result,
        "node_ids": [email_id, domain_id, url_id, file_id, process_id, ip_id],
        "timestamps": {
            "email": t0,
            "visit": t1,
            "download": t2,
            "exec": t3,
            "connect": t4,
        },
    }

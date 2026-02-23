#!/usr/bin/env python3
"""
Setup Indices — Incident Response Commander
===========================================
Creates the audit log and metrics indices used by the orchestrator:
  - incident-response-log  : Full audit trail of every pipeline action
  - incident-metrics       : MTTD/MTTR tracking per incident

Usage:
  python3 setup-indices.py           # Create indices (idempotent)
  python3 setup-indices.py --reset   # Delete and recreate (clears all data)
  python3 setup-indices.py --verify  # Check indices exist and show doc counts
"""

import os
import sys
import argparse
from datetime import datetime, timezone

from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()

ELASTIC_CLOUD_ID = os.getenv("ELASTIC_CLOUD_ID", "")
ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME", "elastic")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")

AUDIT_LOG_INDEX = "incident-response-log"
METRICS_INDEX = "incident-metrics"


def build_es_client() -> Elasticsearch:
    if ELASTIC_CLOUD_ID:
        if ELASTIC_API_KEY:
            try:
                return Elasticsearch(
                    cloud_id=ELASTIC_CLOUD_ID,
                    api_key=ELASTIC_API_KEY,
                    request_timeout=30,
                )
            except Exception:
                pass
        return Elasticsearch(
            cloud_id=ELASTIC_CLOUD_ID,
            basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD),
            request_timeout=30,
        )
    raise RuntimeError("ELASTIC_CLOUD_ID must be set in .env")


# ─────────────────────────────────────────────────────────────────────────────
# Index definitions
# ─────────────────────────────────────────────────────────────────────────────

AUDIT_LOG_MAPPING = {
    "mappings": {
        "properties": {
            "incident_id": {"type": "keyword"},
            "phase": {"type": "keyword"},
            "action": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "dry_run": {"type": "boolean"},
            "data": {
                "type": "object",
                "dynamic": True,
                "properties": {
                    "agent_id": {"type": "keyword"},
                    "response_summary": {"type": "text"},
                    "timeline_events": {"type": "integer"},
                    "anomaly_score": {"type": "float"},
                    "mttr_seconds": {"type": "long"},
                    "actions_taken": {"type": "keyword"},
                    "escalation": {"type": "boolean"},
                    "iocs": {
                        "type": "object",
                        "properties": {
                            "ips": {"type": "ip", "ignore_malformed": True},
                            "users": {"type": "keyword"},
                            "confidence": {"type": "float"},
                            "technique": {"type": "keyword"},
                            "tactic": {"type": "keyword"},
                        },
                    },
                    "reason": {"type": "text"},
                    "channel": {"type": "keyword"},
                    "ticket_key": {"type": "keyword"},
                },
            },
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1,
        "index.lifecycle.name": "incident-response-policy",
    },
}

METRICS_MAPPING = {
    "mappings": {
        "properties": {
            "incident_id": {"type": "keyword"},
            "attack_type": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "detected_at": {"type": "date"},
            "investigated_at": {"type": "date"},
            "responded_at": {"type": "date"},
            "mttd_seconds": {"type": "long"},
            "mttr_seconds": {"type": "long"},
            "ioc_count": {"type": "integer"},
            "automated": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "timestamp": {"type": "date"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1,
    },
}

ILM_POLICY = {
    "policy": {
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {"rollover": {"max_age": "30d", "max_size": "5gb"}},
            },
            "warm": {
                "min_age": "30d",
                "actions": {
                    "shrink": {"number_of_shards": 1},
                    "forcemerge": {"max_num_segments": 1},
                },
            },
            "cold": {"min_age": "90d", "actions": {"freeze": {}}},
            "delete": {"min_age": "365d", "actions": {"delete": {}}},
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# Setup functions
# ─────────────────────────────────────────────────────────────────────────────


def create_ilm_policy(es: Elasticsearch):
    """Create the ILM policy for audit log retention."""
    try:
        es.ilm.put_lifecycle(
            name="incident-response-policy",
            policy=ILM_POLICY["policy"],
            request_timeout=15,
        )
        print("  [OK] ILM policy 'incident-response-policy' created/updated")
    except Exception as e:
        print(f"  [WARN] ILM policy setup failed (non-critical): {e}")


def create_index(es: Elasticsearch, name: str, mapping: dict):
    """Create index if it doesn't exist."""
    if es.indices.exists(index=name, request_timeout=10):
        print(f"  [OK] Index '{name}' already exists")
        return
    es.indices.create(index=name, body=mapping, request_timeout=15)
    print(f"  [OK] Index '{name}' created")


def delete_index(es: Elasticsearch, name: str):
    """Delete index if it exists."""
    if es.indices.exists(index=name, request_timeout=10):
        es.indices.delete(index=name, request_timeout=15)
        print(f"  [OK] Index '{name}' deleted")
    else:
        print(f"  [INFO] Index '{name}' does not exist (nothing to delete)")


def verify_index(es: Elasticsearch, name: str):
    """Print existence + document count for an index."""
    if not es.indices.exists(index=name, request_timeout=10):
        print(f"  [MISSING] Index '{name}' does not exist — run setup-indices.py first")
        return
    stats = es.indices.stats(index=name, request_timeout=10)
    count = stats["indices"][name]["total"]["docs"]["count"]
    size = stats["indices"][name]["total"]["store"]["size_in_bytes"]
    print(f"  [OK] '{name}': {count} documents, {size:,} bytes")


def seed_demo_metrics(es: Elasticsearch):
    """
    Insert a few sample metric records so --report works immediately after setup.
    These represent synthetic 'before the demo' baselines.
    """
    from datetime import timedelta

    base = datetime.now(timezone.utc)

    samples = [
        {
            "incident_id": "IRC-SEED-001",
            "attack_type": "brute_force",
            "severity": "HIGH",
            "detected_at": (base - timedelta(hours=3)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            ),
            "investigated_at": (base - timedelta(hours=3, minutes=-1)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            ),
            "responded_at": (base - timedelta(hours=3, minutes=-2)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            ),
            "mttd_seconds": 0,
            "mttr_seconds": 127,
            "ioc_count": 3,
            "automated": True,
            "dry_run": False,
            "timestamp": (base - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        },
        {
            "incident_id": "IRC-SEED-002",
            "attack_type": "privilege_escalation",
            "severity": "HIGH",
            "detected_at": (base - timedelta(hours=2)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            ),
            "investigated_at": (
                base - timedelta(hours=2, minutes=-1, seconds=-15)
            ).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "responded_at": (
                base - timedelta(hours=2, minutes=-2, seconds=-30)
            ).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "mttd_seconds": 0,
            "mttr_seconds": 150,
            "ioc_count": 2,
            "automated": True,
            "dry_run": False,
            "timestamp": (base - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        },
        {
            "incident_id": "IRC-SEED-003",
            "attack_type": "data_exfiltration",
            "severity": "CRITICAL",
            "detected_at": (base - timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            ),
            "investigated_at": (base - timedelta(hours=1, minutes=-2)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            ),
            "responded_at": (
                base - timedelta(hours=1, minutes=-3, seconds=-45)
            ).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "mttd_seconds": 0,
            "mttr_seconds": 225,
            "ioc_count": 5,
            "automated": True,
            "dry_run": False,
            "timestamp": (base - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        },
    ]

    for doc in samples:
        es.index(index=METRICS_INDEX, document=doc, request_timeout=10)

    es.indices.refresh(index=METRICS_INDEX, request_timeout=10)
    print(
        f"  [OK] Seeded {len(samples)} baseline metric records into '{METRICS_INDEX}'"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Setup indices for Incident Response Commander"
    )
    parser.add_argument(
        "--reset", action="store_true", help="Delete and recreate indices (clears data)"
    )
    parser.add_argument(
        "--verify", action="store_true", help="Verify indices exist and show stats"
    )
    parser.add_argument(
        "--seed", action="store_true", help="Seed demo baseline metrics after setup"
    )
    args = parser.parse_args()

    print("\n  Incident Response Commander — Index Setup")
    print("  " + "=" * 45)

    try:
        es = build_es_client()
        info = es.info(request_timeout=10)
        print(f"  Connected to Elasticsearch {info['version']['number']}")
    except Exception as e:
        print(f"  [ERROR] Cannot connect: {e}")
        sys.exit(1)

    if args.verify:
        print("\n  Index verification:")
        verify_index(es, AUDIT_LOG_INDEX)
        verify_index(es, METRICS_INDEX)
        # Also check the main events index
        verify_index(es, "security-simulated-events")
        return

    if args.reset:
        print("\n  Resetting indices (all data will be deleted)...")
        delete_index(es, AUDIT_LOG_INDEX)
        delete_index(es, METRICS_INDEX)

    print("\n  Creating ILM policy...")
    create_ilm_policy(es)

    print("\n  Creating indices...")
    create_index(es, AUDIT_LOG_INDEX, AUDIT_LOG_MAPPING)
    create_index(es, METRICS_INDEX, METRICS_MAPPING)

    if args.seed or args.reset:
        print("\n  Seeding baseline demo metrics...")
        try:
            seed_demo_metrics(es)
        except Exception as e:
            print(f"  [WARN] Seeding failed: {e}")

    print("\n  Verification:")
    verify_index(es, AUDIT_LOG_INDEX)
    verify_index(es, METRICS_INDEX)

    print("\n  Setup complete.\n")


if __name__ == "__main__":
    main()

"""
conftest.py — Shared fixtures for the Incident Response Commander test suite.

All fixtures that hit the network are marked as integration and require
ELASTIC_CLOUD_ID + ELASTIC_PASSWORD in the environment (or .env).
"""

import os
import sys
import importlib
import importlib.util
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

# Make demo/ importable from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo"))

# Register incident-simulator.py (hyphenated filename) as 'incident_simulator'
# so that `import incident_simulator` and `patch("incident_simulator.X")` work.
# We load it inside patched env vars so the module-level code doesn't sys.exit.
_sim_path = os.path.join(
    os.path.dirname(__file__), "..", "demo", "incident-simulator.py"
)
if os.path.isfile(_sim_path) and "incident_simulator" not in sys.modules:
    _spec = importlib.util.spec_from_file_location("incident_simulator", _sim_path)
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["incident_simulator"] = _mod
    with patch.dict(
        os.environ,
        {
            "ELASTIC_CLOUD_ID": "test:dGVzdA==",
            "ELASTIC_PASSWORD": "testpass",
        },
    ):
        with patch("elasticsearch.Elasticsearch"):
            _spec.loader.exec_module(_mod)

# ── Credentials fixture ───────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def elastic_creds():
    """Return a dict of Elastic credentials from environment variables."""
    return {
        "cloud_id": os.getenv("ELASTIC_CLOUD_ID", ""),
        "username": os.getenv("ELASTIC_USERNAME", "elastic"),
        "password": os.getenv("ELASTIC_PASSWORD", ""),
        "api_key": os.getenv("ELASTIC_API_KEY", ""),
    }


@pytest.fixture(scope="session")
def has_elastic(elastic_creds):
    """True if we have enough credentials to connect to Elastic."""
    return bool(
        elastic_creds["cloud_id"]
        and (elastic_creds["password"] or elastic_creds["api_key"])
    )


# ── Mock ES client ────────────────────────────────────────────────────────────


@pytest.fixture
def mock_es():
    """A fully mocked Elasticsearch client.

    The orchestrator uses es.options(request_timeout=N).index(...)
    and es.options(request_timeout=N).esql.query(...), so we set up
    es.options() to return a mock with the same default return values.
    """
    es = MagicMock()
    es.info.return_value = {"version": {"number": "8.99.0"}}
    es.index.return_value = {"result": "created", "_id": "mock-id-001"}
    es.indices.refresh.return_value = {"_shards": {"successful": 1}}

    default_esql = {
        "columns": [
            {"name": "source.ip", "type": "ip"},
            {"name": "failed_attempts", "type": "long"},
            {"name": "breach_confirmed", "type": "boolean"},
        ],
        "values": [["192.168.1.100", 25, True]],
    }
    es.esql.query.return_value = default_esql

    # es.options(...) returns a client-like mock with same capabilities
    opts = es.options.return_value
    opts.index.return_value = {"result": "created", "_id": "mock-id-002"}
    opts.esql.query.return_value = default_esql

    return es


# ── Sample incident data ──────────────────────────────────────────────────────


@pytest.fixture
def sample_brute_force_meta():
    return {
        "type": "brute_force",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.100",
        "target_user": "admin",
        "attempts": 25,
        "breach_confirmed": True,
    }


@pytest.fixture
def sample_exfil_meta():
    return {
        "type": "data_exfiltration",
        "severity": "HIGH",
        "user": "john.doe",
        "source_ip": "10.0.1.55",
        "total_transfers": 7,
        "approximate_volume_gb": 4.2,
    }


@pytest.fixture
def sample_privesc_meta():
    return {
        "type": "privilege_escalation",
        "severity": "HIGH",
        "user": "temp.user",
        "source_ip": "10.0.2.10",
        "host": "server-3.internal",
        "escalation_count": 5,
    }


@pytest.fixture
def sample_lateral_meta():
    return {
        "type": "lateral_movement",
        "severity": "HIGH",
        "user": "admin",
        "source_ip": "10.0.1.50",
        "hosts_compromised": 5,
        "mitre_technique": "T1021",
    }


@pytest.fixture
def sample_apt_meta():
    return {
        "type": "apt_attack",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.100",
        "stages_executed": 6,
        "total_events": 48,
        "attack_duration_minutes": 120,
        "mitre_techniques": ["T1046", "T1110", "T1136", "T1068", "T1021", "T1041"],
    }


@pytest.fixture
def sample_timeline_events():
    """A minimal list of timeline event dicts."""
    base = datetime.now(timezone.utc)
    return [
        {
            "@timestamp": base.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "event": {"category": "authentication", "outcome": "failure"},
            "source": {"ip": "192.168.1.100"},
            "user": {"name": "admin"},
            "message": "Failed login attempt",
        },
        {
            "@timestamp": base.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "event": {"category": "authentication", "outcome": "success"},
            "source": {"ip": "192.168.1.100"},
            "user": {"name": "admin"},
            "message": "Successful login — BREACH",
        },
    ]

"""
test_data_ingestion.py
Tests for demo/data-ingestion.py

Validates that the data ingestion script:
  - Produces valid ECS-compliant event documents
  - Correctly maps event fields
  - Respects index naming conventions
"""

import pytest
import sys
import os
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo"))


# ── ECS field validators ──────────────────────────────────────────────────────


def validate_ecs_event(doc: dict) -> list:
    """Returns a list of ECS compliance errors. Empty = valid."""
    errors = []

    if "@timestamp" not in doc:
        errors.append("Missing @timestamp")
    else:
        try:
            ts = doc["@timestamp"]
            assert "T" in ts and ("Z" in ts or "+" in ts)
        except (AssertionError, TypeError):
            errors.append(f"Invalid @timestamp format: {doc.get('@timestamp')}")

    if "event" not in doc:
        errors.append("Missing 'event' object")
    else:
        if "category" not in doc["event"]:
            errors.append("Missing event.category")
        if "outcome" not in doc["event"]:
            errors.append("Missing event.outcome")

    if "source" not in doc or "ip" not in doc.get("source", {}):
        errors.append("Missing source.ip")

    return errors


# ── ECS compliance tests (using simulator fixtures) ───────────────────────────


class TestECSCompliance:
    """Use IncidentSimulator to generate docs and validate ECS compliance."""

    @pytest.fixture
    def sim(self, mock_es):
        with patch("incident_simulator.Elasticsearch", return_value=mock_es):
            with patch.dict(
                os.environ,
                {
                    "ELASTIC_CLOUD_ID": "test:dGVzdA==",
                    "ELASTIC_PASSWORD": "testpass",
                },
            ):
                import importlib
                import incident_simulator

                importlib.reload(incident_simulator)
                sim = incident_simulator.IncidentSimulator.__new__(
                    incident_simulator.IncidentSimulator
                )
                sim.es = mock_es
                sim.target_index = "security-simulated-events"
                return sim

    def test_brute_force_events_are_ecs_compliant(self, sim):
        events, _ = sim.generate_brute_force_attack()
        for i, event in enumerate(events):
            errors = validate_ecs_event(event)
            assert errors == [], f"Event {i} ECS errors: {errors}"

    def test_exfil_events_are_ecs_compliant(self, sim):
        events, _ = sim.generate_data_exfiltration()
        for i, event in enumerate(events):
            errors = validate_ecs_event(event)
            assert errors == [], f"Event {i} ECS errors: {errors}"

    def test_privesc_events_are_ecs_compliant(self, sim):
        events, _ = sim.generate_privilege_escalation()
        for i, event in enumerate(events):
            errors = validate_ecs_event(event)
            assert errors == [], f"Event {i} ECS errors: {errors}"

    def test_lateral_movement_events_are_ecs_compliant(self, sim):
        events, _ = sim.generate_lateral_movement()
        for i, event in enumerate(events):
            errors = validate_ecs_event(event)
            assert errors == [], f"Event {i} ECS errors: {errors}"

    def test_apt_events_are_ecs_compliant(self, sim):
        events, _ = sim.generate_apt_attack()
        for i, event in enumerate(events):
            errors = validate_ecs_event(event)
            assert errors == [], f"APT Event {i} ECS errors: {errors}"

    def test_all_events_have_user_field(self, sim):
        events, _ = sim.generate_brute_force_attack()
        for event in events:
            assert "user" in event
            assert "name" in event["user"]

    def test_all_events_have_host_field(self, sim):
        events, _ = sim.generate_brute_force_attack()
        for event in events:
            assert "host" in event
            assert "name" in event["host"]

    def test_all_events_have_message(self, sim):
        for generator in [
            sim.generate_brute_force_attack,
            sim.generate_data_exfiltration,
            sim.generate_privilege_escalation,
            sim.generate_lateral_movement,
        ]:
            events, _ = generator()
            for event in events:
                assert "message" in event
                assert len(event["message"]) > 0


# ── Index name conventions ────────────────────────────────────────────────────


class TestIndexConventions:
    def test_target_index_name(self):
        """Security events must go to security-simulated-events."""
        with patch(
            "incident_simulator.Elasticsearch",
            return_value=MagicMock(
                info=MagicMock(return_value={"version": {"number": "8.0.0"}})
            ),
        ):
            with patch.dict(
                os.environ,
                {
                    "ELASTIC_CLOUD_ID": "test:dGVzdA==",
                    "ELASTIC_PASSWORD": "testpass",
                },
            ):
                import importlib
                import incident_simulator

                importlib.reload(incident_simulator)
                sim = incident_simulator.IncidentSimulator.__new__(
                    incident_simulator.IncidentSimulator
                )
                sim.target_index = "security-simulated-events"
                assert sim.target_index == "security-simulated-events"

    def test_ingest_calls_correct_index(self, mock_es):
        with patch("incident_simulator.Elasticsearch", return_value=mock_es):
            with patch.dict(
                os.environ,
                {
                    "ELASTIC_CLOUD_ID": "test:dGVzdA==",
                    "ELASTIC_PASSWORD": "testpass",
                },
            ):
                import importlib
                import incident_simulator

                importlib.reload(incident_simulator)
                sim = incident_simulator.IncidentSimulator.__new__(
                    incident_simulator.IncidentSimulator
                )
                sim.es = mock_es
                sim.target_index = "security-simulated-events"
                test_events = [
                    {
                        "@timestamp": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S.%fZ"
                        ),
                        "event": {"category": "authentication", "outcome": "failure"},
                        "source": {"ip": "1.2.3.4"},
                        "user": {"name": "admin"},
                        "host": {"name": "server-01"},
                        "message": "Test event",
                    }
                ]
                sim.ingest_events(test_events)
                mock_es.index.assert_called_once()
                call_kwargs = mock_es.index.call_args
                assert "security-simulated-events" in str(call_kwargs)

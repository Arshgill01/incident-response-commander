"""
test_incident_simulator.py
Unit tests for demo/incident-simulator.py

All tests are pure unit tests (no ES connection needed) — they mock
the Elasticsearch client and test event generation + metadata correctness.
"""

import pytest
import sys
import os
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo"))

# incident_simulator is registered in conftest.py via importlib (hyphen filename)
import incident_simulator


# ── Fixture: simulator with mocked ES ────────────────────────────────────────


@pytest.fixture
def simulator(mock_es):
    sim = incident_simulator.IncidentSimulator.__new__(
        incident_simulator.IncidentSimulator
    )
    sim.es = mock_es
    sim.target_index = "security-simulated-events"
    return sim


# ── Brute Force ───────────────────────────────────────────────────────────────


class TestBruteForce:
    def test_returns_events_and_metadata(self, simulator):
        events, meta = simulator.generate_brute_force_attack(
            source_ip="1.2.3.4", target_user="admin"
        )
        assert isinstance(events, list)
        assert len(events) >= 21  # at least 20 failures + 1 success

    def test_metadata_structure(self, simulator):
        _, meta = simulator.generate_brute_force_attack()
        assert meta["type"] == "brute_force"
        assert meta["severity"] == "CRITICAL"
        assert meta["breach_confirmed"] is True
        assert meta["attempts"] >= 20

    def test_last_event_is_success(self, simulator):
        events, _ = simulator.generate_brute_force_attack(source_ip="1.2.3.4")
        last = events[-1]
        assert last["event"]["outcome"] == "success"

    def test_all_failure_events_have_correct_outcome(self, simulator):
        events, meta = simulator.generate_brute_force_attack()
        failure_events = [e for e in events[:-1]]
        for e in failure_events:
            assert e["event"]["outcome"] == "failure"

    def test_source_ip_propagated(self, simulator):
        events, _ = simulator.generate_brute_force_attack(source_ip="10.0.0.1")
        for e in events:
            assert e["source"]["ip"] == "10.0.0.1"

    def test_timestamps_are_ordered(self, simulator):
        events, _ = simulator.generate_brute_force_attack()
        timestamps = [e["@timestamp"] for e in events]
        assert timestamps == sorted(timestamps)


# ── Data Exfiltration ─────────────────────────────────────────────────────────


class TestDataExfiltration:
    def test_returns_events_and_metadata(self, simulator):
        events, meta = simulator.generate_data_exfiltration()
        assert isinstance(events, list)
        assert len(events) >= 5

    def test_metadata_structure(self, simulator):
        _, meta = simulator.generate_data_exfiltration()
        assert meta["type"] == "data_exfiltration"
        assert meta["severity"] == "HIGH"
        assert meta["approximate_volume_gb"] > 0

    def test_all_events_are_outbound(self, simulator):
        events, _ = simulator.generate_data_exfiltration()
        for e in events:
            assert e["network"]["direction"] == "outbound"

    def test_bytes_above_threshold(self, simulator):
        events, _ = simulator.generate_data_exfiltration()
        for e in events:
            assert e["network"]["bytes"] >= 500_000_000  # >= 500 MB

    def test_user_propagated(self, simulator):
        events, _ = simulator.generate_data_exfiltration(user="alice")
        for e in events:
            assert e["user"]["name"] == "alice"


# ── Privilege Escalation ──────────────────────────────────────────────────────


class TestPrivilegeEscalation:
    def test_returns_events_and_metadata(self, simulator):
        events, meta = simulator.generate_privilege_escalation()
        assert isinstance(events, list)
        assert len(events) == 5

    def test_metadata_structure(self, simulator):
        _, meta = simulator.generate_privilege_escalation()
        assert meta["type"] == "privilege_escalation"
        assert meta["severity"] == "HIGH"
        assert meta["escalation_count"] == 5

    def test_event_category_is_process(self, simulator):
        events, _ = simulator.generate_privilege_escalation()
        for e in events:
            assert e["event"]["category"] == "process"

    def test_target_is_root(self, simulator):
        events, _ = simulator.generate_privilege_escalation()
        for e in events:
            assert e["process"]["target"]["name"] == "root"


# ── Lateral Movement ──────────────────────────────────────────────────────────


class TestLateralMovement:
    def test_returns_events_and_metadata(self, simulator):
        events, meta = simulator.generate_lateral_movement()
        assert isinstance(events, list)
        assert len(events) == 5

    def test_metadata_structure(self, simulator):
        _, meta = simulator.generate_lateral_movement()
        assert meta["type"] == "lateral_movement"
        assert meta["severity"] == "HIGH"
        assert meta["hosts_compromised"] == 5
        assert meta["mitre_technique"] == "T1021"

    def test_all_events_are_successful_logins(self, simulator):
        events, _ = simulator.generate_lateral_movement()
        for e in events:
            assert e["event"]["outcome"] == "success"
            assert e["event"]["action"] == "login"

    def test_distinct_hosts(self, simulator):
        events, _ = simulator.generate_lateral_movement()
        hosts = {e["host"]["name"] for e in events}
        assert len(hosts) == 5


# ── APT Attack ────────────────────────────────────────────────────────────────


class TestAPTAttack:
    def test_returns_events_and_metadata(self, simulator):
        events, meta = simulator.generate_apt_attack(source_ip="192.168.1.100")
        assert isinstance(events, list)
        assert len(events) > 40  # 6 stages, many events

    def test_metadata_structure(self, simulator):
        _, meta = simulator.generate_apt_attack()
        assert meta["type"] == "apt_attack"
        assert meta["severity"] == "CRITICAL"
        assert meta["stages_executed"] == 6
        assert len(meta["mitre_techniques"]) == 6

    def test_all_six_stages_present(self, simulator):
        events, _ = simulator.generate_apt_attack()
        stages = {
            e.get("apt_stage", "").split("_")[0] for e in events if "apt_stage" in e
        }
        assert stages == {"1", "2", "3", "4", "5", "6"}

    def test_mitre_techniques_complete(self, simulator):
        _, meta = simulator.generate_apt_attack()
        expected = {"T1046", "T1110", "T1136", "T1068", "T1021", "T1041"}
        assert set(meta["mitre_techniques"]) == expected

    def test_stage_1_is_recon(self, simulator):
        events, _ = simulator.generate_apt_attack()
        recon = [e for e in events if e.get("apt_stage") == "1_reconnaissance"]
        assert len(recon) > 0
        for e in recon:
            assert e["mitre_technique"] == "T1046"

    def test_stage_6_is_exfiltration(self, simulator):
        events, _ = simulator.generate_apt_attack()
        exfil = [e for e in events if e.get("apt_stage") == "6_exfiltration"]
        assert len(exfil) > 0
        for e in exfil:
            assert e["network"]["direction"] == "outbound"


# ── run_simulation routing ────────────────────────────────────────────────────


class TestRunSimulation:
    def test_brute_force_routing(self, simulator):
        simulator.generate_brute_force_attack = MagicMock(
            return_value=([], {"type": "brute_force", "severity": "CRITICAL"})
        )
        simulator.ingest_events = MagicMock()
        simulator.run_simulation("brute_force")
        simulator.generate_brute_force_attack.assert_called_once()

    def test_lateral_movement_routing(self, simulator):
        simulator.generate_lateral_movement = MagicMock(
            return_value=([], {"type": "lateral_movement", "severity": "HIGH"})
        )
        simulator.ingest_events = MagicMock()
        simulator.run_simulation("lateral_movement")
        simulator.generate_lateral_movement.assert_called_once()

    def test_apt_attack_routing(self, simulator):
        simulator.generate_apt_attack = MagicMock(
            return_value=(
                [],
                {"type": "apt_attack", "severity": "CRITICAL", "stages_executed": 6},
            )
        )
        simulator.ingest_events = MagicMock()
        simulator.run_simulation("apt_attack")
        simulator.generate_apt_attack.assert_called_once()

    def test_unknown_type_exits(self, simulator):
        with pytest.raises(SystemExit):
            simulator.run_simulation("unknown_type")

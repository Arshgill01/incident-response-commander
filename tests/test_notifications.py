"""
test_notifications.py
Unit tests for demo/notifications.py

All HTTP calls are mocked — no real Slack/Jira endpoints are hit.
"""

import pytest
import sys
import os
import json
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo"))

import notifications
from notifications import (
    SlackNotifier,
    JiraNotifier,
    NotificationManager,
    SEVERITY_CONFIG,
    _incident_id,
    _safe_list,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


class TestHelpers:
    def test_incident_id_format(self):
        inc_id = _incident_id()
        assert inc_id.startswith("INC-")
        assert len(inc_id) == 18  # INC-YYYYMMDD-HHMMSS

    def test_safe_list_with_list(self):
        assert _safe_list(["a", "b", "c"]) == ["a", "b", "c"]

    def test_safe_list_truncates(self):
        assert len(_safe_list(list(range(100)), limit=5)) == 5

    def test_safe_list_with_string(self):
        assert _safe_list("192.168.1.1") == ["192.168.1.1"]

    def test_safe_list_with_none(self):
        assert _safe_list(None) == []

    def test_severity_config_completeness(self):
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            cfg = SEVERITY_CONFIG[level]
            assert "emoji" in cfg
            assert "color" in cfg
            assert "jira_priority" in cfg
            assert "slack_channel" in cfg


# ── SlackNotifier ─────────────────────────────────────────────────────────────


class TestSlackNotifier:
    @pytest.fixture
    def slack_with_webhook(self):
        with patch.dict(
            os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"}
        ):
            return SlackNotifier()

    @pytest.fixture
    def slack_no_webhook(self):
        env = {k: v for k, v in os.environ.items() if k != "SLACK_WEBHOOK_URL"}
        with patch.dict(os.environ, env, clear=True):
            return SlackNotifier()

    def test_disabled_without_webhook(self, slack_no_webhook):
        assert slack_no_webhook.enabled is False

    def test_enabled_with_webhook(self, slack_with_webhook):
        assert slack_with_webhook.enabled is True

    def test_returns_error_when_disabled(self, slack_no_webhook):
        result = slack_no_webhook.send_incident_alert(
            "brute_force", "CRITICAL", "1.2.3.4", [], [], [], [], []
        )
        assert result["ok"] is False
        assert "webhook_not_configured" in result["error"]

    def test_successful_send(self, slack_with_webhook):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("notifications.requests.post", return_value=mock_resp) as mock_post:
            result = slack_with_webhook.send_incident_alert(
                incident_type="brute_force",
                severity="CRITICAL",
                source_ip="192.168.1.100",
                affected_users=["admin"],
                affected_hosts=["server-01.internal"],
                mitre_techniques=["T1110"],
                automated_actions=["Blocked IP"],
                human_actions=["Review logs"],
                jira_ticket="SCRUM-42",
                mttd_minutes=3.5,
                mttr_minutes=7.2,
            )
            assert result["ok"] is True
            mock_post.assert_called_once()

    def test_failed_send_returns_error(self, slack_with_webhook):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "invalid_token"
        with patch("notifications.requests.post", return_value=mock_resp):
            result = slack_with_webhook.send_incident_alert(
                "brute_force", "HIGH", "1.2.3.4", [], [], [], [], []
            )
            assert result["ok"] is False

    def test_build_blocks_contains_header(self, slack_with_webhook):
        cfg = SEVERITY_CONFIG["CRITICAL"]
        blocks = slack_with_webhook._build_blocks(
            incident_type="brute_force",
            severity="CRITICAL",
            cfg=cfg,
            source_ip="1.2.3.4",
            affected_users=["admin"],
            affected_hosts=["server-01"],
            mitre_techniques=["T1110"],
            automated_actions=["Blocked IP"],
            human_actions=[],
            jira_ticket="SCRUM-1",
            mttd_minutes=2.0,
            mttr_minutes=5.0,
            inc_id="INC-20250101-120000",
        )
        assert blocks[0]["type"] == "header"
        assert "BRUTE FORCE" in blocks[0]["text"]["text"]

    def test_resolution_notice_sends(self, slack_with_webhook):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("notifications.requests.post", return_value=mock_resp):
            result = slack_with_webhook.send_resolution_notice(
                incident_id="INC-20250101-120000",
                incident_type="brute_force",
                severity="CRITICAL",
                mttd_minutes=3.2,
                mttr_minutes=6.8,
                actions_taken=["IP blocked", "Account locked"],
            )
            assert result["ok"] is True


# ── JiraNotifier ──────────────────────────────────────────────────────────────


class TestJiraNotifier:
    @pytest.fixture
    def jira_configured(self):
        with patch.dict(
            os.environ,
            {
                "JIRA_URL": "https://example.atlassian.net",
                "JIRA_EMAIL": "user@example.com",
                "JIRA_API_TOKEN": "fake-token-123",
                "JIRA_PROJECT_KEY": "SCRUM",
            },
        ):
            return JiraNotifier()

    @pytest.fixture
    def jira_unconfigured(self):
        env_clean = {
            k: v
            for k, v in os.environ.items()
            if k not in ("JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN")
        }
        with patch.dict(os.environ, env_clean, clear=True):
            return JiraNotifier()

    def test_disabled_without_config(self, jira_unconfigured):
        assert jira_unconfigured.enabled is False

    def test_enabled_with_config(self, jira_configured):
        assert jira_configured.enabled is True

    def test_returns_error_when_disabled(self, jira_unconfigured):
        result = jira_unconfigured.create_incident_ticket(
            "brute_force", "HIGH", "1.2.3.4", [], [], [], [], [], []
        )
        assert result["ok"] is False

    def test_successful_ticket_creation(self, jira_configured):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"key": "SCRUM-99", "id": "10099"}
        with patch("notifications.requests.post", return_value=mock_resp):
            result = jira_configured.create_incident_ticket(
                incident_type="brute_force",
                severity="CRITICAL",
                source_ip="192.168.1.100",
                affected_users=["admin"],
                affected_hosts=["server-01.internal"],
                mitre_techniques=["T1110"],
                timeline_events=[],
                automated_actions=["Blocked source IP"],
                human_actions=["Review account"],
                mttd_minutes=3.5,
                mttr_minutes=8.1,
            )
            assert result["ok"] is True
            assert result["ticket_key"] == "SCRUM-99"

    def test_description_contains_mitre_section(self, jira_configured):
        desc = jira_configured._build_description(
            incident_type="brute_force",
            severity="CRITICAL",
            source_ip="1.2.3.4",
            affected_users=["admin"],
            affected_hosts=["server-01"],
            mitre_techniques=["T1110", "T1078"],
            timeline_events=[],
            automated_actions=["IP blocked"],
            human_actions=[],
            mttd_minutes=3.0,
            mttr_minutes=6.0,
            inc_id="INC-20250101-120000",
        )
        assert "T1110" in desc
        assert "T1078" in desc
        assert "MITRE ATT&CK" in desc

    def test_description_contains_metrics(self, jira_configured):
        desc = jira_configured._build_description(
            incident_type="exfiltration",
            severity="HIGH",
            source_ip="10.0.0.1",
            affected_users=[],
            affected_hosts=[],
            mitre_techniques=[],
            timeline_events=[],
            automated_actions=[],
            human_actions=[],
            mttd_minutes=12.5,
            mttr_minutes=25.0,
            inc_id="INC-20250101-120000",
        )
        assert "12.5" in desc
        assert "25.0" in desc


# ── NotificationManager ───────────────────────────────────────────────────────


class TestNotificationManager:
    @pytest.fixture
    def nm_mocked(self):
        nm = NotificationManager.__new__(NotificationManager)
        nm.slack = MagicMock()
        nm.jira = MagicMock()
        nm.slack.send_incident_alert.return_value = {"ok": True}
        nm.slack.send_resolution_notice.return_value = {"ok": True}
        nm.jira.create_incident_ticket.return_value = {
            "ok": True,
            "ticket_key": "SCRUM-7",
        }
        return nm

    def test_dispatch_returns_incident_id(self, nm_mocked):
        result = nm_mocked.dispatch_incident("brute_force", "CRITICAL", "1.2.3.4")
        assert "incident_id" in result
        assert result["incident_id"].startswith("INC-")

    def test_dispatch_calls_both_channels(self, nm_mocked):
        nm_mocked.dispatch_incident("brute_force", "HIGH", "1.2.3.4")
        nm_mocked.slack.send_incident_alert.assert_called_once()
        nm_mocked.jira.create_incident_ticket.assert_called_once()

    def test_jira_ticket_key_passed_to_slack(self, nm_mocked):
        result = nm_mocked.dispatch_incident("brute_force", "HIGH", "1.2.3.4")
        assert result["jira_ticket"] == "SCRUM-7"

    def test_dispatch_resolution_calls_slack(self, nm_mocked):
        result = nm_mocked.dispatch_resolution(
            incident_id="INC-20250101-120000",
            incident_type="brute_force",
            severity="CRITICAL",
            mttd_minutes=3.2,
            mttr_minutes=6.8,
        )
        nm_mocked.slack.send_resolution_notice.assert_called_once()
        assert result["incident_id"] == "INC-20250101-120000"

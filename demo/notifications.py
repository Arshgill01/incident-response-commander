#!/usr/bin/env python3
"""
Notifications Module — Slack Block Kit + Jira REST API
Formats and dispatches security incident alerts with full context.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

# ── Severity config ───────────────────────────────────────────────────────────
SEVERITY_CONFIG = {
    "CRITICAL": {
        "emoji": "🔴",
        "color": "#CC0000",
        "jira_priority": "Highest",
        "slack_channel": os.getenv("SLACK_CHANNEL_CRITICAL", "#security-critical"),
    },
    "HIGH": {
        "emoji": "🟠",
        "color": "#FF6600",
        "jira_priority": "High",
        "slack_channel": os.getenv("SLACK_CHANNEL_HIGH", "#security-alerts"),
    },
    "MEDIUM": {
        "emoji": "🟡",
        "color": "#FFC000",
        "jira_priority": "Medium",
        "slack_channel": os.getenv("SLACK_CHANNEL_MEDIUM", "#security-monitoring"),
    },
    "LOW": {
        "emoji": "🔵",
        "color": "#0070C0",
        "jira_priority": "Low",
        "slack_channel": os.getenv("SLACK_CHANNEL_LOW", "#security-monitoring"),
    },
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _incident_id() -> str:
    return "INC-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _safe_list(val, limit: int = 5) -> list:
    """Coerce val to a list, truncate to limit."""
    if isinstance(val, list):
        return val[:limit]
    if val:
        return [str(val)]
    return []


# ── Slack ─────────────────────────────────────────────────────────────────────
class SlackNotifier:
    """
    Sends Slack Block Kit messages via Incoming Webhook.
    Falls back to plain text if block rendering fails.
    """

    def __init__(self):
        self.webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        self.enabled = bool(self.webhook_url)
        if not self.enabled:
            print("  [Slack] SLACK_WEBHOOK_URL not set — notifications disabled")

    # ── Public API ────────────────────────────────────────────────────────────

    def send_incident_alert(
        self,
        incident_type: str,
        severity: str,
        source_ip: str,
        affected_users: list,
        affected_hosts: list,
        mitre_techniques: list,
        automated_actions: list,
        human_actions: list,
        jira_ticket: Optional[str] = None,
        mttd_minutes: Optional[float] = None,
        mttr_minutes: Optional[float] = None,
        incident_id: Optional[str] = None,
    ) -> dict:
        """Build and send a Block Kit alert. Returns response dict."""
        if not self.enabled:
            return {"ok": False, "error": "webhook_not_configured"}

        severity = severity.upper()
        cfg = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["MEDIUM"])
        inc_id = incident_id or _incident_id()

        blocks = self._build_blocks(
            incident_type=incident_type,
            severity=severity,
            cfg=cfg,
            source_ip=source_ip,
            affected_users=_safe_list(affected_users),
            affected_hosts=_safe_list(affected_hosts),
            mitre_techniques=_safe_list(mitre_techniques),
            automated_actions=_safe_list(automated_actions),
            human_actions=_safe_list(human_actions),
            jira_ticket=jira_ticket,
            mttd_minutes=mttd_minutes,
            mttr_minutes=mttr_minutes,
            inc_id=inc_id,
        )

        payload = {
            "channel": cfg["slack_channel"],
            "text": f"{cfg['emoji']} Security Incident — {incident_type.upper()} [{severity}]",
            "attachments": [
                {
                    "color": cfg["color"],
                    "blocks": blocks,
                    "fallback": f"[{severity}] {incident_type} from {source_ip}",
                }
            ],
        }

        return self._post(payload)

    def send_resolution_notice(
        self,
        incident_id: str,
        incident_type: str,
        severity: str,
        mttd_minutes: float,
        mttr_minutes: float,
        actions_taken: list,
    ) -> dict:
        """Send a green resolution block when the incident is contained."""
        if not self.enabled:
            return {"ok": False, "error": "webhook_not_configured"}

        cfg = SEVERITY_CONFIG.get(severity.upper(), SEVERITY_CONFIG["MEDIUM"])
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"✅ RESOLVED — {incident_type.upper()} Incident Contained",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n{incident_id}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*MTTD:*\n{mttd_minutes:.1f} min",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*MTTR:*\n{mttr_minutes:.1f} min",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Actions Taken:*\n"
                    + "\n".join(f"• {a}" for a in _safe_list(actions_taken, 10)),
                },
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Resolved at {_now_iso()}"}],
            },
        ]

        payload = {
            "channel": cfg["slack_channel"],
            "text": f"✅ Resolved — {incident_type} [{severity}] | MTTD {mttd_minutes:.1f}m | MTTR {mttr_minutes:.1f}m",
            "attachments": [
                {
                    "color": "#36A64F",
                    "blocks": blocks,
                }
            ],
        }
        return self._post(payload)

    # ── Block builder ─────────────────────────────────────────────────────────

    def _build_blocks(
        self,
        incident_type,
        severity,
        cfg,
        source_ip,
        affected_users,
        affected_hosts,
        mitre_techniques,
        automated_actions,
        human_actions,
        jira_ticket,
        mttd_minutes,
        mttr_minutes,
        inc_id,
    ) -> list:
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{cfg['emoji']} SECURITY INCIDENT — {incident_type.upper().replace('_', ' ')}",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n`{inc_id}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n`{severity}`"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n`{source_ip}`"},
                    {"type": "mrkdwn", "text": f"*Detected:*\n{_now_iso()}"},
                ],
            },
        ]

        # Affected users / hosts
        if affected_users or affected_hosts:
            fields = []
            if affected_users:
                fields.append(
                    {
                        "type": "mrkdwn",
                        "text": "*Affected Users:*\n"
                        + "\n".join(f"`{u}`" for u in affected_users),
                    }
                )
            if affected_hosts:
                fields.append(
                    {
                        "type": "mrkdwn",
                        "text": "*Affected Hosts:*\n"
                        + "\n".join(f"`{h}`" for h in affected_hosts),
                    }
                )
            blocks.append({"type": "section", "fields": fields})

        # MITRE techniques
        if mitre_techniques:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*MITRE ATT&CK Techniques:*\n"
                        + "  ".join(f"`{t}`" for t in mitre_techniques),
                    },
                }
            )

        blocks.append({"type": "divider"})

        # Automated actions
        if automated_actions:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Automated Actions Taken:*\n"
                        + "\n".join(f"✅ {a}" for a in automated_actions),
                    },
                }
            )

        # Human actions required
        if human_actions:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Actions Required (Human Approval):*\n"
                        + "\n".join(f"⚠️ {a}" for a in human_actions),
                    },
                }
            )

        # Metrics
        metrics_parts = []
        if mttd_minutes is not None:
            metrics_parts.append(f"*MTTD:* {mttd_minutes:.1f} min")
        if mttr_minutes is not None:
            metrics_parts.append(f"*MTTR:* {mttr_minutes:.1f} min")
        if jira_ticket:
            metrics_parts.append(f"*Jira:* `{jira_ticket}`")

        if metrics_parts:
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": "  |  ".join(metrics_parts)}
                    ],
                }
            )

        return blocks

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _post(self, payload: dict) -> dict:
        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                print(f"  [Slack] Alert sent ✅  (HTTP {resp.status_code})")
                return {"ok": True, "status_code": resp.status_code}
            else:
                print(f"  [Slack] Failed (HTTP {resp.status_code}): {resp.text[:200]}")
                return {
                    "ok": False,
                    "status_code": resp.status_code,
                    "error": resp.text,
                }
        except requests.exceptions.RequestException as e:
            print(f"  [Slack] Request error: {e}")
            return {"ok": False, "error": str(e)}


# ── Jira ──────────────────────────────────────────────────────────────────────
class JiraNotifier:
    """
    Creates Jira issues via REST API v3.
    Supports Jira Cloud (atlassian.net) with basic auth (email + API token).
    """

    def __init__(self):
        self.base_url = os.getenv("JIRA_URL", "").rstrip("/")
        self.email = os.getenv("JIRA_EMAIL", "")
        self.api_token = os.getenv("JIRA_API_TOKEN", "")
        self.project_key = os.getenv("JIRA_PROJECT_KEY", "SCRUM")
        self.enabled = bool(self.base_url and self.email and self.api_token)
        if not self.enabled:
            print("  [Jira] JIRA_URL / JIRA_EMAIL / JIRA_API_TOKEN not set — disabled")

    # ── Public API ────────────────────────────────────────────────────────────

    def create_incident_ticket(
        self,
        incident_type: str,
        severity: str,
        source_ip: str,
        affected_users: list,
        affected_hosts: list,
        mitre_techniques: list,
        timeline_events: list,
        automated_actions: list,
        human_actions: list,
        mttd_minutes: Optional[float] = None,
        mttr_minutes: Optional[float] = None,
        incident_id: Optional[str] = None,
    ) -> dict:
        """Create a Jira issue and return the response dict."""
        if not self.enabled:
            return {"ok": False, "error": "jira_not_configured"}

        severity = severity.upper()
        cfg = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["MEDIUM"])
        inc_id = incident_id or _incident_id()

        summary = (
            f"[{severity}] Security Incident: {incident_type.replace('_', ' ').title()} "
            f"from {source_ip} — {inc_id}"
        )
        description = self._build_description(
            incident_type=incident_type,
            severity=severity,
            source_ip=source_ip,
            affected_users=_safe_list(affected_users),
            affected_hosts=_safe_list(affected_hosts),
            mitre_techniques=_safe_list(mitre_techniques),
            timeline_events=_safe_list(timeline_events, 20),
            automated_actions=_safe_list(automated_actions),
            human_actions=_safe_list(human_actions),
            mttd_minutes=mttd_minutes,
            mttr_minutes=mttr_minutes,
            inc_id=inc_id,
        )

        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary,
                "description": {
                    "version": 1,
                    "type": "doc",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}],
                        }
                    ],
                },
                "issuetype": {"name": "Bug"},
                "priority": {"name": cfg["jira_priority"]},
                "labels": [
                    "security-incident",
                    incident_type.replace("_", "-"),
                    severity.lower(),
                ],
            }
        }

        return self._post_issue(payload, inc_id)

    # ── Description builder ───────────────────────────────────────────────────

    def _build_description(
        self,
        incident_type,
        severity,
        source_ip,
        affected_users,
        affected_hosts,
        mitre_techniques,
        timeline_events,
        automated_actions,
        human_actions,
        mttd_minutes,
        mttr_minutes,
        inc_id,
    ) -> str:
        lines = [
            f"h2. Incident Summary",
            f"",
            f"*Incident ID:* {inc_id}",
            f"*Type:* {incident_type.replace('_', ' ').title()}",
            f"*Severity:* {severity}",
            f"*Source IP:* {source_ip}",
            f"*Detected:* {_now_iso()}",
            f"",
            f"h2. Affected Assets",
            f"",
            f"*Users:* {', '.join(affected_users) if affected_users else 'N/A'}",
            f"*Hosts:* {', '.join(affected_hosts) if affected_hosts else 'N/A'}",
            f"",
            f"h2. MITRE ATT&CK Techniques",
            f"",
        ]
        for t in mitre_techniques:
            lines.append(f"* {t}")

        if timeline_events:
            lines += [
                f"",
                f"h2. Attack Timeline",
                f"",
                f"||Time||Event||Source||",
            ]
            for ev in timeline_events:
                if isinstance(ev, dict):
                    ts = ev.get("@timestamp", "")[:19]
                    msg = ev.get("message", str(ev))[:120]
                    src = (
                        ev.get("source", {}).get("ip", "")
                        if isinstance(ev.get("source"), dict)
                        else ""
                    )
                    lines.append(f"|{ts}|{msg}|{src}|")
                else:
                    lines.append(f"|--|{str(ev)[:120]}|--|")

        lines += [
            f"",
            f"h2. Response Actions",
            f"",
            f"*Automated (Completed):*",
        ]
        for a in automated_actions:
            lines.append(f"* (/) {a}")

        lines.append(f"")
        lines.append(f"*Pending Human Approval:*")
        for a in human_actions:
            lines.append(f"* (!) {a}")

        if mttd_minutes is not None or mttr_minutes is not None:
            lines += [
                f"",
                f"h2. Response Metrics",
                f"",
            ]
            if mttd_minutes is not None:
                lines.append(f"* *MTTD:* {mttd_minutes:.1f} minutes")
            if mttr_minutes is not None:
                lines.append(f"* *MTTR:* {mttr_minutes:.1f} minutes")

        return "\n".join(lines)

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _post_issue(self, payload: dict, inc_id: str) -> dict:
        url = f"{self.base_url}/rest/api/3/issue"
        try:
            resp = requests.post(
                url,
                json=payload,
                auth=(self.email, self.api_token),
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                ticket_key = data.get("key", "UNKNOWN")
                print(f"  [Jira] Ticket created: {ticket_key} ✅")
                return {"ok": True, "ticket_key": ticket_key, "incident_id": inc_id}
            else:
                print(f"  [Jira] Failed (HTTP {resp.status_code}): {resp.text[:300]}")
                return {
                    "ok": False,
                    "status_code": resp.status_code,
                    "error": resp.text,
                }
        except requests.exceptions.RequestException as e:
            print(f"  [Jira] Request error: {e}")
            return {"ok": False, "error": str(e)}


# ── NotificationManager — unified dispatcher ─────────────────────────────────
class NotificationManager:
    """
    Single entry point for all notifications.
    Dispatches to Slack + Jira concurrently and returns combined result.
    """

    def __init__(self):
        self.slack = SlackNotifier()
        self.jira = JiraNotifier()

    def dispatch_incident(
        self,
        incident_type: str,
        severity: str,
        source_ip: str,
        affected_users: list = None,
        affected_hosts: list = None,
        mitre_techniques: list = None,
        timeline_events: list = None,
        automated_actions: list = None,
        human_actions: list = None,
        mttd_minutes: float = None,
        mttr_minutes: float = None,
        incident_id: str = None,
    ) -> dict:
        """
        Dispatch incident to all notification channels.
        Returns dict: { 'incident_id': ..., 'slack': {...}, 'jira': {...} }
        """
        inc_id = incident_id or _incident_id()
        print(f"\n[Notifications] Dispatching {severity} alert for {inc_id} ...")

        affected_users = affected_users or []
        affected_hosts = affected_hosts or []
        mitre_techniques = mitre_techniques or []
        timeline_events = timeline_events or []
        automated_actions = automated_actions or []
        human_actions = human_actions or []

        # Jira first (so we have ticket key for Slack)
        jira_result = self.jira.create_incident_ticket(
            incident_type=incident_type,
            severity=severity,
            source_ip=source_ip,
            affected_users=affected_users,
            affected_hosts=affected_hosts,
            mitre_techniques=mitre_techniques,
            timeline_events=timeline_events,
            automated_actions=automated_actions,
            human_actions=human_actions,
            mttd_minutes=mttd_minutes,
            mttr_minutes=mttr_minutes,
            incident_id=inc_id,
        )

        jira_ticket = jira_result.get("ticket_key") if jira_result.get("ok") else None

        slack_result = self.slack.send_incident_alert(
            incident_type=incident_type,
            severity=severity,
            source_ip=source_ip,
            affected_users=affected_users,
            affected_hosts=affected_hosts,
            mitre_techniques=mitre_techniques,
            automated_actions=automated_actions,
            human_actions=human_actions,
            jira_ticket=jira_ticket,
            mttd_minutes=mttd_minutes,
            mttr_minutes=mttr_minutes,
            incident_id=inc_id,
        )

        return {
            "incident_id": inc_id,
            "slack": slack_result,
            "jira": jira_result,
            "jira_ticket": jira_ticket,
        }

    def dispatch_resolution(
        self,
        incident_id: str,
        incident_type: str,
        severity: str,
        mttd_minutes: float,
        mttr_minutes: float,
        actions_taken: list = None,
    ) -> dict:
        """Send resolution notice to Slack."""
        actions_taken = actions_taken or []
        slack_result = self.slack.send_resolution_notice(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=severity,
            mttd_minutes=mttd_minutes,
            mttr_minutes=mttr_minutes,
            actions_taken=actions_taken,
        )
        return {"incident_id": incident_id, "slack": slack_result}


# ── CLI test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("Notification Module — Self-Test")
    print("=" * 60)

    nm = NotificationManager()

    result = nm.dispatch_incident(
        incident_type="brute_force",
        severity="CRITICAL",
        source_ip="192.168.1.100",
        affected_users=["admin", "root"],
        affected_hosts=["server-01.internal", "ssh-gateway.internal"],
        mitre_techniques=["T1110", "T1078"],
        automated_actions=[
            "Source IP 192.168.1.100 blocked at firewall",
            "User 'admin' account locked",
            "All active sessions for 'admin' terminated",
        ],
        human_actions=[
            "Verify IP block hasn't affected legitimate traffic",
            "Review VPN logs for prior access from same IP",
            "Notify user 'admin' to change password",
        ],
        mttd_minutes=4.2,
        mttr_minutes=8.7,
    )

    print("\nResult:")
    print(json.dumps(result, indent=2))

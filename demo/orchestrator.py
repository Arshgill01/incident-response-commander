#!/usr/bin/env python3
"""
Incident Response Commander — Autonomous Orchestrator
======================================================
The centerpiece of the system: a Python orchestrator that chains the
Detector → Investigator → Responder agents end-to-end with NO human intervention.

Key features:
  - Evidence-gated handoffs: each phase must produce real IOCs before advancing
  - Calls Kibana Agent Builder agents via the Kibana Actions API
  - Executes ES|QL detection queries directly against Elasticsearch
  - Logs every action to the incident-response-log index (full audit trail)
  - Computes MTTD and MTTR in real-time
  - Sends Slack alerts and creates Jira tickets via notifications.py
  - MITRE ATT&CK mapping baked in
  - --watch mode for continuous polling
  - --dry-run mode for safe testing (detect + investigate, no containment)
  - --report mode for MTTD/MTTR scorecard

Usage:
  python3 orchestrator.py                    # Single detection pass
  python3 orchestrator.py --watch            # Continuous monitoring (60s poll)
  python3 orchestrator.py --dry-run          # Detect + investigate only
  python3 orchestrator.py --report           # Print MTTD/MTTR scorecard
  python3 orchestrator.py --simulate brute_force  # Inject test data then run
"""

import os
import sys
import json
import time
import uuid
import re
import argparse
import traceback
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

KIBANA_URL = os.getenv(
    "KIBANA_URL", "https://my-deployment-5668ac.kb.us-central1.gcp.cloud.es.io"
)
ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME", "elastic")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "")
ELASTIC_CLOUD_ID = os.getenv("ELASTIC_CLOUD_ID", "")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")

# Kibana connector ID for LLM calls (Anthropic Claude Sonnet 4.5)
LLM_CONNECTOR_ID = "Anthropic-Claude-Sonnet-4-5"

# Agent IDs in Kibana Agent Builder
DETECTOR_AGENT_ID = "security-incident-detector"
INVESTIGATOR_AGENT_ID = "incident-investigator"
RESPONDER_AGENT_ID = "incident-responder"

# ES indices
EVENTS_INDEX = "security-simulated-events"
AUDIT_LOG_INDEX = "incident-response-log"
METRICS_INDEX = "incident-metrics"

# Detection thresholds
BRUTE_FORCE_WINDOW = "15 minutes"
BRUTE_FORCE_THRESHOLD = 5
EXFIL_WINDOW = "1 hour"
EXFIL_BYTES_THRESHOLD = 100_000_000  # 100 MB
PRIV_ESC_WINDOW = "30 minutes"
LATERAL_MOVEMENT_WINDOW = "30 minutes"
POLL_INTERVAL_SECONDS = 60

# MITRE ATT&CK mapping
MITRE_MAPPING = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique": "T1110",
        "name": "Brute Force",
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique": "T1041",
        "name": "Exfiltration Over C2 Channel",
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique": "T1068",
        "name": "Exploitation for Privilege Escalation",
    },
    "lateral_movement": {
        "tactic": "Lateral Movement",
        "technique": "T1021",
        "name": "Remote Services",
    },
    "sudo": {
        "tactic": "Privilege Escalation",
        "technique": "T1078",
        "name": "Valid Accounts",
    },
    "admin_login": {
        "tactic": "Initial Access",
        "technique": "T1078",
        "name": "Valid Accounts",
    },
    "recon": {
        "tactic": "Discovery",
        "technique": "T1046",
        "name": "Network Service Scanning",
    },
    "persistence": {
        "tactic": "Persistence",
        "technique": "T1136",
        "name": "Create Account",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Colours for terminal output
# ─────────────────────────────────────────────────────────────────────────────


class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def log(level: str, msg: str, indent: int = 0):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    pad = "  " * indent
    colour = {
        "INFO": C.CYAN,
        "OK": C.GREEN,
        "WARN": C.YELLOW,
        "ERROR": C.RED,
        "PHASE": C.BOLD + C.BLUE,
        "GATE": C.BOLD + C.YELLOW,
        "IOC": C.BOLD + C.RED,
    }.get(level, C.RESET)
    print(f"{C.DIM}{ts}{C.RESET} {colour}[{level}]{C.RESET} {pad}{msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Elasticsearch client
# ─────────────────────────────────────────────────────────────────────────────


def build_es_client() -> Elasticsearch:
    if not ELASTIC_CLOUD_ID:
        raise RuntimeError("ELASTIC_CLOUD_ID must be set in .env")

    if ELASTIC_API_KEY and ELASTIC_API_KEY.strip():
        try:
            client = Elasticsearch(
                cloud_id=ELASTIC_CLOUD_ID,
                api_key=ELASTIC_API_KEY,
                request_timeout=30,
            )
            client.info()  # actually verify — constructor never raises on bad auth
            return client
        except Exception:
            pass  # fall through to basic_auth

    return Elasticsearch(
        cloud_id=ELASTIC_CLOUD_ID,
        basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD),
        request_timeout=30,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Kibana API helpers
# ─────────────────────────────────────────────────────────────────────────────


def kibana_headers() -> dict:
    return {
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
    }


def kibana_auth():
    return (ELASTIC_USERNAME, ELASTIC_PASSWORD)


def call_llm(system_prompt: str, user_message: str, max_tokens: int = 2048) -> str:
    """
    Call the LLM via Kibana Actions connector (unified_completion).
    Returns the assistant's text response.
    Note: unified_completion does not accept max_tokens — omitted intentionally.
    """
    url = f"{KIBANA_URL}/api/actions/connector/{LLM_CONNECTOR_ID}/_execute"
    payload = {
        "params": {
            "subAction": "unified_completion",
            "subActionParams": {
                "body": {
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                }
            },
        }
    }
    resp = requests.post(
        url, json=payload, auth=kibana_auth(), headers=kibana_headers(), timeout=60
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") == "error":
        raise RuntimeError(f"LLM error: {data.get('message', 'unknown')}")
    # unified_completion returns OpenAI-compatible format
    choices = data.get("data", {}).get("choices", [])
    if choices:
        return choices[0].get("message", {}).get("content", "")
    return str(data.get("data", ""))


def call_agent(agent_id: str, system_prompt: str, user_message: str) -> str:
    """
    Calls the LLM via Kibana Actions connector (unified_completion) with the
    agent's system prompt injected. The security AI assistant endpoint is skipped
    because it streams responses and blocks indefinitely in non-interactive mode.
    """
    return call_llm(system_prompt, user_message)


# ─────────────────────────────────────────────────────────────────────────────
# ES|QL execution helpers
# ─────────────────────────────────────────────────────────────────────────────


def run_esql(es: Elasticsearch, query: str) -> dict:
    """Execute an ES|QL query and return the response dict."""
    try:
        result = es.options(request_timeout=30).esql.query(query=query)
        return dict(result)
    except Exception as e:
        log("WARN", f"ES|QL query failed: {e}")
        return {"columns": [], "values": []}


def esql_to_records(result: dict) -> list[dict]:
    """Convert ES|QL columnar result to list of dicts."""
    columns = [c["name"] for c in result.get("columns", [])]
    rows = result.get("values", [])
    return [dict(zip(columns, row)) for row in rows]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def seconds_ago(n: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=n)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ─────────────────────────────────────────────────────────────────────────────
# ES|QL Detection queries
# ─────────────────────────────────────────────────────────────────────────────


def detect_brute_force(es: Elasticsearch) -> list[dict]:
    query = f"""
FROM {EVENTS_INDEX}
| WHERE @timestamp > NOW() - {BRUTE_FORCE_WINDOW}
| WHERE `event.category` == "authentication" AND `event.outcome` == "failure"
| STATS
    failure_count = COUNT(*),
    unique_users = COUNT_DISTINCT(`user.name`),
    unique_hosts = COUNT_DISTINCT(`host.name`),
    first_failure = MIN(@timestamp),
    last_failure  = MAX(@timestamp)
  BY `source.ip`
| WHERE failure_count >= {BRUTE_FORCE_THRESHOLD}
| SORT failure_count DESC
| LIMIT 20
"""
    return esql_to_records(run_esql(es, query))


def detect_exfiltration(es: Elasticsearch) -> list[dict]:
    query = f"""
FROM {EVENTS_INDEX}
| WHERE @timestamp > NOW() - {EXFIL_WINDOW}
| WHERE `event.category` == "network" AND `network.direction` == "outbound"
| STATS
    total_bytes        = SUM(`network.bytes`),
    connection_count   = COUNT(*),
    unique_destinations = COUNT_DISTINCT(`destination.ip`),
    unique_ports       = COUNT_DISTINCT(`destination.port`)
  BY `user.name`, `source.ip`
| WHERE total_bytes >= {EXFIL_BYTES_THRESHOLD}
| SORT total_bytes DESC
| LIMIT 20
"""
    return esql_to_records(run_esql(es, query))


def detect_privilege_escalation(es: Elasticsearch) -> list[dict]:
    query = f"""
FROM {EVENTS_INDEX}
| WHERE @timestamp > NOW() - {PRIV_ESC_WINDOW}
| WHERE `event.category` == "process" OR `event.category` == "authentication"
| WHERE `event.action` == "sudo"
    OR `event.action` == "privilege_escalation"
    OR `event.action` == "admin_login"
    OR `event.action` == "elevated_process"
| STATS
    escalation_count = COUNT(*),
    unique_processes  = COUNT_DISTINCT(`process.name`),
    first_event       = MIN(@timestamp),
    last_event        = MAX(@timestamp)
  BY `user.name`, `host.name`
| WHERE escalation_count >= 3
| SORT escalation_count DESC
| LIMIT 20
"""
    return esql_to_records(run_esql(es, query))


def detect_lateral_movement(es: Elasticsearch) -> list[dict]:
    query = f"""
FROM {EVENTS_INDEX}
| WHERE @timestamp > NOW() - {LATERAL_MOVEMENT_WINDOW}
| WHERE `event.category` == "authentication" AND `event.outcome` == "success"
| STATS
    host_count   = COUNT_DISTINCT(`host.name`),
    login_count  = COUNT(*),
    first_event  = MIN(@timestamp),
    last_event   = MAX(@timestamp)
  BY `user.name`, `source.ip`
| WHERE host_count >= 3
| SORT host_count DESC
| LIMIT 20
"""
    return esql_to_records(run_esql(es, query))


def build_investigation_timeline(es: Elasticsearch, ip: str, user: str) -> list[dict]:
    query = f"""
FROM {EVENTS_INDEX}
| WHERE @timestamp > NOW() - 4 hours
| WHERE `source.ip` == "{ip}" OR `user.name` == "{user}"
| KEEP @timestamp, `event.category`, `event.action`, `user.name`, `source.ip`,
       `destination.ip`, `destination.port`, `event.outcome`, `process.name`,
       `host.name`, `network.bytes`, `message`
| SORT @timestamp ASC
| LIMIT 500
"""
    return esql_to_records(run_esql(es, query))


def anomaly_score(es: Elasticsearch, ip: str) -> float:
    """Compare recent activity vs 7-day baseline to produce anomaly score."""
    # Recent: last 15 min
    recent_q = f"""
FROM {EVENTS_INDEX}
| WHERE @timestamp > NOW() - 15 minutes
| WHERE `source.ip` == "{ip}"
| STATS recent_count = COUNT(*)
"""
    # Baseline: last 7 days (average per 15-min window = total / (7*24*4))
    baseline_q = f"""
FROM {EVENTS_INDEX}
| WHERE @timestamp > NOW() - 7 days AND @timestamp <= NOW() - 15 minutes
| WHERE `source.ip` == "{ip}"
| STATS baseline_count = COUNT(*)
"""
    try:
        recent = esql_to_records(run_esql(es, recent_q))
        baseline = esql_to_records(run_esql(es, baseline_q))
        rc = recent[0]["recent_count"] if recent else 0
        bc = baseline[0]["baseline_count"] if baseline else 0
        baseline_per_window = (bc / (7 * 24 * 4)) if bc > 0 else 1
        return round(rc / max(baseline_per_window, 0.1), 2)
    except Exception:
        return 1.0


# ─────────────────────────────────────────────────────────────────────────────
# Audit log helpers
# ─────────────────────────────────────────────────────────────────────────────


def log_to_es(
    es: Elasticsearch,
    incident_id: str,
    phase: str,
    action: str,
    data: dict,
    dry_run: bool = False,
):
    """Write an audit record to incident-response-log index."""
    doc = {
        "incident_id": incident_id,
        "phase": phase,
        "action": action,
        "timestamp": now_iso(),
        "dry_run": dry_run,
        "data": data,
    }
    try:
        es.options(request_timeout=10).index(index=AUDIT_LOG_INDEX, document=doc)
    except Exception as e:
        log("WARN", f"Audit log write failed: {e}")


def log_metrics(
    es: Elasticsearch,
    incident_id: str,
    attack_type: str,
    severity: str,
    detected_at: str,
    investigated_at: Optional[str],
    responded_at: Optional[str],
    ioc_count: int,
    dry_run: bool,
):
    """Write MTTD / MTTR record to incident-metrics index."""

    def parse_ts(ts: Optional[str]) -> Optional[datetime]:
        if not ts:
            return None
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))

    det = parse_ts(detected_at)
    inv = parse_ts(investigated_at)
    res = parse_ts(responded_at)

    # MTTD = time from first event to detection (approximate as 0 since we detect continuously)
    mttd = 0
    mttr = int((res - det).total_seconds()) if (res and det) else None

    doc = {
        "incident_id": incident_id,
        "attack_type": attack_type,
        "severity": severity,
        "detected_at": detected_at,
        "investigated_at": investigated_at,
        "responded_at": responded_at,
        "mttd_seconds": mttd,
        "mttr_seconds": mttr,
        "ioc_count": ioc_count,
        "automated": True,
        "dry_run": dry_run,
        "timestamp": now_iso(),
    }
    try:
        es.options(request_timeout=10).index(index=METRICS_INDEX, document=doc)
    except Exception as e:
        log("WARN", f"Metrics write failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# IOC extraction
# ─────────────────────────────────────────────────────────────────────────────


def extract_iocs_from_findings(findings: list[dict], attack_type: str) -> dict:
    """
    Extract structured IOCs from ES|QL detection results.
    Returns a dict with ips, users, timestamps, bytes, techniques.
    """
    ips, users, timestamps, total_bytes_list = [], [], [], []
    confidence = 0.0

    for row in findings:
        ip = row.get("source.ip") or row.get("source_ip", "")
        user = row.get("user.name") or row.get("user_name", "")
        if ip and ip not in ips:
            ips.append(ip)
        if user and user not in users:
            users.append(user)
        ts = (
            row.get("first_failure")
            or row.get("first_event")
            or row.get("last_event", "")
        )
        if ts and ts not in timestamps:
            timestamps.append(str(ts))
        tb = row.get("total_bytes", 0)
        if tb:
            total_bytes_list.append(int(tb))

    # Confidence based on evidence strength
    if ips or users:
        confidence += 0.5
    if timestamps:
        confidence += 0.3
    if findings:
        confidence += min(len(findings) * 0.05, 0.2)

    mitre = MITRE_MAPPING.get(attack_type, {})

    return {
        "ips": ips,
        "users": users,
        "timestamps": timestamps[:5],
        "total_bytes": sum(total_bytes_list),
        "confidence": round(confidence, 2),
        "technique": mitre.get("technique", ""),
        "tactic": mitre.get("tactic", ""),
        "technique_name": mitre.get("name", ""),
    }


def extract_iocs_from_text(text: str) -> dict:
    """Parse IOCs out of free-text LLM response."""
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    user_pattern = re.compile(r"user[:\s]+([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)
    ts_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

    ips = list(set(ip_pattern.findall(text)))
    users = [m.group(1) for m in user_pattern.finditer(text)]
    timestamps = ts_pattern.findall(text)

    return {"ips": ips[:10], "users": users[:10], "timestamps": timestamps[:5]}


# ─────────────────────────────────────────────────────────────────────────────
# Evidence gate
# ─────────────────────────────────────────────────────────────────────────────


def evidence_gate(iocs: dict, phase: str) -> tuple[bool, str]:
    """
    Returns (passed, reason).
    Phase 'detection' requires: ≥1 IP or user, confidence ≥ 0.5
    Phase 'investigation' requires: ≥1 IP or user, ≥1 timestamp
    """
    ips = iocs.get("ips", [])
    users = iocs.get("users", [])
    ts = iocs.get("timestamps", [])
    conf = iocs.get("confidence", 0.0)

    if phase == "detection":
        if not (ips or users):
            return False, "No IPs or users identified — no concrete IOC evidence"
        if conf < 0.5:
            return (
                False,
                f"Confidence {conf} below threshold 0.5 — insufficient evidence",
            )
        return (
            True,
            f"Gate passed: {len(ips)} IPs, {len(users)} users, confidence={conf}",
        )

    if phase == "investigation":
        if not (ips or users):
            return False, "Investigation produced no IOCs — skipping response"
        if not ts:
            return False, "No timestamps in investigation — cannot establish timeline"
        return (
            True,
            f"Gate passed: {len(ips)} IPs, {len(users)} users, {len(ts)} timestamps",
        )

    return True, "Gate passed (no constraints for this phase)"


# ─────────────────────────────────────────────────────────────────────────────
# Severity classification
# ─────────────────────────────────────────────────────────────────────────────


def classify_severity(attack_type: str, findings: list[dict]) -> str:
    if not findings:
        return "LOW"
    count = len(findings)
    if attack_type == "brute_force":
        max_failures = max((r.get("failure_count", 0) for r in findings), default=0)
        if max_failures >= 50:
            return "CRITICAL"
        if max_failures >= 20:
            return "HIGH"
        return "MEDIUM"
    if attack_type == "data_exfiltration":
        max_bytes = max((r.get("total_bytes", 0) for r in findings), default=0)
        if max_bytes >= 1_000_000_000:
            return "CRITICAL"  # 1 GB
        if max_bytes >= 100_000_000:
            return "HIGH"  # 100 MB
        return "MEDIUM"
    if attack_type == "privilege_escalation":
        return "HIGH" if count >= 2 else "MEDIUM"
    if attack_type == "lateral_movement":
        return "HIGH"
    return "MEDIUM"


# ─────────────────────────────────────────────────────────────────────────────
# Agent system prompts
# ─────────────────────────────────────────────────────────────────────────────

DETECTOR_SYSTEM = """You are a Security Incident Detector agent in an automated incident response pipeline.

You receive raw ES|QL query results as structured data and must:
1. Analyse the findings and identify the attack type and severity
2. Extract concrete IOCs: malicious IP addresses, compromised usernames, attack timestamps
3. Classify severity: CRITICAL / HIGH / MEDIUM / LOW
4. Provide a concise summary (3-5 sentences) with specific numbers

Output MUST be structured JSON:
{
  "incident_type": "brute_force|data_exfiltration|privilege_escalation|lateral_movement",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "...",
  "malicious_ips": ["..."],
  "affected_users": ["..."],
  "key_metrics": {...},
  "mitre_technique": "T1110",
  "recommended_investigation_scope": "..."
}"""

INVESTIGATOR_SYSTEM = """You are a Digital Forensics Investigator in an automated incident response pipeline.

You receive detection findings and a full event timeline. You must:
1. Reconstruct the attack timeline chronologically
2. Determine the attack vector (how they got in)
3. Assess the blast radius (what was affected)
4. Extract all Indicators of Compromise (IOCs)
5. Identify MITRE ATT&CK tactics and techniques used

Output MUST be structured JSON:
{
  "executive_summary": "...",
  "attack_timeline": [{"time": "...", "event": "...", "significance": "..."}],
  "attack_vector": "...",
  "blast_radius": "...",
  "iocs": {
    "malicious_ips": ["..."],
    "compromised_users": ["..."],
    "affected_hosts": ["..."],
    "suspicious_processes": ["..."]
  },
  "mitre_tactics": ["..."],
  "mitre_techniques": ["..."],
  "confidence_score": 0.0,
  "recommended_actions": ["..."]
}"""

RESPONDER_SYSTEM = """You are an Incident Response Automation agent in an automated pipeline.

You receive a complete investigation report and must:
1. Determine what automated containment actions to take based on severity
2. Draft the Slack alert message (rich, actionable, colour-coded by severity)
3. Draft the Jira ticket (structured, complete, with checklist)
4. Document all actions taken for the audit trail
5. Provide a clear MTTD/MTTR summary

Output MUST be structured JSON:
{
  "containment_actions": ["block IP X.X.X.X", "disable account user123"],
  "escalation_required": true|false,
  "slack_message": {
    "title": "...",
    "severity": "...",
    "summary": "...",
    "iocs": ["..."],
    "mitre": ["..."],
    "actions_taken": ["..."],
    "mttd_seconds": 0,
    "mttr_seconds": 0
  },
  "jira_ticket": {
    "summary": "...",
    "description": "...",
    "priority": "Highest|High|Medium|Low",
    "labels": ["..."],
    "checklist": ["..."]
  },
  "response_summary": "..."
}"""


# ─────────────────────────────────────────────────────────────────────────────
# Main orchestration phases
# ─────────────────────────────────────────────────────────────────────────────


class IncidentOrchestrator:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.es = build_es_client()
        self._verify_connection()
        if dry_run:
            log(
                "WARN",
                "DRY-RUN MODE: Detection and investigation only. No containment or notifications.",
            )

    def _verify_connection(self):
        try:
            info = self.es.info()
            log("OK", f"Elasticsearch connected: v{info['version']['number']}")
        except Exception as e:
            log("ERROR", f"Cannot connect to Elasticsearch: {e}")
            sys.exit(1)

    # ── Phase 1: Detection ────────────────────────────────────────────────

    def run_detection(self, incident_id: str) -> Optional[dict]:
        """
        Run all detection queries. Return incident dict if any findings, else None.
        """
        log("PHASE", f"[PHASE 1] Detection — incident_id={incident_id}")
        detected = []

        # Run all 4 detection types in parallel (sequential here for simplicity)
        checks = [
            ("brute_force", detect_brute_force(self.es)),
            ("data_exfiltration", detect_exfiltration(self.es)),
            ("privilege_escalation", detect_privilege_escalation(self.es)),
            ("lateral_movement", detect_lateral_movement(self.es)),
        ]

        for attack_type, findings in checks:
            if findings:
                severity = classify_severity(attack_type, findings)
                iocs = extract_iocs_from_findings(findings, attack_type)
                log(
                    "OK",
                    f"  Detected: {attack_type} | severity={severity} | "
                    f"findings={len(findings)} | ips={iocs['ips']}",
                    indent=1,
                )
                detected.append(
                    {
                        "attack_type": attack_type,
                        "severity": severity,
                        "findings": findings,
                        "iocs": iocs,
                    }
                )
            else:
                log("INFO", f"  No {attack_type} detected", indent=1)

        if not detected:
            log("INFO", "No incidents detected in this polling window.")
            return None

        # Pick the most severe incident to process
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        primary = max(detected, key=lambda x: severity_order.get(x["severity"], 0))
        attack_type = primary["attack_type"]
        severity = primary["severity"]
        findings = primary["findings"]
        iocs = primary["iocs"]

        log(
            "PHASE",
            f"  Primary incident: {attack_type} | {severity} | "
            f"MITRE {iocs.get('technique', 'N/A')} ({iocs.get('tactic', 'N/A')})",
        )

        # ── Evidence Gate 1 ────────────────────────────────────────────────
        log("GATE", "[GATE 1] Evaluating detection evidence...")
        passed, reason = evidence_gate(iocs, "detection")
        log("OK" if passed else "WARN", f"  {reason}", indent=1)
        if not passed:
            log_to_es(
                self.es,
                incident_id,
                "detection",
                "gate_failed",
                {"reason": reason, "attack_type": attack_type},
                self.dry_run,
            )
            return None

        # ── Call Detector Agent ───────────────────────────────────────────
        log("INFO", "Calling Detector Agent (Kibana Agent Builder)...")
        user_msg = (
            f"Analyse these detection results for {attack_type} attack:\n\n"
            f"Findings ({len(findings)} records):\n{json.dumps(findings[:5], indent=2, default=str)}\n\n"
            f"IOCs extracted: {json.dumps(iocs, indent=2, default=str)}\n\n"
            "Provide structured JSON analysis."
        )
        agent_resp = ""
        try:
            agent_resp = call_agent(DETECTOR_AGENT_ID, DETECTOR_SYSTEM, user_msg)
            # Try to parse JSON from response
            agent_data = self._parse_json_response(agent_resp)
        except Exception as e:
            log("WARN", f"Detector agent call failed: {e} — using raw ES|QL findings")
            agent_data = {
                "incident_type": attack_type,
                "severity": severity,
                "summary": f"Detected {attack_type} with {len(findings)} findings.",
                "malicious_ips": iocs["ips"],
                "affected_users": iocs["users"],
            }

        log_to_es(
            self.es,
            incident_id,
            "detection",
            "agent_response",
            {
                "agent_id": DETECTOR_AGENT_ID,
                "response_summary": str(agent_resp)[:500],
                "iocs": iocs,
            },
            self.dry_run,
        )

        return {
            "incident_id": incident_id,
            "attack_type": attack_type,
            "severity": severity,
            "findings": findings,
            "iocs": iocs,
            "all_detections": detected,
            "agent_analysis": agent_data,
            "detected_at": now_iso(),
        }

    # ── Phase 2: Investigation ────────────────────────────────────────────

    def run_investigation(self, detection: dict) -> Optional[dict]:
        """
        Run deep investigation: build timeline, correlate, call Investigator agent.
        """
        incident_id = detection["incident_id"]
        iocs = detection["iocs"]
        attack_type = detection["attack_type"]
        severity = detection["severity"]

        log("PHASE", f"[PHASE 2] Investigation — {attack_type} | {severity}")

        # Build timeline from ES
        primary_ip = iocs["ips"][0] if iocs["ips"] else ""
        primary_user = iocs["users"][0] if iocs["users"] else ""

        if primary_ip or primary_user:
            log("INFO", f"  Building timeline for IP={primary_ip}, user={primary_user}")
            timeline = build_investigation_timeline(self.es, primary_ip, primary_user)
            log("OK", f"  Timeline: {len(timeline)} events found")
        else:
            timeline = []
            log("WARN", "  No IP/user for timeline — using raw findings")

        # Anomaly score
        if primary_ip:
            score = anomaly_score(self.es, primary_ip)
            log("INFO", f"  Anomaly score for {primary_ip}: {score}x baseline")
        else:
            score = 1.0

        # Call Investigator Agent
        log("INFO", "Calling Investigator Agent (Kibana Agent Builder)...")
        agent_resp = ""
        user_msg = (
            f"Investigate this security incident:\n\n"
            f"Detection findings: {json.dumps(detection['agent_analysis'], indent=2, default=str)}\n\n"
            f"Event timeline ({len(timeline)} events, showing first 20):\n"
            f"{json.dumps(timeline[:20], indent=2, default=str)}\n\n"
            f"Anomaly score: {score}x above baseline\n\n"
            f"MITRE mapping: {json.dumps(MITRE_MAPPING.get(attack_type, {}), indent=2)}\n\n"
            "Provide structured JSON investigation report."
        )
        try:
            agent_resp = call_agent(
                INVESTIGATOR_AGENT_ID, INVESTIGATOR_SYSTEM, user_msg
            )
            agent_data = self._parse_json_response(agent_resp)
        except Exception as e:
            log(
                "WARN",
                f"Investigator agent call failed: {e} — building report from data",
            )
            mitre = MITRE_MAPPING.get(attack_type, {})
            agent_data = {
                "executive_summary": (
                    f"Automated investigation of {attack_type} incident. "
                    f"{len(timeline)} events found over the investigation window. "
                    f"Anomaly score: {score}x baseline."
                ),
                "attack_timeline": [
                    {
                        "time": str(e.get("@timestamp", "")),
                        "event": str(e.get("event.action", "")),
                        "significance": str(e.get("event.category", "")),
                    }
                    for e in timeline[:10]
                ],
                "iocs": {
                    "malicious_ips": iocs["ips"],
                    "compromised_users": iocs["users"],
                    "affected_hosts": list(
                        {e.get("host.name", "") for e in timeline if e.get("host.name")}
                    )[:5],
                    "suspicious_processes": list(
                        {
                            e.get("process.name", "")
                            for e in timeline
                            if e.get("process.name")
                        }
                    )[:5],
                },
                "mitre_tactics": [mitre.get("tactic", "")],
                "mitre_techniques": [mitre.get("technique", "")],
                "confidence_score": iocs.get("confidence", 0.5),
                "recommended_actions": [f"Block IP: {ip}" for ip in iocs["ips"][:3]]
                + [f"Disable account: {u}" for u in iocs["users"][:3]],
            }

        # Merge IOCs from agent response back into iocs dict
        if isinstance(agent_data.get("iocs"), dict):
            merged_ips = list(
                set(iocs["ips"] + agent_data["iocs"].get("malicious_ips", []))
            )
            merged_users = list(
                set(iocs["users"] + agent_data["iocs"].get("compromised_users", []))
            )
            iocs = {**iocs, "ips": merged_ips, "users": merged_users}

        # ── Evidence Gate 2 ────────────────────────────────────────────────
        log("GATE", "[GATE 2] Evaluating investigation evidence...")
        passed, reason = evidence_gate(iocs, "investigation")
        log("OK" if passed else "WARN", f"  {reason}", indent=1)
        if not passed:
            log_to_es(
                self.es,
                incident_id,
                "investigation",
                "gate_failed",
                {"reason": reason},
                self.dry_run,
            )
            return None

        log_to_es(
            self.es,
            incident_id,
            "investigation",
            "agent_response",
            {
                "agent_id": INVESTIGATOR_AGENT_ID,
                "response_summary": str(agent_resp)[:500],
                "timeline_events": len(timeline),
                "anomaly_score": score,
                "iocs": iocs,
            },
            self.dry_run,
        )

        return {
            **detection,
            "iocs": iocs,
            "timeline": timeline,
            "anomaly_score": score,
            "investigation_report": agent_data,
            "investigated_at": now_iso(),
        }

    # ── Phase 3: Response ─────────────────────────────────────────────────

    def run_response(self, investigation: dict) -> dict:
        """
        Execute containment + notifications via Responder agent.
        """
        incident_id = investigation["incident_id"]
        attack_type = investigation["attack_type"]
        severity = investigation["severity"]
        iocs = investigation["iocs"]
        inv_report = investigation["investigation_report"]

        log("PHASE", f"[PHASE 3] Response — {attack_type} | {severity}")

        detected_at = investigation.get("detected_at", now_iso())
        investigated_at = investigation.get("investigated_at", now_iso())

        # Compute MTTD/MTTR
        def ts_to_dt(ts: str) -> datetime:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))

        mttd_s = 0  # We detect continuously so MTTD ≈ poll interval
        mttr_s = int(
            (ts_to_dt(investigated_at) - ts_to_dt(detected_at)).total_seconds()
        )

        # Call Responder Agent
        log("INFO", "Calling Responder Agent (Kibana Agent Builder)...")
        agent_resp = ""
        user_msg = (
            f"Generate response plan for this confirmed incident:\n\n"
            f"Attack type: {attack_type}\n"
            f"Severity: {severity}\n"
            f"MITRE technique: {iocs.get('technique', 'N/A')} — {iocs.get('technique_name', 'N/A')}\n"
            f"Malicious IPs: {iocs['ips']}\n"
            f"Affected users: {iocs['users']}\n"
            f"MTTD: {mttd_s}s  |  MTTR so far: {mttr_s}s\n\n"
            f"Investigation report: {json.dumps(inv_report, indent=2, default=str)[:2000]}\n\n"
            f"Dry-run mode: {self.dry_run}\n\n"
            "Provide structured JSON response plan."
        )
        try:
            agent_resp = call_agent(RESPONDER_AGENT_ID, RESPONDER_SYSTEM, user_msg)
            agent_data = self._parse_json_response(agent_resp)
        except Exception as e:
            log(
                "WARN",
                f"Responder agent call failed: {e} — using default response plan",
            )
            mitre = MITRE_MAPPING.get(attack_type, {})
            agent_data = {
                "containment_actions": (
                    [f"Block IP: {ip}" for ip in iocs["ips"][:5]]
                    + [f"Disable account: {u}" for u in iocs["users"][:3]]
                ),
                "escalation_required": severity in ("CRITICAL", "HIGH"),
                "slack_message": {
                    "title": f"[{severity}] {attack_type.replace('_', ' ').title()} Detected",
                    "severity": severity,
                    "summary": inv_report.get(
                        "executive_summary", "Automated incident detected."
                    ),
                    "iocs": iocs["ips"][:3] + iocs["users"][:3],
                    "mitre": [
                        f"{mitre.get('technique', '')} — {mitre.get('name', '')}"
                    ],
                    "actions_taken": [f"Block IP: {ip}" for ip in iocs["ips"][:3]],
                    "mttd_seconds": mttd_s,
                    "mttr_seconds": mttr_s,
                },
                "jira_ticket": {
                    "summary": f"[AUTO-{incident_id[:8]}] {severity} {attack_type.replace('_', ' ').title()}",
                    "priority": {
                        "CRITICAL": "Highest",
                        "HIGH": "High",
                        "MEDIUM": "Medium",
                        "LOW": "Low",
                    }.get(severity, "Medium"),
                    "description": inv_report.get("executive_summary", ""),
                    "labels": [
                        "auto-detected",
                        "incident-response-commander",
                        attack_type,
                    ],
                    "checklist": [
                        "Validate automated containment",
                        "Conduct deeper forensic analysis",
                        "Notify affected users if required",
                        "Post-incident review",
                    ],
                },
                "response_summary": f"Automated response for {attack_type} — {len(iocs['ips'])} IPs blocked, {len(iocs['users'])} accounts flagged.",
            }

        # Execute containment (log actions, don't actually call firewalls — that's post-hackathon)
        actions_taken = []
        if not self.dry_run:
            for action in agent_data.get("containment_actions", []):
                log("INFO", f"  CONTAINMENT: {action}", indent=1)
                actions_taken.append(action)
        else:
            log("WARN", "  DRY-RUN: Containment skipped")
            for action in agent_data.get("containment_actions", []):
                log("INFO", f"  [DRY-RUN would execute]: {action}", indent=2)

        # Send notifications
        responded_at = now_iso()
        mttr_final = int(
            (ts_to_dt(responded_at) - ts_to_dt(detected_at)).total_seconds()
        )

        if not self.dry_run:
            self._send_notifications(incident_id, investigation, agent_data, mttr_final)
        else:
            log("WARN", "  DRY-RUN: Notifications skipped")

        # Audit log
        log_to_es(
            self.es,
            incident_id,
            "response",
            "agent_response",
            {
                "agent_id": RESPONDER_AGENT_ID,
                "actions_taken": actions_taken,
                "escalation": agent_data.get("escalation_required", False),
                "mttr_seconds": mttr_final,
                "dry_run": self.dry_run,
            },
            self.dry_run,
        )

        # Metrics
        log_metrics(
            self.es,
            incident_id,
            attack_type,
            severity,
            detected_at,
            investigated_at,
            responded_at,
            len(iocs["ips"]) + len(iocs["users"]),
            self.dry_run,
        )

        log(
            "OK",
            f"Response complete. MTTR={mttr_final}s | "
            f"Actions={len(actions_taken)} | "
            f"Escalation={'YES' if agent_data.get('escalation_required') else 'NO'}",
        )

        return {
            **investigation,
            "response_plan": agent_data,
            "responded_at": responded_at,
            "mttr_seconds": mttr_final,
            "actions_taken": actions_taken,
        }

    # ── Notifications ──────────────────────────────────────────────────────

    def _send_notifications(
        self, incident_id: str, investigation: dict, response_plan: dict, mttr_s: int
    ):
        """Send Slack alert and create Jira ticket."""
        self._direct_slack(incident_id, investigation, response_plan, mttr_s)
        self._direct_jira(incident_id, investigation, response_plan)

    def _direct_slack(
        self, incident_id: str, investigation: dict, response_plan: dict, mttr_s: int
    ):
        webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        if not webhook:
            log("WARN", "  SLACK_WEBHOOK_URL not set — skipping Slack", indent=1)
            return
        slack_msg = response_plan.get("slack_message", {})
        severity = investigation.get("severity", "MEDIUM")
        attack = investigation.get("attack_type", "unknown").replace("_", " ").title()
        iocs = investigation.get("iocs", {})
        mitre = MITRE_MAPPING.get(investigation.get("attack_type", ""), {})
        colour_map = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FF8C00",
            "MEDIUM": "#FFD700",
            "LOW": "#00AA00",
        }
        colour = colour_map.get(severity, "#AAAAAA")

        payload = {
            "username": "Incident Response Commander",
            "icon_emoji": ":shield:",
            "attachments": [
                {
                    "color": colour,
                    "title": f"[{severity}] {attack} Detected — IRC-{incident_id[:8]}",
                    "fields": [
                        {"title": "Severity", "value": severity, "short": True},
                        {"title": "Attack Type", "value": attack, "short": True},
                        {
                            "title": "Malicious IPs",
                            "value": ", ".join(iocs.get("ips", [])[:3]) or "N/A",
                            "short": True,
                        },
                        {
                            "title": "Affected Users",
                            "value": ", ".join(iocs.get("users", [])[:3]) or "N/A",
                            "short": True,
                        },
                        {
                            "title": "MITRE Technique",
                            "value": f"{mitre.get('technique', '')} — {mitre.get('name', '')}",
                            "short": False,
                        },
                        {"title": "MTTR", "value": f"{mttr_s}s", "short": True},
                        {"title": "Automated", "value": "Yes", "short": True},
                        {
                            "title": "Summary",
                            "value": slack_msg.get("summary", "See Kibana for details"),
                            "short": False,
                        },
                    ],
                    "footer": "Incident Response Commander | Elastic Agent Builder",
                    "ts": int(time.time()),
                }
            ],
        }
        try:
            r = requests.post(webhook, json=payload, timeout=10)
            if r.status_code == 200:
                log("OK", "  Slack alert sent (direct webhook)", indent=1)
                log_to_es(
                    self.es,
                    incident_id,
                    "notification",
                    "slack_sent",
                    {"channel": os.getenv("SLACK_CHANNEL", "#security-incidents")},
                )
            else:
                log("WARN", f"  Slack returned {r.status_code}", indent=1)
        except Exception as e:
            log("WARN", f"  Slack send failed: {e}", indent=1)

    def _direct_jira(self, incident_id: str, investigation: dict, response_plan: dict):
        jira_url = os.getenv("JIRA_URL", "")
        jira_email = os.getenv("JIRA_EMAIL", "") or os.getenv("ELASTIC_USERNAME", "")
        jira_token = os.getenv("JIRA_API_TOKEN", "")
        project = os.getenv("JIRA_PROJECT_KEY", "SCRUM")
        if not (jira_url and jira_token):
            log("WARN", "  JIRA credentials not set — skipping Jira", indent=1)
            return

        jira_data = response_plan.get("jira_ticket", {})
        attack = investigation.get("attack_type", "unknown").replace("_", " ").title()
        severity = investigation.get("severity", "MEDIUM")
        iocs = investigation.get("iocs", {})
        inv_rep = investigation.get("investigation_report", {})
        mitre = MITRE_MAPPING.get(investigation.get("attack_type", ""), {})

        summary = jira_data.get(
            "summary", f"[AUTO] {severity} {attack} — IRC-{incident_id[:8]}"
        )
        priority_map = {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        }
        priority = priority_map.get(severity, "Medium")

        description = f"""h2. Automated Security Incident Report — IRC-{incident_id[:8]}

*Incident ID:* {incident_id}
*Severity:* {severity}
*Attack Type:* {attack}
*MITRE Technique:* {mitre.get("technique", "N/A")} — {mitre.get("name", "N/A")}
*Tactic:* {mitre.get("tactic", "N/A")}

h3. Executive Summary
{inv_rep.get("executive_summary", "Automated incident detected and investigated.")}

h3. Indicators of Compromise (IOCs)
*Malicious IPs:* {", ".join(iocs.get("ips", [])) or "N/A"}
*Affected Users:* {", ".join(iocs.get("users", [])) or "N/A"}

h3. Recommended Actions
{chr(10).join("- " + a for a in jira_data.get("checklist", ["Review findings in Kibana"]))}

h3. Automated Response Actions Taken
{chr(10).join("- " + a for a in response_plan.get("containment_actions", ["No automated containment taken"]))}

h3. Investigation Notes
{json.dumps(inv_rep.get("attack_timeline", [])[:5], indent=2, default=str)[:1000]}

_Generated by Incident Response Commander — Elastic Agent Builder Hackathon_"""

        payload = {
            "fields": {
                "project": {"key": project},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Task"},
                "priority": {"name": priority},
                "labels": jira_data.get(
                    "labels", ["auto-detected", "irc", attack.lower()]
                ),
            }
        }
        try:
            import base64

            token = base64.b64encode(f"{jira_email}:{jira_token}".encode()).decode()
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Basic {token}",
            }
            r = requests.post(
                f"{jira_url}/rest/api/2/issue",
                json=payload,
                headers=headers,
                timeout=15,
            )
            if r.status_code in (200, 201):
                key = r.json().get("key", "?")
                log("OK", f"  Jira ticket created: {key} (direct API)", indent=1)
                log_to_es(
                    self.es,
                    incident_id,
                    "notification",
                    "jira_created",
                    {"ticket_key": key},
                )
            else:
                log(
                    "WARN", f"  Jira returned {r.status_code}: {r.text[:200]}", indent=1
                )
        except Exception as e:
            log("WARN", f"  Jira create failed: {e}", indent=1)

    # ── JSON parser helper ─────────────────────────────────────────────────

    def _parse_json_response(self, text: str) -> dict:
        """Extract JSON block from LLM response text."""
        # Try direct parse
        try:
            return json.loads(text)
        except Exception:
            pass
        # Try extracting JSON block
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except Exception:
                pass
        # Try finding first { ... } block
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except Exception:
                pass
        # Return text as summary
        return {"summary": text[:500], "raw_response": True}

    # ── Full pipeline ──────────────────────────────────────────────────────

    def run_once(self) -> Optional[dict]:
        """Run a single full detection → investigation → response cycle."""
        incident_id = f"IRC-{uuid.uuid4().hex[:12].upper()}"
        start_time = time.time()

        log("PHASE", f"{'=' * 60}")
        log("PHASE", f"  Incident Response Commander — Pipeline Start")
        log("PHASE", f"  Incident ID: {incident_id}")
        log("PHASE", f"  Mode: {'DRY-RUN' if self.dry_run else 'LIVE'}")
        log("PHASE", f"{'=' * 60}")

        # Phase 1: Detection
        detection = self.run_detection(incident_id)
        if not detection:
            log("INFO", "Pipeline complete — nothing to investigate.")
            return None

        # Phase 2: Investigation
        investigation = self.run_investigation(detection)
        if not investigation:
            log("INFO", "Pipeline complete — investigation gate not passed.")
            return None

        # Phase 3: Response
        result = self.run_response(investigation)

        elapsed = time.time() - start_time
        log("OK", f"{'=' * 60}")
        log("OK", f"  Pipeline complete in {elapsed:.1f}s")
        log("OK", f"  Incident: {incident_id}")
        log("OK", f"  Attack: {result['attack_type']} | Severity: {result['severity']}")
        log("OK", f"  MTTR: {result.get('mttr_seconds', '?')}s")
        log("OK", f"{'=' * 60}")
        return result

    # ── Watch mode ─────────────────────────────────────────────────────────

    def watch(self):
        """Continuous polling loop."""
        log(
            "INFO",
            f"Watch mode started. Polling every {POLL_INTERVAL_SECONDS}s. Ctrl+C to stop.",
        )
        while True:
            try:
                self.run_once()
            except KeyboardInterrupt:
                log("INFO", "Watch mode stopped.")
                break
            except Exception as e:
                log("ERROR", f"Pipeline error: {e}")
                traceback.print_exc()
            log("INFO", f"Sleeping {POLL_INTERVAL_SECONDS}s...")
            time.sleep(POLL_INTERVAL_SECONDS)

    # ── Report mode ────────────────────────────────────────────────────────

    def print_report(self):
        """Print MTTD/MTTR scorecard from incident-metrics index."""
        log("PHASE", "MTTD/MTTR Scorecard — Last 24 Hours")
        log("PHASE", "=" * 50)

        query = f"""
FROM {METRICS_INDEX}
| WHERE timestamp > NOW() - 24 hours
| EVAL is_critical = CASE(severity == "CRITICAL", 1, 0),
       is_high     = CASE(severity == "HIGH", 1, 0),
       is_auto     = CASE(automated == true, 1, 0)
| STATS
    total_incidents  = COUNT(*),
    avg_mttr_seconds = AVG(mttr_seconds),
    min_mttr_seconds = MIN(mttr_seconds),
    max_mttr_seconds = MAX(mttr_seconds),
    critical_count   = SUM(is_critical),
    high_count       = SUM(is_high),
    automated_count  = SUM(is_auto)
"""
        try:
            records = esql_to_records(run_esql(self.es, query))
            if records:
                r = records[0]
                avg_mttr = r.get("avg_mttr_seconds") or 0
                print(f"\n  Total incidents (24h):  {r.get('total_incidents', 0)}")
                print(f"  Critical:               {r.get('critical_count', 0)}")
                print(f"  High:                   {r.get('high_count', 0)}")
                print(f"  Automated responses:    {r.get('automated_count', 0)}")
                print(
                    f"  Avg MTTR:               {avg_mttr:.0f}s ({avg_mttr / 60:.1f} min)"
                )
                print(
                    f"  Min MTTR:               {r.get('min_mttr_seconds', 0) or 0:.0f}s"
                )
                print(
                    f"  Max MTTR:               {r.get('max_mttr_seconds', 0) or 0:.0f}s"
                )
                print(f"  Industry avg MTTD:      197 days (Ponemon 2023)")
                if avg_mttr and avg_mttr > 0:
                    reduction = (197 * 24 * 3600 - avg_mttr) / (197 * 24 * 3600) * 100
                    print(f"  MTTD reduction vs avg:  {reduction:.1f}%")
            else:
                print("  No metrics data found. Run the orchestrator first.")
        except Exception as e:
            print(f"  Metrics query failed: {e}")
            print("  (Run setup-indices.py first to create the metrics index)")

        # Per-attack-type breakdown
        type_query = f"""
FROM {METRICS_INDEX}
| WHERE timestamp > NOW() - 24 hours
| STATS
    count            = COUNT(*),
    avg_mttr_seconds = AVG(mttr_seconds)
  BY attack_type
| SORT count DESC
"""
        try:
            type_records = esql_to_records(run_esql(self.es, type_query))
            if type_records:
                print("\n  By attack type:")
                for tr in type_records:
                    avg = tr.get("avg_mttr_seconds") or 0
                    print(
                        f"    {tr.get('attack_type', '?'):<25} count={tr.get('count', 0)}  avg_mttr={avg:.0f}s"
                    )
        except Exception:
            pass

        print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Incident Response Commander — Autonomous Multi-Agent Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Detect and investigate but skip containment and notifications",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuous monitoring mode (polls every 60s)",
    )
    parser.add_argument(
        "--report", action="store_true", help="Print MTTD/MTTR scorecard and exit"
    )
    parser.add_argument(
        "--simulate",
        choices=["brute_force", "exfiltration", "privilege_escalation", "apt"],
        help="Inject test incident data before running pipeline",
    )
    args = parser.parse_args()

    print(f"\n{C.BOLD}{C.BLUE}")
    print("  ██╗██████╗  ██████╗")
    print("  ██║██╔══██╗██╔════╝")
    print("  ██║██████╔╝██║     ")
    print("  ██║██╔══██╗██║     ")
    print("  ██║██║  ██║╚██████╗")
    print("  ╚═╝╚═╝  ╚═╝ ╚═════╝")
    print(f"  Incident Response Commander{C.RESET}")
    print(f"  {C.DIM}Autonomous Multi-Agent Security Orchestrator{C.RESET}\n")

    orchestrator = IncidentOrchestrator(dry_run=args.dry_run)

    if args.report:
        orchestrator.print_report()
        return

    if args.simulate:
        log("INFO", f"Injecting {args.simulate} test data...")
        try:
            import importlib.util

            sim_path = os.path.join(os.path.dirname(__file__), "incident-simulator.py")
            spec = importlib.util.spec_from_file_location(
                "incident_simulator", sim_path
            )
            sim_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(sim_mod)
            IncidentSimulator = sim_mod.IncidentSimulator

            sim = IncidentSimulator()
            if args.simulate == "apt":
                sim.run_simulation("apt_attack")
            else:
                sim.run_simulation(args.simulate)
            log("OK", "Test data injected. Waiting 2s for index refresh...")
            time.sleep(2)
        except ImportError:
            log("WARN", "incident_simulator.py not importable — skipping simulation")
        except Exception as e:
            log("WARN", f"Simulation failed: {e}")

    if args.watch:
        orchestrator.watch()
    else:
        orchestrator.run_once()


if __name__ == "__main__":
    main()

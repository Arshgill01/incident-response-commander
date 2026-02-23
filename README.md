# Incident Response Commander

**Fully autonomous multi-agent security incident response system built on Elastic's Agent Builder**

*Elastic Agent Builder Hackathon 2025*

---

## Overview

Incident Response Commander chains three Kibana Agent Builder agents — **Detector**, **Investigator**, and **Responder** — into a zero-human-intervention pipeline. A Python orchestrator runs ES|QL detection queries directly against Elasticsearch, calls each agent via the Kibana Actions API (`unified_completion`), enforces evidence gates between phases, and dispatches Slack alerts + Jira tickets on confirmed incidents. The entire cycle — from raw security event to blocked IP, closed ticket, and Slack notification — completes in under 90 seconds.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     INCIDENT RESPONSE COMMANDER                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                  Python Orchestrator (autonomous)                      │  │
│  │  Evidence gates · MITRE mapping · Anomaly scoring · Audit trail       │  │
│  └──────┬────────────────────┬────────────────────────┬──────────────────┘  │
│         │                    │                        │                     │
│    PHASE 1               PHASE 2                 PHASE 3                   │
│         ▼                    ▼                        ▼                     │
│  ┌──────────────┐    ┌──────────────┐    ┌─────────────────────┐           │
│  │   DETECTOR   │───▶│ INVESTIGATOR │───▶│     RESPONDER       │           │
│  │    Agent     │    │    Agent     │    │      Agent          │           │
│  ├──────────────┤    ├──────────────┤    ├─────────────────────┤           │
│  │ 4 ES|QL      │    │ Timeline     │    │ Containment plan    │           │
│  │ detection    │    │ builder      │    │ Slack webhook       │           │
│  │ queries      │    │ Anomaly      │    │ Jira REST API       │           │
│  │              │    │ scorer       │    │ MTTD/MTTR metrics   │           │
│  │ Gate 1:      │    │ Correlation  │    │                     │           │
│  │ confidence   │    │              │    │ Gate 2:             │           │
│  │ >= 0.5       │    │ LLM analysis │    │ timestamps required │           │
│  └──────────────┘    └──────────────┘    └─────────────────────┘           │
│         │                    │                        │                     │
│         ▼                    ▼                        ▼                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Elasticsearch 9.x                            │   │
│  │                                                                     │   │
│  │  security-simulated-events    Raw security events (ECS)             │   │
│  │  incident-response-log        Full audit trail of every action      │   │
│  │  incident-metrics             MTTD/MTTR per incident                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│         ┌─────────────────┐              ┌─────────────────┐               │
│         │  Slack Webhook   │              │  Jira REST API  │               │
│         │  #security-      │              │  /rest/api/2    │               │
│         │  incidents       │              │  Auto-ticket    │               │
│         └─────────────────┘              └─────────────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### How the LLM Integration Works

The orchestrator does **not** use the Agent Builder chat UI. Instead, it calls the Kibana Actions API directly:

```
POST /api/actions/connector/Anthropic-Claude-Sonnet-4-5/_execute
{
  "params": {
    "subAction": "unified_completion",
    "subActionParams": {
      "body": {
        "messages": [
          {"role": "system", "content": "<agent system prompt>"},
          {"role": "user", "content": "<findings + IOCs>"}
        ]
      }
    }
  }
}
```

Each agent's system prompt is injected programmatically. The LLM returns structured JSON that the orchestrator parses (with regex fallback for markdown-wrapped responses) and feeds into the next phase.

---

## Pipeline Deep Dive

### Phase 1 — Detection

The orchestrator runs four ES|QL detection queries in sequence against the `security-simulated-events` index:

| Detection Type | ES|QL Pattern | Trigger Threshold |
|---|---|---|
| Brute Force | `event.category == "authentication"` AND `event.outcome == "failure"` grouped by `source.ip` | >= 5 failures in 15 min |
| Data Exfiltration | `event.category == "network"` AND `network.direction == "outbound"` grouped by `user.name`, `source.ip` | >= 100 MB in 1 hour |
| Privilege Escalation | `event.action` in `(sudo, privilege_escalation, admin_login, elevated_process)` grouped by `user.name`, `host.name` | >= 3 escalations in 30 min |
| Lateral Movement | `event.category == "authentication"` AND `event.outcome == "success"` grouped by `user.name`, `source.ip` | >= 3 distinct hosts in 30 min |

If multiple attack types are detected simultaneously, the orchestrator selects the **most severe** incident (CRITICAL > HIGH > MEDIUM > LOW) as the primary for investigation.

**Severity classification:**

| Attack Type | MEDIUM | HIGH | CRITICAL |
|---|---|---|---|
| Brute Force | < 20 failures | >= 20 failures | >= 50 failures |
| Data Exfiltration | < 100 MB | >= 100 MB | >= 1 GB |
| Privilege Escalation | < 2 events | >= 2 events | — |
| Lateral Movement | — | Always HIGH | — |

### Evidence Gate 1 — Detection Confidence

Before advancing to investigation, the orchestrator computes a **confidence score**:

```
+0.5  if any IPs or user accounts extracted
+0.3  if any timestamps found
+min(finding_count * 0.05, 0.2)  scaled by evidence volume (capped at 0.2)
```

**Minimum to pass: 0.5.** If the gate fails, the incident is logged but not escalated.

### Phase 2 — Investigation

For the primary incident, the orchestrator:

1. **Builds a timeline** — queries all events for the suspect IP/user over a 4-hour window (up to 500 events), sorted chronologically
2. **Computes anomaly score** — compares the source IP's last 15 minutes of activity against its 7-day rolling baseline. Score = `recent_events / (baseline_events / 672)`, where 672 is the number of 15-minute windows in 7 days. A score of 30x means the IP generated 30 times more events than its historical average.
3. **Calls the Investigator Agent** — sends timeline, anomaly score, and MITRE mapping to Claude Sonnet 4.5 for structured analysis. The LLM returns an investigation report with executive summary, attack timeline, IOCs, and affected systems.

### Evidence Gate 2 — Investigation Quality

Before advancing to response, the gate requires:
- At least 1 IP or user account in the IOC set
- At least 1 timestamp in the evidence

### Phase 3 — Response

The Responder Agent receives the full investigation report and generates:

1. **Containment actions** — per-attack-type playbook (block IPs, disable accounts, isolate hosts, force password resets)
2. **Slack alert** — colour-coded attachment with severity, MITRE technique, IOCs, MTTR, and summary
3. **Jira ticket** — structured with executive summary, IOC list, timeline, recommended actions, and containment actions taken
4. **MTTD/MTTR metrics** — written to `incident-metrics` index

In `--dry-run` mode, containment actions and notifications are logged but not executed.

---

## Attack Scenarios

### Detection Matrix

| Attack Type | MITRE ID | MITRE Tactic | Simulated Events | Detection Window | Trigger Condition |
|---|---|---|---|---|---|
| Brute Force | T1110 | Credential Access | 21–31 (failures + 1 success) | 15 min | >= 5 failed auths from same IP |
| Data Exfiltration | T1041 | Exfiltration | 5–10 transfers | 1 hour | >= 100 MB outbound from same user/IP |
| Privilege Escalation | T1068 | Privilege Escalation | 5 events | 30 min | >= 3 escalation actions by same user |
| Lateral Movement | T1021 | Lateral Movement | 5 events | 30 min | Same user authenticates to >= 3 hosts |
| APT Kill-Chain | T1046 → T1041 | 6 tactics | ~48 events | 2 hours | Multi-stage coordinated campaign |

### APT Kill-Chain Simulation

The `apt_attack` scenario simulates a full 6-stage advanced persistent threat over a 2-hour window from a single source IP:

| Stage | Time Window | MITRE Technique | Events | Description |
|---|---|---|---|---|
| 1. Reconnaissance | 0–5 min | T1046 (Network Service Scanning) | 7 | Port scan against 22, 443, 3389, 8080, 21, 3306, 5432 |
| 2. Initial Access | 5–20 min | T1110 (Brute Force) | 26 | 25 SSH login failures + 1 success against `admin` |
| 3. Persistence | 22–35 min | T1136 (Create Account) | 5 | Backdoor user `svc_backup`: useradd, sudoers, SSH key |
| 4. Privilege Escalation | 36–50 min | T1068 (Exploitation for Priv Esc) | 5 | `sudo su -`, `chmod 777 /etc/passwd`, `pkexec bash` |
| 5. Lateral Movement | 51–80 min | T1021 (Remote Services) | 4 | Login to server-01, db-primary, file-share, backup-01 |
| 6. Exfiltration | 82–120 min | T1041 (Exfil Over C2 Channel) | 6 | 200–800 MB per transfer to external C2 servers |

---

## MITRE ATT&CK Coverage

The system maps 8 MITRE ATT&CK techniques across 7 tactics:

| Technique ID | Name | Tactic | Detected By |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | `brute-force-detection.esql` + orchestrator inline query |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | `data-exfiltration-detection.esql` + orchestrator inline query |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation | `privilege-escalation-detection.esql` + orchestrator inline query |
| T1021 | Remote Services | Lateral Movement | `lateral-movement-detector.esql` + orchestrator inline query |
| T1078 | Valid Accounts | Initial Access / Priv Esc | `mitre-attack-mapper.esql` |
| T1046 | Network Service Scanning | Discovery | `campaign-correlation.esql` + `mitre-attack-mapper.esql` |
| T1136 | Create Account | Persistence | `mitre-attack-mapper.esql` |

---

## ES|QL Tool Reference

10 ES|QL tools power the agent pipeline. Each is registered in Kibana Agent Builder and also executed directly by the orchestrator.

### Detection Tools

| Tool | Index | Purpose | Key Aggregations |
|---|---|---|---|
| `brute-force-detection` | `security-simulated-events` | Failed login clustering by source IP | `COUNT(*)`, `COUNT_DISTINCT(user.name)`, `COUNT_DISTINCT(host.name)`, `MIN/MAX(@timestamp)` grouped by `source.ip` |
| `data-exfiltration-detection` | `security-simulated-events` | Outbound data volume anomalies | `SUM(network.bytes)`, `COUNT_DISTINCT(destination.ip)`, `COUNT_DISTINCT(destination.port)` grouped by `user.name`, `source.ip` |
| `privilege-escalation-detection` | `security-simulated-events` | Sudo/elevation action clustering | `COUNT(*)`, `COUNT_DISTINCT(process.name)`, `COUNT_DISTINCT(process.target.name)` grouped by `user.name`, `host.name` |
| `lateral-movement-detector` | `security-simulated-events` | Multi-host authentication from single source | `COUNT_DISTINCT(host.name)`, `DATE_DIFF("minute", first_seen, last_seen)` grouped by `source.ip`, `user.name` |

### Investigation Tools

| Tool | Index | Purpose | Output |
|---|---|---|---|
| `timeline-builder` | `security-simulated-events` | 5-minute-bucketed chronological view | `event_count`, `unique_categories`, `unique_actions` per `DATE_TRUNC(5 min)` bucket |
| `incident-correlation` | `security-simulated-events` | Raw event retrieval for suspect IP/user | Full event fields: `@timestamp`, `event.*`, `user.name`, `source.ip`, `destination.*`, `process.name`, `host.name`, `network.bytes`, `message` (LIMIT 1000) |
| `anomaly-scorer` | `security-simulated-events` | 15-min vs 7-day baseline comparison | Normalized score 0.0–1.0 per source IP. >= 0.3 reported, >= 0.5 suspicious, >= 0.75 high-confidence |
| `mitre-attack-mapper` | `security-simulated-events` | Maps raw event patterns to MITRE technique IDs | Binary flags + counts for T1110, T1041, T1068, T1021, T1136, T1046 per source IP |

### Correlation & Metrics Tools

| Tool | Index | Purpose | Output |
|---|---|---|---|
| `campaign-correlation` | `security-simulated-events` | Multi-attack-type correlation from same source IP | `attack_types_count`, `campaign_duration_minutes`, severity scoring: 5 types = APT_CRITICAL, 3–4 = HIGH, 2 = MEDIUM |
| `mttd-mttr-scorecard` | `incident-metrics` | 30-day performance grading | Avg/P50/P95/Max MTTD and MTTR. Grading: MTTD < 5 min = Excellent, MTTR < 15 min = Excellent |

---

## Agent Configuration

Three agents are configured in Kibana Agent Builder, each with assigned ES|QL tools and platform capabilities:

### Detector Agent (`security-incident-detector`)

| Property | Value |
|---|---|
| Tools | `brute-force-detection`, `data-exfiltration-detection`, `privilege-escalation-detection`, `platform.core.search`, `platform.core.list_indices` |
| LLM | Claude Sonnet 4.5 via `unified_completion` |
| Output | Structured JSON: `incident_type`, `severity`, `confidence`, `malicious_ips[]`, `affected_users[]`, `summary` |

### Investigator Agent (`incident-investigator`)

| Property | Value |
|---|---|
| Tools | `incident-correlation`, `timeline-builder`, `platform.core.search`, `platform.core.get_document_by_id`, `platform.core.get_index_mapping` |
| LLM | Claude Sonnet 4.5 via `unified_completion` |
| Output | Structured JSON: `executive_summary`, `attack_timeline[]`, `iocs{}`, `affected_systems[]`, `risk_assessment` |

### Responder Agent (`incident-responder`)

| Property | Value |
|---|---|
| Tools | `incident-correlation`, `timeline-builder`, `platform.core.search`, `platform.core.get_document_by_id`, `platform.core.get_index_mapping` |
| LLM | Claude Sonnet 4.5 via `unified_completion` |
| Output | Structured JSON: `containment_actions[]`, `escalation_required`, `slack_message{}`, `jira_ticket{}`, `mttd_seconds`, `mttr_seconds` |

**Per-attack-type response playbooks** are embedded in the Responder's system prompt:

| Attack Type | Containment Actions |
|---|---|
| Brute Force (T1110) | Block IP, lock account, terminate sessions, force password reset, enable MFA |
| Data Exfiltration (T1041) | Block dest IPs/domains, revoke credentials + API tokens, terminate outbound, snapshot for forensics, notify DPO if PII |
| Privilege Escalation (T1068) | Revert permission changes, disable account, audit sudoers, scan persistence mechanisms, patch vulnerability |
| Lateral Movement (T1021) | Isolate compromised hosts, rotate credentials, block SSH/RDP from source, audit 24h logins, review service accounts |
| APT (Kill-Chain) | Network isolation, emergency credential rotation, forensic snapshots, activate CIRT, preserve logs 90 days, notify legal/compliance |

---

## Notification Integration

### Slack

The orchestrator posts to Slack via an incoming webhook. Messages use the attachments format with colour-coded severity:

| Severity | Colour | Escalation |
|---|---|---|
| CRITICAL | `#FF0000` (red) | Pages on-call SOC lead |
| HIGH | `#FF8C00` (orange) | Notifies SOC team |
| MEDIUM | `#FFD700` (yellow) | Creates ticket |
| LOW | `#00AA00` (green) | Logs for review |

**Attachment fields:** Severity, Attack Type, Malicious IPs, Affected Users, MITRE Technique, MTTR, Automated status, Summary.

### Jira

Tickets are created via the Jira REST API v2 (`POST /rest/api/2/issue`):

| Field | Value |
|---|---|
| Project | Configurable via `JIRA_PROJECT_KEY` (default: `SCRUM`) |
| Issue Type | Task |
| Priority | Mapped from severity: CRITICAL → Highest, HIGH → High, MEDIUM → Medium, LOW → Low |
| Summary | `[AUTO] {SEVERITY} {Attack Type} — IRC-{ID}` |
| Description | Wiki markup with: Executive Summary, IOCs, MITRE Technique, Recommended Actions, Containment Actions Taken, Investigation Timeline |
| Labels | `auto-detected`, `irc`, `{attack_type}` |

---

## Elasticsearch Index Schema

### `security-simulated-events`

The primary event index uses [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) field naming:

| Field | Type | Example |
|---|---|---|
| `@timestamp` | date | `2026-02-23T09:30:00.000Z` |
| `event.category` | keyword | `authentication`, `network`, `process` |
| `event.action` | keyword | `login`, `privilege_escalation`, `sudo` |
| `event.outcome` | keyword | `success`, `failure` |
| `source.ip` | ip | `192.168.39.91` |
| `destination.ip` | ip | `10.0.0.11` |
| `destination.port` | integer | `443` |
| `user.name` | keyword | `admin` |
| `host.name` | keyword | `server-01.internal` |
| `process.name` | keyword | `sudo` |
| `network.bytes` | long | `524288000` |
| `network.direction` | keyword | `outbound` |
| `message` | text | `Failed SSH login for admin from 192.168.39.91` |

### `incident-response-log`

Full audit trail of every orchestrator action across all three phases:

| Field | Type | Description |
|---|---|---|
| `incident_id` | keyword | Unique incident identifier (`IRC-{UUID[:12]}`) |
| `phase` | keyword | `detection`, `investigation`, `response`, `notification` |
| `action` | keyword | `agent_response`, `gate_passed`, `gate_failed`, `slack_sent`, `jira_created` |
| `timestamp` | date | Action timestamp |
| `dry_run` | boolean | Whether this was a dry-run execution |
| `data.agent_id` | keyword | Which agent produced this entry |
| `data.response_summary` | text | Truncated agent response |
| `data.timeline_events` | integer | Event count from investigation |
| `data.anomaly_score` | float | IP anomaly score |
| `data.iocs.ips` | ip | Extracted malicious IPs |
| `data.iocs.users` | keyword | Affected user accounts |
| `data.iocs.confidence` | float | Detection confidence (0.0–1.0) |
| `data.mttr_seconds` | long | Mean time to respond |

### `incident-metrics`

One document per resolved incident, used by the `--report` scorecard:

| Field | Type | Description |
|---|---|---|
| `incident_id` | keyword | Matches the audit log |
| `attack_type` | keyword | `brute_force`, `data_exfiltration`, `privilege_escalation`, `lateral_movement` |
| `severity` | keyword | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `detected_at` | date | When Phase 1 completed |
| `investigated_at` | date | When Phase 2 completed |
| `responded_at` | date | When Phase 3 completed |
| `mttd_seconds` | long | Mean time to detect (0 for continuous polling) |
| `mttr_seconds` | long | Mean time to respond (`responded_at - detected_at`) |
| `ioc_count` | integer | Total IPs + users extracted |
| `automated` | boolean | Always `true` (fully autonomous) |
| `dry_run` | boolean | Whether containment was actually executed |

### ILM Policy (`incident-response-policy`)

| Phase | Trigger | Actions |
|---|---|---|
| Hot | — | Rollover at 30 days or 5 GB |
| Warm | 30 days | Shrink to 1 shard, force merge to 1 segment |
| Cold | 90 days | Freeze index |
| Delete | 365 days | Delete index |

---

## MTTD/MTTR Metrics

The `--report` flag generates a scorecard from the `incident-metrics` index:

```
$ python3 demo/orchestrator.py --report

  MTTD/MTTR Scorecard — Last 24 Hours
  ==================================================

  Total incidents (24h):  3
  Critical:               0
  High:                   3
  Automated responses:    3
  Avg MTTR:               77s (1.3 min)
  Min MTTR:               71s
  Max MTTR:               82s
  Industry avg MTTD:      197 days (Ponemon 2023)
  MTTD reduction vs avg:  100.0%

  By attack type:
    brute_force               count=3  avg_mttr=77s
```

**Grading benchmarks** (from `mttd-mttr-scorecard.esql`):

| Metric | Excellent | Good | Fair | Poor |
|---|---|---|---|---|
| MTTD | < 5 min | < 15 min | < 60 min | > 60 min |
| MTTR | < 15 min | < 30 min | < 2 hours | > 2 hours |

Industry average MTTD is **197 days** (Ponemon Institute, 2023). This system achieves **continuous detection** (MTTD effectively the polling interval, default 60 seconds) and **MTTR of ~77 seconds** — a reduction of over 99.99%.

---

## Quick Start

### Prerequisites

- **Elastic Cloud 9.x** with Agent Builder enabled
- **Python 3.9+**
- **Slack incoming webhook URL** (optional — notifications degrade gracefully)
- **Jira Cloud account** (optional — requires email + API token)

### 1. Clone and install

```bash
git clone https://github.com/Arshgill01/incident-response-commander.git
cd incident-response-commander
pip install -r requirements.txt
```

Dependencies: `elasticsearch>=9.0.0`, `python-dotenv`, `requests`, `pytest>=7.0.0`, `pytest-mock>=3.10.0`

### 2. Configure environment

```bash
cp .env.example .env
```

**Required variables:**

| Variable | Description |
|---|---|
| `ELASTIC_CLOUD_ID` | Elastic Cloud deployment ID |
| `ELASTIC_PASSWORD` | `elastic` user password |

**Optional variables:**

| Variable | Description |
|---|---|
| `ELASTIC_API_KEY` | API key (tried first, falls back to password) |
| `KIBANA_URL` | Kibana base URL (for LLM connector calls) |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for `#security-incidents` |
| `SLACK_CHANNEL` | Override Slack channel name |
| `JIRA_URL` | Jira Cloud instance (e.g. `https://yourorg.atlassian.net`) |
| `JIRA_EMAIL` | Atlassian account email for API auth |
| `JIRA_API_TOKEN` | Jira API token (Atlassian account settings) |
| `JIRA_PROJECT_KEY` | Jira project key (default: `SCRUM`) |

### 3. Set up Elasticsearch indices

```bash
python3 demo/setup-indices.py            # Create indices + ILM policy
python3 demo/setup-indices.py --verify   # Confirm indices exist
python3 demo/setup-indices.py --seed     # Add baseline demo metrics
```

### 4. Configure Kibana Agent Builder

Follow [MANUAL_SETUP.md](MANUAL_SETUP.md) to create the 3 agents and 10 ES|QL tools in the Kibana Agent Builder UI. This is a manual step — there is no API for agent creation.

### 5. Run the pipeline

```bash
# Simulate brute force + run full pipeline (live notifications)
python3 demo/orchestrator.py --simulate brute_force

# Dry run — detect + investigate only, no containment or notifications
python3 demo/orchestrator.py --simulate brute_force --dry-run

# Full APT kill-chain simulation
python3 demo/orchestrator.py --simulate apt

# Continuous monitoring mode (polls every 60s)
python3 demo/orchestrator.py --watch

# MTTD/MTTR scorecard
python3 demo/orchestrator.py --report
```

### 6. Shell script demo (alternative)

```bash
bash demo/run-demo.sh                     # Full APT kill-chain
bash demo/run-demo.sh --type brute_force  # Specific attack type
bash demo/run-demo.sh --dry-run           # No data injection
```

### 7. Reset between runs

```bash
bash demo/reset-demo.sh        # Soft reset (clear events, keep indices)
bash demo/reset-demo.sh --hard # Delete and recreate all indices
```

### 8. Run tests

```bash
pytest                   # All tests
pytest -m unit           # Fast unit tests only (no network)
pytest -m integration    # Tests requiring live Elasticsearch
```

---

## Repository Structure

```
incident-response-commander/
├── demo/
│   ├── orchestrator.py            # Autonomous pipeline engine (~1,550 lines)
│   ├── incident-simulator.py      # 5 attack scenario generators (~700 lines)
│   ├── notifications.py           # Slack Block Kit + Jira REST dispatcher (~680 lines)
│   ├── setup-indices.py           # ES index/mapping/ILM setup (~340 lines)
│   ├── data-ingestion.py          # Baseline event ingestion
│   ├── test-connection.py         # Quick auth verification
│   ├── run-demo.sh                # One-command full demo
│   └── reset-demo.sh              # Clean slate reset
│
├── agents/
│   ├── detector-agent.json        # Detector config (5 tools)
│   ├── investigator-agent.json    # Investigator config (5 tools)
│   └── responder-agent.json       # Responder config (5 tools)
│
├── tools/esql/                    # 10 ES|QL query files
│   ├── brute-force-detection.esql
│   ├── data-exfiltration-detection.esql
│   ├── privilege-escalation-detection.esql
│   ├── lateral-movement-detector.esql
│   ├── anomaly-scorer.esql
│   ├── timeline-builder.esql
│   ├── incident-correlation.esql
│   ├── mitre-attack-mapper.esql
│   ├── campaign-correlation.esql
│   └── mttd-mttr-scorecard.esql
│
├── tests/                         # pytest suite (6 files, 60+ tests)
│   ├── conftest.py                # Shared fixtures + mock ES client
│   ├── test_orchestrator.py       # Evidence gates, MITRE mapping, audit log
│   ├── test_notifications.py      # Slack/Jira enable/disable, HTTP mocking
│   ├── test_incident_simulator.py # All 5 attack types + routing
│   ├── test_esql_queries.py       # File existence, syntax, index names
│   └── test_data_ingestion.py     # ECS compliance, index naming
│
├── docs/
│   ├── ARCHITECTURE.md            # Technical architecture and data flow
│   ├── SETUP.md                   # Environment setup guide
│   ├── KIBANA_TOOL_SETUP.md       # Tool creation walkthrough
│   ├── PHASE1_CHECKLIST.md        # Development checklist
│   └── TOOL_PARAMETERS_QUICKREF.md
│
├── submission/
│   └── project-description.md     # Hackathon submission writeup
│
├── MANUAL_SETUP.md                # Kibana Agent Builder UI walkthrough
├── requirements.txt               # Python dependencies
├── pytest.ini                     # Test configuration
└── .env.example                   # Environment variable template
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Event Storage & Search | Elasticsearch 9.x (Elastic Cloud) |
| Query Language | ES|QL (Elasticsearch Query Language) |
| Agent Framework | Kibana Agent Builder |
| LLM | Claude Sonnet 4.5 via Kibana Actions API (`unified_completion`) |
| Orchestrator | Python 3.9+ |
| ES Client | `elasticsearch-py` 9.x |
| Notifications | Slack Incoming Webhooks, Jira REST API v2 |
| Testing | pytest + pytest-mock |
| Index Lifecycle | ILM policy (hot → warm → cold → delete over 365 days) |

---

## Documentation

- **[MANUAL_SETUP.md](MANUAL_SETUP.md)** — Step-by-step Kibana Agent Builder configuration
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Technical architecture and data flow
- **[docs/KIBANA_TOOL_SETUP.md](docs/KIBANA_TOOL_SETUP.md)** — ES|QL tool creation reference
- **[submission/project-description.md](submission/project-description.md)** — Hackathon submission

---

## License

MIT — see [LICENSE](LICENSE)

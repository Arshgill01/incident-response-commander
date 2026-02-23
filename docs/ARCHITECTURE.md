# Architecture Documentation

## System Overview

Incident Response Commander is a multi-agent AI system built on Elastic Agent Builder that detects, investigates, and responds to security incidents using a three-agent pipeline.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           INCIDENT RESPONSE COMMANDER                        │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                  DATA LAYER (Elasticsearch)                              │ │
│  │                                                                         │ │
│  │              ┌──────────────────────────────────┐                       │ │
│  │              │   security-simulated-events       │                       │ │
│  │              │   (auth + network + process logs) │                       │ │
│  │              └──────────────┬───────────────────┘                       │ │
│  └─────────────────────────────┼───────────────────────────────────────────┘ │
│                                │                                             │
│                                ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                 DETECTION LAYER (Agent 1: DETECTOR)                      │ │
│  │                                                                         │ │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │ │
│  │  │ Brute Force     │  │ Data            │  │ Privilege       │         │ │
│  │  │ Detection       │  │ Exfiltration    │  │ Escalation      │         │ │
│  │  │ (ES|QL)         │  │ Detection       │  │ Detection       │         │ │
│  │  │                 │  │ (ES|QL)         │  │ (ES|QL)         │         │ │
│  │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │ │
│  │           └────────────────────┴────────┬───────────┘                   │ │
│  │                                         ▼                               │ │
│  │                              ┌──────────────────┐                      │ │
│  │                              │  Severity        │                      │ │
│  │                              │  Classification  │                      │ │
│  │                              └────────┬─────────┘                      │ │
│  └───────────────────────────────────────┼────────────────────────────────┘ │
│                                          ▼                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │               INVESTIGATION LAYER (Agent 2: INVESTIGATOR)               │ │
│  │                                                                         │ │
│  │  ┌──────────────────┐  ┌──────────────────┐                            │ │
│  │  │ Incident         │  │ Timeline         │                            │ │
│  │  │ Correlation      │  │ Builder          │                            │ │
│  │  │ (ES|QL)          │  │ (ES|QL)          │                            │ │
│  │  └────────┬─────────┘  └────────┬─────────┘                            │ │
│  │           └─────────────────────┴────────┐                              │ │
│  │                                          ▼                               │ │
│  │                               ┌──────────────────┐                      │ │
│  │                               │ Investigation    │                      │ │
│  │                               │ Report           │                      │ │
│  │                               └────────┬─────────┘                      │ │
│  └────────────────────────────────────────┼─────────────────────────────────┘│
│                                           ▼                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                  RESPONSE LAYER (Agent 3: RESPONDER)                     │ │
│  │                                                                         │ │
│  │  ┌──────────────────┐  ┌──────────────────┐                            │ │
│  │  │ Slack            │  │ Jira             │                            │ │
│  │  │ Connector        │  │ Connector        │                            │ │
│  │  │ (Kibana)         │  │ (Kibana)         │                            │ │
│  │  └────────┬─────────┘  └────────┬─────────┘                            │ │
│  │           └─────────────────────┴────────┐                              │ │
│  │                                          ▼                               │ │
│  │                               ┌──────────────────┐                      │ │
│  │                               │ Response         │                      │ │
│  │                               │ Complete         │                      │ │
│  │                               └──────────────────┘                      │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼                               ▼
            ┌───────────┐                   ┌───────────┐
            │   Slack   │                   │   Jira    │
            │  Alerts   │                   │  Tickets  │
            └───────────┘                   └───────────┘
```

## Orchestrator Layer (Autonomous Pipeline Engine)

`demo/orchestrator.py` is the centerpiece of the autonomous pipeline. It runs entirely without human interaction:

1. **Detection phase** — Executes 4 ES|QL queries (brute force, exfiltration, privilege escalation, lateral movement) directly via the Elasticsearch Python client. If any query returns results above threshold, it calls the LLM via the Kibana `unified_completion` connector API with the Detector agent's system prompt injected.

2. **Evidence gate** — Before proceeding to investigation, validates: confidence ≥ 0.5 AND at least one IOC present.

3. **Investigation phase** — Calls the LLM with the Investigator agent's system prompt and the raw detection results as context. Runs `incident-correlation` and `timeline-builder` ES|QL queries and attaches results.

4. **Evidence gate** — Before proceeding to response, validates: confidence ≥ 0.5 AND non-empty timeline.

5. **Response phase** — Calls the LLM with the Responder agent's system prompt. Dispatches Slack Block Kit alert and Jira ticket via `demo/notifications.py`. Writes MTTD/MTTR to `incident-metrics`.

6. **Audit trail** — Every phase result is written to `incident-response-log`.

**CLI flags:** `--dry-run` (skip ES/LLM calls), `--watch` (continuous polling), `--report` (print MTTD/MTTR scorecard), `--simulate` (inject synthetic events first).

---

## Component Details

### 1. Data Layer

**Indices:**
- `security-simulated-events` — All simulated security events for detection and investigation
- `incident-response-log` — Full audit trail of every orchestrator phase result
- `incident-metrics` — MTTD/MTTR per-incident records for dashboard tracking

**Event Types:**
- Authentication logs (login attempts, failures, successes)
- Network logs (connections, outbound transfers)
- Process logs (privilege escalation, command execution)

**Schema Fields:**
- `@timestamp`, `event.category`, `event.action`, `event.outcome`, `event.type`
- `source.ip`, `destination.ip`, `destination.port`, `destination.domain`
- `network.direction`, `network.bytes`
- `user.name`, `host.name`
- `process.name`, `process.args`, `process.target.name`
- `message`

### 2. Detection Layer (Agent 1: DETECTOR)

**Purpose:** Identify security incidents from event patterns

**ES|QL Tools (detection):**
- `brute-force-detection` — Auth failures ≥5 in 15 min, breach detection
- `data-exfiltration-detection` — Outbound bytes > 100 MB in 1 hour
- `privilege-escalation-detection` — Process privilege_escalation action in 30 min
- `lateral-movement-detector` — 3+ distinct host logins from same IP in 30 min (T1021)
- `anomaly-scorer` — Compares 15-min activity to 7-day baseline; returns 0.0–1.0 anomaly score
- `mitre-attack-mapper` — Maps raw events to 6 MITRE ATT&CK T-codes
- `campaign-correlation` — Flags IPs with 2+ attack types as coordinated actors

#### Brute Force Detection
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?time_window
| WHERE `event.category` == "authentication" AND `event.outcome` == "failure"
| STATS failure_count = COUNT(*), unique_users = COUNT_DISTINCT(`user.name`)
  BY `source.ip`
| WHERE failure_count >= ?failure_threshold
| SORT failure_count DESC
```

**Detection Logic:**
- Threshold-based: Configurable failure count (default: 5)
- Time-windowed: Configurable period (default: 15 minutes)
- IP-based grouping: Identifies attack sources

#### Data Exfiltration Detection
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?time_window
| WHERE `event.category` == "network" AND `network.direction` == "outbound"
| STATS total_bytes = SUM(`network.bytes`), transfer_count = COUNT(*)
  BY `user.name`, `source.ip`
| WHERE total_bytes >= ?bytes_threshold
| SORT total_bytes DESC
```

**Detection Logic:**
- Volume-based: Configurable byte threshold (default: 100MB)
- Time-windowed: Configurable period (default: 1 hour)
- User-grouped: Identifies which user is transferring data

#### Privilege Escalation Detection
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?time_window
| WHERE `event.category` == "process"
  AND `event.action` == "privilege_escalation"
| STATS escalation_count = COUNT(*),
  commands = COUNT_DISTINCT(`process.name`)
  BY `user.name`, `host.name`
| WHERE escalation_count >= 3
| SORT escalation_count DESC
```

### 3. Investigation Layer (Agent 2: INVESTIGATOR)

**Purpose:** Correlate events and build attack timelines

**ES|QL Tools:**
- `incident-correlation` — All events by source IP/user in investigation window
- `timeline-builder` — Chronological time-bucketed event sequence

#### Incident Correlation
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?investigation_window
| WHERE `source.ip` == ?suspicious_ip OR `user.name` == ?suspicious_user
| KEEP @timestamp, `event.category`, `event.action`, `event.outcome`,
  `user.name`, `source.ip`, `host.name`, message
| SORT @timestamp ASC
```

**Investigation Process:**
1. Gather all events related to suspicious indicators
2. Filter by IP address or username
3. Build chronological timeline
4. Identify attack progression

#### Timeline Builder
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?time_window
| WHERE `source.ip` == ?target_ip OR `user.name` == ?target_user
| EVAL time_bucket = DATE_TRUNC(5 minutes, @timestamp)
| STATS event_count = COUNT(*),
  categories = COUNT_DISTINCT(`event.category`)
  BY time_bucket
| SORT time_bucket ASC
```

### 4. Response Layer (Agent 3: RESPONDER)

**Purpose:** Generate playbooks, send Slack alerts, create Jira tickets

**Integration Method:**
- `demo/notifications.py` → Slack Block Kit webhook (direct HTTP)
- `demo/notifications.py` → Jira REST API v3 (direct HTTP)
- `mttd-mttr-scorecard` ES|QL tool — Reads `incident-metrics` index for scorecard grading

#### Slack Notification
Sends formatted incident alerts to a Slack channel via a Slack Webhook connector.

**Message includes:**
- Incident type and severity
- Affected users and IP addresses
- Summary of detection findings

#### Jira Ticket Creation
Creates incident tickets in Jira via a Jira connector.

**Ticket fields:**
- Project: SCRUM
- Issue Type: Task
- Priority: Mapped from incident severity
- Description: Investigation report with timeline and IOCs

### Workflow Reference Designs

The `workflows/` directory contains YAML reference designs for response workflows (containment, Slack, Jira, evidence preservation). These illustrate the intended response logic but are **not directly executable** in Kibana — the actual integrations use Kibana Connectors as described above.

## Data Flow

```
1. Python Scripts → Elasticsearch
   └─ data-ingestion.py creates index template and ingests baseline events
   └─ incident-simulator.py injects attack event sequences

2. Detector Agent → Monitors logs via ES|QL
   └─ Runs detection queries when prompted
   └─ Classifies severity (CRITICAL/HIGH/MEDIUM/LOW)

3. Investigator Agent ← Receives detection findings
   └─ Correlates events by IP/user
   └─ Builds chronological timeline
   └─ Extracts IOCs

4. Responder Agent ← Receives investigation report
   └─ Evaluates response based on severity
   └─ Sends Slack notification via Connector
   └─ Creates Jira ticket via Connector
```

## Key Technologies

### Elastic Agent Builder
- **Custom Agents**: Task-specific AI agents with tailored instructions
- **ES|QL Tools**: Parameterized security queries assigned to agents
- **Built-in Tools**: Search, index exploration, document retrieval

### ES|QL (Elasticsearch Query Language)
- **Piped Syntax**: Chainable query commands (WHERE, STATS, EVAL, SORT)
- **Aggregations**: COUNT, SUM, COUNT_DISTINCT for statistical analysis
- **Time Functions**: NOW(), DATE_TRUNC() for time-windowed analysis

### Kibana Connectors
- **Slack Webhook**: Send formatted messages to Slack channels
- **Jira**: Create and manage tickets in Jira Cloud

## Performance Considerations

### Query Design
- Time-window filtering applied first to limit scan scope
- Aggregations use field-level grouping for efficiency
- Results sorted by severity indicators (count, volume)

### Data Management
- ILM policy with hot/warm/cold phases for data lifecycle
- Index template with explicit mappings for consistent schema
- Index refresh after simulation for immediate searchability

---

**This architecture enables a streamlined detect → investigate → respond pipeline using Elastic Agent Builder.**

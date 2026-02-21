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

## Component Details

### 1. Data Layer

**Index:**
- `security-simulated-events` — All simulated security events for detection and investigation

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

**ES|QL Tools:**

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

**Purpose:** Coordinate incident response actions

**Integration Method:** Kibana Connectors (Stack Management → Connectors)

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

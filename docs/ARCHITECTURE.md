# Architecture Documentation

## System Overview

Incident Response Commander is a multi-agent AI system built on Elastic Agent Builder that autonomously detects, investigates, and responds to security incidents.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           INCIDENT RESPONSE COMMANDER                        │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                      DATA LAYER (Elasticsearch)                          │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │ │
│  │  │   auth-logs  │  │ network-logs │  │ process-logs │  │  file-logs   │  │ │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │ │
│  └─────────┼────────────────┼────────────────┼────────────────┼──────────┘ │
│            │                │                │                │             │
│            └────────────────┴───────┬────────┴────────────────┘             │
│                                     │                                       │
│                                     ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    DETECTION LAYER (Agent 1: DETECTOR)                   ││
│  │                                                                         ││
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         ││
│  │  │ Brute Force     │  │ Data            │  │ Privilege       │         ││
│  │  │ Detection       │  │ Exfiltration    │  │ Escalation      │         ││
│  │  │ Tool (ES|QL)    │  │ Detection       │  │ Detection       │         ││
│  │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         ││
│  │           │                    │                    │                   ││
│  │           └────────────────────┴────────┬───────────┘                   ││
│  │                                         │                               ││
│  │                                         ▼                               ││
│  │                              ┌──────────────────┐                      ││
│  │                              │  Severity        │                      ││
│  │                              │  Classification  │                      ││
│  │                              └────────┬─────────┘                      ││
│  └───────────────────────────────────────┼────────────────────────────────┘│
│                                          │                                 │
│                                          ▼                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                  INVESTIGATION LAYER (Agent 2: INVESTIGATOR)             ││
│  │                                                                         ││
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐       ││
│  │  │ Cross-Index      │  │ Timeline         │  │ IOC              │       ││
│  │  │ Correlation      │  │ Builder          │  │ Extraction       │       ││
│  │  │ (ES|QL JOINs)    │  │ (ES|QL)          │  │ (ES|QL)          │       ││
│  │  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘       ││
│  │           │                     │                     │                  ││
│  │           └─────────────────────┴────────┬────────────┘                  ││
│  │                                          │                               ││
│  │                                          ▼                               ││
│  │                               ┌──────────────────┐                      ││
│  │                               │ Investigation    │                      ││
│  │                               │ Report           │                      ││
│  │                               └────────┬─────────┘                      ││
│  └────────────────────────────────────────┼─────────────────────────────────┘│
│                                           │                                  │
│                                           ▼                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    RESPONSE LAYER (Agent 3: RESPONDER)                   ││
│  │                                                                         ││
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐       ││
│  │  │ Containment      │  │ Notification     │  │ Evidence         │       ││
│  │  │ Workflow         │  │ Workflows        │  │ Preservation     │       ││
│  │  │ (IP Block,       │  │ (Slack, Jira)    │  │ Workflow         │       ││
│  │  │ Account Disable) │  │                  │  │                  │       ││
│  │  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘       ││
│  │           │                     │                     │                  ││
│  │           └─────────────────────┴────────┬────────────┘                  ││
│  │                                          │                               ││
│  │                                          ▼                               ││
│  │                               ┌──────────────────┐                      ││
│  │                               │ Response         │                      ││
│  │                               │ Complete         │                      ││
│  │                               └──────────────────┘                      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
            ┌───────────┐   ┌───────────┐   ┌───────────┐
            │   Slack   │   │   Jira    │   │  Evidence │
            │  Alerts   │   │  Tickets  │   │  Storage  │
            └───────────┘   └───────────┘   └───────────┘
```

## Component Details

### 1. Data Layer

**Indices Structure:**
- `security-simulated-events`: Simulated security events for testing
- `incident-response-log`: Audit log of all response actions
- `incident-evidence-*`: Per-incident forensic evidence (read-only)
- `incident-*`: Incident metadata and reports

**Data Types:**
- Authentication logs (login attempts, failures, successes)
- Network logs (connections, transfers, outbound traffic)
- Process logs (privilege escalation, command execution)
- File logs (access patterns, modifications)

### 2. Detection Layer (Agent 1: DETECTOR)

**Purpose:** Continuously monitor and identify security incidents

**ES|QL Tools:**

#### Brute Force Detection
```sql
FROM logs-*
| WHERE @timestamp > NOW() - ?time_window
| WHERE event.category == "authentication" AND event.outcome == "failure"
| STATS failure_count = COUNT(*) BY source.ip
| WHERE failure_count >= ?failure_threshold
```

**Detection Logic:**
- Threshold-based: Configurable failure count (default: 10)
- Time-windowed: Configurable time period (default: 15 minutes)
- IP-based grouping: Identifies attack sources
- Success correlation: Detects successful breaches

**Output:**
- Severity: CRITICAL if successful login after failures
- Indicators: Source IP, target user, attempt count
- Timeline: First to last failure

#### Data Exfiltration Detection
```sql
FROM logs-*
| WHERE @timestamp > NOW() - ?time_window
| WHERE event.category == "network" AND network.direction == "outbound"
| STATS total_bytes = SUM(destination.bytes) BY user.name
| WHERE total_bytes >= ?bytes_threshold
```

**Detection Logic:**
- Volume-based: Configurable byte threshold (default: 1GB)
- Baseline comparison: Compares to historical averages
- Direction analysis: Outbound-only monitoring
- User correlation: Identifies insider threats

**Output:**
- Severity: HIGH for large transfers
- Indicators: User, source IP, destination domains
- Volume: Total bytes transferred

#### Privilege Escalation Detection
```sql
FROM logs-*
| WHERE @timestamp > NOW() - ?time_window
| WHERE event.action IN ("sudo", "privilege_escalation")
| STATS escalation_count = COUNT(*) BY user.name
| WHERE escalation_count >= 3
```

**Detection Logic:**
- Action-based: Monitors specific privilege commands
- Frequency analysis: Multiple escalations trigger alert
- User tracking: Identifies account abuse
- Host correlation: Tracks lateral movement

**Output:**
- Severity: HIGH for confirmed escalations
- Indicators: User, host, escalation commands
- Timeline: Escalation sequence

### 3. Investigation Layer (Agent 2: INVESTIGATOR)

**Purpose:** Deep forensic analysis and correlation

**ES|QL Tools:**

#### Cross-Index Correlation
```sql
FROM logs-*
| WHERE @timestamp > NOW() - ?investigation_window
| WHERE source.ip == ?suspicious_ip OR user.name == ?suspicious_user
| KEEP @timestamp, event.category, event.action, user.name, source.ip
| SORT @timestamp ASC
```

**Investigation Process:**
1. Gather all events related to IOCs
2. Cross-reference across all log types
3. Build chronological timeline
4. Identify attack progression
5. Extract additional IOCs

**Output:**
- Complete event timeline
- Correlated activities
- Additional indicators
- Scope assessment

#### Timeline Builder
```sql
FROM logs-*
| WHERE @timestamp > NOW() - ?time_window
| EVAL time_bucket = BUCKET(@timestamp, 5 minutes)
| STATS event_count = COUNT(*) BY time_bucket
| SORT time_bucket ASC
```

**Purpose:** Visualize attack progression over time

### 4. Response Layer (Agent 3: RESPONDER)

**Purpose:** Execute automated response actions

**Workflows:**

#### Immediate Containment
- **IP Blocking**: Add deny rules to firewall
- **Account Disable**: Disable compromised accounts
- **Session Termination**: Kill active sessions
- **Evidence Preservation**: Snapshot logs before changes

#### Slack Notification
**Message Format:**
```
🚨 Security Incident: INC-2026-001

Type: Brute Force Attack
Severity: CRITICAL
Status: Contained

Affected Users: admin
Affected IPs: 192.168.1.100

Actions Taken:
✅ IP blocked at firewall
✅ Account disabled
✅ Sessions terminated

View Full Report: [Link]
```

#### Jira Ticket Creation
**Fields:**
- Project: SCRUM
- Issue Type: Task
- Priority: Mapped from severity
- Labels: auto-detected, security, incident-type
- Description: Full investigation report with timeline and IOCs

#### Evidence Preservation
- **Snapshot Creation**: Point-in-time backup
- **Index Locking**: Read-only evidence indices
- **Chain of Custody**: Automated logging
- **Retention**: 90-day default retention

## Data Flow

```
1. Raw Logs → Elasticsearch
   └─ Ingestion pipeline normalizes events

2. Detector Agent → Monitors logs
   └─ ES|QL queries identify patterns
   └─ Severity classification

3. Investigator Agent ← Receives alerts
   └─ Correlates events
   └─ Builds timeline
   └─ Extracts IOCs

4. Responder Agent ← Receives report
   └─ Evaluates response options
   └─ Executes containment
   └─ Sends notifications
   └─ Preserves evidence

5. External Systems
   └─ Slack: Real-time alerts
   └─ Jira: Ticket tracking
   └─ Firewall: IP blocking
   └─ Evidence Storage: Forensic data
```

## Key Technologies

### Elastic Agent Builder
- **Custom Agents**: Task-specific AI agents
- **ES|QL Tools**: Precise data queries
- **Built-in Tools**: Search, index exploration
- **Reasoning Models**: Claude 4.5 for decision-making

### ES|QL (Elasticsearch Query Language)
- **Piped Syntax**: Chainable query commands
- **Aggregations**: Statistical analysis
- **JOINs**: Cross-index correlation
- **Time-Series**: Temporal analysis

### Elastic Workflows
- **YAML-Based**: Declarative automation
- **Triggers**: Manual, scheduled, alert-based
- **Actions**: Multi-step orchestration
- **Secrets Management**: Secure credential storage

### MCP/A2A Protocols
- **Standardized Integration**: Connect external systems
- **Tool Exposure**: Make Elastic tools available externally
- **Agent Interoperability**: Multi-agent communication

## Security Considerations

### Data Access Control
- Role-based access to indices
- API key permissions
- Field-level security

### Audit Trail
- All actions logged
- Immutable evidence indices
- Chain of custody maintained

### Response Safety
- Human-in-the-loop for critical actions
- Graduated response based on severity
- Rollback capabilities

## Performance Optimization

### Query Optimization
- Time-window filtering first
- Index patterns for efficiency
- Aggregation limits

### Resource Management
- ILM policies for data lifecycle
- Snapshot retention
- Index templates

### Scalability
- Distributed processing
- Parallel query execution
- Efficient data structures

## Monitoring & Observability

### Metrics to Track
- Detection time (MTTD)
- Response time (MTTR)
- False positive rate
- System performance

### Dashboards
- Incident overview
- Agent performance
- Workflow execution
- System health

---

**This architecture enables fully autonomous incident response with human oversight.**

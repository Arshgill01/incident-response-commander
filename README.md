# Incident Response Commander

**Autonomous multi-agent security incident response system — Elastic Agent Builder Hackathon**

---

## Overview

Incident Response Commander is a fully autonomous, multi-agent security incident response system built on Elastic's Agent Builder. Three specialized AI agents — **Detector**, **Investigator**, and **Responder** — are chained into a zero-human-intervention pipeline driven by a Python orchestrator. The system detects threats in real time, correlates evidence, generates playbooks, and dispatches Slack + Jira notifications in under 10 minutes from first alert.

```
┌──────────────────────────────────────────────────────────────────────┐
│                  INCIDENT RESPONSE COMMANDER                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   ┌────────────────────────────────────────────────────────────┐     │
│   │              Python Orchestrator (autonomous)               │     │
│   └────────┬───────────────────┬──────────────────┬────────────┘     │
│            │                   │                  │                  │
│            ▼                   ▼                  ▼                  │
│   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐           │
│   │   DETECTOR   │──▶│  INVESTIGATOR │──▶│  RESPONDER   │           │
│   │    Agent     │   │     Agent    │   │    Agent     │           │
│   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘           │
│          │                  │                  │                    │
│      ES|QL            ES|QL + LLM         LLM + Notify             │
│      Queries          Correlation          Slack / Jira             │
│   (4 patterns)      + Timeline           Playbook Gen              │
│                                                                       │
│   ┌─────────────────────────────────────────────────────────────┐    │
│   │  Elasticsearch: security-simulated-events                    │    │
│   │  Audit log: incident-response-log                           │    │
│   │  Metrics:   incident-metrics (MTTD / MTTR)                 │    │
│   └─────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Attack Scenarios Supported

| Type | MITRE Technique | Severity | Detection Window |
|---|---|---|---|
| Brute Force | T1110 | CRITICAL | 15 min / ≥5 failures |
| Data Exfiltration | T1041 | HIGH | 1 hour / >100 MB |
| Privilege Escalation | T1068 | HIGH | 30 min |
| Lateral Movement | T1021 | HIGH | 30 min / 3+ hosts |
| APT Kill-Chain | T1046→T1041 | CRITICAL | 2 hour full campaign |

---

## Features

- **Autonomous 3-phase pipeline** — Detection → Investigation → Response with zero human intervention
- **Evidence gates** — Each phase transition validates confidence score and IOC quality before proceeding
- **10 ES|QL tools** — Detection, correlation, timeline, anomaly scoring, MITRE mapping, campaign correlation, MTTD/MTTR scorecard
- **APT kill-chain simulation** — Full 6-stage attack (Recon → Exfiltration) with realistic timestamps
- **Slack Block Kit alerts** — Severity-colour-coded with automated vs. human actions clearly separated
- **Jira REST API tickets** — Structured with timeline table, IOC list, impact assessment
- **MTTD/MTTR metrics** — Written to `incident-metrics` index, graded against industry benchmarks
- **Anomaly scoring** — Compares 15-min activity to 7-day baseline per source IP
- **MITRE ATT&CK mapper** — Identifies technique hits from raw events automatically
- **Campaign correlation** — Flags source IPs with 2+ attack types as coordinated actors

---

## Quick Start

### Prerequisites
- Elastic Cloud 9.x with Agent Builder enabled
- Python 3.9+
- Slack webhook URL (optional — notifications gracefully degrade)
- Jira Cloud account (optional)

### 1. Clone and install
```bash
git clone https://github.com/arshgill01/incident-response-commander.git
cd incident-response-commander
pip install -r requirements.txt
```

### 2. Configure environment
```bash
cp .env.example .env
# Fill in: ELASTIC_CLOUD_ID, ELASTIC_PASSWORD
# Optional: SLACK_WEBHOOK_URL, JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN
```

### 3. Manual Kibana setup
Follow [MANUAL_SETUP.md](MANUAL_SETUP.md) to create agents and tools in the Kibana Agent Builder UI.

### 4. Run the demo
```bash
# Full APT kill-chain (default)
bash demo/run-demo.sh

# Specific attack type
bash demo/run-demo.sh --type brute_force

# Dry run (no data injection)
bash demo/run-demo.sh --dry-run
```

### 5. Reset between runs
```bash
bash demo/reset-demo.sh        # Soft reset (keep index, clear events)
bash demo/reset-demo.sh --hard # Delete and recreate all indices
```

### 6. Run tests
```bash
pytest
```

---

## Repository Structure

```
├── agents/               # Agent JSON configs (Detector, Investigator, Responder)
├── tools/esql/           # 10 ES|QL query files
│   ├── brute-force-detection.esql
│   ├── data-exfiltration-detection.esql
│   ├── privilege-escalation-detection.esql
│   ├── incident-correlation.esql
│   ├── timeline-builder.esql
│   ├── anomaly-scorer.esql
│   ├── mitre-attack-mapper.esql
│   ├── lateral-movement-detector.esql
│   ├── campaign-correlation.esql
│   └── mttd-mttr-scorecard.esql
├── demo/
│   ├── orchestrator.py         # Autonomous pipeline engine (centerpiece)
│   ├── incident-simulator.py   # 5 attack scenario generators
│   ├── notifications.py        # Slack Block Kit + Jira REST dispatcher
│   ├── setup-indices.py        # ES index/mapping/ILM setup
│   ├── data-ingestion.py       # Baseline event ingestion
│   ├── run-demo.sh             # One-command full demo
│   └── reset-demo.sh           # Clean slate reset
├── tests/                # Full pytest suite (60+ tests)
├── docs/                 # Architecture + setup docs
├── submission/           # Hackathon submission files
└── requirements.txt
```

---

## Documentation

- **[MANUAL_SETUP.md](MANUAL_SETUP.md)** — Kibana Agent Builder configuration walkthrough
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Technical architecture and data flow
- **[submission/project-description.md](submission/project-description.md)** — Hackathon submission

---

## License

MIT — see [LICENSE](LICENSE)

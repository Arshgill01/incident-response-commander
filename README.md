# Incident Response Commander

A multi-agent security incident response system built with Elastic Agent Builder for the Elastic Agent Builder Hackathon.

## Overview

Incident Response Commander uses three specialized AI agents working in a pipeline (Detector -> Investigator -> Responder) to detect, investigate, and respond to security incidents. Each agent has custom ES|QL tools for querying security event data stored in Elasticsearch.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│            INCIDENT RESPONSE COMMANDER               │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│  │ DETECTOR │───>│INVESTIGATOR│───>│ RESPONDER│      │
│  │  Agent   │    │   Agent   │    │   Agent  │      │
│  └──────────┘    └──────────┘    └──────────┘      │
│       │               │               │            │
│   ES|QL            ES|QL           Kibana          │
│   Detection        Correlation     Connectors      │
│   Queries          & Timeline      (Slack, Jira)   │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## Features

- **Multi-Agent Pipeline**: Three specialized agents for detection, investigation, and response
- **ES|QL-Powered Detection**: 5 custom ES|QL tools for querying security event patterns
- **Multiple Incident Types**: Brute force attacks, data exfiltration, privilege escalation
- **Team Integration**: Slack notifications and Jira ticket creation via Kibana Connectors
- **Demo Simulation**: Python scripts to generate synthetic attack events for testing

## Incident Types Supported

1. **Brute Force Attacks** - Detects multiple failed login attempts from a single IP
2. **Data Exfiltration** - Identifies unusual outbound data transfer volumes
3. **Privilege Escalation** - Detects suspicious privilege elevation attempts

## Technologies Used

- **Elastic Agent Builder** - Agent orchestration with custom instructions and tools
- **ES|QL** - Security queries with aggregations and time-series analysis
- **Elasticsearch** - Data storage, indexing, and ILM policies
- **Kibana Connectors** - Slack and Jira integration for the Responder agent
- **Python** - Data ingestion and attack simulation scripts

## Quick Start

### Prerequisites
- Elastic Cloud account (9.x with Agent Builder enabled)
- Python 3.8+
- Slack workspace (for notifications)
- Jira Cloud account (for ticket creation)

### 1. Clone Repository
```bash
git clone https://github.com/arshgill01/incident-response-commander.git
cd incident-response-commander
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your Elastic Cloud credentials
# Supports both API key and username/password authentication
```

### 3. Manual Setup in Kibana
Follow [MANUAL_SETUP.md](MANUAL_SETUP.md) to configure:
- 5 custom ES|QL tools in Agent Builder
- 3 AI agents in Agent Builder
- Slack and Jira Connectors in Stack Management

### 4. Ingest Data and Test
```bash
cd demo
python3 data-ingestion.py                          # Ingest sample security events
python3 incident-simulator.py brute_force          # Simulate a brute force attack
```

### 5. Run the Demo
```bash
./demo/run-demo.sh
```

## Documentation

- **[MANUAL_SETUP.md](MANUAL_SETUP.md)** - Step-by-step Kibana configuration
- **[SETUP.md](docs/SETUP.md)** - Complete installation guide
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Technical architecture details

## Repository Structure

```
├── agents/          # Agent configurations (JSON reference files)
├── tools/esql/      # ES|QL detection queries
├── workflows/       # Response workflow reference designs (YAML)
├── demo/            # Data ingestion, simulation, and demo scripts
├── docs/            # Documentation
└── submission/      # Hackathon submission files
```

## Demo Flow

1. **Simulate Attack** - Inject synthetic security events into Elasticsearch
2. **Detection** - Detector agent identifies attack patterns using ES|QL
3. **Investigation** - Investigator agent correlates events and builds timeline
4. **Response** - Responder agent coordinates containment and notifications
5. **Result** - Slack alert sent and Jira ticket created

## License

MIT License - See LICENSE file

## Author

arshgill01

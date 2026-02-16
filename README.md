# Incident Response Commander

An autonomous multi-agent security incident response system powered by Elastic Agent Builder.

## Overview

Incident Response Commander is a sophisticated AI-driven system that autonomously detects, investigates, and responds to security incidents. It uses three specialized agents working together to provide end-to-end incident response automation.

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
│   ES|QL + ML      ES|QL JOINs    Workflows +      │
│   Anomaly         Correlation    MCP Actions      │
│   Detection                                    │
│                                                      │
└─────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                 Slack              Jira Cloud
              Notifications         Tickets
```

## Features

- **Multi-Agent System**: Three specialized agents for detection, investigation, and response
- **Multiple Incident Types**: Brute force attacks, data exfiltration, privilege escalation
- **Automated Response**: IP blocking, account disabling, session termination
- **Team Integration**: Slack notifications and Jira ticket creation
- **Context Engineering**: ES|QL for complex cross-index correlations

## Incident Types Supported

1. **Brute Force Attacks**: Detects multiple failed login attempts
2. **Data Exfiltration**: Identifies unusual data transfer volumes
3. **Privilege Escalation**: Detects unauthorized access elevation

## Technologies Used

- **Elastic Agent Builder**: Agent orchestration and reasoning
- **ES|QL**: Complex security queries and correlations
- **Elastic Workflows**: Automated response actions
- **MCP Protocol**: External integrations (Slack, Jira)
- **Machine Learning**: Anomaly detection

## Quick Start

### Prerequisites
- Elastic Cloud account with Security deployment
- Slack workspace
- Jira Cloud account
- Python 3.8+

### 1. Clone Repository
```bash
git clone https://github.com/arshgill01/incident-response-commander.git
cd incident-response-commander
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
# Edit .env file with your credentials
# Elastic Cloud, Slack, and Jira credentials already configured
```

### 3. Manual Setup in Kibana
Follow [MANUAL_SETUP.md](MANUAL_SETUP.md) to configure:
- 5 custom ES|QL tools
- 3 AI agents
- 4 automated workflows

### 4. Test the System
```bash
cd demo
python3 data-ingestion.py              # Ingest sample data
python3 incident-simulator.py brute_force  # Simulate attack
```

### 5. Run Demo
```bash
./demo/run-demo.sh
```

## Documentation

- **[MANUAL_SETUP.md](MANUAL_SETUP.md)** - Step-by-step Kibana configuration
- **[SETUP.md](docs/SETUP.md)** - Complete installation guide
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Technical architecture details

## Repository Structure

```
├── agents/          # Agent configurations (JSON)
├── tools/esql/      # ES|QL detection queries
├── workflows/       # Automation workflows (YAML)
├── demo/           # Testing and simulation scripts
├── docs/           # Documentation
└── submission/     # Hackathon submission files
```

## Demo Flow

1. **Simulate Attack** - Inject synthetic security events
2. **Detection** - Agent identifies brute force pattern
3. **Investigation** - Agent correlates events across indices
4. **Response** - Automated containment + notifications
5. **Result** - Slack alert + Jira ticket created

**Total Response Time: < 60 seconds**

## License

MIT License - See LICENSE file

## Author

arshgill01

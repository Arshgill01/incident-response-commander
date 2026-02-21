# Incident Response Commander

**Multi-Agent Security Incident Response System**

## Problem Statement

Security Operations Centers (SOCs) face an overwhelming challenge: they receive thousands of alerts daily but lack the resources to investigate each one thoroughly. Manual investigation and response create bottlenecks — analysts must context-switch between detection tools, investigation consoles, and communication platforms. This fragmented process slows response times and allows attackers to maintain persistence.

## Solution Overview

Incident Response Commander is a multi-agent AI system built on Elastic Agent Builder that streamlines the detect-investigate-respond workflow. The system uses three specialized agents working in a pipeline: a Detector agent that identifies attack patterns in security logs, an Investigator agent that correlates events and builds timelines, and a Responder agent that coordinates containment actions and notifies the team through Slack and Jira.

## Technical Implementation

The system is built around five custom ES|QL tools created in Elastic Agent Builder. Brute Force Detection identifies clusters of failed authentication attempts from single IP addresses using time-windowed aggregations. Data Exfiltration Detection monitors outbound data transfer volumes grouped by user. Privilege Escalation Detection tracks suspicious elevation attempts by process category. Incident Correlation queries all events related to a suspicious IP or user across a configurable investigation window. Timeline Builder creates chronological views of activity using time bucketing.

All security events are stored in a single Elasticsearch index (`security-simulated-events`) with a schema covering authentication, network, and process events. Python scripts handle data ingestion and attack simulation — generating realistic event sequences for brute force, exfiltration, and privilege escalation scenarios.

Each agent has carefully crafted instructions defining its role and decision boundaries. The Detector classifies incidents by severity (CRITICAL/HIGH/MEDIUM/LOW) based on statistical thresholds. The Investigator gathers context from authentication, network, and process events to extract indicators of compromise (IOCs). The Responder evaluates response options based on severity and coordinates through Kibana Connectors for Slack notifications and Jira ticket creation.

## What We Built With Agent Builder

- **3 custom agents** with specialized instructions and tool assignments
- **5 ES|QL tools** for detection, correlation, and timeline analysis
- **Kibana Connectors** for Slack and Jira integration on the Responder agent
- **Python simulation framework** for generating realistic attack scenarios
- **Interactive demo script** that walks through the full detection-to-response pipeline

## Features We Liked and Challenges

The **Agent Builder interface** made it easy to define agent personas, assign specific tools, and test agent behavior through the built-in chat. ES|QL's piped syntax was well-suited for security queries — aggregations over time windows with field-level filtering mapped directly to detection logic.

Our main challenge was getting ES|QL syntax right — functions like `COUNT_DISTINCT()` and backtick-escaping for nested fields like `` `event.category` `` required careful attention. We also had to work around the Elasticsearch Python client v9.x API changes (`document=` instead of `body=`, `query=` for ES|QL).

## Technologies Used

- Elastic Agent Builder (Custom Agents, ES|QL Tools)
- Elasticsearch 9.x (Data storage, ILM, Index Templates)
- ES|QL (Aggregations, Time-series analysis, Filtering)
- Kibana Connectors (Slack, Jira)
- Python (Data ingestion, Attack simulation)

## Repository

https://github.com/arshgill01/incident-response-commander

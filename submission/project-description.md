# Incident Response Commander

**Autonomous Multi-Agent Security Incident Response — Elastic Agent Builder Hackathon**

---

## Problem Statement

Security Operations Centers (SOCs) are drowning in alerts. The median SOC receives thousands of alerts per day, yet the Mean Time to Respond (MTTR) for critical incidents is often measured in hours — not minutes. The bottleneck is human coordination: analysts must pivot between detection dashboards, investigation tools, and communication platforms, losing critical time at every handoff.

Existing tools give analysts *individual* capabilities. What they lack is an **autonomous pipeline** that chains detection → investigation → response with no manual handoffs.

---

## Solution

**Incident Response Commander** is a fully autonomous security incident response system built on Elastic's Agent Builder. It chains three specialized AI agents into a zero-human-intervention pipeline:

1. **Detector Agent** — Runs ES|QL detection queries across 4 threat patterns, scores confidence, and classifies severity
2. **Investigator Agent** — Performs deep forensic correlation, extracts IOCs, and reconstructs the attack timeline
3. **Responder Agent** — Generates containment playbooks, dispatches Slack Block Kit alerts, and creates structured Jira tickets

A Python **orchestrator** drives the full pipeline autonomously, enforces evidence gates between phases, writes a complete audit trail to Elasticsearch, and tracks MTTD/MTTR metrics against industry benchmarks.

---

## Technical Implementation

### Orchestrator (the centerpiece)

`demo/orchestrator.py` is a ~1,550-line Python engine that:

- Runs 4 ES|QL detection queries directly via the Elasticsearch Python client (v9.x)
- Calls the Kibana `unified_completion` connector API to invoke Claude Sonnet with agent-specific system prompts
- Enforces **evidence gates**: phase transitions require minimum confidence score + valid IOC list + timeline presence
- Writes every phase result to `incident-response-log` (full audit trail)
- Writes MTTD/MTTR to `incident-metrics` for dashboard tracking
- Supports `--dry-run`, `--watch`, `--report`, and `--simulate` CLI modes

### ES|QL Tool Library (10 tools)

| Tool | Purpose |
|---|---|
| `brute-force-detection` | Auth failures ≥5 in 15 min → breach confirmed |
| `data-exfiltration-detection` | Outbound bytes > 100 MB in 1 hour |
| `privilege-escalation-detection` | Process privilege_escalation action in 30 min |
| `incident-correlation` | All events by source IP in investigation window |
| `timeline-builder` | Chronological event sequence with time buckets |
| `anomaly-scorer` | Recent vs. 7-day baseline ratio per source IP |
| `mitre-attack-mapper` | Maps event patterns → T-codes (6 techniques) |
| `lateral-movement-detector` | 3+ distinct host logins from same IP in 30 min |
| `campaign-correlation` | 2+ attack types from same IP = coordinated actor |
| `mttd-mttr-scorecard` | 30-day P50/P95 stats with industry grade labels |

### Attack Simulation (5 scenarios)

`demo/incident-simulator.py` generates ECS-compliant synthetic events:

- **Brute Force** — 20-30 failures + successful breach
- **Data Exfiltration** — 5-10 transfers of 500 MB–1.5 GB each
- **Privilege Escalation** — 5 sudo/pkexec commands targeting root
- **Lateral Movement** — Same user, 5 distinct internal hosts (T1021)
- **APT Kill-Chain** — 6 stages over 120 minutes: Recon → Initial Access → Persistence → Privilege Escalation → Lateral Movement → Exfiltration (T1046 → T1110 → T1136 → T1068 → T1021 → T1041)

### Notification Pipeline

`demo/notifications.py` dispatches:
- **Slack Block Kit** — Severity-colour-coded, with emoji-labelled automated vs. human-approval action lists, MITRE technique badges, and MTTD/MTTR metrics
- **Jira REST API** — Structured Jira-wiki-markup tickets with timeline table, IOC section, impact assessment, and response checklist

### Testing (167 tests, all passing)

`tests/` covers:
- Event generation correctness and ECS compliance
- ES|QL file existence, syntax (no legacy `COUNT_DISTINCT()`), index names, content accuracy
- Notification channel enable/disable, block structure, HTTP success/failure handling
- Orchestrator evidence gate logic, audit log writes, LLM call mocking
- All 5 attack type routing paths in `run_simulation()`

---

## What We Built With Agent Builder

- **3 custom agents** — each with full instructions, severity decision trees, and response playbooks
- **10 ES|QL tools** — all registered in Agent Builder and runnable from chat
- **Autonomous orchestrator** — no human clicks required from simulation to Jira ticket
- **MITRE ATT&CK coverage** — 6 techniques across 5 attack scenarios
- **Industry-grade metrics** — MTTD/MTTR tracked and graded (Excellent / Good / Fair / Poor)

---

## Key Technical Discoveries

1. **No direct agent invocation API** — Agent Builder chat is UI-only. The orchestrator calls the `unified_completion` Kibana connector directly and injects agent system prompts, achieving the same result without UI.
2. **ES|QL syntax** — `COUNT_DISTINCT(x)` not `COUNT(DISTINCT x)`. Nested fields require backtick escaping (`` `event.category` ``).
3. **ES Python client v9** — `document=` not `body=`; `query=` for ES|QL; `request_timeout=` not `timeout=`.
4. **Auth** — API key was broken on our deployment. Username/password fallback works reliably.
5. **Security AI Assistant** (`/api/security_ai_assistant/chat/complete`) — Works for pure LLM calls but does not invoke custom ES|QL tools, so native ES|QL in Python was the right choice.

---

## Technologies

- **Elastic Agent Builder** — Custom agents, ES|QL tools
- **Elasticsearch 9.x** — Event storage, ILM, index templates, ES|QL engine
- **Kibana** — Connector API (`unified_completion`), Agent Builder UI
- **Anthropic Claude Sonnet** — LLM backbone via Kibana connector
- **Python 3.9+** — Orchestrator, simulator, notifications, tests
- **Slack Block Kit** — Rich incident alert formatting
- **Jira REST API v2** — Structured ticket creation
- **pytest** — 167 unit tests (all passing)

---

## Repository

https://github.com/arshgill01/incident-response-commander

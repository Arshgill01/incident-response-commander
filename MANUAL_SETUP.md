# MANUAL SETUP CHECKLIST - Complete These Steps in Kibana

## Overview
All configuration files have been created. Now you need to manually configure Agent Builder in Kibana using these files.

---

## Step 1: Create Custom Tools (5 Tools)

Navigate to: **Agent Builder → Tools → New Tool**

### Tool 1: Brute Force Detection
```
Name: brute-force-detection
Type: ES|QL
Description: Detect brute force attack patterns from authentication logs
```

**Copy ES|QL Query from:** `tools/esql/brute-force-detection.esql`

**Parameters to add:**
1. `time_window` (Time Duration) - Default: "15 minutes"
2. `failure_threshold` (Integer) - Default: 5

**ES|QL Note:** Ensure nested fields use backticks (`` `event.category` ``) and aggregations use `COUNT_DISTINCT()` syntax.

---

### Tool 2: Data Exfiltration Detection
```
Name: data-exfiltration-detection
Type: ES|QL
Description: Detect unusual outbound data transfers indicating exfiltration
```

**Copy ES|QL Query from:** `tools/esql/data-exfiltration-detection.esql`

**Parameters to add:**
1. `time_window` (Time Duration) - Default: "1 hour"
2. `bytes_threshold` (Integer) - Default: 100000000

---

### Tool 3: Privilege Escalation Detection
```
Name: privilege-escalation-detection
Type: ES|QL
Description: Detect suspicious privilege elevation attempts
```

**Copy ES|QL Query from:** `tools/esql/privilege-escalation-detection.esql`

**Parameters to add:**
1. `time_window` (Time Duration) - Default: "30 minutes"

---

### Tool 4: Incident Correlation
```
Name: incident-correlation
Type: ES|QL
Description: Correlate events for comprehensive incident investigation
```

**Copy ES|QL Query from:** `tools/esql/incident-correlation.esql`

**Parameters to add:**
1. `investigation_window` (Time Duration) - Default: "4 hours"
2. `suspicious_ip` (Text)
3. `suspicious_user` (Text)

---

### Tool 5: Timeline Builder
```
Name: timeline-builder
Type: ES|QL
Description: Build chronological timeline of suspicious activity
```

**Copy ES|QL Query from:** `tools/esql/timeline-builder.esql`

**Parameters to add:**
1. `time_window` (Time Duration)
2. `target_ip` (Text)
3. `target_user` (Text)

---

## Step 2: Create Custom Agents (3 Agents)

Navigate to: **Agent Builder → Agents → New Agent**

### Agent 1: Security Detector

**Settings Tab:**
```
Display Name: Security Incident Detector
Description: Monitors security logs to detect brute force attacks, data exfiltration, and privilege escalation attempts
Avatar: Red shield
```

**Instructions:** Copy from `agents/detector-agent.json` (the "instructions" field)

**Tools Tab - Select these tools:**
- brute-force-detection
- data-exfiltration-detection
- privilege-escalation-detection
- platform.core.search
- platform.core.list_indices

---

### Agent 2: Incident Investigator

**Settings Tab:**
```
Display Name: Incident Investigator
Description: Performs forensic analysis of security incidents using event correlation and timeline reconstruction
Avatar: Orange search
```

**Instructions:** Copy from `agents/investigator-agent.json`

**Tools Tab - Select these tools:**
- incident-correlation
- timeline-builder
- platform.core.search
- platform.core.get_document_by_id
- platform.core.get_index_mapping

---

### Agent 3: Incident Responder

**Settings Tab:**
```
Display Name: Incident Responder
Description: Coordinates incident response through Slack notifications and Jira ticket creation
Avatar: Green bolt
```

**Instructions:** Copy from `agents/responder-agent.json`

**Tools Tab:**
Assign Slack and Jira connector tools after creating them in Step 3.

---

## Step 3: Create Kibana Connectors (for Responder Agent)

Navigate to: **Stack Management → Connectors → Create Connector**

### Connector 1: Slack Notification
- **Type**: Slack (Webhook)
- **Name**: `Security Slack Notification`
- **Webhook URL**: Your Slack incoming webhook URL

### Connector 2: Jira Ticket Creation
- **Type**: Jira
- **Name**: `Security Jira Tickets`
- **URL**: Your Jira instance URL (e.g., `https://your-instance.atlassian.net`)
- **Email**: Your Jira account email
- **API Token**: Your Jira API token
- **Project Key**: `SCRUM`

After creating connectors, go back to the Responder agent and assign the connector tools.

**Note:** The `workflows/` directory contains YAML reference designs that illustrate the intended response logic. The actual integrations use Kibana Connectors as described above.

---

## Step 4: Test the System

### 4.1 Ingest Sample Data

```bash
cd demo
python3 data-ingestion.py
```

### 4.2 Simulate an Attack

```bash
python3 incident-simulator.py brute_force
```

### 4.3 Test Detection

1. Go to **Agent Builder → Chat**
2. Select **"Security Incident Detector"**
3. Type: "Detect brute force attacks in the last 15 minutes"
4. Verify it finds the simulated attack

### 4.4 Test Investigation

1. Switch to **"Incident Investigator"**
2. Provide the suspicious IP from detection
3. Type: "Investigate IP [IP_ADDRESS] and build timeline"
4. Verify it correlates events

### 4.5 Test Response

1. Switch to **"Incident Responder"**
2. Type: "Execute response for this CRITICAL incident"
3. Check Slack for notification
4. Check Jira for ticket

---

## Step 5: Push to GitHub

```bash
cd /path/to/incident-response-commander
git add .
git commit -m "Incident Response Commander for Elastic Agent Builder Hackathon"
git push -u origin master
```

---

## Step 6: Submit to Devpost

### Required Submission Elements:

1. **Project Description** (400 words)
   - Copy from: `submission/project-description.md`

2. **Demo Video** (3 minutes)
   - Record screen showing:
     - System architecture overview
     - Simulated attack injection
     - Detection by Detector agent
     - Investigation results
     - Response actions (Slack/Jira)

3. **GitHub Repository URL**
   - https://github.com/arshgill01/incident-response-commander

---

## Quick Reference: File Locations

```
├── agents/                    # Agent configurations (JSON reference)
│   ├── detector-agent.json
│   ├── investigator-agent.json
│   └── responder-agent.json
├── tools/esql/               # ES|QL queries for tools
│   ├── brute-force-detection.esql
│   ├── data-exfiltration-detection.esql
│   ├── privilege-escalation-detection.esql
│   ├── incident-correlation.esql
│   └── timeline-builder.esql
├── workflows/                # Response workflow reference designs (YAML)
│   ├── immediate-containment.yml
│   ├── slack-notification.yml
│   ├── jira-ticket-creation.yml
│   └── evidence-preservation.yml
├── demo/                     # Testing scripts
│   ├── data-ingestion.py
│   ├── incident-simulator.py
│   ├── test-connection.py
│   └── run-demo.sh
└── docs/                     # Documentation
    ├── SETUP.md
    ├── ARCHITECTURE.md
    └── PHASE1_CHECKLIST.md
```

---

## Troubleshooting

### Agent Builder not visible?
- Check Stack Management → Advanced Settings
- Ensure `xpack.agent_builder.enabled: true`

### Tools not working?
- Verify ES|QL syntax in Dev Tools first
- Check that `security-simulated-events` index exists
- Ensure nested fields use backticks
- Use `COUNT_DISTINCT()` not `COUNT(DISTINCT ...)`

### Connectors not working?
- Check connector configuration in Stack Management
- Verify webhook URLs and API tokens are correct
- Test connectors individually before assigning to agent

### No data detected?
- Run `data-ingestion.py` first
- Run `incident-simulator.py` to generate attack events
- Check time ranges in queries
- Verify index exists: Stack Management → Index Management

---

## Success Criteria

After completing all steps, you should have:

- [ ] 5 custom ES|QL tools created in Agent Builder
- [ ] 3 custom agents configured in Agent Builder
- [ ] Slack and Jira connectors set up
- [ ] Sample data ingested into `security-simulated-events`
- [ ] Successfully tested detection with simulated attack
- [ ] GitHub repository pushed
- [ ] Devpost submission complete

---

Estimated time to complete manual setup: **1-2 hours**

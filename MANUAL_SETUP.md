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
2. `failure_threshold` (Integer) - Default: 10

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
2. `bytes_threshold` (Integer) - Default: 1000000000

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
Description: Cross-index correlation for comprehensive incident investigation
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
Agent ID: security-detector
Display Name: Security Incident Detector
Description: Continuously monitors security logs to detect brute force attacks, data exfiltration, and privilege escalation attempts
Avatar: Red shield
```

**Instructions:** Copy from `agents/detector-agent.json` (the "instructions" field)

**Tools Tab - Select these tools:**
- ☑️ brute-force-detection
- ☑️ data-exfiltration-detection
- ☑️ privilege-escalation-detection
- ☑️ platform.core.search
- ☑️ platform.core.list_indices

---

### Agent 2: Incident Investigator

**Settings Tab:**
```
Agent ID: incident-investigator
Display Name: Incident Investigator
Description: Performs deep forensic analysis of security incidents using multi-source correlation and timeline reconstruction
Avatar: Orange search
```

**Instructions:** Copy from `agents/investigator-agent.json`

**Tools Tab - Select these tools:**
- ☑️ incident-correlation
- ☑️ timeline-builder
- ☑️ platform.core.search
- ☑️ platform.core.get_document_by_id
- ☑️ platform.core.get_index_mapping

---

### Agent 3: Incident Responder

**Settings Tab:**
```
Agent ID: incident-responder
Display Name: Incident Responder
Description: Executes automated containment actions and coordinates incident response through Slack and Jira integration
Avatar: Green bolt
```

**Instructions:** Copy from `agents/responder-agent.json`

**Tools Tab:**
Note: Workflow tools need to be created first (Step 3), then assigned here.

---

## Step 3: Create Workflows (4 Workflows)

Navigate to: **Stack Management → Workflows → Create Workflow**

### Workflow 1: Immediate Containment
```yaml
# Copy content from: workflows/immediate-containment.yml
# Configure secrets for firewall API if available
```

---

### Workflow 2: Slack Notification
```yaml
# Copy content from: workflows/slack-notification.yml
# Secret to configure: slack_webhook_url
```

**Configure Secret:**
1. Go to **Stack Management → Secrets**
2. Create secret: `slack_webhook_url`
3. Value: `<YOUR_SLACK_WEBHOOK_URL>`

---

### Workflow 3: Jira Ticket Creation
```yaml
# Copy content from: workflows/jira-ticket-creation.yml
# Secrets to configure: jira_url, jira_email, jira_api_token
```

**Configure Secrets:**
1. `jira_url`: `<YOUR_JIRA_URL>`
2. `jira_email`: Your email
3. `jira_api_token`: `<YOUR_JIRA_API_TOKEN>`

---

### Workflow 4: Evidence Preservation
```yaml
# Copy content from: workflows/evidence-preservation.yml
```

---

## Step 4: Assign Workflow Tools to Responder Agent

Go back to **Agent Builder → Agents → incident-responder → Edit**

**Tools Tab - Add workflow tools:**
- ☑️ immediate-containment
- ☑️ slack-notification
- ☑️ jira-ticket-creation
- ☑️ evidence-preservation

---

## Step 5: Test the System

### 5.1 Ingest Sample Data

```bash
cd /path/to/incident-response-commander/demo
python3 data-ingestion.py
```

### 5.2 Simulate an Attack

```bash
python3 incident-simulator.py brute_force
```

### 5.3 Test Detection

1. Go to **Agent Builder → Chat**
2. Select **"Security Incident Detector"**
3. Type: "Detect brute force attacks in the last 15 minutes"
4. Verify it finds the simulated attack

### 5.4 Test Investigation

1. Switch to **"Incident Investigator"**
2. Provide the suspicious IP from detection
3. Type: "Investigate IP [IP_ADDRESS] and build timeline"
4. Verify it correlates events

### 5.5 Test Response

1. Switch to **"Incident Responder"**
2. Type: "Execute response for this CRITICAL incident"
3. Check Slack for notification
4. Check Jira for ticket

---

## Step 6: Push to GitHub

```bash
cd /path/to/incident-response-commander

# Initialize git (if not done)
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit: Incident Response Commander for Elastic Agent Builder Hackathon

- 3 specialized agents (Detector, Investigator, Responder)
- 5 custom ES|QL detection tools
- 4 automated workflows (Containment, Slack, Jira, Evidence)
- 3 incident types (Brute Force, Data Exfiltration, Privilege Escalation)
- Full documentation and demo scripts"

# Add remote (replace with your repo)
git remote add origin https://github.com/arshgill01/incident-response-commander.git

# Push
git push -u origin main
```

---

## Step 7: Submit to Devpost

### Required Submission Elements:

1. **Project Description** (400 words)
   - Copy from: `submission/project-description.md`

2. **Demo Video** (3 minutes)
   - Record screen showing:
     - System architecture
     - Simulated attack injection
     - Detection by Agent
     - Investigation results
     - Response actions
     - Slack/Jira notifications

3. **GitHub Repository URL**
   - Your GitHub repo link

4. **Social Media Post** (Bonus points)
   - Post about your project on Twitter/LinkedIn
   - Tag @elastic_devs
   - Include repository link

---

## Quick Reference: File Locations

```
├── agents/                    # Agent configurations
│   ├── detector-agent.json
│   ├── investigator-agent.json
│   └── responder-agent.json
├── tools/esql/               # ES|QL queries
│   ├── brute-force-detection.esql
│   ├── data-exfiltration-detection.esql
│   ├── privilege-escalation-detection.esql
│   ├── incident-correlation.esql
│   └── timeline-builder.esql
├── workflows/                # Workflow definitions
│   ├── immediate-containment.yml
│   ├── slack-notification.yml
│   ├── jira-ticket-creation.yml
│   └── evidence-preservation.yml
├── demo/                     # Testing scripts
│   ├── data-ingestion.py
│   ├── incident-simulator.py
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
- Check index patterns exist
- Verify parameters are configured

### Workflows failing?
- Check secret configuration
- Verify webhook URLs are correct
- Review execution logs

### No data detected?
- Run data-ingestion.py first
- Check time ranges in queries
- Verify indices exist in Stack Management

---

## Success Criteria ✅

After completing all steps, you should have:

- [ ] 5 custom ES|QL tools created
- [ ] 3 custom agents configured
- [ ] 4 workflows with secrets
- [ ] Sample data ingested
- [ ] Successfully tested all 3 incident types
- [ ] Slack notifications working
- [ ] Jira tickets created
- [ ] GitHub repository pushed
- [ ] Demo video recorded
- [ ] Devpost submission complete

---

**You're ready to win! 🚀**

Estimated time to complete manual setup: **2-3 hours**

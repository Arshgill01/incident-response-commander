# Incident Response Commander - Complete Setup Guide

## Prerequisites

- Elastic Cloud account with Security deployment
- Slack workspace (free tier works)
- Jira Cloud account (free tier works)
- Python 3.8+ (for simulation scripts)

## Step 1: Environment Setup

### 1.1 Clone and Setup Repository

```bash
git clone https://github.com/arshgill01/incident-response-commander.git
cd incident-response-commander
```

### 1.2 Create Virtual Environment (Optional but Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 1.3 Install Dependencies

```bash
pip install elasticsearch python-dotenv requests
```

### 1.4 Configure Environment Variables

Create `.env` file in root directory:

```env
# Elastic Cloud (Already configured)
ELASTIC_CLOUD_ID=<YOUR_ELASTIC_CLOUD_ID>
ELASTIC_API_KEY=<YOUR_ELASTIC_API_KEY>
KIBANA_URL=<YOUR_KIBANA_URL>

# Slack Integration
SLACK_WEBHOOK_URL=<YOUR_SLACK_WEBHOOK_URL>
SLACK_CHANNEL=#security-incidents

# Jira Integration
JIRA_URL=<YOUR_JIRA_URL>
JIRA_API_TOKEN=<YOUR_JIRA_API_TOKEN>
JIRA_PROJECT_KEY=SCRUM
```

## Step 2: Ingest Sample Data

```bash
cd demo
python3 data-ingestion.py
```

This will:
- Create index templates
- Setup ILM policies
- Ingest sample security events
- Verify ES|QL queries work

## Step 3: Configure Agent Builder

### 3.1 Create Custom Tools in Kibana

1. Navigate to **Agent Builder** → **Tools**
2. Click **"New Tool"**
3. Create each tool from the `tools/esql/` directory:

#### Tool 1: Brute Force Detection
- **Name**: `brute-force-detection`
- **Type**: ES|QL
- **Description**: "Detect brute force attack patterns from authentication logs"
- **Query**: Copy from `tools/esql/brute-force-detection.esql`
- **Parameters**:
  - `time_window`: Time duration (default: "15 minutes")
  - `failure_threshold`: Integer (default: 10)

#### Tool 2: Data Exfiltration Detection
- **Name**: `data-exfiltration-detection`
- **Type**: ES|QL
- **Description**: "Detect unusual outbound data transfers indicating exfiltration"
- **Query**: Copy from `tools/esql/data-exfiltration-detection.esql`
- **Parameters**:
  - `time_window`: Time duration (default: "1 hour")
  - `bytes_threshold`: Integer (default: 1000000000)

#### Tool 3: Privilege Escalation Detection
- **Name**: `privilege-escalation-detection`
- **Type**: ES|QL
- **Description**: "Detect suspicious privilege elevation attempts"
- **Query**: Copy from `tools/esql/privilege-escalation-detection.esql`
- **Parameters**:
  - `time_window`: Time duration (default: "30 minutes")

#### Tool 4: Incident Correlation
- **Name**: `incident-correlation`
- **Type**: ES|QL
- **Description**: "Cross-index correlation for comprehensive incident investigation"
- **Query**: Copy from `tools/esql/incident-correlation.esql`
- **Parameters**:
  - `investigation_window`: Time duration (default: "4 hours")
  - `suspicious_ip`: IP address
  - `suspicious_user`: Username

#### Tool 5: Timeline Builder
- **Name**: `timeline-builder`
- **Type**: ES|QL
- **Description**: "Build chronological timeline of suspicious activity"
- **Query**: Copy from `tools/esql/timeline-builder.esql`
- **Parameters**:
  - `time_window`: Time duration
  - `target_ip`: IP address
  - `target_user`: Username

### 3.2 Create Custom Agents

Navigate to **Agent Builder** → **Agents** → **New Agent**

#### Agent 1: Security Detector
- **Agent ID**: `security-detector`
- **Display Name**: `Security Incident Detector`
- **Instructions**: Copy from `agents/detector-agent.json`
- **Tools**: Select all detection tools
- **Avatar**: Red shield

#### Agent 2: Incident Investigator
- **Agent ID**: `incident-investigator`
- **Display Name**: `Incident Investigator`
- **Instructions**: Copy from `agents/investigator-agent.json`
- **Tools**: Select correlation and timeline tools
- **Avatar**: Orange search

#### Agent 3: Incident Responder
- **Agent ID**: `incident-responder`
- **Display Name**: `Incident Responder`
- **Instructions**: Copy from `agents/responder-agent.json`
- **Tools**: Select workflow tools (if available)
- **Avatar**: Green bolt

## Step 4: Configure Workflows

Navigate to **Stack Management** → **Workflows**

Create each workflow from `workflows/` directory:

### 4.1 Immediate Containment
- Import: `workflows/immediate-containment.yml`
- Configure secrets for firewall API

### 4.2 Slack Notification
- Import: `workflows/slack-notification.yml`
- Configure `slack_webhook_url` secret

### 4.3 Jira Ticket Creation
- Import: `workflows/jira-ticket-creation.yml`
- Configure `jira_url`, `jira_email`, `jira_api_token` secrets

### 4.4 Evidence Preservation
- Import: `workflows/evidence-preservation.yml`

## Step 5: Test the System

### 5.1 Simulate an Attack

```bash
cd demo

# Simulate brute force attack
python3 incident-simulator.py brute_force

# Simulate data exfiltration
python3 incident-simulator.py exfiltration

# Simulate privilege escalation
python3 incident-simulator.py privilege_escalation
```

### 5.2 Verify Detection

1. Go to **Agent Builder** → **Chat**
2. Select **"Security Incident Detector"** agent
3. Ask: "Are there any brute force attacks in the last 15 minutes?"
4. Verify it detects the simulated attack

### 5.3 Verify Response

Check:
- Slack notification received
- Jira ticket created
- Evidence logs updated

## Step 6: Demo Script

For your hackathon demo, use this flow:

```bash
# 1. Show current state
"Our system is monitoring security logs..."

# 2. Trigger attack
python3 demo/incident-simulator.py brute_force

# 3. Show detection
"The Detector agent identifies the pattern..."

# 4. Show investigation
"The Investigator agent correlates events..."

# 5. Show response
"The Responder agent takes action..."
"Slack notification sent, Jira ticket created"

# 6. Show metrics
"Detection time: 47 seconds"
"Response time: 12 seconds"
```

## Troubleshooting

### Connection Issues
- Verify `.env` file has correct credentials
- Check Elastic Cloud deployment is running
- Ensure API key has proper permissions

### Agent Builder Not Visible
- Check Agent Builder is enabled in Advanced Settings
- Verify you have Enterprise license/trial
- Try refreshing Kibana

### Workflow Failures
- Check secret configuration
- Verify webhook URLs are correct
- Review workflow execution logs

### No Data Detected
- Run `data-ingestion.py` first
- Check index patterns match
- Verify time ranges in queries

## Support

For issues:
1. Check Elastic documentation
2. Review agent execution logs
3. Test ES|QL queries directly in Dev Tools
4. Verify all integrations with curl

## Next Steps

1. **Tune Detection Thresholds**: Adjust parameters based on your environment
2. **Add More Integrations**: PagerDuty, email, SIEM tools
3. **Customize Response Actions**: Add more containment options
4. **Build Dashboards**: Create Kibana dashboards for monitoring

---

**Ready to win this hackathon! 🚀**

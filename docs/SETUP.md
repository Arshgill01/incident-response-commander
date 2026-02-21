# Incident Response Commander - Complete Setup Guide

## Prerequisites

- Elastic Cloud account with Agent Builder enabled (9.x)
- Python 3.8+ (for simulation scripts)
- Slack workspace (optional, for notifications)
- Jira Cloud account (optional, for ticket creation)

## Step 1: Environment Setup

### 1.1 Clone and Setup Repository

```bash
git clone https://github.com/arshgill01/incident-response-commander.git
cd incident-response-commander
```

### 1.2 Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 1.3 Install Dependencies

```bash
pip install -r requirements.txt
```

### 1.4 Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# Elastic Cloud
ELASTIC_CLOUD_ID=<your-cloud-id>
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=<your-password>

# Optional: API Key (if password auth doesn't work)
# ELASTIC_API_KEY=<your-api-key>

# Slack Integration (optional)
SLACK_WEBHOOK_URL=<your-slack-webhook-url>

# Jira Integration (optional)
JIRA_URL=<your-jira-url>
JIRA_EMAIL=<your-email>
JIRA_API_TOKEN=<your-jira-api-token>
JIRA_PROJECT_KEY=SCRUM
```

**Note:** The scripts support both API key and username/password authentication. If one method fails, it automatically falls back to the other.

## Step 2: Ingest Sample Data

```bash
cd demo
python3 data-ingestion.py
```

This will:
- Create an index template for `security-simulated-events`
- Set up an ILM policy for data lifecycle management
- Ingest baseline security events (authentication, network, process)
- Verify ES|QL queries work against the data

## Step 3: Configure Agent Builder in Kibana

### 3.1 Create Custom Tools

Navigate to **Agent Builder** -> **Tools** -> **New Tool**

Create each tool using the queries from `tools/esql/`:

#### Tool 1: Brute Force Detection
- **Name**: `brute-force-detection`
- **Type**: ES|QL
- **Description**: "Detect brute force attack patterns from authentication logs"
- **Query**: Copy from `tools/esql/brute-force-detection.esql`
- **Parameters**:
  - `time_window`: Time duration (default: "15 minutes")
  - `failure_threshold`: Integer (default: 5)

#### Tool 2: Data Exfiltration Detection
- **Name**: `data-exfiltration-detection`
- **Type**: ES|QL
- **Description**: "Detect unusual outbound data transfers indicating exfiltration"
- **Query**: Copy from `tools/esql/data-exfiltration-detection.esql`
- **Parameters**:
  - `time_window`: Time duration (default: "1 hour")
  - `bytes_threshold`: Integer (default: 100000000)

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
- **Description**: "Correlate events for comprehensive incident investigation"
- **Query**: Copy from `tools/esql/incident-correlation.esql`
- **Parameters**:
  - `investigation_window`: Time duration (default: "4 hours")
  - `suspicious_ip`: Text (IP address)
  - `suspicious_user`: Text (username)

#### Tool 5: Timeline Builder
- **Name**: `timeline-builder`
- **Type**: ES|QL
- **Description**: "Build chronological timeline of suspicious activity"
- **Query**: Copy from `tools/esql/timeline-builder.esql`
- **Parameters**:
  - `time_window`: Time duration
  - `target_ip`: Text (IP address)
  - `target_user`: Text (username)

**Important ES|QL Notes:**
- Nested fields need backticks: `` `event.category` ``, `` `source.ip` ``
- Use `COUNT_DISTINCT()` not `COUNT(DISTINCT ...)`
- Index is `security-simulated-events` (not `logs-*`)

### 3.2 Create Custom Agents

Navigate to **Agent Builder** -> **Agents** -> **New Agent**

#### Agent 1: Security Detector
- **Display Name**: `Security Incident Detector`
- **Instructions**: Copy from `agents/detector-agent.json` (the "instructions" field)
- **Tools**: brute-force-detection, data-exfiltration-detection, privilege-escalation-detection, platform.core.search, platform.core.list_indices
- **Avatar**: Red shield

#### Agent 2: Incident Investigator
- **Display Name**: `Incident Investigator`
- **Instructions**: Copy from `agents/investigator-agent.json`
- **Tools**: incident-correlation, timeline-builder, platform.core.search, platform.core.get_document_by_id, platform.core.get_index_mapping
- **Avatar**: Orange search

#### Agent 3: Incident Responder
- **Display Name**: `Incident Responder`
- **Instructions**: Copy from `agents/responder-agent.json`
- **Tools**: Slack and Jira connectors (see Step 4)
- **Avatar**: Green bolt

## Step 4: Configure Kibana Connectors (for Responder)

Navigate to **Stack Management** -> **Connectors** -> **Create Connector**

### 4.1 Slack Connector
- **Type**: Slack (Webhook)
- **Name**: `Security Slack Notification`
- **Webhook URL**: Your Slack webhook URL

### 4.2 Jira Connector
- **Type**: Jira
- **Name**: `Security Jira Tickets`
- **URL**: Your Jira instance URL
- **Email**: Your Jira email
- **API Token**: Your Jira API token
- **Project Key**: SCRUM

After creating connectors, go back to the Responder agent and assign the connector tools.

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

1. Go to **Agent Builder** -> **Chat**
2. Select **"Security Incident Detector"** agent
3. Ask: "Are there any brute force attacks in the last 15 minutes?"
4. Verify it detects the simulated attack

### 5.3 Verify Response

1. Switch to **"Incident Responder"** agent
2. Provide the detection findings
3. Check Slack for notification
4. Check Jira for ticket

## Troubleshooting

### Connection Issues
- Verify `.env` file has correct credentials
- Check Elastic Cloud deployment is running
- Run `python3 demo/test-connection.py` to diagnose

### Agent Builder Not Visible
- Check Agent Builder is enabled in Advanced Settings
- Verify you have Enterprise license or trial active

### No Data Detected
- Run `data-ingestion.py` first to create baseline data
- Run `incident-simulator.py` to generate attack events
- Check time ranges in queries match when events were ingested
- Verify index `security-simulated-events` exists in Stack Management

### ES|QL Query Errors
- Test queries directly in Kibana Dev Tools first
- Remember to backtick-escape nested fields
- Use `COUNT_DISTINCT()` syntax (not `COUNT(DISTINCT ...)`)

---

**Setup complete! See MANUAL_SETUP.md for the detailed step-by-step checklist.**

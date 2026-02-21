# Phase 1: Environment Setup Checklist

## Elastic Cloud Setup

### 1. Create Deployment
- [ ] Go to Elastic Cloud console
- [ ] Click "Create deployment"
- [ ] Select "Elastic for Security"
- [ ] Choose region (closest to you)
- [ ] Select "Storage optimized" tier
- [ ] Wait for deployment (5-10 minutes)

### 2. Get Kibana URL
- [ ] Go to Deployments page
- [ ] Click deployment name
- [ ] Copy Kibana endpoint URL
- [ ] Test: Open URL in browser, should see Kibana login

### 3. Enable Agent Builder
- [ ] Login to Kibana
- [ ] Click user icon → "Stack Management"
- [ ] Go to "Advanced Settings"
- [ ] Search for "agent_builder"
- [ ] Set `xpack.agent_builder.enabled` to `true`
- [ ] Save changes
- [ ] Verify: "Agents" appears in left sidebar

## Slack Setup

### 4. Create Slack App
- [ ] Go to https://api.slack.com/apps
- [ ] Click "Create New App" → "From scratch"
- [ ] App name: "Incident Response Bot"
- [ ] Select your workspace
- [ ] Create App

### 5. Configure Webhook
- [ ] In app settings, go to "Incoming Webhooks"
- [ ] Toggle to "On"
- [ ] Click "Add New Webhook to Workspace"
- [ ] Select channel: #security-incidents (or create it)
- [ ] Authorize
- [ ] Copy webhook URL
- [ ] Save to `.env` file

## Jira Setup

### 6. Create Jira Instance
- [ ] Go to https://www.atlassian.com/software/jira/free
- [ ] Sign up for Jira Cloud (free tier works)
- [ ] Site name: your-choice (e.g., "incident-response")
- [ ] Complete setup wizard

### 7. Create Project
- [ ] In Jira, click "Create project"
- [ ] Select "Kanban"
- [ ] Name: "Security Operations"
- [ ] Key: "SCRUM"
- [ ] Create

### 8. Get API Token
- [ ] Go to https://id.atlassian.com/manage-profile/security/api-tokens
- [ ] Click "Create API token"
- [ ] Label: "Incident Response Commander"
- [ ] Copy token immediately
- [ ] Save to `.env` file

## Data Setup

### 9. Download Sample Data
We'll use Elastic's built-in sample security data:
- [ ] In Kibana, go to "Add data"
- [ ] Search for "Sample data"
- [ ] Install "Sample web logs"
- [ ] Install "Sample eCommerce orders" (for auth patterns)

### 10. Verify Data
- [ ] Go to Discover
- [ ] Check indices exist
- [ ] Run test ES|QL query: `FROM kibana_sample_data_logs* | LIMIT 10`
- [ ] Should see sample log data

## Integration Verification

### 11. Test Slack Integration
- [ ] Use curl or Postman to test webhook:
```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test message from Incident Response Commander"}' \
  YOUR_SLACK_WEBHOOK_URL
```
- [ ] Should see message in Slack

### 12. Test Jira Integration
- [ ] Test API connection with curl:
```bash
curl -u your-email:your-api-token \
  https://your-instance.atlassian.net/rest/api/3/project
```
- [ ] Should see list of projects including "SCRUM"

## Phase 1 Complete When:
- [ ] Elastic Security deployment running
- [ ] Agent Builder enabled and visible
- [ ] Slack webhook working
- [ ] Jira API token working
- [ ] Sample data ingested
- [ ] All credentials saved in `.env` file
- [ ] `.env` added to `.gitignore`

## Next Phase: Agent Configuration
Once Phase 1 is complete, we'll configure the three agents and their tools.

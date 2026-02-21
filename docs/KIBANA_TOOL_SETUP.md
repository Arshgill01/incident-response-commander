# Kibana Agent Builder - Tool Setup Guide

## CRITICAL: Field Name Syntax

In ES|QL queries, **ALL nested field names must be wrapped in backticks**:
- ✅ Correct: `` `event.category` ``, `` `user.name` ``, `` `source.ip` ``
- ❌ Wrong: `event.category`, `user.name`, `source.ip`

## Tool 1: Brute Force Detection

### Basic Info
- **Name**: `brute-force-detection`
- **Type**: ES|QL
- **Description**: Detect brute force attack patterns from authentication logs

### ES|QL Query (COPY THIS EXACTLY):
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?time_window
| WHERE `event.category` == "authentication" AND `event.outcome` == "failure"
| STATS 
    failure_count = COUNT(*),
    unique_users = COUNT(DISTINCT `user.name`),
    unique_hosts = COUNT(DISTINCT `host.name`),
    first_failure = MIN(@timestamp),
    last_failure = MAX(@timestamp)
  BY `source.ip`
| WHERE failure_count >= ?failure_threshold
| SORT failure_count DESC
| LIMIT 100
```

### Parameters (ADD THESE):
1. **time_window**
   - Type: `Time Duration`
   - Default value: `30 minutes`
   - Description: Time window to search for failed logins

2. **failure_threshold**
   - Type: `Integer`
   - Default value: `5`
   - Description: Minimum number of failures to trigger alert

---

## Tool 2: Data Exfiltration Detection

### Basic Info
- **Name**: `data-exfiltration-detection`
- **Type**: ES|QL
- **Description**: Detect unusual outbound data transfers indicating exfiltration

### ES|QL Query (COPY THIS EXACTLY):
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?time_window
| WHERE `event.category` == "network" AND `network.direction` == "outbound"
| STATS 
    total_bytes = SUM(`network.bytes`),
    connection_count = COUNT(*),
    unique_destinations = COUNT(DISTINCT `destination.ip`),
    unique_ports = COUNT(DISTINCT `destination.port`)
  BY `user.name`, `source.ip`
| WHERE total_bytes >= ?bytes_threshold
| SORT total_bytes DESC
| LIMIT 50
```

### Parameters (ADD THESE):
1. **time_window**
   - Type: `Time Duration`
   - Default value: `1 hour`
   - Description: Time window for detection

2. **bytes_threshold**
   - Type: `Integer`
   - Default value: `100000000` (100MB)
   - Description: Minimum bytes transferred to trigger alert

---

## Tool 3: Privilege Escalation Detection

### Basic Info
- **Name**: `privilege-escalation-detection`
- **Type**: ES|QL
- **Description**: Detect suspicious privilege elevation attempts

### ES|QL Query (COPY THIS EXACTLY):
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?time_window
| WHERE `event.category` == "process" OR `event.category` == "authentication"
| WHERE `event.action` == "sudo" 
    OR `event.action` == "privilege_escalation" 
    OR `event.action` == "admin_login" 
    OR `event.action` == "elevated_process"
| STATS 
    escalation_count = COUNT(*),
    unique_processes = COUNT(DISTINCT `process.name`),
    unique_targets = COUNT(DISTINCT `process.target.name`),
    first_event = MIN(@timestamp),
    last_event = MAX(@timestamp)
  BY `user.name`, `host.name`
| WHERE escalation_count >= 3
| SORT escalation_count DESC
| LIMIT 50
```

### Parameters (ADD THESE):
1. **time_window**
   - Type: `Time Duration`
   - Default value: `30 minutes`
   - Description: Time window to search for privilege escalations

---

## Tool 4: Incident Correlation

### Basic Info
- **Name**: `incident-correlation`
- **Type**: ES|QL
- **Description**: Cross-index correlation for comprehensive incident investigation

### ES|QL Query (COPY THIS EXACTLY):
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?investigation_window
| WHERE `source.ip` == ?suspicious_ip OR `user.name` == ?suspicious_user
| KEEP @timestamp, `event.category`, `event.action`, `user.name`, `source.ip`, `destination.ip`, 
       `destination.port`, `event.outcome`, `process.name`, `host.name`, `network.bytes`, `message`
| SORT @timestamp ASC
| LIMIT 1000
```

### Parameters (ADD THESE):
1. **investigation_window**
   - Type: `Time Duration`
   - Default value: `4 hours`
   - Description: Time window for investigation

2. **suspicious_ip**
   - Type: `Text`
   - Default value: (leave empty)
   - Description: IP address to investigate

3. **suspicious_user**
   - Type: `Text`
   - Default value: (leave empty)
   - Description: Username to investigate

---

## Tool 5: Timeline Builder

### Basic Info
- **Name**: `timeline-builder`
- **Type**: ES|QL
- **Description**: Build chronological timeline of suspicious activity

### ES|QL Query (COPY THIS EXACTLY):
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?time_window
| WHERE `source.ip` == ?target_ip OR `user.name` == ?target_user
| EVAL time_bucket = DATE_TRUNC(5 minutes, @timestamp)
| STATS 
    event_count = COUNT(*),
    unique_categories = COUNT(DISTINCT `event.category`),
    unique_actions = COUNT(DISTINCT `event.action`),
    first_event = MIN(@timestamp),
    last_event = MAX(@timestamp)
  BY time_bucket
| SORT time_bucket ASC
| LIMIT 100
```

### Parameters (ADD THESE):
1. **time_window**
   - Type: `Time Duration`
   - Default value: `2 hours`
   - Description: Investigation time window

2. **target_ip**
   - Type: `Text`
   - Default value: (leave empty)
   - Description: Target IP address

3. **target_user**
   - Type: `Text`
   - Default value: (leave empty)
   - Description: Target username

---

## Testing Your Tools

After creating each tool:

1. Click **"Save & Test"**
2. Fill in the parameter values
3. Click **"Test"**
4. Verify results appear

### Test Values:
- **time_window**: `30 minutes`
- **failure_threshold**: `5`
- **bytes_threshold**: `100000000`
- **suspicious_ip**: Use an IP from your simulated data (e.g., `192.168.46.19`)
- **suspicious_user**: `admin`

---

## Troubleshooting

### "Unknown column" errors:
- Make sure ALL field names are wrapped in backticks
- Example: `` `event.category` `` not `event.category`

### "No data found":
- Run the incident simulator first: `python3 incident-simulator.py brute_force`
- Make sure to use `security-simulated-events` as the index
- Check the time window includes your simulated data

### Tool won't save:
- Check that all parameters are properly configured
- Verify the ES|QL syntax is valid
- Look for red error indicators in the query editor

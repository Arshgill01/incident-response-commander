# QUICK REFERENCE - Agent Builder Tool Parameters

## Tool 1: brute-force-detection

**Query:**
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

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| time_window | Time Duration | 30 minutes | Search window |
| failure_threshold | Integer | 5 | Min failures to alert |

---

## Tool 2: data-exfiltration-detection

**Query:**
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

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| time_window | Time Duration | 1 hour | Search window |
| bytes_threshold | Integer | 100000000 | Min bytes (100MB) |

---

## Tool 3: privilege-escalation-detection

**Query:**
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

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| time_window | Time Duration | 30 minutes | Search window |

---

## Tool 4: incident-correlation

**Query:**
```sql
FROM security-simulated-events
| WHERE @timestamp > NOW() - ?investigation_window
| WHERE `source.ip` == ?suspicious_ip OR `user.name` == ?suspicious_user
| KEEP @timestamp, `event.category`, `event.action`, `user.name`, `source.ip`, `destination.ip`, 
       `destination.port`, `event.outcome`, `process.name`, `host.name`, `network.bytes`, `message`
| SORT @timestamp ASC
| LIMIT 1000
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| investigation_window | Time Duration | 4 hours | Investigation window |
| suspicious_ip | Text | (empty) | IP to investigate |
| suspicious_user | Text | (empty) | User to investigate |

---

## Tool 5: timeline-builder

**Query:**
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

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| time_window | Time Duration | 2 hours | Investigation window |
| target_ip | Text | (empty) | Target IP address |
| target_user | Text | (empty) | Target username |

---

## KEY REMINDERS

1. **ALL nested fields need backticks:**
   - `` `event.category` ``, `` `user.name` ``, `` `source.ip` ``, etc.

2. **Index name is:** `security-simulated-events`

3. **Parameter syntax in query:** `?parameter_name`

4. **Click "Add a parameter" button for each parameter**

5. **Parameter types:**
   - `Time Duration` - for time windows
   - `Integer` - for numeric thresholds
   - `Text` - for IP addresses and usernames

6. **Test values to use:**
   - time_window: `30 minutes`
   - failure_threshold: `5`
   - bytes_threshold: `100000000`
   - suspicious_ip: `192.168.46.19` (from brute force sim)
   - suspicious_user: `admin`

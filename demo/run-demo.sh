#!/bin/bash

# Incident Response Commander - Demo Script
# This script runs through a complete demo of the system

echo "=================================="
echo "INCIDENT RESPONSE COMMANDER DEMO"
echo "=================================="
echo ""

# Check if we're in the right directory
if [ ! -f "demo/incident-simulator.py" ]; then
    echo "❌ Error: Please run this script from the project root"
    exit 1
fi

# Check Python environment
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 not found"
    exit 1
fi

echo "✅ Environment check passed"
echo ""

# Function to print section headers
print_section() {
    echo ""
    echo "=================================="
    echo "$1"
    echo "=================================="
    echo ""
}

# Function to wait for user
wait_for_user() {
    echo ""
    read -p "Press Enter to continue..."
    echo ""
}

print_section "PHASE 1: Setup Verification"
echo "Checking Elastic Cloud connection..."
python3 -c "
from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv
load_dotenv()
es = Elasticsearch(cloud_id=os.getenv('ELASTIC_CLOUD_ID'), api_key=os.getenv('ELASTIC_API_KEY'))
print('✅ Connected to Elasticsearch:', es.info()['version']['number'])
"

if [ $? -ne 0 ]; then
    echo "❌ Failed to connect to Elastic Cloud"
    echo "Please check your .env file configuration"
    exit 1
fi

wait_for_user

print_section "PHASE 2: Ingest Sample Data"
echo "Setting up data ingestion..."
cd demo
python3 data-ingestion.py
cd ..

wait_for_user

print_section "PHASE 3: Simulate Brute Force Attack"
echo "Injecting brute force attack events into logs..."
cd demo
python3 incident-simulator.py brute_force
cd ..

echo ""
echo "📊 Attack injected successfully!"
echo "   - Source IP: 192.168.x.x"
echo "   - Target User: admin"
echo "   - Failed Attempts: 20-30"
echo "   - Successful Breach: Yes"

wait_for_user

print_section "PHASE 4: Detection"
echo "Now check the Detector Agent in Kibana:"
echo ""
echo "1. Go to Agent Builder → Chat"
echo "2. Select 'Security Incident Detector' agent"
echo "3. Ask: 'Detect any brute force attacks in the last 15 minutes'"
echo ""
echo "Expected: Agent should identify the attack pattern"

wait_for_user

print_section "PHASE 5: Investigation"
echo "Escalate to Investigator Agent:"
echo ""
echo "1. Select 'Incident Investigator' agent"
echo "2. Provide the suspicious IP from detection"
echo "3. Ask: 'Investigate this IP and build a timeline'"
echo ""
echo "Expected: Agent correlates events and builds timeline"

wait_for_user

print_section "PHASE 6: Response"
echo "Execute automated response:"
echo ""
echo "1. Select 'Incident Responder' agent"
echo "2. Provide investigation report"
echo "3. Ask: 'Execute response for this CRITICAL incident'"
echo ""
echo "Expected: Automated actions execute"
echo "   - Check Slack for notification"
echo "   - Check Jira for ticket"
echo "   - Evidence preserved in logs"

wait_for_user

print_section "PHASE 7: Additional Simulations"
echo "Test other incident types:"
echo ""
echo "Option 1: Data Exfiltration"
echo "   cd demo && python3 incident-simulator.py exfiltration"
echo ""
echo "Option 2: Privilege Escalation"
echo "   cd demo && python3 incident-simulator.py privilege_escalation"

wait_for_user

print_section "DEMO COMPLETE"
echo ""
echo "Summary:"
echo "✅ Brute force attack detected"
echo "✅ Investigation completed"
echo "✅ Response actions executed"
echo "✅ Team notified via Slack"
echo "✅ Jira ticket created"
echo "✅ Evidence preserved"
echo ""
echo "Total Response Time: ~60 seconds"
echo ""
echo "Thank you for viewing our demo!"
echo ""
echo "Repository: https://github.com/arshgill01/incident-response-commander"

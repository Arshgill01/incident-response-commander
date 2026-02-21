#!/usr/bin/env python3
"""
Incident Simulator for Testing
Generates synthetic security incidents for demo purposes
"""

import json
import random
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv
import sys

load_dotenv()


class IncidentSimulator:
    def __init__(self):
        self.es = None
        self.cloud_id = os.getenv("ELASTIC_CLOUD_ID")
        self.api_key = os.getenv("ELASTIC_API_KEY")
        self.username = os.getenv("ELASTIC_USERNAME", "elastic")
        self.password = os.getenv("ELASTIC_PASSWORD")
        self.target_index = "security-simulated-events"

        if not self.cloud_id:
            print("❌ ERROR: ELASTIC_CLOUD_ID not found in .env file")
            sys.exit(1)

        self._connect()

    def _connect(self):
        """Try to connect using API key first, then fallback to username/password"""
        # Try API Key authentication first
        if self.api_key and self.api_key.strip():
            try:
                print("🔑 Attempting connection with API Key...")
                self.es = Elasticsearch(
                    cloud_id=self.cloud_id,
                    api_key=self.api_key,
                    request_timeout=30,
                    retry_on_timeout=True,
                    max_retries=3,
                )
                # Test the connection
                info = self.es.info()
                print(
                    f"✅ Connected to Elasticsearch {info['version']['number']} using API Key"
                )
                return
            except Exception as e:
                print(f"⚠️ API Key connection failed: {e}")
                print("   Falling back to username/password...")

        # Fallback to username/password
        if self.password and self.password.strip():
            try:
                print(
                    f"🔐 Attempting connection with username/password ({self.username})..."
                )
                self.es = Elasticsearch(
                    cloud_id=self.cloud_id,
                    basic_auth=(self.username, self.password),
                    request_timeout=30,
                    retry_on_timeout=True,
                    max_retries=3,
                )
                # Test the connection
                info = self.es.info()
                print(
                    f"✅ Connected to Elasticsearch {info['version']['number']} using username/password"
                )
                return
            except Exception as e:
                print(f"❌ Username/Password connection failed: {e}")

        # If both failed
        print("\n❌ FAILED TO CONNECT TO ELASTICSEARCH")
        print("\nPlease ensure your .env file contains ONE of the following:")
        print("  Option 1 (API Key): ELASTIC_API_KEY=<your_api_key>")
        print("  Option 2 (Password): ELASTIC_USERNAME=elastic")
        print("                       ELASTIC_PASSWORD=<your_password>")
        sys.exit(1)

    def generate_brute_force_attack(self, source_ip=None, target_user=None):
        """Generate brute force attack events"""
        if not source_ip:
            source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        if not target_user:
            target_user = random.choice(["admin", "root", "administrator", "sysadmin"])

        events = []
        base_time = datetime.now(timezone.utc)

        # Generate 20-30 failed login attempts
        num_attempts = random.randint(20, 30)
        for i in range(num_attempts):
            event = {
                "@timestamp": (base_time + timedelta(seconds=i * 30)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "authentication",
                    "action": "login",
                    "outcome": "failure",
                    "type": ["start"],
                },
                "source": {"ip": source_ip},
                "user": {"name": target_user},
                "host": {"name": f"server-{random.randint(1, 5)}.internal"},
                "message": f"Failed login attempt for user {target_user} from {source_ip}",
            }
            events.append(event)

        # Add one successful login (breach)
        success_event = {
            "@timestamp": (base_time + timedelta(minutes=16)).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "event": {
                "category": "authentication",
                "action": "login",
                "outcome": "success",
                "type": ["start"],
            },
            "source": {"ip": source_ip},
            "user": {"name": target_user},
            "host": {"name": f"server-{random.randint(1, 5)}.internal"},
            "message": f"Successful login for user {target_user} from {source_ip}",
        }
        events.append(success_event)

        return events, {
            "type": "brute_force",
            "severity": "CRITICAL",
            "source_ip": source_ip,
            "target_user": target_user,
            "attempts": num_attempts,
            "breach_confirmed": True,
        }

    def generate_data_exfiltration(self, user=None, source_ip=None):
        """Generate data exfiltration events"""
        if not user:
            user = random.choice(["john.doe", "jane.smith", "developer1", "analyst2"])
        if not source_ip:
            source_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"

        events = []
        base_time = datetime.now(timezone.utc)
        destinations = [
            "external-server-1.com",
            "suspicious-cloud.xyz",
            "data-drop.evil",
        ]

        # Generate large data transfers (5-10 transfers)
        num_transfers = random.randint(5, 10)
        total_bytes = 0
        for i in range(num_transfers):
            bytes_transferred = random.randint(500000000, 1500000000)  # 500MB-1.5GB
            total_bytes += bytes_transferred
            event = {
                "@timestamp": (base_time + timedelta(minutes=i * 5)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "network",
                    "action": "connection",
                    "outcome": "success",
                },
                "source": {"ip": source_ip},
                "destination": {
                    "ip": f"203.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "port": random.choice([443, 80, 8080, 9001]),
                    "domain": random.choice(destinations),
                },
                "network": {
                    "direction": "outbound",
                    "bytes": bytes_transferred,
                },
                "user": {"name": user},
                "host": {"name": f"server-{random.randint(1, 5)}.internal"},
                "message": f"Large outbound transfer by {user} to {random.choice(destinations)}",
            }
            events.append(event)

        return events, {
            "type": "data_exfiltration",
            "severity": "HIGH",
            "user": user,
            "source_ip": source_ip,
            "total_transfers": num_transfers,
            "approximate_volume_gb": round(total_bytes / 1e9, 2),
        }

    def generate_privilege_escalation(self, user=None, host=None, source_ip=None):
        """Generate privilege escalation events"""
        if not user:
            user = random.choice(["temp.user", "contractor1", "intern.dev"])
        if not host:
            host = f"server-{random.randint(1, 5)}.internal"
        if not source_ip:
            source_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"

        events = []
        base_time = datetime.now(timezone.utc)

        escalation_actions = [
            "sudo su -",
            "sudo chmod 777 /etc/passwd",
            "sudo usermod -aG root",
            "sudo -i",
            "pkexec bash",
        ]

        for i, action in enumerate(escalation_actions):
            event = {
                "@timestamp": (base_time + timedelta(minutes=i * 3)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "process",
                    "action": "privilege_escalation",
                    "outcome": "success",
                },
                "source": {"ip": source_ip},
                "user": {"name": user},
                "host": {"name": host},
                "process": {
                    "name": action.split()[0],
                    "args": action,
                    "target": {"name": "root"},
                },
                "message": f"Privilege escalation attempt: {action}",
            }
            events.append(event)

        return events, {
            "type": "privilege_escalation",
            "severity": "HIGH",
            "user": user,
            "source_ip": source_ip,
            "host": host,
            "escalation_count": len(events),
        }

    def ingest_events(self, events):
        """Ingest events into Elasticsearch"""
        success_count = 0
        for i, event in enumerate(events):
            try:
                response = self.es.index(index=self.target_index, document=event)
                success_count += 1
                print(f"  ✅ Event {i + 1}/{len(events)} indexed")
            except Exception as e:
                print(f"  ❌ Failed to index event {i + 1}: {e}")

        print(
            f"\n📊 Ingested {success_count}/{len(events)} events into {self.target_index}"
        )

        # Refresh index to make data immediately searchable
        try:
            self.es.indices.refresh(index=self.target_index)
            print("✅ Index refreshed - events are now searchable")
        except Exception as e:
            print(f"⚠️ Failed to refresh index: {e}")

    def run_simulation(self, incident_type="brute_force"):
        """Run a complete simulation"""
        print(f"\n{'=' * 60}")
        print(f"🎯 SIMULATING: {incident_type.upper().replace('_', ' ')} ATTACK")
        print(f"{'=' * 60}\n")

        if incident_type == "brute_force":
            events, metadata = self.generate_brute_force_attack()
        elif incident_type == "exfiltration":
            events, metadata = self.generate_data_exfiltration()
        elif incident_type == "privilege_escalation":
            events, metadata = self.generate_privilege_escalation()
        else:
            print(f"❌ Unknown incident type: {incident_type}")
            print("   Valid types: brute_force, exfiltration, privilege_escalation")
            sys.exit(1)

        # Ingest events
        self.ingest_events(events)

        # Print summary
        print(f"\n📋 Attack Summary:")
        print(f"  Type: {metadata['type']}")
        print(f"  Severity: {metadata['severity']}")
        print(f"  Events Generated: {len(events)}")
        for key, value in metadata.items():
            if key not in ["type", "severity"]:
                print(f"  {key.replace('_', ' ').title()}: {value}")

        return metadata


def print_usage():
    print("""
Usage: python incident-simulator.py <incident_type>

Incident Types:
  brute_force          - Simulate multiple failed login attempts followed by success
  exfiltration         - Simulate large outbound data transfers
  privilege_escalation - Simulate privilege elevation attempts

Examples:
  python incident-simulator.py brute_force
  python incident-simulator.py exfiltration
  python incident-simulator.py privilege_escalation

Environment:
  Requires .env file with Elastic Cloud credentials:
    - ELASTIC_CLOUD_ID (required)
    - ELASTIC_API_KEY or ELASTIC_PASSWORD (either one works)
""")


if __name__ == "__main__":
    print("=" * 60)
    print("🚨 Incident Response Simulator")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\n❌ Error: No incident type specified")
        print_usage()
        sys.exit(1)

    incident_type = sys.argv[1].lower()

    # Validate incident type
    valid_types = ["brute_force", "exfiltration", "privilege_escalation"]
    if incident_type not in valid_types:
        print(f"\n❌ Error: Invalid incident type '{incident_type}'")
        print_usage()
        sys.exit(1)

    try:
        simulator = IncidentSimulator()
    except SystemExit:
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during initialization: {e}")
        sys.exit(1)

    try:
        metadata = simulator.run_simulation(incident_type)
        print("\n" + "=" * 60)
        print("✅ Simulation complete!")
        print("=" * 60)
        print("\nNext steps:")
        print("  1. Open Kibana → Agent Builder")
        print("  2. Select 'Security Incident Detector' agent")
        print(
            "  3. Ask: 'Detect",
            incident_type.replace("_", " "),
            "attacks in the last 30 minutes'",
        )
        print("  4. Verify the agent finds the simulated attack")
    except Exception as e:
        print(f"\n❌ Simulation failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

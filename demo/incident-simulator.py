#!/usr/bin/env python3
"""
Incident Simulator for Testing
Generates synthetic security incidents for demo purposes
"""

import json
import random
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv

load_dotenv()


class IncidentSimulator:
    def __init__(self):
        self.es = Elasticsearch(
            cloud_id=os.getenv("ELASTIC_CLOUD_ID"), api_key=os.getenv("ELASTIC_API_KEY")
        )
        self.target_index = "security-simulated-events"

    def generate_brute_force_attack(self, source_ip=None, target_user=None):
        """Generate brute force attack events"""
        if not source_ip:
            source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        if not target_user:
            target_user = random.choice(["admin", "root", "administrator", "sysadmin"])

        events = []
        base_time = datetime.utcnow() - timedelta(minutes=15)

        # Generate 20-30 failed login attempts
        for i in range(random.randint(20, 30)):
            event = {
                "@timestamp": (base_time + timedelta(seconds=i * 30)).isoformat(),
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

        # Add one successful login
        success_event = {
            "@timestamp": (base_time + timedelta(minutes=16)).isoformat(),
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
            "attempts": len(events) - 1,
            "breach_confirmed": True,
        }

    def generate_data_exfiltration(self, user=None, source_ip=None):
        """Generate data exfiltration events"""
        if not user:
            user = random.choice(["john.doe", "jane.smith", "developer1", "analyst2"])
        if not source_ip:
            source_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"

        events = []
        base_time = datetime.utcnow() - timedelta(hours=1)
        destinations = [
            "external-server-1.com",
            "suspicious-cloud.xyz",
            "data-drop.evil",
        ]

        # Generate large data transfers
        for i in range(random.randint(5, 10)):
            event = {
                "@timestamp": (base_time + timedelta(minutes=i * 5)).isoformat(),
                "event": {
                    "category": "network",
                    "action": "connection",
                    "outcome": "success",
                },
                "source": {"ip": source_ip, "user": user},
                "destination": {
                    "ip": f"203.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "port": random.choice([443, 80, 8080, 9001]),
                    "domain": random.choice(destinations),
                },
                "network": {
                    "direction": "outbound",
                    "bytes": random.randint(500000000, 1500000000),  # 500MB-1.5GB
                },
                "user": {"name": user},
                "message": f"Large outbound transfer by {user} to {random.choice(destinations)}",
            }
            events.append(event)

        return events, {
            "type": "data_exfiltration",
            "severity": "HIGH",
            "user": user,
            "source_ip": source_ip,
            "total_transfers": len(events),
            "approximate_volume_gb": sum(e["network"]["bytes"] for e in events) / 1e9,
        }

    def generate_privilege_escalation(self, user=None, host=None):
        """Generate privilege escalation events"""
        if not user:
            user = random.choice(["temp.user", "contractor1", "intern.dev"])
        if not host:
            host = f"server-{random.randint(1, 5)}.internal"

        events = []
        base_time = datetime.utcnow() - timedelta(minutes=30)

        escalation_actions = [
            "sudo su -",
            "sudo chmod 777 /etc/passwd",
            "sudo usermod -aG root",
            "sudo -i",
            "pkexec bash",
        ]

        for i, action in enumerate(escalation_actions):
            event = {
                "@timestamp": (base_time + timedelta(minutes=i * 3)).isoformat(),
                "event": {
                    "category": "process",
                    "action": "privilege_escalation",
                    "outcome": "success",
                },
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
            "host": host,
            "escalation_count": len(events),
        }

    def ingest_events(self, events):
        """Ingest events into Elasticsearch"""
        for event in events:
            self.es.index(index=self.target_index, body=event)
        print(f"Ingested {len(events)} events into {self.target_index}")

    def run_simulation(self, incident_type="brute_force"):
        """Run a complete simulation"""
        print(f"\n{'=' * 60}")
        print(f"SIMULATING: {incident_type.upper()} ATTACK")
        print(f"{'=' * 60}\n")

        if incident_type == "brute_force":
            events, metadata = self.generate_brute_force_attack()
        elif incident_type == "exfiltration":
            events, metadata = self.generate_data_exfiltration()
        elif incident_type == "privilege_escalation":
            events, metadata = self.generate_privilege_escalation()
        else:
            raise ValueError(f"Unknown incident type: {incident_type}")

        # Ingest events
        self.ingest_events(events)

        # Print summary
        print(f"\nAttack Summary:")
        print(f"  Type: {metadata['type']}")
        print(f"  Severity: {metadata['severity']}")
        for key, value in metadata.items():
            if key not in ["type", "severity"]:
                print(f"  {key}: {value}")

        return metadata


if __name__ == "__main__":
    import sys

    simulator = IncidentSimulator()

    if len(sys.argv) > 1:
        incident_type = sys.argv[1]
    else:
        incident_type = "brute_force"

    try:
        metadata = simulator.run_simulation(incident_type)
        print("\n✅ Simulation complete! Check Agent Builder for detection.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("Make sure your .env file has valid Elastic credentials.")

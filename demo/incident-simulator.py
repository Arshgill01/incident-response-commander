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

    def generate_lateral_movement(self, user=None, source_ip=None):
        """Generate lateral movement events — same user authenticating to multiple hosts."""
        if not user:
            user = random.choice(["admin", "sysadmin", "root", "administrator"])
        if not source_ip:
            source_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"

        events = []
        base_time = datetime.now(timezone.utc)
        target_hosts = [
            "server-01.internal",
            "server-02.internal",
            "db-primary.internal",
            "file-share.internal",
            "backup-01.internal",
        ]

        for i, host in enumerate(target_hosts):
            event = {
                "@timestamp": (base_time + timedelta(minutes=i * 4)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "authentication",
                    "action": "login",
                    "outcome": "success",
                    "type": ["start"],
                },
                "source": {"ip": source_ip},
                "user": {"name": user},
                "host": {"name": host},
                "message": f"Lateral movement: {user} authenticated to {host} from {source_ip}",
            }
            events.append(event)

        return events, {
            "type": "lateral_movement",
            "severity": "HIGH",
            "user": user,
            "source_ip": source_ip,
            "hosts_compromised": len(target_hosts),
            "mitre_technique": "T1021",
        }

    def generate_apt_attack(self, source_ip=None):
        """
        Generate a full APT kill-chain attack spanning 6 stages:
          Stage 1 — Reconnaissance    (T1046: Network Service Scanning)
          Stage 2 — Initial Access    (T1110: Brute Force → successful login)
          Stage 3 — Persistence       (T1136: Create Account)
          Stage 4 — Privilege Escal.  (T1068: Exploitation)
          Stage 5 — Lateral Movement  (T1021: Remote Services)
          Stage 6 — Exfiltration      (T1041: Data over C2 Channel)

        All stages are injected with realistic timestamps across a 2-hour window.
        """
        if not source_ip:
            source_ip = "192.168.1.100"

        attacker_user = "suspicious.user"
        internal_user = "admin"
        backdoor_user = "svc_backup"
        internal_ip = f"10.0.{random.randint(1, 10)}.{random.randint(1, 50)}"
        base_time = datetime.now(timezone.utc) - timedelta(hours=2)
        all_events = []

        def ts(offset_minutes: float) -> str:
            return (base_time + timedelta(minutes=offset_minutes)).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )

        # ── Stage 1: Reconnaissance (T1046) — 0-5 min ────────────────────
        scan_targets = ["22", "443", "3389", "8080", "21", "3306", "5432"]
        for i, port in enumerate(scan_targets):
            all_events.append(
                {
                    "@timestamp": ts(i * 0.7),
                    "event": {
                        "category": "network",
                        "action": "connection",
                        "outcome": "failure",
                    },
                    "source": {"ip": source_ip},
                    "destination": {
                        "ip": internal_ip,
                        "port": int(port),
                    },
                    "network": {"direction": "inbound", "bytes": 64},
                    "user": {"name": "unknown"},
                    "host": {"name": "firewall-01.internal"},
                    "message": f"Port scan detected: {source_ip} → {internal_ip}:{port}",
                    "apt_stage": "1_reconnaissance",
                    "mitre_technique": "T1046",
                }
            )

        # ── Stage 2: Initial Access via Brute Force (T1110) — 5-20 min ──
        for i in range(25):
            all_events.append(
                {
                    "@timestamp": ts(5 + i * 0.6),
                    "event": {
                        "category": "authentication",
                        "action": "login",
                        "outcome": "failure",
                        "type": ["start"],
                    },
                    "source": {"ip": source_ip},
                    "user": {"name": internal_user},
                    "host": {"name": "ssh-gateway.internal"},
                    "message": f"Brute force: failed login for {internal_user} from {source_ip}",
                    "apt_stage": "2_initial_access",
                    "mitre_technique": "T1110",
                }
            )
        # Successful breach
        all_events.append(
            {
                "@timestamp": ts(21),
                "event": {
                    "category": "authentication",
                    "action": "login",
                    "outcome": "success",
                    "type": ["start"],
                },
                "source": {"ip": source_ip},
                "user": {"name": internal_user},
                "host": {"name": "ssh-gateway.internal"},
                "message": f"BREACH: {internal_user} authenticated from attacker IP {source_ip}",
                "apt_stage": "2_initial_access",
                "mitre_technique": "T1110",
            }
        )

        # ── Stage 3: Persistence — create backdoor account (T1136) — 22-35 min
        persistence_actions = [
            ("useradd -m -s /bin/bash svc_backup", "Create backdoor user"),
            ("usermod -aG sudo svc_backup", "Add to sudo group"),
            (
                "echo 'svc_backup ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
                "Grant passwordless sudo",
            ),
            ("mkdir -p /home/svc_backup/.ssh", "Create SSH directory"),
            (
                "echo 'ATTACKER_KEY' >> /home/svc_backup/.ssh/authorized_keys",
                "Install SSH backdoor",
            ),
        ]
        for i, (cmd, desc) in enumerate(persistence_actions):
            all_events.append(
                {
                    "@timestamp": ts(22 + i * 2.5),
                    "event": {
                        "category": "process",
                        "action": "elevated_process",
                        "outcome": "success",
                    },
                    "source": {"ip": source_ip},
                    "user": {"name": internal_user},
                    "host": {"name": "ssh-gateway.internal"},
                    "process": {
                        "name": cmd.split()[0],
                        "args": cmd,
                        "target": {"name": backdoor_user},
                    },
                    "message": f"Persistence: {desc}",
                    "apt_stage": "3_persistence",
                    "mitre_technique": "T1136",
                }
            )

        # ── Stage 4: Privilege Escalation (T1068) — 36-50 min ────────────
        priv_esc_cmds = [
            ("sudo su -", "privilege_escalation"),
            ("sudo chmod 777 /etc/passwd", "privilege_escalation"),
            ("sudo usermod -aG root", "privilege_escalation"),
            ("pkexec bash", "elevated_process"),
            ("sudo -i", "privilege_escalation"),
        ]
        for i, (cmd, action) in enumerate(priv_esc_cmds):
            all_events.append(
                {
                    "@timestamp": ts(36 + i * 2.8),
                    "event": {
                        "category": "process",
                        "action": action,
                        "outcome": "success",
                    },
                    "source": {"ip": source_ip},
                    "user": {"name": backdoor_user},
                    "host": {"name": "ssh-gateway.internal"},
                    "process": {
                        "name": cmd.split()[0],
                        "args": cmd,
                        "target": {"name": "root"},
                    },
                    "message": f"Privilege escalation: {cmd}",
                    "apt_stage": "4_privilege_escalation",
                    "mitre_technique": "T1068",
                }
            )

        # ── Stage 5: Lateral Movement (T1021) — 51-80 min ────────────────
        lateral_targets = [
            ("server-01.internal", "10.0.0.11"),
            ("db-primary.internal", "10.0.0.20"),
            ("file-share.internal", "10.0.0.30"),
            ("backup-01.internal", "10.0.0.40"),
        ]
        for i, (host, host_ip) in enumerate(lateral_targets):
            all_events.append(
                {
                    "@timestamp": ts(51 + i * 7),
                    "event": {
                        "category": "authentication",
                        "action": "admin_login",
                        "outcome": "success",
                        "type": ["start"],
                    },
                    "source": {"ip": source_ip},
                    "destination": {"ip": host_ip},
                    "user": {"name": backdoor_user},
                    "host": {"name": host},
                    "message": f"Lateral movement: {backdoor_user} → {host}",
                    "apt_stage": "5_lateral_movement",
                    "mitre_technique": "T1021",
                }
            )

        # ── Stage 6: Exfiltration (T1041) — 82-120 min ───────────────────
        exfil_targets = [
            ("203.0.113.10", "external-c2-server.xyz"),
            ("198.51.100.5", "data-drop.attacker.io"),
            ("203.0.113.25", "cloud-exfil.evil"),
        ]
        for i in range(6):
            dest_ip, dest_domain = random.choice(exfil_targets)
            bytes_exfil = random.randint(200_000_000, 800_000_000)  # 200-800 MB
            all_events.append(
                {
                    "@timestamp": ts(82 + i * 6),
                    "event": {
                        "category": "network",
                        "action": "connection",
                        "outcome": "success",
                    },
                    "source": {"ip": source_ip},
                    "destination": {
                        "ip": dest_ip,
                        "port": random.choice([443, 80, 53, 8443]),
                        "domain": dest_domain,
                    },
                    "network": {
                        "direction": "outbound",
                        "bytes": bytes_exfil,
                    },
                    "user": {"name": backdoor_user},
                    "host": {"name": random.choice([h for h, _ in lateral_targets])},
                    "message": f"Data exfiltration: {round(bytes_exfil / 1e6)}MB → {dest_domain}",
                    "apt_stage": "6_exfiltration",
                    "mitre_technique": "T1041",
                }
            )

        total_events = len(all_events)
        return all_events, {
            "type": "apt_attack",
            "severity": "CRITICAL",
            "source_ip": source_ip,
            "attacker_user": attacker_user,
            "backdoor_user": backdoor_user,
            "stages_executed": 6,
            "total_events": total_events,
            "attack_duration_minutes": 120,
            "mitre_techniques": ["T1046", "T1110", "T1136", "T1068", "T1021", "T1041"],
            "mitre_tactics": [
                "Discovery",
                "Credential Access",
                "Persistence",
                "Privilege Escalation",
                "Lateral Movement",
                "Exfiltration",
            ],
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
        elif incident_type == "lateral_movement":
            events, metadata = self.generate_lateral_movement()
        elif incident_type == "apt_attack":
            events, metadata = self.generate_apt_attack()
        else:
            print(f"❌ Unknown incident type: {incident_type}")
            print(
                "   Valid types: brute_force, exfiltration, privilege_escalation, lateral_movement, apt_attack"
            )
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
                if isinstance(value, list):
                    print(
                        f"  {key.replace('_', ' ').title()}: {', '.join(str(v) for v in value)}"
                    )
                else:
                    print(f"  {key.replace('_', ' ').title()}: {value}")

        # APT-specific stage breakdown
        if incident_type == "apt_attack":
            print(f"\n🎯 APT Kill-Chain Stages:")
            stage_labels = {
                "1": "Reconnaissance    (T1046 — Network Service Scanning)",
                "2": "Initial Access    (T1110 — Brute Force)",
                "3": "Persistence       (T1136 — Create Account)",
                "4": "Privilege Escal.  (T1068 — Exploitation)",
                "5": "Lateral Movement  (T1021 — Remote Services)",
                "6": "Exfiltration      (T1041 — Data over C2 Channel)",
            }
            for num, label in stage_labels.items():
                stage_events = [
                    e for e in events if e.get("apt_stage", "").startswith(num)
                ]
                print(f"  Stage {num}: {label}  [{len(stage_events)} events]")

        return metadata


def print_usage():
    print("""
Usage: python incident-simulator.py <incident_type>

Incident Types:
  brute_force          - Simulate multiple failed login attempts followed by success
  exfiltration         - Simulate large outbound data transfers
  privilege_escalation - Simulate privilege elevation attempts
  lateral_movement     - Simulate same user authenticating across multiple hosts (T1021)
  apt_attack           - Simulate full 6-stage APT kill-chain (T1046→T1110→T1136→T1068→T1021→T1041)

Examples:
  python incident-simulator.py brute_force
  python incident-simulator.py exfiltration
  python incident-simulator.py privilege_escalation
  python incident-simulator.py lateral_movement
  python incident-simulator.py apt_attack

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
    valid_types = [
        "brute_force",
        "exfiltration",
        "privilege_escalation",
        "lateral_movement",
        "apt_attack",
    ]
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

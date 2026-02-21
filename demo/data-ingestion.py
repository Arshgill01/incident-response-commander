#!/usr/bin/env python3
"""
Data Ingestion Script for Sample Security Data
Downloads and ingests Elastic's sample security datasets
"""

from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv
import json
import sys

load_dotenv()


class DataIngestion:
    def __init__(self):
        self.es = None
        self.cloud_id = os.getenv("ELASTIC_CLOUD_ID")
        self.api_key = os.getenv("ELASTIC_API_KEY")
        self.username = os.getenv("ELASTIC_USERNAME", "elastic")
        self.password = os.getenv("ELASTIC_PASSWORD")

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
        print("\nTo get your credentials:")
        print("  1. API Key: Kibana → Stack Management → API Keys → Create API Key")
        print("  2. Password: Elastic Cloud Console → Your Deployment → Reset Password")
        sys.exit(1)

    def check_connection(self):
        """Verify Elasticsearch connection"""
        try:
            info = self.es.info()
            print(f"✅ Connection verified: Elasticsearch {info['version']['number']}")
            print(f"   Cluster: {info['cluster_name']}")
            return True
        except Exception as e:
            print(f"❌ Connection check failed: {e}")
            return False

    def install_sample_data(self):
        """Install Elastic's sample data sets"""
        print("\n📦 Installing Sample Data...")

        print("Creating synthetic security event data...")

        # Current timestamp for realistic data
        now = datetime.now(timezone.utc)

        # Sample auth events with realistic timestamps
        auth_events = [
            {
                "@timestamp": (now - timedelta(minutes=5)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "authentication",
                    "action": "login",
                    "outcome": "failure",
                },
                "source": {"ip": "192.168.1.100"},
                "user": {"name": "admin"},
                "host": {"name": "server-01.internal"},
                "message": "Failed login attempt for user admin",
            },
            {
                "@timestamp": (now - timedelta(minutes=4)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "authentication",
                    "action": "login",
                    "outcome": "failure",
                },
                "source": {"ip": "192.168.1.100"},
                "user": {"name": "admin"},
                "host": {"name": "server-01.internal"},
                "message": "Failed login attempt for user admin",
            },
            {
                "@timestamp": (now - timedelta(minutes=3)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "authentication",
                    "action": "login",
                    "outcome": "failure",
                },
                "source": {"ip": "192.168.1.100"},
                "user": {"name": "admin"},
                "host": {"name": "server-01.internal"},
                "message": "Failed login attempt for user admin",
            },
            {
                "@timestamp": (now - timedelta(minutes=2)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "authentication",
                    "action": "login",
                    "outcome": "success",
                },
                "source": {"ip": "192.168.1.50"},
                "user": {"name": "john.doe"},
                "host": {"name": "server-02.internal"},
                "message": "Successful login for user john.doe",
            },
            # Network events for exfiltration detection
            {
                "@timestamp": (now - timedelta(minutes=30)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "network",
                    "action": "connection",
                    "outcome": "success",
                },
                "source": {"ip": "10.0.1.100"},
                "destination": {
                    "ip": "203.0.113.50",
                    "port": 443,
                    "domain": "external-server.com",
                },
                "network": {
                    "direction": "outbound",
                    "bytes": 1500000000,  # 1.5GB
                },
                "user": {"name": "john.doe"},
                "host": {"name": "server-02.internal"},
                "message": "Large outbound data transfer",
            },
            # Process events for privilege escalation
            {
                "@timestamp": (now - timedelta(minutes=15)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "event": {
                    "category": "process",
                    "action": "privilege_escalation",
                    "outcome": "success",
                },
                "user": {"name": "temp.user"},
                "host": {"name": "server-03.internal"},
                "process": {
                    "name": "sudo",
                    "args": "sudo su -",
                    "target": {"name": "root"},
                },
                "message": "Privilege escalation attempt detected",
            },
        ]

        # Index sample events
        for i, event in enumerate(auth_events):
            try:
                response = self.es.index(
                    index="security-simulated-events", document=event
                )
                print(
                    f"  ✅ Indexed event {i + 1}/{len(auth_events)}: {event['event']['category']} - {event['event']['action']}"
                )
            except Exception as e:
                print(f"  ❌ Failed to index event {i + 1}: {e}")

        print(f"\n✅ Indexed {len(auth_events)} sample events")

        # Refresh the index to make data immediately searchable
        try:
            self.es.indices.refresh(index="security-simulated-events")
            print("✅ Index refreshed - data is now searchable")
        except Exception as e:
            print(f"⚠️ Failed to refresh index: {e}")

    def verify_data(self):
        """Verify data is indexed correctly"""
        print("\n🔍 Verifying Data...")

        # Check indices
        try:
            indices = self.es.indices.get(index="security-*")
            print(f"✅ Found security-related indices: {list(indices.keys())}")
        except Exception as e:
            print(f"⚠️ Could not list indices: {e}")

        # Count documents
        try:
            count = self.es.count(index="security-simulated-events")
            print(f"✅ Documents in security-simulated-events: {count['count']}")
        except Exception as e:
            print(f"⚠️ Could not count documents: {e}")

        # Test ES|QL query
        print("\n🧪 Testing ES|QL query...")
        try:
            # Try the new ES|QL endpoint format
            query = """FROM security-simulated-events
| LIMIT 10"""

            result = self.es.esql.query(query=query)
            print("✅ ES|QL query successful")

            # Show sample data
            if result and "values" in result:
                print(f"   Sample data rows: {len(result['values'])}")
        except Exception as e:
            print(f"⚠️ ES|QL query test failed: {e}")
            print(
                "   Note: This might be a permissions issue. ES|QL may need specific privileges."
            )

    def setup_ilm_policy(self):
        """Setup Index Lifecycle Management for incident logs"""
        print("\n⚙️ Setting up ILM Policy...")

        policy = {
            "policy": {
                "phases": {
                    "hot": {
                        "min_age": "0ms",
                        "actions": {
                            "rollover": {
                                "max_primary_shard_size": "50gb",
                                "max_age": "30d",
                            }
                        },
                    },
                    "warm": {
                        "min_age": "7d",
                        "actions": {
                            "shrink": {"number_of_shards": 1},
                            "forcemerge": {"max_num_segments": 1},
                        },
                    },
                    "cold": {"min_age": "30d", "actions": {"readonly": {}}},
                    "delete": {"min_age": "90d", "actions": {"delete": {}}},
                }
            }
        }

        try:
            self.es.ilm.put_lifecycle(
                name="incident-response-policy", policy=policy["policy"]
            )
            print("✅ ILM policy created/updated: incident-response-policy")
        except Exception as e:
            print(f"⚠️ ILM policy setup: {e}")

    def create_index_templates(self):
        """Create index templates for incident data"""
        print("\n📋 Creating Index Templates...")

        template = {
            "index_patterns": ["logs-*", "security-*", "incident-*"],
            "template": {
                "settings": {"number_of_shards": 1, "number_of_replicas": 1},
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event": {
                            "properties": {
                                "category": {"type": "keyword"},
                                "action": {"type": "keyword"},
                                "outcome": {"type": "keyword"},
                            }
                        },
                        "source": {"properties": {"ip": {"type": "ip"}}},
                        "destination": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "integer"},
                                "domain": {"type": "keyword"},
                            }
                        },
                        "network": {
                            "properties": {
                                "direction": {"type": "keyword"},
                                "bytes": {"type": "long"},
                            }
                        },
                        "user": {"properties": {"name": {"type": "keyword"}}},
                        "host": {"properties": {"name": {"type": "keyword"}}},
                        "process": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "args": {"type": "text"},
                                "target": {"properties": {"name": {"type": "keyword"}}},
                            }
                        },
                        "message": {"type": "text"},
                    }
                },
            },
        }

        try:
            self.es.indices.put_index_template(
                name="incident-response-template",
                index_patterns=template["index_patterns"],
                template=template["template"],
            )
            print("✅ Index template created/updated: incident-response-template")
            print("   Matching patterns: logs-*, security-*, incident-*")
        except Exception as e:
            print(f"⚠️ Index template: {e}")

    def check_indices_health(self):
        """Check health of security indices"""
        print("\n🏥 Checking Index Health...")
        try:
            health = self.es.cluster.health()
            print(f"✅ Cluster status: {health['status']}")
            print(f"   Nodes: {health['number_of_nodes']}")
            print(f"   Active shards: {health['active_primary_shards']}")
        except Exception as e:
            print(f"⚠️ Could not check cluster health: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Security Data Ingestion Tool")
    print("=" * 60)

    try:
        ingestion = DataIngestion()
    except SystemExit:
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during initialization: {e}")
        sys.exit(1)

    if ingestion.check_connection():
        ingestion.check_indices_health()
        ingestion.create_index_templates()
        ingestion.setup_ilm_policy()
        ingestion.install_sample_data()
        ingestion.verify_data()
        print("\n" + "=" * 60)
        print("✅ Setup complete!")
        print("=" * 60)
        print("\nNext steps:")
        print("  1. Check data in Kibana: Analytics → Discover")
        print("  2. Run incident simulator: python3 incident-simulator.py")
        print("  3. Create tools in Agent Builder")
    else:
        print("\n❌ Setup failed. Please check your credentials and try again.")
        sys.exit(1)

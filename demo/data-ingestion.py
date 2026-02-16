#!/usr/bin/env python3
"""
Data Ingestion Script for Sample Security Data
Downloads and ingests Elastic's sample security datasets
"""

from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv
import json

load_dotenv()


class DataIngestion:
    def __init__(self):
        self.es = Elasticsearch(
            cloud_id=os.getenv("ELASTIC_CLOUD_ID"), api_key=os.getenv("ELASTIC_API_KEY")
        )

    def check_connection(self):
        """Verify Elasticsearch connection"""
        try:
            info = self.es.info()
            print(f"✅ Connected to Elasticsearch {info['version']['number']}")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False

    def install_sample_data(self):
        """Install Elastic's sample data sets"""
        print("\n📦 Installing Sample Data...")

        # Sample data is typically available via Kibana UI
        # For API approach, we'll create synthetic data
        print("Creating synthetic security event data...")

        # Sample auth events
        auth_events = [
            {
                "@timestamp": "2026-02-16T10:00:00Z",
                "event": {
                    "category": "authentication",
                    "action": "login",
                    "outcome": "failure",
                },
                "source": {"ip": "192.168.1.100"},
                "user": {"name": "admin"},
                "message": "Failed login attempt",
            },
            {
                "@timestamp": "2026-02-16T10:01:00Z",
                "event": {
                    "category": "authentication",
                    "action": "login",
                    "outcome": "success",
                },
                "source": {"ip": "192.168.1.50"},
                "user": {"name": "john.doe"},
                "message": "Successful login",
            },
        ]

        # Index sample events
        for event in auth_events:
            self.es.index(index="security-simulated-events", body=event)

        print(f"✅ Indexed {len(auth_events)} sample events")

    def verify_data(self):
        """Verify data is indexed correctly"""
        print("\n🔍 Verifying Data...")

        # Check indices
        indices = self.es.indices.get_alias("*security*")
        print(f"Found security-related indices: {list(indices.keys())}")

        # Count documents
        try:
            count = self.es.count(index="security-simulated-events")
            print(f"Documents in security-simulated-events: {count['count']}")
        except:
            print("No security-simulated-events index yet")

        # Test ES|QL query
        print("\nTesting ES|QL query...")
        query = """
        FROM security-simulated-events
        | LIMIT 10
        """
        try:
            result = self.es.esql.query(body={"query": query})
            print("✅ ES|QL query successful")
        except Exception as e:
            print(f"⚠️ ES|QL query test: {e}")

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
                    "cold": {"min_age": "30d", "actions": {"freeze": {}}},
                    "delete": {"min_age": "90d", "actions": {"delete": {}}},
                }
            }
        }

        try:
            self.es.ilm.put_lifecycle(name="incident-response-policy", body=policy)
            print("✅ ILM policy created")
        except Exception as e:
            print(f"⚠️ ILM policy: {e}")

    def create_index_templates(self):
        """Create index templates for incident data"""
        print("\n📋 Creating Index Templates...")

        template = {
            "index_patterns": ["incident-*", "security-*"],
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
                        "user": {"properties": {"name": {"type": "keyword"}}},
                    }
                },
            },
        }

        try:
            self.es.indices.put_index_template(
                name="incident-response-template", body=template
            )
            print("✅ Index template created")
        except Exception as e:
            print(f"⚠️ Index template: {e}")


if __name__ == "__main__":
    print("🚀 Security Data Ingestion\n")

    ingestion = DataIngestion()

    if ingestion.check_connection():
        ingestion.create_index_templates()
        ingestion.setup_ilm_policy()
        ingestion.install_sample_data()
        ingestion.verify_data()
        print("\n✅ Setup complete!")
    else:
        print("\n❌ Failed to connect. Check your .env file.")

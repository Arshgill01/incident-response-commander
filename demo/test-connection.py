#!/usr/bin/env python3
"""
Quick Test Script - Verify Elasticsearch Connection
Run this first to ensure your credentials work before proceeding with setup
"""

from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv
import sys

load_dotenv()


def test_connection():
    """Test connection to Elasticsearch"""
    cloud_id = os.getenv("ELASTIC_CLOUD_ID")
    api_key = os.getenv("ELASTIC_API_KEY")
    username = os.getenv("ELASTIC_USERNAME", "elastic")
    password = os.getenv("ELASTIC_PASSWORD")

    print("=" * 60)
    print("🔍 Testing Elasticsearch Connection")
    print("=" * 60)

    if not cloud_id:
        print("\n❌ ERROR: ELASTIC_CLOUD_ID is not set in .env file")
        return False

    print(f"\n📍 Cloud ID: {cloud_id[:50]}...")

    es = None

    # Try API Key first
    if api_key and api_key.strip():
        print("\n🔑 Testing API Key authentication...")
        try:
            es = Elasticsearch(cloud_id=cloud_id, api_key=api_key, request_timeout=30)
            info = es.info()
            print(f"✅ SUCCESS! Connected using API Key")
            print(f"   Elasticsearch version: {info['version']['number']}")
            print(f"   Cluster name: {info['cluster_name']}")
            auth_method = "API Key"
        except Exception as e:
            print(f"❌ API Key failed: {e}")
            es = None

    # Try username/password if API key failed or not provided
    if es is None and password and password.strip():
        print(f"\n🔐 Testing username/password authentication...")
        print(f"   Username: {username}")
        try:
            es = Elasticsearch(
                cloud_id=cloud_id, basic_auth=(username, password), request_timeout=30
            )
            info = es.info()
            print(f"✅ SUCCESS! Connected using username/password")
            print(f"   Elasticsearch version: {info['version']['number']}")
            print(f"   Cluster name: {info['cluster_name']}")
            auth_method = "Username/Password"
        except Exception as e:
            print(f"❌ Username/Password failed: {e}")
            es = None

    if es is None:
        print("\n" + "=" * 60)
        print("❌ CONNECTION FAILED")
        print("=" * 60)
        print("\nTroubleshooting steps:")
        print("1. Check your .env file exists in the project root")
        print("2. Verify ELASTIC_CLOUD_ID is correct")
        print("3. Add either ELASTIC_API_KEY or ELASTIC_PASSWORD")
        print("\nTo get credentials:")
        print("• API Key: Kibana → Stack Management → API Keys → Create")
        print("• Password: Elastic Cloud Console → Deployment → Security → Reset")
        return False

    # Test additional operations
    print("\n🧪 Testing additional operations...")

    try:
        # Check cluster health
        health = es.cluster.health()
        print(f"✅ Cluster health: {health['status']}")

        # List indices
        indices = es.cat.indices(format="json")
        print(f"✅ Found {len(indices)} indices")
        if len(indices) > 0:
            print(f"   Sample indices: {[idx['index'] for idx in indices[:3]]}")

        # Test ES|QL if available
        try:
            result = es.esql.query(query="FROM security-simulated-events | LIMIT 1")
            print("✅ ES|QL query test: PASSED")
        except Exception as e:
            print(f"⚠️ ES|QL query test: {str(e)[:100]}")
            print("   (ES|QL may need specific privileges)")

    except Exception as e:
        print(f"⚠️ Some operations failed: {e}")

    print("\n" + "=" * 60)
    print("✅ CONNECTION SUCCESSFUL!")
    print("=" * 60)
    print(f"\nAuthentication method used: {auth_method}")
    print("\nYou can now proceed with:")
    print("  1. python3 data-ingestion.py")
    print("  2. python3 incident-simulator.py brute_force")
    print("  3. Creating tools in Kibana Agent Builder")

    return True


if __name__ == "__main__":
    try:
        success = test_connection()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

#!/usr/bin/env python3
"""
ELASTICSEARCH CONNECTION DIAGNOSTIC TOOL
This will help identify exactly what's failing with your connection
"""

import os
import sys
import ssl
import urllib.request
from dotenv import load_dotenv

load_dotenv()

print("=" * 70)
print("🔍 ELASTICSEARCH CONNECTION DIAGNOSTIC")
print("=" * 70)

# Get all credentials
CLOUD_ID = os.getenv("ELASTIC_CLOUD_ID")
API_KEY = os.getenv("ELASTIC_API_KEY")
USERNAME = os.getenv("ELASTIC_USERNAME")
PASSWORD = os.getenv("ELASTIC_PASSWORD")
KIBANA_URL = os.getenv("KIBANA_URL")

print("\n📋 ENVIRONMENT CHECK:")
print(f"  Cloud ID present: {'✅ Yes' if CLOUD_ID else '❌ No'}")
print(f"  API Key present: {'✅ Yes' if API_KEY else '❌ No'}")
print(f"  Username present: {'✅ Yes' if USERNAME else '❌ No'}")
print(f"  Password present: {'✅ Yes' if PASSWORD else '❌ No'}")
print(f"  Kibana URL: {KIBANA_URL}")

if not CLOUD_ID:
    print("\n❌ CRITICAL: ELASTIC_CLOUD_ID is missing!")
    sys.exit(1)

# Test 1: Check if we can reach the internet
print("\n🌐 TEST 1: Network Connectivity")
print("-" * 70)
try:
    import socket

    socket.create_connection(("www.google.com", 80), timeout=5)
    print("✅ Internet connectivity: OK")
except Exception as e:
    print(f"❌ Internet connectivity failed: {e}")

# Test 2: Parse Cloud ID and test connection
print("\n☁️  TEST 2: Cloud ID Parsing")
print("-" * 70)
try:
    # Cloud ID format: cluster_name:base64_data
    if ":" not in CLOUD_ID:
        print("❌ Invalid Cloud ID format - missing ':' separator")
    else:
        cluster_name, base64_data = CLOUD_ID.split(":", 1)
        print(f"✅ Cloud ID format valid")
        print(f"   Cluster name: {cluster_name}")

        import base64

        decoded = base64.b64decode(base64_data).decode("utf-8")
        parts = decoded.split("$")

        if len(parts) >= 3:
            print(f"   Decoded successfully")
            print(f"   Parts found: {len(parts)}")

            # Extract endpoint (remove port if present)
            endpoint = parts[0]
            if ":" in endpoint:
                endpoint = endpoint.split(":")[0]
            print(f"   Endpoint: {endpoint}")

            # Try to construct the Elasticsearch URL
            es_host = f"https://{endpoint}"
            print(f"   ES URL: {es_host}")
        else:
            print(f"⚠️  Cloud ID decoded but has unexpected format")
            print(f"   Raw decoded: {decoded[:100]}...")
except Exception as e:
    print(f"❌ Cloud ID parsing failed: {e}")
    import traceback

    traceback.print_exc()

# Test 3: Try connecting with urllib first (lower level)
print("\n🔌 TEST 3: Basic HTTPS Connection")
print("-" * 70)
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Try to reach the Kibana URL
    if KIBANA_URL:
        req = urllib.request.Request(KIBANA_URL, method="HEAD")
        req.add_header("User-Agent", "Python/Diagnostic")

        try:
            response = urllib.request.urlopen(req, context=ctx, timeout=10)
            print(f"✅ Kibana URL reachable: HTTP {response.status}")
        except urllib.error.HTTPError as e:
            print(
                f"⚠️  Kibana URL returned HTTP {e.code} (this may be normal without auth)"
            )
        except Exception as e:
            print(f"❌ Cannot reach Kibana URL: {e}")
except Exception as e:
    print(f"❌ HTTPS test failed: {e}")

# Test 4: Try Elasticsearch client connection with detailed errors
print("\n📦 TEST 4: Elasticsearch Client Connection")
print("-" * 70)

try:
    from elasticsearch import Elasticsearch
    import elasticsearch

    print(f"✅ Elasticsearch Python client version: {elasticsearch.__version__}")
except ImportError:
    print("❌ Elasticsearch Python client not installed!")
    print("   Run: pip install elasticsearch")
    sys.exit(1)

# Test 4a: API Key connection (v9.x compatible)
if API_KEY:
    print("\n  Testing API Key connection...")
    try:
        es = Elasticsearch(
            cloud_id=CLOUD_ID,
            api_key=API_KEY,
            request_timeout=30,
            verify_certs=False,
            ssl_show_warn=False,
        )
        info = es.info()
        print(f"  ✅ API Key connection SUCCESS!")
        print(f"     Version: {info['version']['number']}")
        print(f"     Cluster: {info['cluster_name']}")
    except Exception as e:
        print(f"  ❌ API Key connection FAILED")
        print(f"     Error: {type(e).__name__}: {str(e)[:200]}")

        # Try to get more details
        if hasattr(e, "info"):
            print(f"     Details: {e.info}")
        if hasattr(e, "status_code"):
            print(f"     HTTP Status: {e.status_code}")
else:
    print("  ⏭️  Skipping API Key test (not provided)")

# Test 4b: Username/Password connection (v9.x compatible)
if USERNAME and PASSWORD:
    print("\n  Testing Username/Password connection...")
    try:
        es = Elasticsearch(
            cloud_id=CLOUD_ID,
            basic_auth=(USERNAME, PASSWORD),
            request_timeout=30,
            verify_certs=False,
            ssl_show_warn=False,
        )
        info = es.info()
        print(f"  ✅ Username/Password connection SUCCESS!")
        print(f"     Version: {info['version']['number']}")
        print(f"     Cluster: {info['cluster_name']}")
    except Exception as e:
        print(f"  ❌ Username/Password connection FAILED")
        print(f"     Error: {type(e).__name__}: {str(e)[:200]}")

        # Try to get more details
        if hasattr(e, "info"):
            print(f"     Details: {e.info}")
        if hasattr(e, "status_code"):
            print(f"     HTTP Status: {e.status_code}")

        # Check if it's an authentication error
        error_str = str(e).lower()
        if (
            "authentication" in error_str
            or "unauthorized" in error_str
            or "401" in error_str
        ):
            print("\n     💡 This appears to be an AUTHENTICATION error")
            print("        The password may be incorrect or the user may be disabled.")
            print("        Try resetting the password in Elastic Cloud Console.")
        elif (
            "connection" in error_str
            or "timeout" in error_str
            or "refused" in error_str
        ):
            print("\n     💡 This appears to be a CONNECTION error")
            print(
                "        Check your network, firewall, or if the deployment is running."
            )
        elif "ssl" in error_str or "certificate" in error_str or "tls" in error_str:
            print("\n     💡 This appears to be an SSL/TLS error")
            print("        Certificate verification may be failing.")
else:
    print("  ⏭️  Skipping Username/Password test (credentials not provided)")

# Test 5: Check if we can construct the URL manually
print("\n🔗 TEST 5: Manual URL Construction")
print("-" * 70)
try:
    # Parse Cloud ID to get the endpoint
    cluster_name, base64_data = CLOUD_ID.split(":", 1)
    import base64

    decoded = base64.b64decode(base64_data).decode("utf-8")
    parts = decoded.split("$")

    # Construct the Elasticsearch URL
    endpoint = parts[0]
    # Remove port if present
    if ":" in endpoint:
        endpoint = endpoint.split(":")[0]
    es_url = f"https://{endpoint}"
    print(f"  Constructed ES URL: {es_url}")

    # Try a simple request with basic auth
    if USERNAME and PASSWORD:
        credentials = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
        req = urllib.request.Request(es_url)
        req.add_header("Authorization", f"Basic {credentials}")
        req.add_header("User-Agent", "Python/Diagnostic")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            response = urllib.request.urlopen(req, context=ctx, timeout=10)
            print(f"  ✅ Manual request with basic auth: HTTP {response.status}")
        except urllib.error.HTTPError as e:
            print(f"  ❌ Manual request failed: HTTP {e.code}")
            if e.code == 401:
                print("     Authentication failed - wrong username/password")
            print(f"     Response: {e.read().decode()[:200]}")
        except Exception as e:
            print(f"  ❌ Manual request failed: {e}")
except Exception as e:
    print(f"  ❌ Manual URL construction test failed: {e}")

print("\n" + "=" * 70)
print("📊 DIAGNOSTIC SUMMARY")
print("=" * 70)
print("\nCommon Issues and Solutions:")
print("\n1. Authentication Failed (401):")
print("   → Reset password in Elastic Cloud Console")
print("   → Ensure user 'elastic' exists and is enabled")
print("   → Check for special characters in password that need escaping")
print("\n2. Connection Timeout:")
print("   → Check if deployment is running in Elastic Cloud Console")
print("   → Verify network connectivity")
print("   → Check firewall/proxy settings")
print("\n3. SSL Certificate Errors:")
print("   → Deployment may not be fully provisioned")
print("   → Try again in a few minutes")
print("\n4. Invalid Cloud ID:")
print("   → Copy Cloud ID exactly from Elastic Cloud Console")
print("   → Should be in format: name:base64string")
print("\n5. Elasticsearch Client Version:")
print("   → This script supports v9.x of the Elasticsearch Python client")
print("   → If using older version, you may need to adjust parameters")
print("\n" + "=" * 70)

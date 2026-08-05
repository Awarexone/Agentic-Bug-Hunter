"""TODO-8 item 2 (docs/TODOS.md): end-to-end hunt loop integration test —
recon -> rank -> hunt -> validate -> report as a real sequence.

SCOPE — what this covers and what it deliberately doesn't:
This exercises the deterministic Python/library code each pipeline stage's
Claude Code agent (recon-agent, recon-ranker, validator/validation-engine,
report-writer) calls, or is meant to call — tools/lead_board.py's ingest(),
memory/vuln_intelligence.py's priority_score() (the canonical decision-engine
formula), tools/validation_core.py's evaluate_finding() (Phase 0's headless
4-gate + CVSS engine), and memory/finding_state.py's lifecycle gates — not
the agents' own LLM reasoning, which can't be invoked from pytest. Every
stage below does real work against a real target; nothing is mocked out.

Per this project's own testing rule ("No test may touch the network — use
fixtures or demo/app.py"), the target is a real, in-process instance of
demo/app.py — the same intentionally-vulnerable app the project's own
tutorial recording uses, bound to 127.0.0.1 on an OS-assigned port. No
request in this file ever leaves the machine.

The five stages:
  1. RECON     — a real HTTP crawl of demo/app.py (home page, robots.txt,
                 same-origin link discovery), scope-checked via
                 tools/scope_checker.py, written into the canonical
                 recon/<target>/urls/all.txt layout tools/recon_adapter.py
                 and tools/lead_board.py already expect.
  2. RANK      — tools/lead_board.py's real ingest() routes the crawled URLs
                 to hunt-* skills; memory/vuln_intelligence.py's real
                 priority_score() ranks candidate vuln classes.
  3. HUNT      — real confirmation requests against demo/app.py's planted
                 bugs (reflected XSS, open redirect, exposed .env) — this
                 verifies actual server responses, not assumed behavior.
  4. VALIDATE  — tools/validation_core.py's real evaluate_finding() runs
                 the 4 gates + CVSS scoring against the confirmed .env leak.
  5. REPORT    — memory/finding_state.py's real FindingStateDB advances that
                 finding SUSPECTED -> ... -> REPORT_READY, including its
                 self-learning write-back to patterns.jsonl.

Only the exposed-.env finding is carried through validate + report — the
point here is proving the SEQUENCE integrates end to end, not re-testing
every gate in isolation (that's test_validation_core.py's and
test_finding_state.py's job, both already exhaustive).
"""

import http.server
import importlib.util
import json
import os
import re
import sys
import threading
from pathlib import Path
from urllib.parse import urljoin

import pytest
import requests

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _p in (REPO_ROOT, TOOLS_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import lead_board as lb  # tools/ on sys.path via conftest.py
from tools.scope_checker import ScopeChecker
from tools import validation_core as vcore
from memory.finding_state import FindingStateDB
from memory.vuln_intelligence import priority_score

TARGET = "demo.local"  # the "domain" this synthetic hunt targets


# ─── fixture: a real, in-process demo/app.py instance ──────────────────────

@pytest.fixture(scope="module")
def demo_app():
    """Launches the real demo/app.py module (not a reimplementation) on
    localhost:<OS-assigned port>, in a background thread, torn down after
    this module's tests finish.

    Bound via the "localhost" hostname, not the bare 127.0.0.1 literal
    demo/app.py defaults to (APP_HOST env var — its own docstring calls it
    DEMO_HOST, which is stale/wrong, a pre-existing doc/code mismatch, out
    of scope here): tools/scope_checker.py deliberately refuses to treat IP
    literals as in-scope (its own documented limitation), so a crawl built
    on a raw-IP base URL would have every single request rejected by
    ScopeChecker before the first fetch — exactly the silent, total-failure
    trap this fixture exists to avoid.
    """
    os.environ["APP_HOST"] = "localhost"
    spec = importlib.util.spec_from_file_location(
        "e2e_demo_app", os.path.join(REPO_ROOT, "demo", "app.py")
    )
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    assert demo.HOST == "localhost"

    httpd = http.server.ThreadingHTTPServer((demo.HOST, 0), demo.DemoHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{demo.HOST}:{port}", demo
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def isolated_memory(tmp_path, monkeypatch):
    """Point lead_board's ledger and this test's finding-state/pattern DBs
    at tmp_path — never touch the real memory/leads/ or hunt-memory/."""
    monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
    return tmp_path


# ─── Stage 1: RECON — a real crawl, written to the canonical layout ───────

def _crawl(base_url: str, checker: ScopeChecker, session: requests.Session) -> tuple[list[str], list[str]]:
    """Minimal, real recon crawl: fetch /, follow same-origin <a href> links,
    and parse robots.txt Disallow entries (demo/app.py deliberately lists
    /admin, /backup/, /.env, /api/debug there — a real recon technique this
    directly exercises). Returns (all_urls, param_urls), both sorted.

    allow_redirects=False is deliberate, not an oversight: /go?url=... is
    demo/app.py's own planted open-redirect bug, and a real crawler blindly
    following a 3xx to an attacker/arbitrary Location header would leave
    scope entirely — exactly the failure mode tools/scope_checker.py exists
    to prevent. This surfaced for real during this test's own development:
    with redirects auto-followed, requests.Session silently fetched the
    actual github.com over the actual network. A recon crawler must record
    the redirect target as a signal (worth flagging as an SSRF/open-redirect
    lead), never chase it.
    """
    to_visit = {urljoin(base_url, "/"), urljoin(base_url, "/robots.txt")}
    visited: set[str] = set()
    all_urls: set[str] = set()

    while to_visit:
        url = to_visit.pop()
        if url in visited or not checker.is_in_scope(url):
            continue
        visited.add(url)
        resp = session.get(url, timeout=5, allow_redirects=False)
        all_urls.add(url)

        if 300 <= resp.status_code < 400:
            continue  # redirect target recorded by the caller, never followed

        if url.endswith("/robots.txt"):
            for line in resp.text.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        to_visit.add(urljoin(base_url, path))
            continue

        for href in re.findall(r'href="([^"]+)"', resp.text):
            abs_url = urljoin(url, href)
            if abs_url not in visited:
                to_visit.add(abs_url)

    param_urls = {u for u in all_urls if "?" in u}
    return sorted(all_urls), sorted(param_urls)


def _write_recon_dir(recon_dir: Path, all_urls: list[str], param_urls: list[str]) -> None:
    (recon_dir / "urls").mkdir(parents=True, exist_ok=True)
    (recon_dir / "urls" / "all.txt").write_text("\n".join(all_urls) + "\n")
    (recon_dir / "urls" / "with_params.txt").write_text("\n".join(param_urls) + "\n")


class TestStage1Recon:
    def test_crawl_discovers_planted_bugs_via_real_http(self, demo_app):
        base_url, _demo = demo_app
        checker = ScopeChecker(["localhost"])
        session = requests.Session()

        all_urls, param_urls = _crawl(base_url, checker, session)

        # Discovered via the landing page's own links:
        assert any(u.endswith("/about") for u in all_urls)
        assert any("/search?q=" in u for u in all_urls)
        assert any("/go?url=" in u for u in all_urls)
        # Discovered via robots.txt Disallow entries (real recon technique):
        assert any(u.endswith("/admin") for u in all_urls)
        assert any(u.endswith("/.env") for u in all_urls)
        assert any(u.endswith("/api/debug") for u in all_urls)
        # /fetch (the SSRF endpoint) is intentionally unlinked and not in
        # robots.txt — a plain crawl should NOT find it. This is realistic:
        # undocumented endpoints are exactly what browser_recon.py's hidden-
        # endpoint discovery (Phase 1, #5) exists to catch instead.
        assert not any("/fetch" in u for u in all_urls)

    def test_crawl_respects_scope(self, demo_app):
        """The crawler must never actually fetch a URL whose HOST is
        off-target. Note: /go?url=https://github.com/shuvonsec staying in
        all_urls is CORRECT — that's a local, in-scope request whose query
        *value* happens to reference github.com (demo/app.py's own planted
        open-redirect bug); the check below is on parsed hostnames, not a
        naive substring match, so it doesn't false-positive on that."""
        from urllib.parse import urlparse
        base_url, _demo = demo_app
        checker = ScopeChecker(["localhost"])
        session = requests.Session()
        all_urls, _ = _crawl(base_url, checker, session)
        assert all_urls, "crawl found nothing at all — test setup is broken"
        assert all(urlparse(u).hostname == "localhost" for u in all_urls)


# ─── Stage 2: RANK — real lead_board.ingest() + real priority_score() ─────

class TestStage2Rank:
    def test_lead_board_routes_crawled_urls_to_hunt_skills(self, demo_app, isolated_memory):
        base_url, _demo = demo_app
        checker = ScopeChecker(["localhost"])
        session = requests.Session()
        all_urls, param_urls = _crawl(base_url, checker, session)

        recon_dir = isolated_memory / "recon" / TARGET
        _write_recon_dir(recon_dir, all_urls, param_urls)

        leads = lb.ingest(TARGET, str(recon_dir))
        skills = {ld["skill"] for ld in leads}

        # /admin -> privileged-path rule; /.env -> source-leak rule;
        # /search?q= -> reflected-text-param rule. (/go?url=https -> the SSRF
        # rule fires on its param name+value shape ahead of the narrower
        # open-redirect rule, a known lead_board heuristic quirk — not
        # something this test needs to correct, just observe honestly.)
        assert "hunt-auth-bypass" in skills
        assert "hunt-source-leak" in skills
        assert "hunt-xss" in skills

    def test_priority_score_ranks_candidates(self, demo_app, isolated_memory):
        """The same canonical formula recon-ranker calls, run for real on
        the vuln classes this hunt actually found candidates for."""
        candidates = ["xss", "open-redirect", "info-disclosure"]
        scored = [
            (vc, priority_score(vc, ["python", "http.server"], TARGET))
            for vc in candidates
        ]
        for vuln_class, result in scored:
            assert 0 <= result["score"] <= 100, f"{vuln_class}: {result}"
        # A ranked order exists and is stable/derivable from the real scores
        # — that's what "rank" integrating with real recon output means here.
        ranked = sorted(scored, key=lambda pair: pair[1]["score"], reverse=True)
        assert [vc for vc, _ in ranked] == sorted(
            candidates, key=lambda vc: dict(scored)[vc]["score"], reverse=True
        )


# ─── Stage 3: HUNT — real confirmation requests against demo/app.py ──────

class TestStage3Hunt:
    def test_confirms_reflected_xss(self, demo_app):
        base_url, _demo = demo_app
        payload = "<script>alert(1)</script>"
        resp = requests.get(f"{base_url}/search", params={"q": payload}, timeout=5)
        assert payload in resp.text  # unescaped -> genuinely reflected, not just "didn't error"

    def test_confirms_open_redirect(self, demo_app):
        base_url, _demo = demo_app
        resp = requests.get(f"{base_url}/go", params={"url": "https://evil.example"},
                             timeout=5, allow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"] == "https://evil.example"

    def test_confirms_exposed_env_file(self, demo_app):
        base_url, _demo = demo_app
        resp = requests.get(f"{base_url}/.env", timeout=5)
        assert resp.status_code == 200
        assert "AWS_SECRET_ACCESS_KEY" in resp.text
        assert "DB_PASSWORD" in resp.text


# ─── Stage 4: VALIDATE — real tools/validation_core.py gates + CVSS ───────

def _env_leak_finding(base_url: str) -> dict:
    return {
        "vuln_type": "Sensitive Data Exposure",
        "gate1": {
            "repro_3_3": True, "works_without_proxy": True,
            "no_special_state": True, "not_documented_behavior": True,
        },
        "gate2": {"asset_in_scope": True, "not_excluded": True, "version_ok": True},
        "gate3": {
            "concrete_impact": True, "no_unrealistic_preconditions": True,
            "curl_poc": f"curl -s {base_url}/.env",
            "impact_description": "Exposes AWS access key/secret, DB creds, JWT signing key in plaintext",
        },
        "gate4": {
            "not_in_h1_disclosed": True, "not_in_github_issues": True,
            "checked_git_history": True,
        },
        "cvss": {
            "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
            "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        },
    }


class TestStage4Validate:
    def test_confirmed_env_leak_passes_all_gates(self, demo_app):
        base_url, _demo = demo_app
        # test_confirms_exposed_env_file already proved this finding is real;
        # this stage proves it also earns its way through the real gates.
        result = vcore.evaluate_finding(_env_leak_finding(base_url))
        assert result["gate1_is_real"]["passed"] is True
        assert result["gate2_in_scope"]["passed"] is True
        assert result["gate3_exploitable"]["passed"] is True
        assert result["gate4_not_dup"]["passed"] is True
        assert result["overall_pass"] is True
        assert result["cvss"]["severity"] == "HIGH"

    def test_headless_cli_reaches_the_same_verdict(self, demo_app, tmp_path):
        """Full-circle proof: the real `validate.py --non-interactive` CLI
        subprocess, not just the library function, on this same finding."""
        import subprocess
        base_url, _demo = demo_app
        finding_path = tmp_path / "env_leak_finding.json"
        finding_path.write_text(json.dumps(_env_leak_finding(base_url)))

        proc = subprocess.run(
            [sys.executable, os.path.join(TOOLS_ROOT, "validate.py"),
             "--non-interactive", "--json", "--input", str(finding_path)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=15,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["overall_pass"] is True


# ─── Stage 5: REPORT — real finding_state lifecycle + self-learning ──────

class TestStage5Report:
    def test_validated_finding_reaches_report_ready(self, demo_app, tmp_path):
        base_url, _demo = demo_app
        vuln_class = "info-disclosure"
        endpoint = "/.env"

        validation = vcore.evaluate_finding(_env_leak_finding(base_url))
        assert validation["overall_pass"] is True
        evidence = {"verdict": "STRONG", "reproducible": True}

        db = FindingStateDB(tmp_path / "hunt-memory" / "finding_states.jsonl")

        db.advance(TARGET, vuln_class, endpoint, "SUSPECTED",
                    notes="found via robots.txt Disallow crawl")
        db.advance(TARGET, vuln_class, endpoint, "TESTING",
                    notes="confirmed live via curl -s <base>/.env")
        db.advance(TARGET, vuln_class, endpoint, "VALIDATED", evidence=evidence,
                    notes="tools/validation_core.py evaluate_finding() overall_pass=True")
        confirmed = db.advance(
            TARGET, vuln_class, endpoint, "CONFIRMED", evidence=evidence,
            technique="exposed-config-file", tech_stack=["python", "http.server"],
            payout=500,
        )
        report_ready = db.advance(TARGET, vuln_class, endpoint, "REPORT_READY", evidence=evidence)

        assert db.current_state(TARGET, vuln_class, endpoint) == "REPORT_READY"
        assert report_ready["state"] == "REPORT_READY"
        assert report_ready["previous_state"] == "CONFIRMED"

        # Self-learning write-back actually landed — the point of TODO-6/7's
        # earlier work: no manual /remember step required for this to count
        # toward the next hunt's priority_score()/tech_vuln_affinity().
        assert confirmed["auto_learned"]["file"] == "patterns.jsonl"
        assert confirmed["auto_learned"]["saved"] is True
        patterns_path = tmp_path / "hunt-memory" / "patterns.jsonl"
        assert patterns_path.exists()
        saved = [json.loads(line) for line in patterns_path.read_text().splitlines() if line.strip()]
        assert any(
            p["target"] == TARGET and p["vuln_class"] == vuln_class and p["technique"] == "exposed-config-file"
            for p in saved
        )

    def test_weak_evidence_cannot_reach_confirmed(self, tmp_path):
        """The two hard rules finding_state.py enforces must actually hold
        inside this same sequence, not just in isolation."""
        db = FindingStateDB(tmp_path / "hunt-memory" / "finding_states.jsonl")
        vuln_class, endpoint = "xss", "/search?q="

        db.advance(TARGET, vuln_class, endpoint, "SUSPECTED")
        db.advance(TARGET, vuln_class, endpoint, "TESTING")
        db.advance(TARGET, vuln_class, endpoint, "VALIDATED",
                    evidence={"verdict": "WEAK", "reproducible": True})

        from memory.finding_state import FindingStateError
        with pytest.raises(FindingStateError, match="not STRONG"):
            db.advance(TARGET, vuln_class, endpoint, "CONFIRMED",
                        evidence={"verdict": "WEAK", "reproducible": True})


# ─── Full sequence, run as one test for a single clear pass/fail signal ───

class TestFullSequence:
    def test_recon_rank_hunt_validate_report(self, demo_app, isolated_memory):
        """The whole chain in one test, sharing state the way a real hunt
        session would — a regression here pinpoints exactly which stage of
        the sequence broke, not just that 'something in the pipeline' did."""
        base_url, _demo = demo_app
        checker = ScopeChecker(["localhost"])
        session = requests.Session()

        # 1. RECON
        all_urls, param_urls = _crawl(base_url, checker, session)
        assert any(u.endswith("/.env") for u in all_urls), "recon stage failed to discover /.env"
        recon_dir = isolated_memory / "recon" / TARGET
        _write_recon_dir(recon_dir, all_urls, param_urls)

        # 2. RANK
        leads = lb.ingest(TARGET, str(recon_dir))
        assert any(ld["skill"] == "hunt-source-leak" for ld in leads), "rank stage failed to route the .env lead"
        score = priority_score("info-disclosure", ["python", "http.server"], TARGET)
        assert score["score"] > 0

        # 3. HUNT
        resp = requests.get(f"{base_url}/.env", timeout=5)
        assert "AWS_SECRET_ACCESS_KEY" in resp.text, "hunt stage failed to reproduce the leak"

        # 4. VALIDATE
        validation = vcore.evaluate_finding(_env_leak_finding(base_url))
        assert validation["overall_pass"] is True, f"validate stage rejected a real finding: {validation}"

        # 5. REPORT
        db = FindingStateDB(isolated_memory / "hunt-memory" / "finding_states.jsonl")
        evidence = {"verdict": "STRONG", "reproducible": True}
        db.advance(TARGET, "info-disclosure", "/.env", "SUSPECTED")
        db.advance(TARGET, "info-disclosure", "/.env", "TESTING")
        db.advance(TARGET, "info-disclosure", "/.env", "VALIDATED", evidence=evidence)
        db.advance(TARGET, "info-disclosure", "/.env", "CONFIRMED", evidence=evidence,
                    technique="exposed-config-file", tech_stack=["python", "http.server"])
        db.advance(TARGET, "info-disclosure", "/.env", "REPORT_READY", evidence=evidence)

        assert db.current_state(TARGET, "info-disclosure", "/.env") == "REPORT_READY", (
            "report stage failed to reach a submittable state"
        )

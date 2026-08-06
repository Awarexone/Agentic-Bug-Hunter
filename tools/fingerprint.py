#!/usr/bin/env python3
"""
Target Intelligence — Phase 3 fingerprinting.

Problem this solves: Phase 1 (browser_recon.py) and recon_engine.sh each
produce their own slice of tech-stack evidence (client-side framework
markers, httpx -tech-detect tags, cookie names, ...) but nothing merges them
into one place a hunter or the Research Director can read. This module's
whole job is CONSOLIDATION: it reads what already exists on disk under
recon/<target>/ and writes recon/<target>/fingerprint.json. It fills a gap
only where Phase 1 has none — server-side framework signals (Rails/Django/
Laravel/Spring/WordPress) that a browser-side crawl wouldn't catch, pulled
from recon_engine.sh's httpx -tech-detect output, which is already on disk.

NO NEW NETWORK CALLS. Every signal here is read from a file already on disk
under recon/<target>/ (and, best-effort, findings/bypass/*/waf_fingerprint.txt
if bypass_403.sh happened to already run for this target). Deterministic
only — no LLM guessing. If recon hasn't produced a given artifact, the
fields that would have come from it degrade to their null/unknown/empty
state; this module never fabricates a signal it doesn't have evidence for.

SCHEMA — recon/<target>/fingerprint.json:
{
  "target": str,
  "framework": str,                 # e.g. "nextjs" | "rails" | ... | "unknown"
  "version": str | null,
  "confidence": float,              # 0.0-1.0, see CONFIDENCE below
  "sources": [str, ...],            # artifacts that actually had usable data,
                                     # e.g. ["browser/routes.json", "live/httpx_full.txt"]
  "infra": {"cdn": str | null, "waf": str | null},
  "auth_model": {...} | null,       # verbatim Phase 1 browser/auth-model.json, or null
  "api_style": [str, ...],          # subset of {"graphql", "json"}
  "spa_framework": str | null,      # "nextjs" | "angular" | "react" | null
  "router_type": str | null,        # best-effort, only where provable — see _detect_router_type
  "cves": [{"id": str, "severity": str, "affected_versions": [str]}]
}

FRAMEWORK DETECTION — priority tiers. A lower tier only fills a gap a
higher tier left silent; it NEVER overrides a higher tier's answer.
  1. manifest/package.json  — no recon phase in this repo fetches this today.
     The tier exists in the priority ordering for when that changes; it is
     always silent right now. Documented gap, not a bug.
  2. browser/routes.json's "framework_detected" (Phase 1, real DOM/bundle
     detection: nextjs/angular/react/unknown).
  3. live/httpx_full.txt's -tech-detect output (recon_engine.sh, already on
     disk, zero new network calls) — a keyword scan for known server-side
     framework markers anywhere in the line. Heuristic, not a strict field
     parser: httpx's exact bracket layout isn't a stable contract across
     versions, and page-title text could coincidentally contain a marker
     word. Same accepted-false-positive tradeoff browser_recon.py's own
     route/role heuristics already document.
  4. browser/auth-model.json's cookie NAMES (e.g. laravel_session,
     connect.sid) — lowest-confidence tier, framework-convention cookie
     names are not a guarantee.

CONFIDENCE — derived from something real, not fabricated: (a) which tier
supplied the winning framework value, and (b) whether a second, independent,
lower tier names the same framework family.
    tier 2 win: 0.85 base   tier 3 win: 0.6 base   tier 4 win: 0.3 base
    tier 1 win: 0.95 base (unreachable today — no source feeds it yet)
    +0.10 if a lower tier corroborates the same framework, capped at 1.0
    no tier fires at all -> framework="unknown", confidence=0.0
This mirrors memory/vuln_intelligence.py's _recalibrated_impact(): a
static/heuristic prior that only ever gets more trust when independent real
evidence agrees, never a hand-waved number.

UNKNOWN STACK: when no tier fires, framework/version/confidence go to their
null/unknown/0.0 state, but infra/auth_model/api_style/spa_framework are
still populated from whatever Phase 1 data independently exists — framework
detection failing does not blank out unrelated signals.

tech_attack_matrix.json (tools/tech_attack_matrix.json) schema:
{"framework_name": {"version_ranges": [{"range": str, "vulns": [
  {"class": str, "weight": float, "cve": str|null, "citation": str|null}
]}]}}
`range` is either "*" (matches any version, including an unknown one) or a
comma-separated AND of "<op><dotted-version>" constraints (op in
>=, <=, >, <, ==, =). `weight` is 0-100, the same scale as
memory.vuln_intelligence.priority_score()'s technology_match component —
see _matrix_technology_match() there for how it plugs in as a cold-start
floor replacement, never a second formula. `cves` in THIS module's output
only ever contains matrix entries that carry a real, non-null `cve` id —
weight-only entries (no known CVE) inform priority_score() instead, they
are deliberately never surfaced as a fabricated "cves" record.

Pure library + thin CLI: no input(), no prompts, JSON in/out — same
convention as memory/vuln_intelligence.py and tools/director.py.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.recon_adapter import ReconAdapter  # noqa: E402
from tools.waf_response_analyzer import WAFSignatureDB  # noqa: E402
from memory.schemas import CURRENT_SCHEMA_VERSION, validate_target_profile  # noqa: E402

DEFAULT_MATRIX_PATH = str(Path(__file__).resolve().parent / "tech_attack_matrix.json")

# ─── Phase 1 / recon-engine readers — pure file I/O, no network ───────────


def _read_browser_json(recon_dir: str, name: str) -> dict | None:
    """Same safe-read convention as tools/director.py's _read_browser_json —
    duplicated here rather than imported since it's a 5-line private helper
    and fingerprint.py is a peer module, not a consumer of director.py."""
    p = Path(recon_dir) / "browser" / name
    if not p.exists():
        return None
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    return payload if isinstance(payload, dict) else None


def _read_httpx_full(recon_dir: str) -> str:
    """recon_engine.sh's httpx -tech-detect output (recon/<target>/live/
    httpx_full.txt) — already on disk after a normal recon run, zero new
    network calls. Empty string if recon never ran or the file is absent."""
    path = Path(recon_dir) / "live" / "httpx_full.txt"
    if not path.exists():
        return ""
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _load_bypass_waf_hint(target: str, bypass_dir: str = "findings/bypass") -> str | None:
    """Best-effort only: bypass_403.sh writes findings/bypass/<timestamp>/
    waf_fingerprint.txt with a `target=<target> waf=<name>` line IF it was
    ever run for this target. Pure glob + read of whatever already exists
    on disk — no new request. Returns None (the common case) if bypass_403
    never ran for this target."""
    base = Path(bypass_dir)
    if not base.is_dir():
        return None
    hint = None
    for p in sorted(base.glob("*/waf_fingerprint.txt")):
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = re.match(r"target=(\S+)\s+waf=(\S+)", line.strip())
            if m and m.group(1) == target:
                hint = m.group(2)
    return hint


# ─── Tier 2/3/4 framework detection ────────────────────────────────────────

_SPA_FRAMEWORKS = {"nextjs", "angular", "react"}

_FRAMEWORK_MARKERS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ruby\s*on\s*rails|\brails\b", re.I), "rails"),
    (re.compile(r"\bdjango\b", re.I), "django"),
    (re.compile(r"\blaravel\b", re.I), "laravel"),
    (re.compile(r"spring\s*boot|\bspring\b", re.I), "spring"),
    (re.compile(r"\bexpress\b", re.I), "express"),
    (re.compile(r"\bwordpress\b", re.I), "wordpress"),
    (re.compile(r"next\.?js", re.I), "nextjs"),
    (re.compile(r"\bangular\b", re.I), "angular"),
    (re.compile(r"\breact\b", re.I), "react"),
    (re.compile(r"\bflask\b", re.I), "flask"),
    (re.compile(r"asp\.net", re.I), "aspnet"),
]

_COOKIE_FRAMEWORK_MARKERS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"laravel_session", re.I), "laravel"),
    (re.compile(r"^django", re.I), "django"),
    (re.compile(r"^_rails_session|_session_id$", re.I), "rails"),
    (re.compile(r"^connect\.sid$", re.I), "express"),
    (re.compile(r"wordpress_logged_in|^wp-", re.I), "wordpress"),
]


def _framework_from_httpx_text(text: str) -> tuple[str | None, str | None]:
    """Keyword scan over recon_engine.sh's httpx -tech-detect output for a
    known framework marker anywhere in the line — see module docstring
    tier 3. Most-frequent marker wins (ties broken alphabetically for
    determinism). Version is extracted only when a `name:1.2.3`/`name
    v1.2.3`-shaped substring immediately follows the matched marker;
    otherwise None — never guessed."""
    counts: dict[str, int] = {}
    version_by_fw: dict[str, str] = {}
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        for pattern, fw in _FRAMEWORK_MARKERS:
            m = pattern.search(line)
            if not m:
                continue
            counts[fw] = counts.get(fw, 0) + 1
            if fw not in version_by_fw:
                vm = re.search(re.escape(m.group(0)) + r"[:/ ]?v?(\d+(?:\.\d+){0,3})", line, re.I)
                if vm:
                    version_by_fw[fw] = vm.group(1)
    if not counts:
        return None, None
    winner = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    return winner, version_by_fw.get(winner)


def _framework_from_cookies(auth_model: dict | None) -> str | None:
    if not auth_model:
        return None
    for cookie in auth_model.get("cookies", []) or []:
        name = cookie.get("name", "") if isinstance(cookie, dict) else ""
        for pattern, fw in _COOKIE_FRAMEWORK_MARKERS:
            if pattern.search(name or ""):
                return fw
    return None


_TIER_BASE_CONFIDENCE = {2: 0.85, 3: 0.6, 4: 0.3}


def _detect_framework(routes: dict | None, httpx_text: str, auth_model: dict | None) -> dict:
    tier2 = None
    if routes:
        fw = routes.get("framework_detected")
        if fw and fw != "unknown":
            tier2 = fw

    tier3, tier3_version = _framework_from_httpx_text(httpx_text)
    tier4 = _framework_from_cookies(auth_model)

    tiers = {2: tier2, 3: tier3, 4: tier4}
    winner_tier = next((t for t in (2, 3, 4) if tiers[t]), None)

    if winner_tier is None:
        return {"framework": "unknown", "version": None, "confidence": 0.0}

    framework = tiers[winner_tier]
    version = tier3_version if winner_tier == 3 else None

    corroborated = any(
        tiers[t] == framework for t in (2, 3, 4) if t != winner_tier and tiers[t] is not None
    )
    confidence = _TIER_BASE_CONFIDENCE[winner_tier] + (0.1 if corroborated else 0.0)
    return {"framework": framework, "version": version, "confidence": round(min(confidence, 1.0), 2)}


# ─── Infra (CDN/WAF) — reuses WAFSignatureDB, never reimplements it ────────

_CDN_VENDOR_NAMES = {"cloudflare", "akamai"}


def _detect_infra(httpx_text: str, bypass_hint: str | None) -> dict:
    """Cross-references recon_engine.sh's already-persisted httpx tech tags
    against tools/waf_response_analyzer.py's WAFSignatureDB vendor names —
    zero new network calls, and "call it, don't reimplement" honored by
    reusing that vendor list rather than hand-rolling a second one. Falls
    back to a bypass_403.sh waf_fingerprint.txt hint if present."""
    cdn = waf = None
    vendor_names = [v["name"] for v in WAFSignatureDB.VENDORS]
    lowered = re.sub(r"[-\s]", "", (httpx_text or "").lower())
    for name in vendor_names:
        marker = name.replace("-", "")
        if marker and marker in lowered:
            waf = waf or name
            if name in _CDN_VENDOR_NAMES:
                cdn = cdn or name
    if bypass_hint:
        waf = waf or bypass_hint
        if bypass_hint in _CDN_VENDOR_NAMES:
            cdn = cdn or bypass_hint
    return {"cdn": cdn, "waf": waf}


# ─── API style — reuses ReconAdapter's existing GraphQL heuristic ─────────

_GRAPHQL_URL_RE = re.compile(r"/graphql", re.I)


def _detect_api_style(recon_dir: str, api_calls: dict | None) -> list[str]:
    """"graphql" from ReconAdapter.get_graphql_endpoints() (reused, not
    reimplemented) plus a URL check over Phase 1's captured calls.  "json"
    only when a call's response_shape proves a JSON body was actually
    captured (on_response() in browser_recon.py only ever sets
    response_shape when content-type contained "json") — request-side
    content-type isn't persisted in api-calls.json (only auth header NAMES
    are), so a request-body-shaped "form" style can't be honestly recovered
    from this data and is deliberately not guessed."""
    styles: set[str] = set()
    if ReconAdapter(recon_dir).get_graphql_endpoints():
        styles.add("graphql")
    if api_calls:
        for call in api_calls.get("calls", []) or []:
            if not isinstance(call, dict):
                continue
            if _GRAPHQL_URL_RE.search(call.get("url", "") or ""):
                styles.add("graphql")
            resp_shape = call.get("response_shape")
            if isinstance(resp_shape, dict) and "_content_type" not in resp_shape:
                styles.add("json")
    return sorted(styles)


# ─── SPA framework / router type ───────────────────────────────────────────


def _detect_spa_framework(routes: dict | None) -> str | None:
    if not routes:
        return None
    fw = routes.get("framework_detected")
    return fw if fw in _SPA_FRAMEWORKS else None


def _detect_router_type(spa_framework: str | None) -> str | None:
    """Best-effort, only where the persisted signal actually proves it:
    - "angular": Angular ships exactly one first-party router, so detecting
      Angular at all safely implies "angular-router".
    - "nextjs": browser_recon.py's detect_framework() only ever returns
      "nextjs" via __NEXT_DATA__/__BUILD_MANIFEST/__SSG_MANIFEST markers,
      and all three are Pages Router-specific artifacts — App Router does
      not emit them. So whenever routes.json says "nextjs", it is Pages
      Router *by construction* of how Phase 1 itself detects it. An actual
      App Router app would currently fingerprint as framework="unknown"
      here rather than being misreported — a documented Phase 1 coverage
      gap, not a fabricated answer.
    - "react": routes.json's detect_framework() collapses "data-reactroot"
      (bare React) and a "react-router" bundle substring into the same
      "react" string — which one fired isn't recoverable from persisted
      data, so router_type stays None rather than guessing.
    """
    if spa_framework == "angular":
        return "angular-router"
    if spa_framework == "nextjs":
        return "pages-router"
    return None


# ─── Version-range matching (no external dependency) ──────────────────────


def _parse_version(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts) if parts else (0,)


def _cmp_versions(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a2 = a + (0,) * (n - len(a))
    b2 = b + (0,) * (n - len(b))
    return (a2 > b2) - (a2 < b2)


_RANGE_CONSTRAINT_RE = re.compile(r"^(>=|<=|==|=|>|<)\s*([\d.]+)$")
_OPS = {
    ">=": lambda c: c >= 0, "<=": lambda c: c <= 0,
    ">": lambda c: c > 0, "<": lambda c: c < 0,
    "==": lambda c: c == 0, "=": lambda c: c == 0,
}


def version_in_range(version: str | None, range_expr: str) -> bool:
    """"*" always matches, including an unknown (None) version — a
    version-independent vuln class applies regardless. Any concrete
    constraint range requires a known version to evaluate: with
    version=None there is no way to *prove* containment, so it fails
    closed (returns False) rather than guessing. A malformed constraint
    also fails closed. `range_expr` is a comma-separated AND of
    "<op><dotted-version>" constraints, op in >=, <=, >, <, ==, =."""
    range_expr = (range_expr or "").strip()
    if range_expr == "*":
        return True
    if version is None:
        return False
    v = _parse_version(version)
    for raw in range_expr.split(","):
        raw = raw.strip()
        if not raw:
            continue
        m = _RANGE_CONSTRAINT_RE.match(raw)
        if not m:
            return False
        op, bound_str = m.group(1), m.group(2)
        c = _cmp_versions(v, _parse_version(bound_str))
        if not _OPS[op](c):
            return False
    return True


def _severity_for_weight(weight: float) -> str:
    if weight >= 90:
        return "critical"
    if weight >= 70:
        return "high"
    if weight >= 40:
        return "medium"
    return "low"


def _match_cves(tag: str, version: str | None, matrix: dict) -> list[dict]:
    """Only matrix entries carrying a real, non-null `cve` id are surfaced
    here — weight-only entries (no known CVE) are a priority_score()
    signal, not a fabricated CVE record."""
    entry = matrix.get(tag) or matrix.get((tag or "").lower())
    if not entry:
        return []
    hits = []
    for vr in entry.get("version_ranges", []):
        rng = vr.get("range", "*")
        if not version_in_range(version, rng):
            continue
        for vuln in vr.get("vulns", []):
            cve = vuln.get("cve")
            if not cve:
                continue
            hits.append({
                "id": cve,
                "severity": _severity_for_weight(vuln.get("weight", 0)),
                "affected_versions": [rng],
            })
    return hits


# ─── Orchestration ──────────────────────────────────────────────────────────


def load_tech_attack_matrix(path: str = DEFAULT_MATRIX_PATH) -> dict:
    """Best-effort: missing/malformed file resolves to {} rather than
    raising — an empty matrix is a legitimate state (no CVE/weight data
    available yet), the same convention load_tech_stack() uses."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def build_fingerprint(
    target: str,
    recon_dir: str,
    tech_attack_matrix: dict | None = None,
    bypass_dir: str = "findings/bypass",
) -> dict:
    """Consolidates recon/<target>/browser/*.json (Phase 1) + recon/<target>/
    live/httpx_full.txt (recon_engine.sh) + a best-effort bypass_403.sh WAF
    hint into recon/<target>/fingerprint.json's shape. Never fetches
    anything; never raises on missing/malformed inputs."""
    routes = _read_browser_json(recon_dir, "routes.json")
    api_calls = _read_browser_json(recon_dir, "api-calls.json")
    auth_model = _read_browser_json(recon_dir, "auth-model.json")
    httpx_text = _read_httpx_full(recon_dir)
    bypass_hint = _load_bypass_waf_hint(target, bypass_dir)

    fw_result = _detect_framework(routes, httpx_text, auth_model)
    infra = _detect_infra(httpx_text, bypass_hint)
    api_style = _detect_api_style(recon_dir, api_calls)
    spa_framework = _detect_spa_framework(routes)
    router_type = _detect_router_type(spa_framework)

    sources = []
    if routes:
        sources.append("browser/routes.json")
    if api_calls:
        sources.append("browser/api-calls.json")
    if auth_model:
        sources.append("browser/auth-model.json")
    if httpx_text.strip():
        sources.append("live/httpx_full.txt")
    if bypass_hint:
        sources.append("findings/bypass/waf_fingerprint.txt")
    sources = sorted(set(sources))

    matrix = tech_attack_matrix or {}
    cve_tags = [t for t in (fw_result["framework"], spa_framework, *api_style) if t and t != "unknown"]
    cves: list[dict] = []
    seen_ids: set[str] = set()
    for tag in dict.fromkeys(cve_tags):
        version = fw_result["version"] if tag == fw_result["framework"] else None
        for c in _match_cves(tag, version, matrix):
            if c["id"] in seen_ids:
                continue
            seen_ids.add(c["id"])
            cves.append(c)

    return {
        "target": target,
        "framework": fw_result["framework"],
        "version": fw_result["version"],
        "confidence": fw_result["confidence"],
        "sources": sources,
        "infra": infra,
        "auth_model": auth_model,
        "api_style": api_style,
        "spa_framework": spa_framework,
        "router_type": router_type,
        "cves": cves,
    }


def write_fingerprint(recon_dir: str, fingerprint: dict) -> Path:
    out_path = Path(recon_dir) / "fingerprint.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(fingerprint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out_path


def sync_tech_stack(target: str, memory_dir: str, fingerprint: dict) -> dict:
    """Merges fingerprint.py's framework/spa_framework/api_style tags into
    memory_dir/targets/<target>.json's "tech_stack" field — the ONE place
    tools/director.py's load_tech_stack() reads (see that function's
    docstring). Not a new tech_stack source: same file, same schema
    (memory/schemas.py::validate_target_profile), same filename convention
    director.py's loader uses (raw f"{target}.json", unnormalized).

    Read-merge-write: every other field on an existing profile (findings,
    tested_endpoints, hunt_sessions, ...) is preserved untouched. A missing
    or malformed existing file starts a fresh minimal profile rather than
    raising — same best-effort convention load_tech_stack() itself uses."""
    path = Path(memory_dir) / "targets" / f"{target}.json"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    profile: dict = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                profile = loaded
        except (ValueError, OSError):
            profile = {}

    existing_stack = profile.get("tech_stack", [])
    if not isinstance(existing_stack, list):
        existing_stack = []

    new_tags = [
        t for t in (fingerprint.get("framework"), fingerprint.get("spa_framework"),
                    *(fingerprint.get("api_style") or []))
        if t and t != "unknown"
    ]
    profile["tech_stack"] = list(dict.fromkeys([*existing_stack, *new_tags]))

    profile.setdefault("target", target)
    profile.setdefault("first_hunted", now)
    profile["last_hunted"] = now
    profile["schema_version"] = CURRENT_SCHEMA_VERSION

    validated = validate_target_profile(profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(validated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return validated


# ─── CLI ────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase 3 — consolidate recon signals into recon/<target>/fingerprint.json"
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--recon-dir", default=None, help="default: recon/<target>")
    parser.add_argument("--memory-dir", default=None,
                         help="if given, also sync tech_stack into <memory-dir>/targets/<target>.json")
    parser.add_argument("--matrix", default=DEFAULT_MATRIX_PATH)
    parser.add_argument("--bypass-dir", default="findings/bypass")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    recon_dir = args.recon_dir or f"recon/{args.target}"
    matrix = load_tech_attack_matrix(args.matrix)
    fingerprint = build_fingerprint(args.target, recon_dir, matrix, args.bypass_dir)
    out_path = write_fingerprint(recon_dir, fingerprint)

    if args.memory_dir:
        sync_tech_stack(args.target, args.memory_dir, fingerprint)

    if not args.quiet:
        print(json.dumps(fingerprint, indent=2, sort_keys=True))
        print(f"\n-> {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

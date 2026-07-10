#!/usr/bin/env python3
"""
eol_check.py — Lifecycle / End-of-Life intel for a target's tech stack.

Looks up each detected technology against the public endoflife.date API and
reports whether the deployed software is still supported, in security-only
maintenance, nearing EOL, or already past it. Past-EOL software is a real,
verifiable finding (no security patches) — it slots into the recon/intel phase
and complements CVE lookup.

Design (matches this repo's tool ethos):
  * PURE STDLIB (urllib/json/ssl) — nothing to install, so it can never be the
    "missing dependency" that skips a scan.
  * PREFERS "indeterminate" OVER GUESSING. If a detected version cannot be
    matched to a specific lifecycle cycle, the result is `unknown` — the tool
    never classifies an install from an unrelated release, and never emits a
    [CONFIRMED] finding it cannot substantiate.
  * Degrades gracefully: outage / unknown product / malformed API or cache data
    returns `unknown` / `no_data`, never a crash.
  * No traffic is sent to the target — endoflife.date is a public metadata API.
  * Distinguishes standard EOL from extended/ESM support: a release past its
    normal `eol` date but still inside `extendedSupport` is reported as
    [POSSIBLE] "extended support", not [CONFIRMED] "no security fixes".
  * Findings carry the repo's confidence tags:
        past-EOL (no extended support) -> [CONFIRMED]
        EOL soon / extended-support / EOL-past-but-ESM -> [POSSIBLE]
        supported / security-only / unknown / no_data -> [INFORMATIONAL]

Credit: all lifecycle data is from https://endoflife.date/ (MIT licensed,
https://github.com/endoflife-date/endoflife.date). Please retain the credit
string when redistributing reports that include this output.

Usage:
    python3 tools/eol_check.py --tech "nginx=1.18,php=7.4,ubuntu=20.04" --target example.com
    python3 tools/eol_check.py --tech nextjs,tomcat --json out.json
    python3 tools/eol_check.py --tech "php=7.4" --strict     # exit 3 on indeterminate
    python3 tools/eol_check.py --list-products
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import ssl
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import date

ENDOFLIFE_BASE = "https://endoflife.date/api"
ENDOFLIFE_HOMEPAGE = "https://endoflife.date/"
ENDOFLIFE_CREDIT = (
    "Lifecycle data courtesy of endoflife.date "
    f"({ENDOFLIFE_HOMEPAGE}) — MIT licensed, please credit when redistributing."
)
CACHE_DIR = os.path.expanduser("~/.cache/bughunter/eol")
CACHE_TTL = 24 * 3600      # seconds
HTTP_TIMEOUT = 10          # per-request, seconds
MAX_BYTES = 4_000_000      # response-size cap (guards against a hostile/huge body)
EOL_SOON_DAYS = 90         # cycles within this window count as "support ending soon"

# Use the system trust store by default. Overriding it unconditionally with
# certifi (as an earlier draft did) can break enterprise CAs / TLS inspection —
# so we don't. On a host with a broken cert store the fetch degrades to
# `unknown`; operators can point urllib at a bundle via SSL_CERT_FILE.
_SSL_CTX = ssl.create_default_context()

# ── ANSI ─────────────────────────────────────────────────────────────────────
RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
CYAN = "\033[96m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"

# ── Confidence tags (repo convention) ────────────────────────────────────────
TAG_CONFIRMED = "[CONFIRMED]"
TAG_POSSIBLE = "[POSSIBLE]"
TAG_INFORMATIONAL = "[INFORMATIONAL]"

# Valid endoflife.date product slugs match this shape (verified against
# /api/all.json). Used to sanitize any slug before it touches a URL or the
# filesystem, so a hostile/library-supplied slug can't traverse paths.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
# Unicode categories that are hostile in a terminal / spoof an identifier:
# Cc control, Cf format (bidi/zero-width/BOM), Cs surrogate, Zl line-sep (U+2028),
# Zp para-sep (U+2029). We handle these by CATEGORY (not a char range) so exotic
# separators like U+2028 can't slip past a narrow regex, and so str.strip()
# canonicalization can't turn a malformed id into a real one.
_BAD_CATS = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_V_PREFIX_RE = re.compile(r"^[vV](?=\d)")            # leading 'v' before a digit
_ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")      # strict endoflife.date schema shape

# ── Tech fingerprint → endoflife.date product slug ───────────────────────────
# Keys are lowercased fingerprint terms (whatweb/httpx/wappalyzer style).
# Values are valid endoflife.date slugs (verified against /api/all.json).
# Deliberately omitted because a bare fingerprint is too ambiguous to place on a
# single product timeline (would risk a wrong-product EOL verdict):
#   iis          — no endoflife.date product; version space != Windows Server
#   powershell   — PowerShell 7.x and Windows PowerShell 5.1 are distinct products
#   java/openjdk — no vendor-neutral Java timeline; Oracle JDK / Temurin / Corretto
#                  / Zulu diverge, so a bare 'java' hit is left unresolved. Only
#                  vendor-specific fingerprints (temurin, corretto, zulu, …) resolve.
PRODUCT_MAP: dict[str, str] = {
    # Microsoft stack
    "asp.net": "dotnetfx", "aspnet": "dotnetfx", "asp.net core": "dotnet",
    "aspnetcore": "dotnet", ".net": "dotnet", ".net framework": "dotnetfx",
    "dotnet": "dotnet", "dotnetcore": "dotnet", "dotnetfx": "dotnetfx",
    "dotnetframework": "dotnetfx", "windows": "windows",
    "windows server": "windows-server", "windows-server": "windows-server",
    # Web servers
    "apache": "apache-http-server", "apache httpd": "apache-http-server",
    "httpd": "apache-http-server", "nginx": "nginx", "tomcat": "tomcat",
    "apache tomcat": "tomcat", "caddy": "caddy",
    # Languages / runtimes
    "php": "php", "python": "python", "node.js": "nodejs", "nodejs": "nodejs",
    "node": "nodejs", "ruby": "ruby", "perl": "perl", "go": "go", "golang": "go",
    "rust": "rust", "kotlin": "kotlin", "bun": "bun",
    # JDKs — vendor-specific only (generic java/openjdk intentionally unmapped)
    "oracle jdk": "oracle-jdk", "oracle-jdk": "oracle-jdk",
    "temurin": "eclipse-temurin", "eclipse temurin": "eclipse-temurin",
    "adoptium": "eclipse-temurin", "adoptopenjdk": "eclipse-temurin",
    "corretto": "amazon-corretto", "amazon corretto": "amazon-corretto",
    "zulu": "azul-zulu", "azul": "azul-zulu", "azul zulu": "azul-zulu",
    "microsoft openjdk": "microsoft-build-of-openjdk",
    "red hat openjdk": "redhat-build-of-openjdk",
    # Frameworks / CMS
    "wordpress": "wordpress", "drupal": "drupal", "phpbb": "phpbb",
    "phpmyadmin": "phpmyadmin", "rails": "rails", "ruby on rails": "rails",
    "django": "django", "laravel": "laravel", "symfony": "symfony",
    "cakephp": "cakephp", "next.js": "nextjs", "nextjs": "nextjs",
    "angular": "angular", "angularjs": "angularjs", "react": "react",
    "vue": "vue", "vue.js": "vue", "svelte": "svelte", "spring": "spring-framework",
    "spring boot": "spring-boot", "spring-boot": "spring-boot",
    "spring framework": "spring-framework", "spring security": "spring-security",
    "apache struts": "apache-struts", "struts": "apache-struts",
    # Databases / caches
    "mysql": "mysql", "mariadb": "mariadb", "postgresql": "postgresql",
    "postgres": "postgresql", "mongodb": "mongodb", "mongo": "mongodb",
    "redis": "redis", "elasticsearch": "elasticsearch", "kibana": "kibana",
    "logstash": "logstash", "cassandra": "apache-cassandra",
    "couchdb": "apache-couchdb", "rabbitmq": "rabbitmq", "kafka": "apache-kafka",
    # Linux distros
    "ubuntu": "ubuntu", "debian": "debian", "centos": "centos",
    "centos stream": "centos-stream", "rhel": "rhel", "redhat": "rhel",
    "red hat": "rhel", "rocky": "rocky-linux", "rocky linux": "rocky-linux",
    "alma": "almalinux", "almalinux": "almalinux", "alpine": "alpine-linux",
    "amazon linux": "amazon-linux", "amazon-linux": "amazon-linux",
    "amzn": "amazon-linux",
    # Cloud / orchestration / runtime
    "kubernetes": "kubernetes", "k8s": "kubernetes", "docker": "docker-engine",
    "openshift": "red-hat-openshift", "amazon eks": "amazon-eks",
    "azure aks": "azure-kubernetes-service", "amazon rds mysql": "amazon-rds-mysql",
    "amazon rds postgres": "amazon-rds-postgresql",
    "amazon aurora postgres": "amazon-aurora-postgresql", "aws lambda": "aws-lambda",
    # Mobile / desktop
    "android": "android", "ios": "ios", "macos": "macos",
}


# ── Slug / value sanitizers ──────────────────────────────────────────────────
def _sanitize_slug(slug):
    """Return a filesystem/URL-safe slug, or None if it is not a valid slug."""
    if not isinstance(slug, str):
        return None
    slug = slug.strip()
    if not SLUG_RE.match(slug) or slug != os.path.basename(slug):
        return None
    return slug


def _has_bad_char(s) -> bool:
    """True if the string contains any control/format/separator char (a char that
    str.strip() might canonicalize away, or that could spoof terminal output)."""
    return any(unicodedata.category(ch) in _BAD_CATS for ch in str(s))


def _strip_controls(s) -> str:
    return "".join(ch for ch in str(s) if unicodedata.category(ch) not in _BAD_CATS)


# ── Cache helpers (fail-soft: any cache error just disables caching) ──────────
def _cache_path(slug):
    slug = _sanitize_slug(slug)
    if slug is None:
        return None
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
    except OSError:
        return None
    return os.path.join(CACHE_DIR, f"{slug}.json")


def _load_cached(slug, ttl: int = CACHE_TTL):
    try:
        path = _cache_path(slug)
        if not path or not os.path.exists(path):
            return None
        if (time.time() - os.path.getmtime(path)) > ttl:
            return None
        if os.path.getsize(path) > MAX_BYTES:      # oversized/poisoned cache → miss
            return None
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError, RecursionError):   # ValueError covers JSONDecodeError
        return None
    return data if isinstance(data, list) else None


def _store_cached(slug, data) -> None:
    path = _cache_path(slug)
    if not path:
        return
    try:
        tmp = f"{path}.{os.getpid()}.tmp"    # per-process temp → no cross-writer race
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)                # atomic; no torn reads
    except (OSError, ValueError, TypeError, RecursionError):
        # Never let a cache-write failure (incl. json.dump recursing on deeply
        # nested junk, or a non-serializable value) crash the scan.
        try:
            os.path.exists(tmp) and os.remove(tmp)
        except OSError:
            pass


# ── HTTP fetch (pure stdlib) ─────────────────────────────────────────────────
def fetch_product_cycles(slug, refresh: bool = False):
    """Return the lifecycle cycles (list of dicts) for ``slug``, ``[]`` for an
    unknown product, or ``None`` on a hard network / bad-response error.
    Cached for CACHE_TTL seconds. Refuses a slug that is not a valid slug."""
    slug = _sanitize_slug(slug)
    if slug is None:
        return None
    if not refresh:
        cached = _load_cached(slug)
        if cached is not None:
            return cached
    url = f"{ENDOFLIFE_BASE}/{urllib.parse.quote(slug, safe='')}.json"
    req = urllib.request.Request(url, headers={
        "User-Agent": "bughunter-eolcheck/1.0 (+https://endoflife.date credited)",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_SSL_CTX) as resp:
            raw = resp.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return None                # implausibly large — treat as failure
        data = json.loads(raw.decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            _store_cached(slug, [])    # cache the negative
            return []
        return None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, RecursionError,
            http.client.HTTPException):
        return None                    # HTTPException: e.g. IncompleteRead on a truncated body;
                                       # RecursionError: pathologically nested JSON
    if not isinstance(data, list):     # rate-limit body / schema change / junk
        return None
    data = [c for c in data if isinstance(c, dict)]
    _store_cached(slug, data)
    return data


# ── Version matching (string-based; canonical cycle identifiers) ─────────────
def _clean_version(v) -> str:
    """Normalize a version for MATCHING. A control-bearing identifier is REFUSED
    (returns ""), never stripped-and-glued — else '7.\\n4' would masquerade as the
    real cycle '7.4' and fabricate a finding. Output escaping is a separate step
    (_strip_controls); normalization must not manufacture a valid identifier."""
    if not isinstance(v, str) or _has_bad_char(v):
        return ""                      # malformed / control-bearing → no match → 'unknown'
    v = _V_PREFIX_RE.sub("", v.strip())   # 'v7.4' -> '7.4'
    return v.lower()                   # case-insensitive ('22H2' == cycle '22h2')


def _match_cycle(cycles, version):
    """Match ``version`` to a cycle by canonical string, NOT lossy numerics.

    A cycle matches when the cleaned version equals the cycle id or extends it at
    a boundary ('.' or '-'). The longest matching cycle wins. If two *different*
    cycles tie on length the match is ambiguous → return None (never guess).
    Only string cycle ids are considered (a malformed int id is not coerced)."""
    cv = _clean_version(version)
    if not isinstance(cycles, list) or not cv:
        return None
    matches = []
    for c in cycles:
        if not isinstance(c, dict) or not isinstance(c.get("cycle"), str):
            continue
        raw = c["cycle"]
        if _has_bad_char(raw):         # control/separator-bearing id → don't normalize into a match
            continue
        cyc = raw.strip().lower()
        if not cyc:
            continue
        if cv == cyc or cv.startswith(cyc + ".") or cv.startswith(cyc + "-"):
            matches.append((len(cyc), cyc, c))
    if not matches:
        return None
    best_len = max(m[0] for m in matches)
    top = [m for m in matches if m[0] == best_len]
    if len(top) > 1:                   # distinct-cycle tie OR duplicate/conflicting ids → refuse
        return None
    return top[0][2]


# ── Classification ───────────────────────────────────────────────────────────
def _as_date(v):
    # date.fromisoformat accepts noncanonical forms ('20200101', ISO week dates);
    # require the exact endoflife.date 'YYYY-MM-DD' shape so a malformed date can't
    # substantiate a verdict.
    if isinstance(v, str) and _ISO_DATE_RE.fullmatch(v):
        try:
            return date.fromisoformat(v)
        except ValueError:
            return None
    return None


def _support_ended(support, today) -> bool:
    """True if active support has ended (a past date, or the boolean ``false``
    endoflife.date uses for 'no active-support phase / ended')."""
    if support is False:
        return True
    if support is True:
        return False
    sd = _as_date(support)
    return sd is not None and sd <= today


def _support_status(support, today):
    return "security_only" if _support_ended(support, today) else "supported"


def _classify(cycle: dict, today=None):
    """Return (status, days_to_eol). status ∈ supported / security_only / soon /
    extended / expired / unknown.

    Past-EOL degrades to a [POSSIBLE] 'extended' (not [CONFIRMED] 'expired') when
    extended/ESM support is either still in the future OR present-but-unparseable
    — we must not assert 'no security fixes' unless we can rule out ESM."""
    today = today or date.today()
    eol = cycle.get("eol")
    ext = cycle.get("extendedSupport")
    ext_date = _as_date(ext)
    # Identity checks (NOT ==): numeric 0/1 must not alias False/True. An ESM
    # value we can't interpret is 'indeterminate' → we can't rule out coverage.
    ext_indeterminate = (ext is not None and ext is not True and ext is not False
                         and ext_date is None)
    # '>= today' mirrors the eol convention (eol == today is not-yet-expired).
    ext_covers = (ext is True) or (ext_date is not None and ext_date >= today) or ext_indeterminate

    if eol is True:
        return ("extended", None) if ext_covers else ("expired", None)
    if eol is False:
        return (_support_status(cycle.get("support"), today), None)
    if isinstance(eol, str):
        eol_date = _as_date(eol)
        if eol_date is None:
            return ("unknown", None)
        days = (eol_date - today).days
        if days < 0:
            return ("extended", days) if ext_covers else ("expired", days)
        if days <= EOL_SOON_DAYS:
            return ("soon", days)
        return (_support_status(cycle.get("support"), today), days)
    return ("unknown", None)


def _tag_for_status(status: str) -> str:
    if status == "expired":
        return TAG_CONFIRMED
    if status in ("soon", "extended"):
        return TAG_POSSIBLE
    return TAG_INFORMATIONAL


def _san_str(v):
    """Control-strip a string field; any non-string (malformed composite) → None,
    so junk types can't be copied through into the JSON artifact."""
    return _strip_controls(v) if isinstance(v, str) else None


def _san_eol(v):
    """eol may legitimately be a bool; keep bools, sanitize strings, drop the rest."""
    if isinstance(v, bool):
        return v
    return _strip_controls(v) if isinstance(v, str) else None


def _resolve_slug(tech_term):
    if not isinstance(tech_term, str):
        return None
    key = tech_term.strip().lower()
    slug = PRODUCT_MAP.get(key)
    if slug:
        return slug
    key2 = re.sub(r"[ ._\-/]", "", key)
    for k, v in PRODUCT_MAP.items():
        if re.sub(r"[ ._\-/]", "", k) == key2:
            return v
    return None


_NOTE = {
    "extended": "standard support ended; extended/ESM may apply — verify entitlement",
    "security_only": "active support ended; security-maintenance only",
    "unknown": "version not matched to a lifecycle cycle",
}


def _base_result(tech, slug, version) -> dict:
    # Store display-sanitized tech/version so BOTH the report and the --json
    # artifact are free of control chars a downstream consumer might echo.
    return {
        "tech": _strip_controls(tech), "slug": slug,
        "version": _strip_controls(version) if isinstance(version, str) else version,
        "status": "no_data", "tag": TAG_INFORMATIONAL, "days_to_eol": None,
        "latest": None, "eol_date": None, "matched_cycle": None,
        "note": "", "credit": ENDOFLIFE_CREDIT,
    }


def _result_from_cycles(tech, slug, version, cycles) -> dict:
    """Core classification for a resolved slug + already-fetched cycles."""
    out = _base_result(tech, slug, version)
    if cycles is None:
        out["status"] = "unknown"
        out["note"] = "lookup failed (network/response error)"
        return out
    if not isinstance(cycles, list) or not cycles:
        return out                     # no_data
    if not version:
        out["status"] = "unknown"
        out["note"] = "no version supplied — cannot assess a specific release"
        first = cycles[0] if isinstance(cycles[0], dict) else {}
        out["latest"] = _san_str(first.get("latest"))
        return out
    cycle = _match_cycle(cycles, version)
    if cycle is None:
        out["status"] = "unknown"
        out["note"] = _NOTE["unknown"]
        return out
    status, days = _classify(cycle)
    note = _NOTE.get(status, "")
    # Preserve the secondary lifecycle fact: if the primary status is soon/extended/
    # expired but active support ALSO already ended, don't silently drop that.
    if status in ("soon", "extended") and _support_ended(cycle.get("support"), date.today()):
        note = (note + "; active support already ended").lstrip("; ")
    out.update({
        "status": status, "tag": _tag_for_status(status), "days_to_eol": days,
        "latest": _san_str(cycle.get("latest")), "eol_date": _san_eol(cycle.get("eol")),
        "matched_cycle": _san_str(cycle.get("cycle")), "note": note,
    })
    return out


# ── Public API ───────────────────────────────────────────────────────────────
def lookup(tech_term: str, version: str | None = None, refresh: bool = False) -> dict:
    """Resolve a fingerprint term (+optional version) to a lifecycle entry.

    status ∈ {supported, security_only, soon, extended, expired, unknown, no_data}.
    Never classifies from an unrelated cycle: an unmatched/absent version yields
    `unknown`, never a fabricated finding."""
    slug = _resolve_slug(tech_term)
    if slug is None:
        return _base_result(tech_term, None, version)
    cycles = fetch_product_cycles(slug, refresh=refresh)
    return _result_from_cycles(tech_term, slug, version, cycles)


def _parse_tech_arg(tech_arg: str):
    """'nginx=1.18,php=7.4,tomcat' -> [('nginx','1.18'),('php','7.4'),('tomcat',None)]"""
    out = []
    for item in tech_arg.split(","):
        item = item.strip(" \t")       # trim only ASCII spaces/tabs — NOT newlines /
        if not item:                   # exotic whitespace, so _clean_version can still
            continue                   # refuse a control-bearing version rather than
        if "=" in item:                # silently canonicalize it into a match.
            name, ver = item.split("=", 1)
            name = name.strip(" \t")
            if name:
                out.append((name, ver.strip(" \t") or None))
        else:
            out.append((item, None))
    return out


def check_eol(techs, refresh: bool = False) -> list:
    """techs: iterable of (name, version) pairs OR a 'name=ver,...' string.

    Fetches each product's cycles at most once per run (dedup by slug), then
    matches every requested version against the cached cycles."""
    if isinstance(techs, str):
        techs = _parse_tech_arg(techs)
    cycles_by_slug = {}
    results = []
    for name, version in techs:
        slug = _resolve_slug(name)
        if slug is None:
            results.append(_base_result(name, None, version))
            continue
        if slug not in cycles_by_slug:
            cycles_by_slug[slug] = fetch_product_cycles(slug, refresh=refresh)
        results.append(_result_from_cycles(name, slug, version, cycles_by_slug[slug]))
    return results


# ── Reporting ────────────────────────────────────────────────────────────────
_STATUS_COLOR = {"expired": RED, "extended": YELLOW, "soon": YELLOW,
                 "security_only": CYAN, "supported": GREEN,
                 "unknown": DIM, "no_data": DIM}
_STATUS_ORDER = {"expired": 0, "extended": 1, "soon": 2, "security_only": 3,
                 "unknown": 4, "supported": 5, "no_data": 6}


def _want_color(color) -> bool:
    if color is None:
        return bool(getattr(sys.stdout, "isatty", lambda: False)()) \
            and os.environ.get("NO_COLOR") is None
    return bool(color)


def format_eol_report(target: str, results: list, color=None) -> str:
    use = _want_color(color)

    def col(code, text):
        return f"{code}{text}{RESET}" if use else str(text)

    lines = [col(BOLD, "Lifecycle / EOL Status") + f" — {_strip_controls(target)}", ""]
    for r in sorted(results, key=lambda x: _STATUS_ORDER.get(x["status"], 9)):
        c = _STATUS_COLOR.get(r["status"], "")
        tech = _strip_controls(r.get("tech", ""))
        ver = f" {_strip_controls(r['version'])}" if r.get("version") else ""
        cyc = f" (cycle {_strip_controls(r['matched_cycle'])})" if r.get("matched_cycle") else ""
        days = ""
        d = r.get("days_to_eol")
        if isinstance(d, int):
            if r["status"] == "expired" or d < 0:
                days = f" — EOL {abs(d)}d ago"
            elif r["status"] in ("soon", "extended"):
                days = f" — EOL in {d}d"
        note = f"  [{_strip_controls(r['note'])}]" if r.get("note") else ""
        lines.append(f"  {r['tag']:<15} {col(c, tech + ver)}{cyc} :: "
                     f"{col(c, r['status'].upper())}{days}{note}")
    lines += ["", col(DIM, ENDOFLIFE_CREDIT)]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Lifecycle / EOL status for a target's tech stack (endoflife.date)")
    parser.add_argument("--tech", help="comma list, optional =version: 'nginx=1.18,php=7.4,tomcat'")
    parser.add_argument("--target", default="target", help="target label for the report header")
    parser.add_argument("--json", help="also write the raw results to this JSON path")
    parser.add_argument("--refresh", action="store_true", help="bust the 24h cache")
    parser.add_argument("--strict", action="store_true",
                        help="exit 3 if any item is indeterminate (unknown/no_data) so a "
                             "CI gate can tell 'checked, fine' from 'could not check'")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--list-products", action="store_true",
                        help="print the fingerprint→endoflife.date slug map and exit")
    args = parser.parse_args()

    if args.list_products:
        for k, v in sorted(PRODUCT_MAP.items()):
            print(f"  {k:<22} -> {v}")
        return 0
    if not args.tech:
        print("No --tech specified. "
              "Example: python3 tools/eol_check.py --tech nginx=1.18,php=7.4 --target example.com")
        return 1

    results = check_eol(args.tech, refresh=args.refresh)
    color = False if args.no_color else None
    print(format_eol_report(args.target, results, color=color))
    json_write_failed = False
    if args.json:
        safe_path = _strip_controls(args.json)     # never echo a raw control-laden path
        try:
            with open(args.json, "w") as f:
                json.dump({"target": _strip_controls(args.target), "results": results,
                           "credit": ENDOFLIFE_CREDIT}, f, indent=2)
            print(f"\nWrote {safe_path}")
        except (OSError, ValueError, TypeError, RecursionError) as e:
            json_write_failed = True
            print(f"Could not write {safe_path}: {e!r}", file=sys.stderr)

    # Exit codes let a caller gate: 2 = a CONFIRMED past-EOL item is present;
    # 3 = (strict) something was indeterminate so coverage is incomplete;
    # 1 = a requested --json artifact could not be written; else 0.
    if any(r["status"] == "expired" for r in results):
        return 2
    if args.strict and any(r["status"] in ("unknown", "no_data") for r in results):
        return 3
    if json_write_failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

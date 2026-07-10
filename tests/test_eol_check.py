"""Regression tests for tools/eol_check.py (lifecycle / EOL intel).

Network is mocked (fetch_product_cycles), so CI needs no outbound access and the
tests are deterministic. Dates are built relative to "today" so no test can rot.

The central contract these tests lock down: a lifecycle checker must prefer
"indeterminate" over guessing. It must NEVER classify a detected install from an
unrelated release, and must not overstate a standard EOL as "no security fixes"
when extended/ESM support still applies.
"""
import io
import os
import sys
from datetime import date, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import eol_check  # noqa: E402

# Capture the real fetch BEFORE the autouse fixture monkeypatches it, so the
# fetch-path test can exercise the genuine function (not the network mock).
_REAL_FETCH = eol_check.fetch_product_cycles


def _d(days_from_today):
    return (date.today() + timedelta(days=days_from_today)).strftime("%Y-%m-%d")


# Canned endoflife.date /api/<slug>.json payloads (relative dates → never rot).
def _php_cycles():
    return [
        {"cycle": "8.3", "support": _d(+400), "eol": _d(+900), "latest": "8.3.10"},
        {"cycle": "8.2", "support": _d(-30), "eol": _d(+300), "latest": "8.2.20"},   # security-only
        {"cycle": "7.4", "support": _d(-1200), "eol": _d(-900), "latest": "7.4.33"},  # long past EOL
    ]


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Default: unknown slug returns empty. Individual tests override."""
    monkeypatch.setattr(eol_check, "fetch_product_cycles", lambda slug, refresh=False: [])


def _use(monkeypatch, cycles):
    monkeypatch.setattr(eol_check, "fetch_product_cycles", lambda slug, refresh=False: cycles)


# ── No-fabrication contract (grok P0-1 / agy / codex #1) ─────────────────────
def test_past_eol_matched_is_confirmed(monkeypatch):
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "7.4")
    assert r["status"] == "expired"
    assert r["tag"] == eol_check.TAG_CONFIRMED
    assert r["matched_cycle"] == "7.4"


def test_supported_matched_is_informational(monkeypatch):
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "8.3")
    assert r["status"] == "supported"
    assert r["tag"] == eol_check.TAG_INFORMATIONAL


def test_unmatched_version_is_unknown_not_guessed(monkeypatch):
    # Version supplied but not present → MUST be unknown, never classified from
    # another cycle. This is the core anti-fabrication guarantee.
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "5.6")            # 5.6 not in the payload
    assert r["status"] == "unknown"
    assert r["matched_cycle"] is None
    assert r["tag"] == eol_check.TAG_INFORMATIONAL


def test_garbage_version_is_unknown(monkeypatch):
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "garbage")
    assert r["status"] == "unknown"
    assert r["tag"] == eol_check.TAG_INFORMATIONAL


def test_no_version_never_confirmed_even_if_newest_expired(monkeypatch):
    # If the newest cycle is itself EOL, a version-less lookup must still NOT
    # emit a CONFIRMED finding — we don't know what is deployed.
    _use(monkeypatch, [{"cycle": "1.0", "eol": True, "latest": "1.0.0"}])
    r = eol_check.lookup("nginx")                 # no version
    assert r["status"] == "unknown"
    assert r["tag"] != eol_check.TAG_CONFIRMED


# ── Version normalization / matching (grok P0-2 / codex #2) ──────────────────
def test_v_prefixed_version_matches(monkeypatch):
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "v7.4")           # banner-style 'v' prefix
    assert r["status"] == "expired"
    assert r["matched_cycle"] == "7.4"


def test_banner_form_version_matches(monkeypatch):
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "7.4.33")         # patch-level version
    assert r["matched_cycle"] == "7.4"


def test_longest_prefix_wins(monkeypatch):
    _use(monkeypatch, [
        {"cycle": "8", "eol": False, "latest": "8.9"},
        {"cycle": "8.1", "eol": _d(-500), "latest": "8.1.7"},
    ])
    r = eol_check.lookup("tomcat", "8.1.5")
    assert r["matched_cycle"] == "8.1"            # not the bare "8"


def test_boundary_prevents_8_3_matching_8_30(monkeypatch):
    # "8.30" must NOT be treated as cycle "8.3".
    _use(monkeypatch, [{"cycle": "8.3", "eol": _d(-500), "latest": "8.3.9"}])
    r = eol_check.lookup("php", "8.30")
    assert r["status"] == "unknown"
    assert r["matched_cycle"] is None


def test_mixed_identifier_cycles_do_not_cross_match(monkeypatch):
    # AWS-Lambda-style cycles: 'nodejs18.x' must never match 'ruby4.0'.
    _use(monkeypatch, [
        {"cycle": "ruby4.0", "eol": _d(-100), "latest": "ruby4.0"},
        {"cycle": "nodejs18.x", "eol": _d(-100), "latest": "nodejs18.x"},
    ])
    r = eol_check.lookup("aws lambda", "nodejs18.x")
    assert r["matched_cycle"] in (None, "nodejs18.x")
    if r["matched_cycle"] == "nodejs18.x":
        assert r["status"] == "expired"           # matched the RIGHT one
    else:
        assert r["status"] == "unknown"           # or honestly unknown


def test_eol_boolean_true_is_expired(monkeypatch):
    _use(monkeypatch, [{"cycle": "5.6", "eol": True, "latest": "5.6.40"}])
    r = eol_check.lookup("php", "5.6")
    assert r["status"] == "expired"
    assert r["tag"] == eol_check.TAG_CONFIRMED


# ── Extended / active support semantics (codex #4 / #5) ──────────────────────
def test_extended_support_softens_confirmed(monkeypatch):
    # Standard EOL passed but ESM/extended support is still in the future →
    # must NOT be a bare CONFIRMED "no security fixes".
    _use(monkeypatch, [{"cycle": "20.04", "support": _d(-800),
                        "eol": _d(-30), "extendedSupport": _d(+1000),
                        "latest": "20.04.6"}])
    r = eol_check.lookup("ubuntu", "20.04")
    assert r["status"] == "extended"
    assert r["tag"] == eol_check.TAG_POSSIBLE      # not CONFIRMED


def test_extended_support_in_past_is_still_expired(monkeypatch):
    _use(monkeypatch, [{"cycle": "16.04", "support": _d(-2000),
                        "eol": _d(-1000), "extendedSupport": _d(-100),
                        "latest": "16.04.7"}])
    r = eol_check.lookup("ubuntu", "16.04")
    assert r["status"] == "expired"
    assert r["tag"] == eol_check.TAG_CONFIRMED


def test_active_support_ended_is_security_only(monkeypatch):
    # eol still in the future but active support ended → security-maintenance.
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "8.2")
    assert r["status"] == "security_only"
    assert r["tag"] == eol_check.TAG_INFORMATIONAL


def test_eol_within_window_is_soon(monkeypatch):
    _use(monkeypatch, [{"cycle": "1.0", "support": _d(-10), "eol": _d(+30),
                        "latest": "1.0.9"}])
    r = eol_check.lookup("nginx", "1.0")
    assert r["status"] == "soon"
    assert r["tag"] == eol_check.TAG_POSSIBLE
    assert 0 <= r["days_to_eol"] <= eol_check.EOL_SOON_DAYS
    # active support already ended → that secondary fact must not be silently
    # dropped just because 'soon' is the primary severity.
    assert "support" in r["note"].lower()


def test_eol_yesterday_reports_one_day(monkeypatch):
    # Date-based math (codex #13): EOL yesterday → 1 day ago, not 2.
    _use(monkeypatch, [{"cycle": "1.0", "eol": _d(-1), "latest": "1.0.0"}])
    r = eol_check.lookup("nginx", "1.0")
    assert r["status"] == "expired"
    assert r["days_to_eol"] == -1


# ── Slug map correctness (grok P0-5 / codex #3, primary-source verified) ─────
def test_all_product_slugs_are_slug_shaped():
    # Guards against typos / accidental bad slugs on future edits.
    import re
    pat = re.compile(r"^[a-z0-9][a-z0-9-]*$")
    bad = [v for v in set(eol_check.PRODUCT_MAP.values()) if not pat.match(v)]
    assert bad == [], f"non-slug-shaped values: {bad}"


def test_fixed_slugs_are_corrected():
    # openshift was live-verified as renamed; iis/powershell have no single product.
    assert eol_check._resolve_slug("openshift") == "red-hat-openshift"
    assert eol_check._resolve_slug("iis") is None          # dropped, not fabricated
    assert eol_check._resolve_slug("powershell") is None   # ambiguous 5.1 vs 7.x


def test_generic_java_is_unresolved_vendor_specific_resolves():
    # A bare 'java'/'openjdk' fingerprint cannot be placed on one vendor's
    # timeline (Oracle vs Temurin vs Corretto diverge) → unresolved, not guessed.
    assert eol_check._resolve_slug("java") is None
    assert eol_check._resolve_slug("openjdk") is None
    # Vendor-specific fingerprints DO resolve.
    assert eol_check._resolve_slug("temurin") == "eclipse-temurin"
    assert eol_check._resolve_slug("amazon corretto") == "amazon-corretto"
    assert eol_check._resolve_slug("azul zulu") == "azul-zulu"
    assert eol_check._resolve_slug("oracle jdk") == "oracle-jdk"


def test_tolerant_slug_resolution():
    assert eol_check._resolve_slug("Node.JS") == "nodejs"
    assert eol_check._resolve_slug("spring-boot") == "spring-boot"


def test_unknown_product_is_no_data():
    r = eol_check.lookup("definitelynotarealproduct")
    assert r["slug"] is None
    assert r["status"] == "no_data"
    assert r["tag"] == eol_check.TAG_INFORMATIONAL


# ── Robustness / never-crash (grok P1-6 / agy #3 / codex #6-7) ───────────────
def test_network_outage_degrades_to_unknown(monkeypatch):
    monkeypatch.setattr(eol_check, "fetch_product_cycles", lambda slug, refresh=False: None)
    r = eol_check.lookup("nginx", "1.18")
    assert r["status"] == "unknown"


def test_non_list_payload_does_not_crash(monkeypatch):
    # A dict / string top-level (rate-limit body, schema change) must not crash.
    for bad in ({"message": "rate limited"}, "oops", [None, "x", 5]):
        monkeypatch.setattr(eol_check, "fetch_product_cycles",
                            lambda slug, refresh=False, _b=bad: _b)
        r = eol_check.lookup("php", "7.4")
        assert r["status"] in ("unknown", "no_data")   # degraded, no exception


def test_cache_path_rejects_traversal():
    # Path-traversal slug must not escape CACHE_DIR (grok/agy/codex/me).
    p = eol_check._cache_path("../../../etc/passwd")
    assert p is None or os.path.realpath(p).startswith(
        os.path.realpath(eol_check.CACHE_DIR) + os.sep)


def test_fetch_rejects_bad_slug():
    # A bad slug must be refused before any URL/filesystem use. fetch_product_cycles
    # gates on _sanitize_slug (the autouse fixture mocks the fetch itself, so we
    # assert the real guard directly).
    assert eol_check._sanitize_slug("../evil") is None
    assert eol_check._sanitize_slug("../../etc/passwd") is None
    assert eol_check._sanitize_slug("red-hat-openshift") == "red-hat-openshift"


# ── Output safety (grok P3 / agy / codex #9) ─────────────────────────────────
def test_report_strips_control_characters(monkeypatch):
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "7.4\x1b[2Jinjected\n")
    out = eol_check.format_eol_report("target", [r], color=False)
    assert "\x1b" not in out
    assert "\n" in out                       # newlines between lines are fine
    assert "injected" in out                 # text kept, control chars gone


def test_no_color_output_has_no_ansi(monkeypatch):
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "7.4")
    out = eol_check.format_eol_report("t", [r], color=False)
    assert "\033[" not in out


# ── Dedup / memoize (codex #10) ──────────────────────────────────────────────
def test_check_eol_dedups_repeated_lookups(monkeypatch):
    calls = {"n": 0}

    def counting(slug, refresh=False):
        calls["n"] += 1
        return _php_cycles()
    monkeypatch.setattr(eol_check, "fetch_product_cycles", counting)
    results = eol_check.check_eol("php=7.4,php=7.4,php=8.3")
    assert len(results) == 3
    assert calls["n"] == 1                   # one fetch for the single 'php' slug


# ── CLI exit codes (codex #8) ────────────────────────────────────────────────
def _run_main(monkeypatch, argv, cycles):
    monkeypatch.setattr(sys, "argv", ["eol_check.py"] + argv)
    monkeypatch.setattr(eol_check, "fetch_product_cycles", lambda slug, refresh=False: cycles)
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    return eol_check.main()


def test_exit_2_when_confirmed_present(monkeypatch):
    rc = _run_main(monkeypatch, ["--tech", "php=7.4", "--no-color"], _php_cycles())
    assert rc == 2


def test_exit_0_when_all_supported(monkeypatch):
    rc = _run_main(monkeypatch, ["--tech", "php=8.3", "--no-color"], _php_cycles())
    assert rc == 0


def test_strict_exit_3_on_indeterminate(monkeypatch):
    # --strict lets a CI gate distinguish "checked, all fine" from "couldn't check".
    rc = _run_main(monkeypatch, ["--tech", "php=5.6", "--no-color", "--strict"], _php_cycles())
    assert rc == 3


def test_credit_string_is_present():
    r = eol_check.lookup("nginx")
    assert "endoflife.date" in r["credit"]


# ── Boolean 'support' field (endoflife.date allows bool or date) ─────────────
def test_boolean_support_false_is_security_only(monkeypatch):
    # support:false + a future eol → active support ended, security-only.
    _use(monkeypatch, [{"cycle": "1.0", "support": False, "eol": _d(+300),
                        "latest": "1.0.0"}])
    r = eol_check.lookup("nginx", "1.0")
    assert r["status"] == "security_only"
    assert r["tag"] == eol_check.TAG_INFORMATIONAL


def test_boolean_support_true_is_supported(monkeypatch):
    _use(monkeypatch, [{"cycle": "2.0", "support": True, "eol": _d(+300),
                        "latest": "2.0.0"}])
    r = eol_check.lookup("nginx", "2.0")
    assert r["status"] == "supported"


# ── Exit-code default contract (documents the deliberate lenient default) ────
def test_default_indeterminate_exits_zero_by_design(monkeypatch):
    # Without --strict, an unmatched/indeterminate result is NOT an error exit —
    # a deliberate, documented default (use --strict for a fail-closed CI gate).
    rc = _run_main(monkeypatch, ["--tech", "php=5.6", "--no-color"], _php_cycles())
    assert rc == 0


# ── --json output must be control-char clean too (not just the terminal) ─────
def test_json_output_sanitizes_version(monkeypatch, tmp_path):
    out_json = tmp_path / "out.json"
    monkeypatch.setattr(sys, "argv",
                        ["eol_check.py", "--tech", "php=7.4\x1b[2Jx", "--no-color",
                         "--json", str(out_json)])
    monkeypatch.setattr(eol_check, "fetch_product_cycles",
                        lambda slug, refresh=False: _php_cycles())
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    eol_check.main()
    import json as _json
    parsed = _json.loads(out_json.read_text())          # what a consumer recovers
    versions = [r.get("version") or "" for r in parsed["results"]]
    assert all("\x1b" not in v and "\n" not in v for v in versions)


def test_report_strips_bidi_override(monkeypatch):
    # RTL/bidi override chars are terminal-spoofing nuisances — strip them too.
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "7.4‮gnp.exe")
    out = eol_check.format_eol_report("t", [r], color=False)
    assert "‮" not in out


# ── Anti-fabrication hardening (codex confirmation pass) ─────────────────────
def test_control_char_version_is_not_fabricated(monkeypatch):
    # '7.\n4' must NOT be stripped-and-glued into '7.4' and matched as CONFIRMED.
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "7.\n4")
    assert r["status"] == "unknown"
    assert r["tag"] != eol_check.TAG_CONFIRMED
    assert r["matched_cycle"] is None


def test_non_string_cycle_id_is_ignored(monkeypatch):
    # A malformed cycle whose id is an int must not be stringified into a match.
    _use(monkeypatch, [{"cycle": 74, "eol": True, "latest": "7.4"}])
    r = eol_check.lookup("php", "74")
    assert r["status"] in ("unknown", "no_data")
    assert r["tag"] != eol_check.TAG_CONFIRMED


def test_malformed_extended_support_is_not_confirmed(monkeypatch):
    # Past eol + an UNPARSEABLE extendedSupport: we cannot prove ESM is absent,
    # so we must NOT emit a hard [CONFIRMED] "no security fixes".
    _use(monkeypatch, [{"cycle": "1.0", "eol": _d(-30),
                        "extendedSupport": "not-a-date", "latest": "1.0.0"}])
    r = eol_check.lookup("nginx", "1.0")
    assert r["tag"] != eol_check.TAG_CONFIRMED


def test_case_insensitive_cycle_match(monkeypatch):
    # Banner form '10-22H2' must match the API's lowercase cycle '10-22h2'.
    _use(monkeypatch, [{"cycle": "10-22h2", "eol": _d(-30), "latest": "10.0"}])
    r = eol_check.lookup("windows", "10-22H2")
    assert r["matched_cycle"] == "10-22h2"
    assert r["status"] == "expired"


def test_strict_with_expired_and_unknown_prioritizes_confirmed(monkeypatch):
    # A CONFIRMED finding (exit 2) outranks indeterminate (exit 3) — documented.
    rc = _run_main(monkeypatch, ["--tech", "php=7.4,php=5.6", "--no-color", "--strict"],
                   _php_cycles())
    assert rc == 2


# ── Real fetch path (mock urlopen, not the whole function) ───────────────────
def test_fetch_real_path_guards(monkeypatch, tmp_path):
    import urllib.request
    monkeypatch.setattr(eol_check, "CACHE_DIR", str(tmp_path))   # never touch real cache

    class _Resp:
        def __init__(self, body):
            self._b = body.encode()
        def read(self, n=-1):
            return self._b
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    # non-list top-level body → None (degrade, no crash), never cached as data.
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: _Resp('{"message":"rate limited"}'))
    assert _REAL_FETCH("nginx", refresh=True) is None

    # malformed JSON → None.
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp("{not json"))
    assert _REAL_FETCH("nginx", refresh=True) is None

    # a valid list of dicts → returned.
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: _Resp('[{"cycle":"1.0","eol":true}]'))
    got = _REAL_FETCH("nginx", refresh=True)
    assert got == [{"cycle": "1.0", "eol": True}]


# ── Round-3 hardening (codex final pass) ─────────────────────────────────────
def test_control_bearing_cycle_id_is_ignored(monkeypatch):
    # A malformed API/cache cycle id with a control char must not be
    # strip-normalized into a match (mirror of the version-side guard).
    _use(monkeypatch, [{"cycle": "7.4\n", "eol": True, "latest": "7.4"}])
    r = eol_check.lookup("php", "7.4")
    assert r["status"] in ("unknown", "no_data")
    assert r["tag"] != eol_check.TAG_CONFIRMED


def test_numeric_extended_support_is_not_confirmed(monkeypatch):
    # extendedSupport as 0/1 (== False/True by value) must use identity checks;
    # an unrecognized ESM type is indeterminate → NOT a hard CONFIRMED.
    for weird in (0, 1, [], {}):
        _use(monkeypatch, [{"cycle": "1.0", "eol": _d(-30),
                            "extendedSupport": weird, "latest": "1.0.0"}])
        r = eol_check.lookup("nginx", "1.0")
        assert r["tag"] != eol_check.TAG_CONFIRMED, f"weird ESM {weird!r} → CONFIRMED"


def test_extended_support_ending_today_is_covered(monkeypatch):
    # ESM ending exactly today is still covered (consistent with eol-today being
    # not-yet-expired) → 'extended', not 'expired'.
    _use(monkeypatch, [{"cycle": "1.0", "eol": _d(-30),
                        "extendedSupport": _d(0), "latest": "1.0.0"}])
    r = eol_check.lookup("nginx", "1.0")
    assert r["status"] == "extended"
    assert r["tag"] != eol_check.TAG_CONFIRMED


def test_duplicate_conflicting_cycles_are_ambiguous(monkeypatch):
    # Two records with the same canonical id but conflicting data → refuse.
    _use(monkeypatch, [{"cycle": "7.4", "eol": True, "latest": "7.4"},
                       {"cycle": "7.4", "eol": False, "latest": "7.4"}])
    r = eol_check.lookup("php", "7.4")
    assert r["status"] == "unknown"
    assert r["matched_cycle"] is None


def test_incomplete_read_degrades_not_crash(monkeypatch, tmp_path):
    import http.client
    import urllib.request
    monkeypatch.setattr(eol_check, "CACHE_DIR", str(tmp_path))

    class _Resp:
        def read(self, n=-1):
            raise http.client.IncompleteRead(b"partial")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp())
    assert _REAL_FETCH("nginx", refresh=True) is None      # caught, no crash


def test_json_sanitizes_api_derived_fields(monkeypatch, tmp_path):
    out_json = tmp_path / "o.json"
    _use(monkeypatch, [{"cycle": "1.0", "eol": _d(-30), "latest": "1.0\x1b[2J"}])
    monkeypatch.setattr(sys, "argv",
                        ["eol_check.py", "--tech", "nginx=1.0", "--no-color",
                         "--json", str(out_json)])
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    eol_check.main()
    import json as _json
    parsed = _json.loads(out_json.read_text())
    for r in parsed["results"]:
        for field in ("latest", "matched_cycle", "eol_date"):
            v = r.get(field)
            if isinstance(v, str):
                assert "\x1b" not in v


def test_resolve_slug_none_is_safe():
    # Library-misuse guard: a non-string term must not raise.
    assert eol_check._resolve_slug(None) is None
    assert eol_check._resolve_slug(1234) is None


def test_unicode_separator_in_cycle_id_is_ignored(monkeypatch):
    # U+2028 (Zl) is whitespace to str.strip() but must not canonicalize a
    # malformed cycle '7.4 ' into a '7.4' match.
    _use(monkeypatch, [{"cycle": "7.4 ", "eol": True, "latest": "7.4"}])
    r = eol_check.lookup("php", "7.4")
    assert r["tag"] != eol_check.TAG_CONFIRMED
    assert r["matched_cycle"] is None


def test_unicode_separator_in_version_is_rejected(monkeypatch):
    _use(monkeypatch, _php_cycles())
    r = eol_check.lookup("php", "7.4 ")
    assert r["status"] == "unknown"
    assert r["tag"] != eol_check.TAG_CONFIRMED


def test_cli_trailing_control_version_not_fabricated(monkeypatch):
    # A control that survives arg-splitting must still be refused, not stripped
    # into a bare '7.4' match.
    rc = _run_main(monkeypatch, ["--tech", "php=7.4\n", "--no-color"], _php_cycles())
    assert rc == 0                       # not exit 2 (no CONFIRMED minted)


def test_noncanonical_date_is_not_authoritative(monkeypatch):
    # date.fromisoformat accepts '20200101' / '2020-W01-1'; a malformed eol in a
    # non-schema format must NOT substantiate a [CONFIRMED] verdict.
    _use(monkeypatch, [{"cycle": "1.0", "eol": "20200101", "latest": "1.0.0"}])
    r = eol_check.lookup("nginx", "1.0")
    assert r["status"] == "unknown"
    assert r["tag"] != eol_check.TAG_CONFIRMED


def test_oversized_cache_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(eol_check, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(eol_check, "MAX_BYTES", 2000)
    big = tmp_path / "nginx.json"
    big.write_text("[" + ",".join('{"cycle":"1.0"}' for _ in range(500)) + "]")
    assert eol_check._load_cached("nginx") is None      # over cap → treated as miss


def test_nonstring_latest_is_nulled(monkeypatch):
    # A malformed non-string 'latest' must not be copied through into results.
    _use(monkeypatch, [{"cycle": "1.0", "eol": _d(+900),
                        "latest": {"build": "1.0\x1b[2J"}}])
    r = eol_check.lookup("nginx", "1.0")
    assert r["latest"] is None


def test_cache_write_recursion_degrades_not_crash(monkeypatch, tmp_path):
    # json.dump of a pathologically nested payload raises RecursionError; the
    # cache write must fail SOFT (never crash the scan) — mirrors the load path.
    monkeypatch.setattr(eol_check, "CACHE_DIR", str(tmp_path))

    def boom(*a, **k):
        raise RecursionError("too deep")
    monkeypatch.setattr(eol_check.json, "dump", boom)
    eol_check._store_cached("nginx", [{"cycle": "1.0"}])     # must not raise


def test_json_write_failure_returns_one(monkeypatch, tmp_path):
    # A requested --json artifact that cannot be written must not exit 0.
    unwritable = tmp_path / "nodir" / "o.json"          # parent doesn't exist
    monkeypatch.setattr(sys, "argv",
                        ["eol_check.py", "--tech", "php=8.3", "--no-color",
                         "--json", str(unwritable)])
    monkeypatch.setattr(eol_check, "fetch_product_cycles",
                        lambda slug, refresh=False: _php_cycles())
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    assert eol_check.main() == 1

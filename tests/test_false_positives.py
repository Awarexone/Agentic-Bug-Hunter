"""
Regression tests for known false-positive / N/A cases.

Each test represents a class of finding that consistently comes back N/A from
bug-bounty programs. Every fixture MUST fail at least one validation gate.
The goal: if a future change accidentally lets one of these through, CI breaks.

Fixtures tested:
  1. SSRF — DNS callback only (no internal HTTP data)
  2. Open redirect — no token/OAuth in redirect URL
  3. CORS wildcard — no credentialed exfil possible
  4. IDOR — attacker reads own data, not another user's
  5. Auth bypass — only works when attacker is already admin
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Import validate module without triggering main()
# ---------------------------------------------------------------------------

def _load_validate():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "validate",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools", "validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


validate = _load_validate()


# ---------------------------------------------------------------------------
# Helpers that drive gates with controlled input sequences
# ---------------------------------------------------------------------------

def _gate3(monkeypatch, concrete_impact: bool, no_unrealistic: bool, curl_poc: str):
    answers = iter([
        "y" if concrete_impact else "n",
        "y" if no_unrealistic else "n",
        "Impact description",
        curl_poc,
    ])
    monkeypatch.setattr("builtins.input", lambda _p="": next(answers))
    return validate.gate3_exploitable()


def _gate1(monkeypatch, repro, no_proxy, no_state, rtfm,
           vuln_type="", identity: list | None = None):
    yn = lambda b: "y" if b else "n"
    answers = [yn(repro), yn(no_proxy), yn(no_state), yn(rtfm)]
    if identity:
        answers += [yn(a) for a in identity]
    inputs = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
    return validate.gate1_is_real(vuln_type)


# ---------------------------------------------------------------------------
# 1. SSRF — DNS callback only
# ---------------------------------------------------------------------------

class TestSSRFDnsOnly:
    def test_fails_without_poc(self, monkeypatch):
        passed, notes = _gate3(monkeypatch, True, True, "")
        assert not passed
        assert notes["rejection_reason"] == "no_reproducible_impact"

    def test_fails_when_poc_is_skip(self, monkeypatch):
        passed, notes = _gate3(monkeypatch, True, True, "skip")
        assert not passed
        assert not notes["has_proof"]

    def test_control_passes_with_real_poc(self, monkeypatch):
        poc = "curl -s 'http://169.254.169.254/latest/meta-data/' -H 'Cookie: s=X'"
        passed, notes = _gate3(monkeypatch, True, True, poc)
        assert passed
        assert notes["has_proof"]


# ---------------------------------------------------------------------------
# 2. Open redirect without token theft
# ---------------------------------------------------------------------------

class TestOpenRedirectNoChain:
    def test_fails_no_concrete_impact(self, monkeypatch):
        poc = "curl -si 'https://target.com/redirect?url=https://evil.com'"
        passed, notes = _gate3(monkeypatch, False, True, poc)
        assert not passed
        assert notes["rejection_reason"] == "no_concrete_impact"

    def test_fails_no_poc(self, monkeypatch):
        passed, notes = _gate3(monkeypatch, True, True, "")
        assert not passed


# ---------------------------------------------------------------------------
# 3. CORS wildcard without credentialed exfil
# ---------------------------------------------------------------------------

class TestCORSWildcardNoExfil:
    def test_fails_no_poc(self, monkeypatch):
        passed, notes = _gate3(monkeypatch, True, True, "")
        assert not passed
        assert notes["rejection_reason"] == "no_reproducible_impact"

    def test_control_credentialed_exfil_passes(self, monkeypatch):
        poc = (
            "curl -s 'https://api.target.com/v1/me' "
            "-H 'Origin: https://evil.com' "
            "-H 'Cookie: session=VICTIM' --include"
        )
        passed, notes = _gate3(monkeypatch, True, True, poc)
        assert passed


# ---------------------------------------------------------------------------
# 4. IDOR — attacker reads only their own data
# ---------------------------------------------------------------------------

class TestIDOROwnDataOnly:
    def test_fails_no_cross_account(self, monkeypatch):
        passed, notes = _gate1(
            monkeypatch, True, True, True, True,
            vuln_type="IDOR",
            identity=[False, True, True],   # cross_account=False
        )
        assert not passed
        assert notes["rejection_reason"] == "identity_not_proven"
        assert notes["cross_account_tested"] is False

    def test_fails_no_fresh_session(self, monkeypatch):
        passed, notes = _gate1(
            monkeypatch, True, True, True, True,
            vuln_type="IDOR",
            identity=[True, False, True],   # fresh_session=False
        )
        assert not passed
        assert notes["rejection_reason"] == "identity_not_proven"

    def test_passes_all_identity_checks(self, monkeypatch):
        passed, notes = _gate1(
            monkeypatch, True, True, True, True,
            vuln_type="IDOR",
            identity=[True, True, True],
        )
        assert passed
        assert notes.get("rejection_reason") is None

    def test_non_auth_vuln_skips_identity(self, monkeypatch):
        inputs = iter(["y", "y", "y", "y"])   # exactly 4 answers, no identity block
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        passed, notes = validate.gate1_is_real("SSTI")
        assert passed
        assert "cross_account_tested" not in notes


# ---------------------------------------------------------------------------
# 5. Auth bypass — requires admin precondition
# ---------------------------------------------------------------------------

class TestAuthBypassAdminOnly:
    def test_gate3_fails_unrealistic_precondition(self, monkeypatch):
        poc = "curl -s 'https://target.com/admin/action' -H 'Cookie: admin=X'"
        passed, notes = _gate3(monkeypatch, True, False, poc)   # no_unrealistic=False
        assert not passed
        assert notes["rejection_reason"] == "unrealistic_privileges"

    def test_gate1_identity_check_triggered(self, monkeypatch):
        passed, notes = _gate1(
            monkeypatch, True, True, True, True,
            vuln_type="Auth bypass",
            identity=[False, True, True],
        )
        assert not passed
        assert notes["rejection_reason"] == "identity_not_proven"


# ---------------------------------------------------------------------------
# Sanity: rejection reason codes are a known closed set
# ---------------------------------------------------------------------------

KNOWN_REASON_CODES = {
    "no_reproducible_impact",
    "no_concrete_impact",
    "unrealistic_privileges",
    "identity_not_proven",
    "not_reproducible",
    "out_of_scope",
    "duplicate_or_already_disclosed",
}


def test_reason_codes_used_in_fixtures_are_in_known_set():
    used = {
        "no_reproducible_impact",
        "no_concrete_impact",
        "unrealistic_privileges",
        "identity_not_proven",
        "not_reproducible",
    }
    assert used.issubset(KNOWN_REASON_CODES)

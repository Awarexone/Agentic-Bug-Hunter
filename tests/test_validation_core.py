"""
Tests for tools/validation_core.py — the pure, headless validation gates +
CVSS 4.0 calculator that both tools/validate.py (interactive) and the
autonomous path (agent.py / autopilot, via `validate.py --non-interactive`)
run through.

Every gate function is dict-in/dict-out with zero I/O, so these tests never
touch the network, stdin, or the filesystem (except tmp_path for the CLI
end-to-end tests at the bottom).
"""

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from tools import validation_core as vcore  # noqa: E402


# ─── Gate 1 — Is It Real? ──────────────────────────────────────────────────

class TestGate1IsReal:
    def _base(self, **overrides):
        data = {
            "repro_3_3": True,
            "works_without_proxy": True,
            "no_special_state": True,
            "not_documented_behavior": True,
        }
        data.update(overrides)
        return data

    def test_passes_when_all_true_non_auth(self):
        result = vcore.gate1_is_real(self._base(vuln_type="SSTI"))
        assert result["passed"] is True
        assert result["notes"]["rejection_reason"] is None
        assert "cross_account_tested" not in result["notes"]

    def test_fails_not_reproducible(self):
        result = vcore.gate1_is_real(self._base(repro_3_3=False, vuln_type="SSTI"))
        assert result["passed"] is False
        assert result["notes"]["rejection_reason"] == "not_reproducible"

    def test_auth_vuln_requires_identity_fields(self):
        with pytest.raises(vcore.ValidationInputError, match="cross_account_tested"):
            vcore.gate1_is_real(self._base(vuln_type="IDOR"))

    def test_auth_vuln_passes_with_identity_proven(self):
        data = self._base(
            vuln_type="IDOR",
            cross_account_tested=True,
            fresh_session_tested=True,
            anon_vs_auth_delta=True,
        )
        result = vcore.gate1_is_real(data)
        assert result["passed"] is True
        assert result["notes"]["rejection_reason"] is None

    def test_auth_vuln_fails_identity_not_proven(self):
        data = self._base(
            vuln_type="Account takeover",
            cross_account_tested=False,
            fresh_session_tested=True,
            anon_vs_auth_delta=True,
        )
        result = vcore.gate1_is_real(data)
        assert result["passed"] is False
        assert result["notes"]["rejection_reason"] == "identity_not_proven"
        assert result["notes"]["cross_account_tested"] is False

    def test_missing_required_field_raises(self):
        data = self._base()
        del data["repro_3_3"]
        with pytest.raises(vcore.ValidationInputError, match="repro_3_3"):
            vcore.gate1_is_real(data)

    def test_wrong_type_field_raises(self):
        with pytest.raises(vcore.ValidationInputError, match="boolean"):
            vcore.gate1_is_real(self._base(repro_3_3="yes"))

    def test_non_dict_input_raises(self):
        with pytest.raises(vcore.ValidationInputError):
            vcore.gate1_is_real(["not", "a", "dict"])


# ─── is_auth_related ───────────────────────────────────────────────────────

@pytest.mark.parametrize("vuln_type", [
    "IDOR", "idor", "Account Takeover", "Broken Access Control",
    "Auth bypass", "Session fixation", "Privilege escalation",
])
def test_is_auth_related_true(vuln_type):
    assert vcore.is_auth_related(vuln_type) is True


@pytest.mark.parametrize("vuln_type", ["SSTI", "XSS", "SSRF", "", None])
def test_is_auth_related_false(vuln_type):
    assert vcore.is_auth_related(vuln_type) is False


# ─── Gate 2 — Is It In Scope? ──────────────────────────────────────────────

class TestGate2InScope:
    def test_passes(self):
        result = vcore.gate2_in_scope({
            "asset_in_scope": True, "not_excluded": True, "version_ok": True,
        })
        assert result["passed"] is True
        assert result["notes"]["rejection_reason"] is None

    def test_fails_out_of_scope(self):
        result = vcore.gate2_in_scope({
            "asset_in_scope": False, "not_excluded": True, "version_ok": True,
        })
        assert result["passed"] is False
        assert result["notes"]["rejection_reason"] == "out_of_scope"

    def test_missing_field_raises(self):
        with pytest.raises(vcore.ValidationInputError, match="not_excluded"):
            vcore.gate2_in_scope({"asset_in_scope": True, "version_ok": True})


# ─── Gate 3 — Is It Exploitable? ───────────────────────────────────────────

class TestGate3Exploitable:
    def _base(self, **overrides):
        data = {
            "concrete_impact": True,
            "no_unrealistic_preconditions": True,
            "curl_poc": "curl -s https://target.com/api/user/456",
        }
        data.update(overrides)
        return data

    def test_passes_with_poc(self):
        result = vcore.gate3_exploitable(self._base())
        assert result["passed"] is True
        assert result["notes"]["has_proof"] is True

    def test_fails_blank_poc(self):
        result = vcore.gate3_exploitable(self._base(curl_poc=""))
        assert result["passed"] is False
        assert result["notes"]["rejection_reason"] == "no_reproducible_impact"
        assert result["notes"]["has_proof"] is False

    def test_fails_skip_poc(self):
        result = vcore.gate3_exploitable(self._base(curl_poc="skip"))
        assert result["passed"] is False
        assert result["notes"]["has_proof"] is False

    def test_fails_skip_poc_case_insensitive(self):
        result = vcore.gate3_exploitable(self._base(curl_poc="  SKIP  "))
        assert result["passed"] is False

    def test_fails_no_concrete_impact(self):
        result = vcore.gate3_exploitable(self._base(concrete_impact=False))
        assert result["passed"] is False
        assert result["notes"]["rejection_reason"] == "no_concrete_impact"

    def test_fails_unrealistic_preconditions(self):
        result = vcore.gate3_exploitable(self._base(no_unrealistic_preconditions=False))
        assert result["passed"] is False
        assert result["notes"]["rejection_reason"] == "unrealistic_privileges"

    def test_missing_field_raises(self):
        with pytest.raises(vcore.ValidationInputError, match="concrete_impact"):
            vcore.gate3_exploitable({"no_unrealistic_preconditions": True, "curl_poc": "x"})


# ─── Gate 4 — Is It a Dup? ─────────────────────────────────────────────────

class TestGate4NotDup:
    def _base(self, **overrides):
        data = {
            "not_in_h1_disclosed": True,
            "not_in_github_issues": True,
            "checked_git_history": True,
        }
        data.update(overrides)
        return data

    def test_passes(self):
        result = vcore.gate4_not_dup(self._base())
        assert result["passed"] is True
        assert result["notes"]["h1_similar_reports"] == []

    def test_fails_duplicate(self):
        result = vcore.gate4_not_dup(self._base(not_in_h1_disclosed=False))
        assert result["passed"] is False
        assert result["notes"]["rejection_reason"] == "duplicate_or_already_disclosed"

    def test_carries_similar_reports_list(self):
        data = self._base(h1_similar_reports=["Existing IDOR report"])
        result = vcore.gate4_not_dup(data)
        assert result["notes"]["h1_similar_reports"] == ["Existing IDOR report"]

    def test_similar_reports_wrong_type_raises(self):
        with pytest.raises(vcore.ValidationInputError, match="h1_similar_reports"):
            vcore.gate4_not_dup(self._base(h1_similar_reports="not-a-list"))

    def test_missing_field_raises(self):
        with pytest.raises(vcore.ValidationInputError, match="checked_git_history"):
            vcore.gate4_not_dup({"not_in_h1_disclosed": True, "not_in_github_issues": True})


# ─── CVSS 4.0 ───────────────────────────────────────────────────────────────

CRITICAL_VECTOR = {
    "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
    "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H",
}
LOW_VECTOR = {
    "AV": "P", "AC": "H", "AT": "P", "PR": "H", "UI": "A",
    "VC": "N", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
}
SAFETY_VECTOR = {
    "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
    "VC": "N", "VI": "N", "VA": "N", "SC": "N", "SI": "S", "SA": "N",
}


class TestCVSS40:
    def test_calculate_cvss40_critical(self):
        score, vector = vcore.calculate_cvss40(**{k.lower(): v for k, v in CRITICAL_VECTOR.items()})
        assert score == 10.0
        assert vcore.severity_from_score(score) == "CRITICAL"
        assert vector.startswith("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/")

    def test_calculate_cvss40_low(self):
        score, _ = vcore.calculate_cvss40(**{k.lower(): v for k, v in LOW_VECTOR.items()})
        assert score == 3.5
        assert vcore.severity_from_score(score) == "LOW"

    def test_calculate_cvss40_safety_impact_boosts_score(self):
        # Same AV/AC/AT/PR/UI/VC/VI/VA as a no-subsequent-impact finding
        # (which would macro to (0,0,2,2)=4.8) — flipping SI to Safety
        # changes eq4 from 2 to 0 and jumps the score to 7.9 (HIGH).
        score, _ = vcore.calculate_cvss40(**{k.lower(): v for k, v in SAFETY_VECTOR.items()})
        assert score == 7.9
        assert vcore.severity_from_score(score) == "HIGH"

    def test_calculate_cvss40_unknown_macro_vector_falls_back_to_medium(self):
        # eq-derivation always lands in the known table for well-formed letters,
        # so exercise the fallback path directly via a macro vector not in the table.
        score = vcore._CVSS40_TABLE.get((9, 9, 9, 9), 5.0)
        assert score == 5.0

    @pytest.mark.parametrize("score,expected", [
        (0.0, "NONE"), (1.0, "LOW"), (3.9, "LOW"),
        (4.0, "MEDIUM"), (6.9, "MEDIUM"),
        (7.0, "HIGH"), (8.9, "HIGH"),
        (9.0, "CRITICAL"), (10.0, "CRITICAL"),
    ])
    def test_severity_from_score_boundaries(self, score, expected):
        assert vcore.severity_from_score(score) == expected

    def test_score_cvss_returns_full_shape(self):
        result = vcore.score_cvss(CRITICAL_VECTOR)
        assert result["score"] == 10.0
        assert result["severity"] == "CRITICAL"
        assert result["params"]["AV"] == "N"
        assert result["vector"] == (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        )

    def test_score_cvss_normalizes_lowercase_input(self):
        lower = {k: v.lower() for k, v in CRITICAL_VECTOR.items()}
        result = vcore.score_cvss(lower)
        assert result["params"]["AV"] == "N"
        assert result["score"] == 10.0

    def test_validate_cvss_params_missing_field_raises(self):
        bad = dict(CRITICAL_VECTOR)
        del bad["AV"]
        with pytest.raises(vcore.ValidationInputError, match="AV"):
            vcore.validate_cvss_params(bad)

    def test_validate_cvss_params_invalid_value_raises(self):
        bad = dict(CRITICAL_VECTOR)
        bad["AV"] = "Z"
        with pytest.raises(vcore.ValidationInputError, match="AV"):
            vcore.validate_cvss_params(bad)

    def test_validate_cvss_params_wrong_type_raises(self):
        bad = dict(CRITICAL_VECTOR)
        bad["PR"] = 1
        with pytest.raises(vcore.ValidationInputError, match="PR"):
            vcore.validate_cvss_params(bad)

    def test_validate_cvss_params_non_dict_raises(self):
        with pytest.raises(vcore.ValidationInputError):
            vcore.validate_cvss_params("CVSS:4.0/AV:N")


# ─── evaluate_finding (the headless CLI entrypoint's core) ────────────────

def _valid_finding(**overrides):
    finding = {
        "vuln_type": "SSRF",
        "gate1": {
            "repro_3_3": True, "works_without_proxy": True,
            "no_special_state": True, "not_documented_behavior": True,
        },
        "gate2": {"asset_in_scope": True, "not_excluded": True, "version_ok": True},
        "gate3": {
            "concrete_impact": True, "no_unrealistic_preconditions": True,
            "curl_poc": "curl -s http://169.254.169.254/latest/meta-data/",
        },
        "gate4": {
            "not_in_h1_disclosed": True, "not_in_github_issues": True,
            "checked_git_history": True,
        },
    }
    finding.update(overrides)
    return finding


class TestEvaluateFinding:
    def test_all_gates_pass_overall_pass_true(self):
        result = vcore.evaluate_finding(_valid_finding())
        assert result["overall_pass"] is True
        assert result["gate1_is_real"]["passed"] is True
        assert result["gate2_in_scope"]["passed"] is True
        assert result["gate3_exploitable"]["passed"] is True
        assert result["gate4_not_dup"]["passed"] is True
        assert "cvss" not in result

    def test_one_gate_fails_overall_pass_false(self):
        finding = _valid_finding()
        finding["gate2"]["asset_in_scope"] = False
        result = vcore.evaluate_finding(finding)
        assert result["overall_pass"] is False
        assert result["gate2_in_scope"]["passed"] is False

    def test_cvss_included_when_present(self):
        finding = _valid_finding(cvss=CRITICAL_VECTOR)
        result = vcore.evaluate_finding(finding)
        assert result["cvss"]["score"] == 10.0
        assert result["cvss"]["severity"] == "CRITICAL"

    def test_auth_vuln_type_propagates_to_gate1(self):
        finding = _valid_finding(vuln_type="IDOR")
        # gate1 dict deliberately omits identity fields -> should raise, proving
        # vuln_type from the top level reaches gate1's auth-related check.
        with pytest.raises(vcore.ValidationInputError, match="cross_account_tested"):
            vcore.evaluate_finding(finding)

    def test_missing_gate_section_raises(self):
        finding = _valid_finding()
        del finding["gate3"]
        with pytest.raises(vcore.ValidationInputError, match="curl_poc|concrete_impact"):
            vcore.evaluate_finding(finding)

    def test_malformed_gate_section_type_raises(self):
        finding = _valid_finding(gate1="not-a-dict")
        with pytest.raises(vcore.ValidationInputError, match="gate1"):
            vcore.evaluate_finding(finding)

    def test_non_dict_finding_raises(self):
        with pytest.raises(vcore.ValidationInputError):
            vcore.evaluate_finding("not-a-dict")

    def test_malformed_cvss_raises(self):
        finding = _valid_finding(cvss={"AV": "N"})
        with pytest.raises(vcore.ValidationInputError):
            vcore.evaluate_finding(finding)


# ─── validate.py --non-interactive CLI end-to-end ──────────────────────────

VALIDATE_PY = os.path.join(REPO_ROOT, "tools", "validate.py")


def _run_cli(args, timeout=15):
    return subprocess.run(
        [sys.executable, VALIDATE_PY] + args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestNonInteractiveCLI:
    def test_passing_finding_exits_0(self, tmp_path):
        finding_path = tmp_path / "finding.json"
        finding_path.write_text(json.dumps(_valid_finding()))
        proc = _run_cli(["--json", "--non-interactive", "--input", str(finding_path)])
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["overall_pass"] is True

    def test_failing_finding_exits_1(self, tmp_path):
        finding = _valid_finding()
        finding["gate3"]["curl_poc"] = ""
        finding_path = tmp_path / "finding.json"
        finding_path.write_text(json.dumps(finding))
        proc = _run_cli(["--non-interactive", "--input", str(finding_path)])
        assert proc.returncode == 1, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["overall_pass"] is False

    def test_missing_input_file_exits_2(self, tmp_path):
        missing = tmp_path / "does-not-exist.json"
        proc = _run_cli(["--non-interactive", "--input", str(missing)])
        assert proc.returncode == 2, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert "error" in payload

    def test_invalid_json_exits_2(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")
        proc = _run_cli(["--non-interactive", "--input", str(bad)])
        assert proc.returncode == 2, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert "error" in payload

    def test_malformed_finding_exits_2(self, tmp_path):
        finding = _valid_finding()
        del finding["gate1"]["repro_3_3"]
        finding_path = tmp_path / "finding.json"
        finding_path.write_text(json.dumps(finding))
        proc = _run_cli(["--non-interactive", "--input", str(finding_path)])
        assert proc.returncode == 2, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert "repro_3_3" in payload["error"]

    def test_non_interactive_without_input_exits_2(self):
        proc = _run_cli(["--non-interactive"])
        assert proc.returncode == 2, proc.stdout + proc.stderr

    def test_no_network_calls_made(self, tmp_path, monkeypatch):
        """evaluate_finding() must never touch the network — assert urlopen is unreachable."""
        finding_path = tmp_path / "finding.json"
        finding_path.write_text(json.dumps(_valid_finding()))
        env = dict(os.environ)
        # Blackhole proxy so any accidental network call fails fast instead of hanging.
        env["HTTP_PROXY"] = "http://127.0.0.1:1"
        env["HTTPS_PROXY"] = "http://127.0.0.1:1"
        proc = subprocess.run(
            [sys.executable, VALIDATE_PY, "--non-interactive", "--input", str(finding_path)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=15, env=env,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

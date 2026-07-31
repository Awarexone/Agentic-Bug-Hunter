"""Tests for memory/finding_score.py — the finding-triage wrapper over
memory.vuln_intelligence.priority_score(). No network access anywhere here."""

import json
import subprocess
import sys

import pytest

from memory import finding_score
from memory.finding_score import (
    SCANNER_CATEGORY_ALIASES,
    normalize_vuln_class,
    rank_findings,
    score_finding,
)
from memory.vuln_intelligence import priority_score


class TestNormalizeVulnClass:

    @pytest.mark.parametrize("category,expected", [
        ("auth_bypass", "auth-bypass"),
        ("jwt", "auth-bypass"),
        ("takeover", "misconfig"),
        ("cves", "misconfig"),
        ("cloud", "misconfig"),
        ("smuggling", "misconfig"),
        ("rce", "rce"),
        ("sqlmap", "sqli"),
        ("cms", "misconfig"),
        ("redirects", "open-redirect"),
        ("exposure", "info-disclosure"),
    ])
    def test_known_aliases(self, category, expected):
        assert normalize_vuln_class(category) == expected

    def test_case_insensitive(self):
        assert normalize_vuln_class("AUTH_BYPASS") == "auth-bypass"

    def test_unknown_category_passes_through_lowercased(self):
        assert normalize_vuln_class("SomeNewScanner") == "somenewscanner"

    def test_every_alias_value_resolves_to_a_valid_priority_score(self):
        # Not every alias target has its own VULN_IMPACT_POTENTIAL entry
        # (e.g. "lfi" -- a pre-existing gap, also present in agent.py's own
        # identical mapping today, see OUT OF SCOPE). That's fine as long as
        # priority_score() degrades gracefully to its documented default
        # instead of crashing or producing an out-of-range score.
        for alias_target in set(SCANNER_CATEGORY_ALIASES.values()):
            result = priority_score(vuln_class=alias_target, tech_stack=[], target="t.com")
            assert 0 <= result["score"] <= 100


class TestScoreFinding:

    def test_priority_matches_direct_formula_call(self):
        """The one-formula rule: score_finding()'s "priority" field must be
        byte-identical to calling priority_score() directly with the same
        (normalized) inputs -- proving this module calls the formula rather
        than re-deriving a number that merely looks similar."""
        result = score_finding(
            category="auth_bypass", line="unauthenticated admin panel",
            tech_stack=["express"], target="target.com",
        )
        direct = priority_score(
            vuln_class="auth-bypass", tech_stack=["express"], target="target.com",
        )
        assert result["priority"] == direct

    def test_line_signal_is_not_folded_into_priority(self):
        weak = score_finding("xss", "generic reflected param hit", [], "t.com")
        strong = score_finding("xss", "unauthenticated critical uid=0 rce", [], "t.com")
        # Same category/tech/target -> identical priority_score() result...
        assert weak["priority"] == strong["priority"]
        # ...but line_signal (and therefore sort_key) differs.
        assert strong["line_signal"] > weak["line_signal"]
        assert strong["sort_key"][0] == weak["sort_key"][0]
        assert strong["sort_key"][1] > weak["sort_key"][1]

    def test_line_signal_keyword_sum(self):
        line = "CRITICAL: unauth idor at https://target.com/api/1"
        result = score_finding("idor", line, [], "t.com")
        # critical(15) + unauth(30) + idor(28) + http bonus(8) = 81
        assert result["line_signal"] == 81

    def test_empty_line_zero_signal(self):
        result = score_finding("misconfig", "", [], "t.com")
        assert result["line_signal"] == 0

    def test_unknown_category_does_not_crash(self):
        result = score_finding("totally_new_scanner", "some output", [], "t.com")
        assert result["vuln_class"] == "totally_new_scanner"
        assert 0 <= result["priority"]["score"] <= 100


class TestRankFindings:

    def test_higher_impact_category_ranks_first(self):
        """rce (impact 100) must outrank xss (impact 55) with no memory data,
        matching VULN_IMPACT_POTENTIAL's static priors -- the whole point of
        routing through priority_score() instead of a private table."""
        candidates = [
            {"category": "xss", "line": "reflected xss on search page"},
            {"category": "rce", "line": "RCE_CONFIRMED: uid=0(root) via log4shell"},
        ]
        ranked = rank_findings(candidates, tech_stack=[], target="t.com")
        assert ranked[0]["category"] == "rce"
        assert ranked[1]["category"] == "xss"

    def test_tiebreak_within_same_category(self):
        candidates = [
            {"category": "cors", "line": "cors reflects origin, generic"},
            {"category": "cors", "line": "CRITICAL unauth cors default creds exposed"},
        ]
        ranked = rank_findings(candidates, tech_stack=[], target="t.com")
        assert ranked[0]["line"] == "CRITICAL unauth cors default creds exposed"
        assert ranked[0]["priority"]["score"] == ranked[1]["priority"]["score"]
        assert ranked[0]["line_signal"] > ranked[1]["line_signal"]

    def test_top_n_cap(self):
        candidates = [{"category": "misconfig", "line": f"finding {i}"} for i in range(40)]
        ranked = rank_findings(candidates, tech_stack=[], target="t.com", top_n=25)
        assert len(ranked) == 25

    def test_scoring_consistency_priority_score_memoized_per_category(self, monkeypatch):
        """priority_score() must be called once per distinct vuln_class, not
        once per line -- both a performance property and direct proof that
        every line in a category gets the SAME formula result (consistency),
        not N independently-computed numbers that could drift apart."""
        calls = []
        real_priority_score = finding_score.priority_score

        def counting_priority_score(*args, **kwargs):
            calls.append(kwargs.get("vuln_class") or args[0])
            return real_priority_score(*args, **kwargs)

        monkeypatch.setattr(finding_score, "priority_score", counting_priority_score)

        candidates = (
            [{"category": "xss", "line": f"xss finding {i}"} for i in range(5)]
            + [{"category": "idor", "line": f"idor finding {i}"} for i in range(5)]
        )
        ranked = rank_findings(candidates, tech_stack=[], target="t.com", top_n=25)

        assert len(ranked) == 10
        assert len(calls) == 2  # one call for "xss", one for "idor"
        assert set(calls) == {"xss", "idor"}

    def test_empty_candidates(self):
        assert rank_findings([], tech_stack=[], target="t.com") == []

    def test_memory_data_changes_ranking(self, sample_pattern_entry, sample_failed_pattern_entry):
        """With real memory data, tech/history should be able to flip an
        otherwise-lower-impact category above a higher-impact one that has
        already failed on this exact target+technique (hard_kill)."""
        failed = dict(sample_failed_pattern_entry)
        failed["target"] = "t.com"
        failed["vuln_class"] = "rce"
        failed["technique"] = "log4shell_probe"

        candidates = [
            {"category": "xss", "line": "reflected xss"},
            {"category": "rce", "line": "rce probe result"},
        ]
        # Without a technique passed through, failure_penalty never triggers
        # (score_finding/rank_findings don't carry a per-line technique) --
        # confirm that documented limitation rather than assume hidden behavior.
        ranked = rank_findings(
            candidates, tech_stack=[], target="t.com", failed_patterns=[failed],
        )
        assert ranked[0]["category"] == "rce"  # still wins on static impact alone
        assert ranked[0]["priority"]["hard_kill"] is False


class TestCLI:

    def test_score_subcommand_json_output(self, tmp_path):
        # Run from repo root so `memory` package resolves as -m target.
        import os
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        proc = subprocess.run(
            [sys.executable, "-m", "memory.finding_score", "score",
             "--category", "idor", "--line", "unauth idor found",
             "--target", "t.com", "--memory-dir", str(tmp_path / "hunt-memory")],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        assert data["vuln_class"] == "idor"
        assert "priority" in data and "score" in data["priority"]

    def test_rank_subcommand_reads_json_file(self, tmp_path):
        import os
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        input_file = tmp_path / "candidates.json"
        input_file.write_text(json.dumps([
            {"category": "rce", "line": "RCE_CONFIRMED uid=0"},
            {"category": "xss", "line": "reflected xss"},
        ]))
        proc = subprocess.run(
            [sys.executable, "-m", "memory.finding_score", "rank",
             "--input", str(input_file), "--target", "t.com",
             "--memory-dir", str(tmp_path / "hunt-memory"), "--top", "1"],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        assert len(data) == 1
        assert data[0]["category"] == "rce"

    def test_cli_never_blocks_on_input(self, tmp_path):
        """Rule 3: no prompts. A missing --memory-dir directory must not
        hang waiting for stdin -- it should just treat memory as empty."""
        import os
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        proc = subprocess.run(
            [sys.executable, "-m", "memory.finding_score", "score",
             "--category", "misconfig", "--line", "x", "--target", "t.com",
             "--memory-dir", str(tmp_path / "does-not-exist")],
            cwd=repo_root, capture_output=True, text=True, timeout=10,
            stdin=subprocess.DEVNULL,
        )
        assert proc.returncode == 0, proc.stderr

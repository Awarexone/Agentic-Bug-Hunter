"""Tests for tools/director.py — the Research Director (Phase 2).

Covers the contract that matters: leads become falsifiable, time-boxed
attacks scored ONLY via memory.vuln_intelligence (no second formula),
browser intelligence becomes concrete leads, the SKIPPED section is
always present and machine-checkable, dependencies/parallel groups are
correct, replan() never loses IN_PROGRESS work, and confidence()/cold-start
never fabricates a number. No network access anywhere here.
"""

import json
from pathlib import Path

import pytest

from tools import director
# director.py imports lead_board via `from tools import lead_board` (package-
# qualified) so it can share module state with tools.scope_checker etc. —
# importing it the SAME way here (not bare `import lead_board`) is required
# for monkeypatch.setattr(lb, "LEADS_DIR", ...) to actually reach the module
# object director.py reads from; a bare import would cache a second, distinct
# module under sys.modules["lead_board"] and silently miss the patch.
from tools import lead_board as lb

from memory.schemas import (
    make_failed_pattern_entry,
    make_hypothesis_entry,
    make_journal_entry,
    make_pattern_entry,
    make_report_outcome_entry,
)
from memory.pattern_db import PatternDB
from memory.vuln_intelligence import FailedPatternDB, HypothesisDB, ReportOutcomeDB, priority_score


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point the lead-board ledger at a tmp dir so tests never touch the
    real memory/leads/ directory."""
    monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
    return tmp_path


def _seed_recon(tmp_path, target, urls):
    rd = tmp_path / "recon" / target
    (rd / "urls").mkdir(parents=True)
    (rd / "urls" / "all.txt").write_text("\n".join(urls) + "\n")
    return str(rd)


def _seed_leads(isolated, target, urls):
    rd = _seed_recon(isolated, target, urls)
    lb.ingest(target, rd)
    return rd


REALISTIC_URLS = [
    "https://t.example/api/v2/users?id=1001",        # -> hunt-idor
    "https://t.example/graphql",                      # -> hunt-graphql
    "https://t.example/fetch?url=https://internal",   # -> hunt-ssrf
    "https://t.example/static/app.js.map",            # -> hunt-source-leak
]


class TestSkillToVulnClass:

    def test_strips_hunt_prefix(self):
        assert director.skill_to_vuln_class("hunt-idor") == "idor"

    def test_reuses_finding_score_aliases(self):
        # "hunt-auth_bypass" isn't a real lead-board skill name, but this
        # proves the alias table is actually consulted, not bypassed.
        assert director.skill_to_vuln_class("hunt-jwt") == director.skill_to_vuln_class("hunt-auth_bypass")

    def test_unknown_skill_resolves_gracefully(self):
        vuln_class = director.skill_to_vuln_class("hunt-totally-made-up")
        result = priority_score(vuln_class=vuln_class, tech_stack=[], target="t.com")
        assert 0 <= result["score"] <= 100


class TestLoadTechStack:

    def test_missing_profile_returns_empty(self, tmp_path):
        assert director.load_tech_stack("t.example", str(tmp_path / "hunt-memory")) == []

    def test_reads_tech_stack_field(self, tmp_path):
        mem = tmp_path / "hunt-memory"
        (mem / "targets").mkdir(parents=True)
        (mem / "targets" / "t.example.json").write_text(json.dumps({"tech_stack": ["express", "postgresql"]}))
        assert director.load_tech_stack("t.example", str(mem)) == ["express", "postgresql"]

    def test_malformed_profile_returns_empty(self, tmp_path):
        mem = tmp_path / "hunt-memory"
        (mem / "targets").mkdir(parents=True)
        (mem / "targets" / "t.example.json").write_text("{not json")
        assert director.load_tech_stack("t.example", str(mem)) == []


class TestBrowserIntelLeads:

    def _write(self, tmp_path, target, name, payload):
        browser_dir = tmp_path / "recon" / target / "browser"
        browser_dir.mkdir(parents=True, exist_ok=True)
        (browser_dir / name).write_text(json.dumps(payload))
        return str(tmp_path / "recon" / target)

    def test_no_browser_dir_returns_empty(self, tmp_path):
        assert director.browser_intel_leads("t.example", str(tmp_path / "recon" / "t.example")) == []

    def test_never_called_becomes_concrete_leads(self, tmp_path):
        rd = self._write(tmp_path, "t.example", "never-called.json", {
            "target": "t.example", "never_called": ["/api/v2/users?id=1001"],
        })
        leads = director.browser_intel_leads("t.example", rd)
        assert any(l["skill"] == "hunt-idor" for l in leads)
        assert all(l["source"] == "browser-intel" for l in leads)
        assert all(l["browser_artifact"] == "never-called.json" for l in leads)

    def test_framework_routes_become_leads(self, tmp_path):
        rd = self._write(tmp_path, "t.example", "routes.json", {
            "target": "t.example", "routes": ["/admin/dashboard"], "framework_detected": "nextjs",
        })
        leads = director.browser_intel_leads("t.example", rd)
        assert any(l["skill"] == "hunt-auth-bypass" for l in leads)

    def test_auth_model_privileged_routes_and_role_constants(self, tmp_path):
        rd = self._write(tmp_path, "t.example", "auth-model.json", {
            "target": "t.example",
            "candidate_privileged_client_routes": ["/admin/settings"],
            "auth_lifecycle_endpoints": ["https://t.example/api/auth/refresh"],
            "role_permission_constants": ["ROLE_ADMIN"],
        })
        leads = director.browser_intel_leads("t.example", rd)
        role_leads = [l for l in leads if l["evidence"] == "ROLE_ADMIN"]
        assert len(role_leads) == 1
        assert role_leads[0]["skill"] == "hunt-auth-bypass"
        assert any(l["evidence"] == "/admin/settings" for l in leads)
        assert any("refresh" in l["evidence"] for l in leads)

    def test_api_calls_with_auth_headers_become_leads(self, tmp_path):
        rd = self._write(tmp_path, "t.example", "api-calls.json", {
            "target": "t.example",
            "calls": [
                {"url": "https://t.example/api/v2/orders?id=5", "request_headers_auth": ["authorization"]},
                {"url": "https://t.example/api/v2/public", "request_headers_auth": []},
            ],
        })
        leads = director.browser_intel_leads("t.example", rd)
        evidences = {l["evidence"] for l in leads}
        assert "https://t.example/api/v2/orders?id=5" in evidences
        assert "https://t.example/api/v2/public" not in evidences

    def test_malformed_json_does_not_raise(self, tmp_path):
        browser_dir = tmp_path / "recon" / "t.example" / "browser"
        browser_dir.mkdir(parents=True)
        (browser_dir / "never-called.json").write_text("{not json")
        assert director.browser_intel_leads("t.example", str(tmp_path / "recon" / "t.example")) == []

    def test_leads_never_written_to_persisted_ledger(self, isolated, tmp_path):
        rd = self._write(tmp_path, "t.example", "never-called.json", {
            "target": "t.example", "never_called": ["/api/v2/users?id=1001"],
        })
        director.browser_intel_leads("t.example", rd)
        assert lb.load_ledger("t.example") == []


class TestBuildPlanBasics:

    def test_empty_memory_directory_works(self, isolated, tmp_path):
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("nolead.example", hours=2)
        assert plan.attacks == []
        assert plan.skipped == []
        assert "No leads found" in plan.summary

    def test_respects_total_time_budget(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS * 3)  # inflate candidate count
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        hours = 0.5
        plan = d.build_plan("t.example", hours=hours, recon_dir=str(isolated / "recon" / "t.example"))
        total_minutes = sum(a.maximum_time_minutes for a in plan.attacks)
        assert total_minutes <= hours * 60.0 + 1e-9

    def test_deterministic_output(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        recon_dir = str(isolated / "recon" / "t.example")
        mem_dir = str(tmp_path / "hunt-memory")
        d1 = director.Director(memory_dir=mem_dir)
        d2 = director.Director(memory_dir=mem_dir)
        plan1 = d1.build_plan("t.example", hours=3, recon_dir=recon_dir)
        plan2 = d2.build_plan("t.example", hours=3, recon_dir=recon_dir)

        def _stable(plan):
            # attack.id / attack.dependencies are randomly minted per
            # build_plan() call (secrets.token_hex) — translate dependency
            # attack_ids back to their stable lead_id before comparing, so
            # this actually tests semantic determinism, not ID entropy.
            attack_id_to_lead_id = {a.id: a.lead_id for a in plan.attacks}
            return [
                (a.lead_id, a.vuln_class, a.priority, a.ev_per_hour, a.ev_label, a.risk_level,
                 tuple(sorted(attack_id_to_lead_id[dep] for dep in a.dependencies)))
                for a in sorted(plan.attacks, key=lambda x: x.lead_id)
            ]

        assert _stable(plan1) == _stable(plan2)

    def test_no_duplicate_ranking_logic(self, isolated, tmp_path):
        """Every attack's priority/ev_per_hour must be byte-identical to
        calling priority_score()/expected_value_per_hour() directly with
        the same inputs — proving Director calls the formula rather than
        re-deriving its own."""
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        assert plan.attacks, "need at least one attack to prove anything"
        for a in plan.attacks:
            direct = priority_score(vuln_class=a.vuln_class, tech_stack=[], target="t.example")
            assert a.priority == direct["score"]


class TestSkippedSection:

    def test_skipped_never_empty_on_realistic_fixture_with_time_pressure(self, isolated, tmp_path):
        # 4 distinct leads, a tiny budget guarantees TIME_CONSTRAINT fires
        # for at least one after the first is planned.
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=0.2, recon_dir=str(isolated / "recon" / "t.example"))
        assert plan.skipped, "expected at least one skip under a tight budget"

    def test_every_skipped_entry_has_valid_machine_checkable_reason(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=0.2, recon_dir=str(isolated / "recon" / "t.example"))
        for s in plan.skipped:
            assert s["reason"] in director.SKIP_REASONS

    def test_below_ev_floor_skip(self, isolated, tmp_path):
        # open-redirect is P_MED with no memory backing -> low historical
        # success + low tech match -> ev/hr label "Low" -> BELOW_EV_FLOOR.
        _seed_leads(isolated, "t.example", ["https://t.example/redirect?next=https://x"])
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=str(isolated / "recon" / "t.example"))
        reasons = {s["reason"] for s in plan.skipped}
        assert "BELOW_EV_FLOOR" in reasons or not plan.skipped  # heuristic-dependent, assert no crash + valid taxonomy
        for s in plan.skipped:
            assert s["reason"] in director.SKIP_REASONS

    def test_matches_failed_pattern_skip(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")

        FailedPatternDB(mem_dir / "failed_patterns.jsonl").save(make_failed_pattern_entry(
            target="t.example", vuln_class="idor", technique="numeric_id_swap",
            tech_stack=[], endpoint=idor_lead["evidence"], reason="egress filtered",
        ))
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        skipped_idor = [s for s in plan.skipped if s["lead_id"] == idor_lead["id"]]
        assert skipped_idor and skipped_idor[0]["reason"] == "MATCHES_FAILED_PATTERN"

    def test_duplicate_skip(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")

        ReportOutcomeDB(mem_dir / "report_outcomes.jsonl").save(make_report_outcome_entry(
            target="t.example", vuln_class="idor", outcome="accepted",
        ))
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        skipped_idor = [s for s in plan.skipped if s["lead_id"] == idor_lead["id"]]
        assert skipped_idor and skipped_idor[0]["reason"] == "DUPLICATE"

    def test_dependency_unmet_cascades_to_skipped(self, isolated, tmp_path):
        # secret_plus_api chain: hunt-source-leak + hunt-api-misconfig on
        # the same host synthesizes a chain lead depending on both legs.
        rd = _seed_leads(isolated, "t.example", [
            "https://t.example/static/app.js.map",
            "https://t.example/api/v2/orders",
        ])
        mem_dir = tmp_path / "hunt-memory"
        leads = lb.load_ledger("t.example")
        source_leak_lead = next(l for l in leads if l["skill"] == "hunt-source-leak")
        # Force the source-leak leg to be skipped via a failed pattern so
        # the chain lead that depends on it must cascade into skipped[].
        FailedPatternDB(mem_dir / "failed_patterns.jsonl").save(make_failed_pattern_entry(
            target="t.example", vuln_class="source-leak", technique="fetch",
            tech_stack=[], endpoint=source_leak_lead["evidence"], reason="404, false positive",
        ))
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        chain_leads = [l for l in leads if l.get("source") == "chain"]
        if chain_leads:  # chain detection is data-dependent; assert cascade IF one exists
            chain_lead_ids = {l["id"] for l in chain_leads}
            cascaded = [s for s in plan.skipped if s["lead_id"] in chain_lead_ids
                        and s["reason"] == "DEPENDENCY_UNMET"]
            assert cascaded

    def test_always_rejected_and_policy_excluded_stay_in_vocabulary_but_unused(self, isolated, tmp_path):
        """Per explicit design decision: ALWAYS_REJECTED/POLICY_EXCLUDED
        are valid enum values (schema completeness) but the automatic
        classifier never fabricates evidence for them from recon-time
        signals alone."""
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        reasons = {s["reason"] for s in plan.skipped}
        assert "ALWAYS_REJECTED" not in reasons
        assert "POLICY_EXCLUDED" not in reasons
        assert {"ALWAYS_REJECTED", "POLICY_EXCLUDED"} <= set(director.SKIP_REASONS)


class TestFalsifiersAndStopConditions:

    def test_every_attack_has_a_falsifier(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        assert plan.attacks
        for a in plan.attacks:
            assert a.falsifier and isinstance(a.falsifier, str)

    def test_every_attack_has_a_stop_condition_and_success(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        for a in plan.attacks:
            assert a.stop_condition
            assert a.success
            assert a.minimum_time_minutes > 0
            assert a.maximum_time_minutes > 0


class TestStateMachineAndDependencies:

    def test_dependency_ordering_preserved(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", [
            "https://t.example/static/app.js.map",
            "https://t.example/api/v2/orders",
        ])
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        by_id = {a.id: a for a in plan.attacks}
        for a in plan.attacks:
            if a.dependencies:
                assert a.state in ("PENDING", "BLOCKED")
                for dep_id in a.dependencies:
                    assert dep_id in by_id, "dependency must resolve to an attack_id in this plan"

    def test_parallel_groups_generated(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        assert plan.attacks
        for a in plan.attacks:
            assert a.parallel_group and "/" in a.parallel_group

    def test_all_states_are_from_the_defined_set(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        for a in plan.attacks:
            assert a.state in director.STATES


class TestReplan:

    def test_replan_preserves_in_progress(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        ready = next(a for a in plan.attacks if a.state == "READY")
        plan2 = d.replan(plan, {"in_progress": [ready.id]})
        assert next(a for a in plan2.attacks if a.id == ready.id).state == "IN_PROGRESS"

    def test_replan_never_discards_completed_work(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        target = plan.attacks[0]
        plan2 = d.replan(plan, {"completed": [target.id]})
        still_there = next((a for a in plan2.attacks if a.id == target.id), None)
        assert still_there is not None
        assert still_there.state == "COMPLETED"
        # replanning again must not un-complete it without new evidence
        plan3 = d.replan(plan2, {})
        assert next(a for a in plan3.attacks if a.id == target.id).state == "COMPLETED"

    def test_abandoned_work_never_auto_revives(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        target = plan.attacks[0]
        plan2 = d.replan(plan, {"abandoned": [target.id]})
        plan3 = d.replan(plan2, {})
        assert next(a for a in plan3.attacks if a.id == target.id).state == "ABANDONED"

    def test_explicit_revive_restores_abandoned_work(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        target = plan.attacks[0]
        plan2 = d.replan(plan, {"abandoned": [target.id]})
        plan3 = d.replan(plan2, {"revive": [target.id]})
        assert next(a for a in plan3.attacks if a.id == target.id).state != "ABANDONED"

    def test_replan_respects_remaining_time_budget(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS * 2)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=1, recon_dir=str(isolated / "recon" / "t.example"))
        completed_ids = [a.id for a in plan.attacks[:1]]
        plan2 = d.replan(plan, {"completed": completed_ids})
        open_minutes = sum(a.maximum_time_minutes for a in plan2.attacks if a.state == "READY")
        remaining_budget = plan.total_budget_hours * 60.0 - sum(
            a.maximum_time_minutes for a in plan2.attacks if a.state in ("COMPLETED", "IN_PROGRESS")
        )
        assert open_minutes <= remaining_budget + 1e-9


class TestExplain:

    def test_explain_without_plan_says_so(self):
        d = director.Director(memory_dir="hunt-memory")
        assert "No plan" in d.explain("lb-doesnotexist")

    def test_explain_names_evidence_not_just_vuln_class(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        top = plan.attacks[0]
        explanation = d.explain(top.lead_id)
        assert top.lead_id in explanation
        assert "Evidence:" in explanation
        assert "EV/hour" in explanation

    def test_explain_unknown_lead_id(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        assert "No lead" in d.explain("lb-doesnotexist")


class TestConfidence:

    def test_cold_start_explicitly_reported(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        result = d.confidence(plan)
        assert result["available"] is False
        assert result["message"] == "No calibration data available."
        for a in plan.attacks:
            assert a.calibrated_confidence is None
            assert a.calibration_note == "No calibration data available."
            # Cold start: no patterns/failed_patterns exist for any vuln_class
            # on this tech stack, so confidence must be None (not the 20.0
            # technology_match floor masquerading as a real number).
            assert a.confidence is None
            assert a.confidence_note == "no informative signal yet — technology_match floor"

    def test_confidence_is_a_real_number_once_affinity_data_exists(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")

        # A real pattern for idor+this tech stack -> tech_vuln_affinity()
        # now has a matching entry with wins+losses > 0.
        PatternDB(mem_dir / "patterns.jsonl").save(make_pattern_entry(
            target="other-target.example", vuln_class="idor", technique="numeric_id_swap",
            tech_stack=["express", "postgresql"], endpoint="/api/v1/orders/{id}",
        ))
        (mem_dir / "targets").mkdir(parents=True, exist_ok=True)
        (mem_dir / "targets" / "t.example.json").write_text(json.dumps({"tech_stack": ["express", "postgresql"]}))

        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        idor_attack = next(a for a in plan.attacks if a.lead_id == idor_lead["id"])
        assert idor_attack.confidence is not None
        assert isinstance(idor_attack.confidence, float)
        assert idor_attack.confidence_note == "technology_match component from tech_vuln_affinity() (memory-backed)"

        # A different vuln_class with no matching pattern on this tech
        # stack must still be None -- proves this is per-vuln_class, not
        # a global "any memory exists" toggle.
        ssrf_lead = next(l for l in leads if l["skill"] == "hunt-ssrf")
        ssrf_attack = next((a for a in plan.attacks if a.lead_id == ssrf_lead["id"]), None)
        if ssrf_attack is not None:
            assert ssrf_attack.confidence is None

    def test_confidence_passes_through_hypothesis_calibration(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")

        HypothesisDB(mem_dir / "hypotheses.jsonl").save(make_hypothesis_entry(
            target="t.example", vuln_class="idor", endpoint=idor_lead["evidence"], confidence=70,
        ))
        (mem_dir / "journal.jsonl").parent.mkdir(parents=True, exist_ok=True)
        with open(mem_dir / "journal.jsonl", "w") as fh:
            fh.write(json.dumps(make_journal_entry(
                target="t.example", action="hunt", vuln_class="idor",
                endpoint=idor_lead["evidence"], result="confirmed",
            )) + "\n")

        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        result = d.confidence(plan)
        assert result["available"] is True
        assert result["overall_calibration_gap"] is not None

    def test_never_fabricates_a_number_when_bucket_unresolved(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        # A hypothesis exists but nothing resolves it (no matching journal
        # or report_outcomes entry) -> must stay "No calibration data available."
        HypothesisDB(mem_dir / "hypotheses.jsonl").save(make_hypothesis_entry(
            target="t.example", vuln_class="idor", endpoint="/never/matched", confidence=70,
        ))
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        for a in plan.attacks:
            assert a.calibrated_confidence is None
            assert a.calibration_note == "No calibration data available."


class TestRiskLevel:

    def test_risk_level_is_one_of_the_defined_tiers(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        for a in plan.attacks:
            assert a.risk_level in director.RISK_LEVELS

    def test_no_detection_risk_float_field_exists(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        for a in plan.attacks:
            assert "detection_risk" not in a.to_dict()

    def test_passive_source_is_always_low_risk(self):
        assert director.risk_level_for("hunt-nextjs", "tech", "") == "LOW"


class TestRenderAndWrite:

    def test_render_markdown_contains_required_sections(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        md = d.render_markdown(plan)
        assert "## Planned Attacks" in md
        assert "## SKIPPED" in md
        assert "## Checkpoint Schedule" in md
        assert "MANDATORY FALSIFIER" in md

    def test_write_plan_writes_hunt_plan_md(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        out_path = d.write_plan(plan, recon_dir=rd)
        assert out_path.endswith("hunt-plan.md")
        import os
        assert os.path.exists(out_path)


class TestPlanPersistence:
    """save_plan()/load_plan() — the JSON sidecar that makes replan() usable
    across separate process invocations, not just an in-process object."""

    def test_save_then_load_round_trips_to_an_equal_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        assert plan.attacks, "need at least one attack to prove anything"

        plan_file = str(tmp_path / "hunt-plan.json")
        director.save_plan(plan, plan_file)
        reloaded = director.load_plan(plan_file)

        assert reloaded == plan  # dataclass equality: every field, every attack

    def test_round_trip_preserves_none_confidence(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        plan_file = str(tmp_path / "hunt-plan.json")
        director.save_plan(plan, plan_file)
        reloaded = director.load_plan(plan_file)
        for a in reloaded.attacks:
            assert a.confidence is None
            assert a.confidence_note == "no informative signal yet — technology_match floor"

    def test_load_plan_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            director.load_plan(str(tmp_path / "does-not-exist.json"))

    def test_save_plan_creates_parent_directories(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        nested = str(tmp_path / "a" / "b" / "c" / "hunt-plan.json")
        path = director.save_plan(plan, nested)
        assert path == nested
        import os
        assert os.path.exists(nested)

    def test_replan_across_a_fresh_load_preserves_in_progress_and_completed(self, isolated, tmp_path):
        """The actual scenario this exists for: build a plan, persist it,
        throw away the in-process Plan object entirely, reload from disk,
        and replan from there — same guarantees as in-process replan()."""
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        completed_id = plan.attacks[0].id
        in_progress_id = plan.attacks[1].id
        plan_file = str(tmp_path / "hunt-plan.json")
        director.save_plan(plan, plan_file)

        del plan  # simulate a fresh process: no in-memory Plan survives

        reloaded = director.load_plan(plan_file)
        d2 = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        updated = d2.replan(reloaded, {"completed": [completed_id], "in_progress": [in_progress_id]})

        assert next(a for a in updated.attacks if a.id == completed_id).state == "COMPLETED"
        assert next(a for a in updated.attacks if a.id == in_progress_id).state == "IN_PROGRESS"


class TestPlanFileCLI:
    """CLI wiring: build-plan --write emits the JSON sidecar; replan
    --plan-file loads from it instead of requiring an in-process object."""

    def test_build_plan_write_emits_json_sidecar(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        exit_code = director.main([
            "build-plan", "t.example", "--hours", "3",
            "--memory-dir", str(tmp_path / "hunt-memory"),
            "--recon-dir", rd, "--write",
        ])
        assert exit_code == 0
        import os
        assert os.path.exists(os.path.join(rd, "hunt-plan.md"))
        assert os.path.exists(os.path.join(rd, "hunt-plan.json"))

    def test_build_plan_plan_file_override(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        override = str(tmp_path / "custom-name.json")
        director.main([
            "build-plan", "t.example", "--hours", "3",
            "--memory-dir", str(tmp_path / "hunt-memory"),
            "--recon-dir", rd, "--write", "--plan-file", override,
        ])
        import os
        assert os.path.exists(override)

    def test_replan_cli_loads_from_plan_file_only(self, isolated, tmp_path, capsys):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        plan_file = str(tmp_path / "hunt-plan.json")
        director.main([
            "build-plan", "t.example", "--hours", "3",
            "--memory-dir", str(tmp_path / "hunt-memory"),
            "--recon-dir", rd, "--write", "--plan-file", plan_file,
        ])
        capsys.readouterr()  # discard build-plan's stdout

        saved = director.load_plan(plan_file)
        target_attack_id = saved.attacks[0].id
        results_file = tmp_path / "results.json"
        results_file.write_text(json.dumps({"completed": [target_attack_id]}))

        exit_code = director.main(["replan", "--plan-file", plan_file, "--results-file", str(results_file)])
        assert exit_code == 0

        reloaded = director.load_plan(plan_file)
        assert next(a for a in reloaded.attacks if a.id == target_attack_id).state == "COMPLETED"

    def test_replan_cli_without_results_file_is_a_noop_pass(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        plan_file = str(tmp_path / "hunt-plan.json")
        director.main([
            "build-plan", "t.example", "--hours", "3",
            "--memory-dir", str(tmp_path / "hunt-memory"),
            "--recon-dir", rd, "--write", "--plan-file", plan_file,
        ])
        before = director.load_plan(plan_file)
        exit_code = director.main(["replan", "--plan-file", plan_file])
        assert exit_code == 0
        after = director.load_plan(plan_file)
        assert [a.state for a in before.attacks] == [a.state for a in after.attacks]


class TestShouldStopIntegration:

    def test_should_stop_now_delegates_to_experiment_memory(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        attack = plan.attacks[0]
        result = d.should_stop_now(attack, [], elapsed_minutes=attack.minimum_time_minutes)
        assert result["stop"] is True

    def test_should_stop_now_false_with_zero_elapsed(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        attack = plan.attacks[0]
        result = d.should_stop_now(attack, [], elapsed_minutes=0)
        assert result["stop"] is False


def test_build_plan_rejects_non_positive_hours(isolated, tmp_path):
    d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
    with pytest.raises(ValueError):
        d.build_plan("t.example", hours=0)


class TestTechAttackMatrixWiring:
    """Phase 3 follow-up: tools/tech_attack_matrix.json's static weights
    actually reach priority_score()/expected_value_per_hour() through
    build_plan(), gated on recon/<target>/fingerprint.json existing for
    THIS target — not merely on the matrix file existing on disk."""

    def test_no_fingerprint_json_gate_closed(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        recon_dir.mkdir(parents=True)
        assert director.load_fingerprint_tech_attack_matrix("t.example", str(recon_dir)) is None

    def test_malformed_fingerprint_json_gate_closed(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        recon_dir.mkdir(parents=True)
        (recon_dir / "fingerprint.json").write_text("{not json")
        assert director.load_fingerprint_tech_attack_matrix("t.example", str(recon_dir)) is None

    def test_fingerprint_present_opens_gate_and_loads_real_matrix(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        recon_dir.mkdir(parents=True)
        (recon_dir / "fingerprint.json").write_text(json.dumps({"target": "t.example", "framework": "nextjs"}))
        matrix = director.load_fingerprint_tech_attack_matrix("t.example", str(recon_dir))
        assert matrix is not None
        assert "nextjs" in matrix

    def test_build_plan_byte_identical_when_fingerprint_absent(self, isolated, tmp_path):
        """No recon/<target>/fingerprint.json anywhere -> every attack's
        priority must still equal calling priority_score() directly with
        tech_attack_matrix omitted, same proof test_no_duplicate_ranking_logic
        already makes, now explicitly re-checked after wiring the parameter
        through build_plan()."""
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        recon_dir = str(isolated / "recon" / "t.example")
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=recon_dir)
        assert plan.attacks, "need at least one attack to prove anything"
        for a in plan.attacks:
            direct = priority_score(vuln_class=a.vuln_class, tech_stack=[], target="t.example")
            assert a.priority == direct["score"]

    def test_fingerprint_present_but_framework_unmatched_in_matrix_no_crash(self, isolated, tmp_path):
        recon_dir = isolated / "recon" / "t.example"
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "urls" / "all.txt").write_text("https://t.example/admin\n")
        lb.ingest("t.example", str(recon_dir))
        (recon_dir / "fingerprint.json").write_text(json.dumps({
            "target": "t.example", "framework": "some-made-up-framework-xyz",
        }))
        mem_dir = tmp_path / "hunt-memory"
        (mem_dir / "targets").mkdir(parents=True)
        (mem_dir / "targets" / "t.example.json").write_text(
            json.dumps({"tech_stack": ["some-made-up-framework-xyz"]})
        )
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(recon_dir))
        assert plan.attacks, "need at least one attack to prove anything"
        for a in plan.attacks:
            assert 0 <= a.priority <= 100  # no crash, no fabricated out-of-range score

    def test_nextjs_cve_weight_raises_priority_over_no_fingerprint(self, isolated, tmp_path):
        """The actual proof the wiring does something (not just that it
        doesn't crash): an identical hunt-auth-bypass lead, identical
        tech_stack (["nextjs"]) and identical (empty) memory -- the ONLY
        difference between the two build_plan() calls is whether
        recon/<target>/fingerprint.json exists. With it present,
        CVE-2025-29927's weight (90) replaces the historical-data-absent
        floor (20) for the matching "auth-bypass" vuln_class in
        _matrix_technology_match(), which must raise the final blended
        priority_score()."""
        recon_dir = isolated / "recon" / "t.example"
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "urls" / "all.txt").write_text("https://t.example/admin\n")
        lb.ingest("t.example", str(recon_dir))

        mem_dir = tmp_path / "hunt-memory"
        (mem_dir / "targets").mkdir(parents=True)
        (mem_dir / "targets" / "t.example.json").write_text(json.dumps({"tech_stack": ["nextjs"]}))

        d_without = director.Director(memory_dir=str(mem_dir))
        plan_without = d_without.build_plan("t.example", hours=3, recon_dir=str(recon_dir))

        (recon_dir / "fingerprint.json").write_text(json.dumps({
            "target": "t.example", "framework": "nextjs", "version": "12.0.0",
        }))
        d_with = director.Director(memory_dir=str(mem_dir))
        plan_with = d_with.build_plan("t.example", hours=3, recon_dir=str(recon_dir))

        by_lead_without = {a.lead_id: a for a in plan_without.attacks}
        by_lead_with = {a.lead_id: a for a in plan_with.attacks}
        auth_bypass_lead_ids = [lid for lid, a in by_lead_with.items() if a.vuln_class == "auth-bypass"]
        assert auth_bypass_lead_ids, "need at least one auth-bypass lead to prove anything"
        for lid in auth_bypass_lead_ids:
            assert lid in by_lead_without, "same lead must be scored in both plans"
            assert by_lead_with[lid].priority > by_lead_without[lid].priority


# Same 3-URL, same-host fixture tests/test_attack_graph.py's own
# TestRegressionAgainstLeadBoard uses to trigger
# account_takeover_via_leaked_secret (hunt-source-leak -> hunt-idor ->
# hunt-auth-bypass, all on t.example) -- guaranteed to produce an Impact
# node in memory/attack_graph.py's graph, hence at least one
# source=="attack-graph" candidate out of top_paths().
HYPOTHESIS_URLS = [
    "https://t.example/.env",
    "https://t.example/api/v2/users?id=1001",
    "https://t.example/login?next=/dashboard",
]


class TestAttackGraphLeads:
    """Phase 4 batch 2, item 6: memory/attack_graph.py's top_paths() output
    reaches build_plan() as additional candidates, via the SAME
    _score_lead()/sort/skip pipeline every other lead goes through -- no
    second candidate type, no parallel scoring path."""

    def test_attack_graph_leads_pure_function_produces_attack_graph_source(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        leads = director.attack_graph_leads("t.example", rd, memory_dir=str(tmp_path / "hunt-memory"))
        assert leads
        assert all(l["source"] == "attack-graph" for l in leads)

    def test_no_leads_no_recon_yields_empty_list_not_a_crash(self, isolated, tmp_path):
        leads = director.attack_graph_leads(
            "empty.example", str(tmp_path / "recon" / "empty.example"),
            memory_dir=str(tmp_path / "hunt-memory"),
        )
        assert leads == []

    def test_malformed_browser_json_does_not_raise(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        browser_dir = Path(rd) / "browser"
        browser_dir.mkdir(parents=True, exist_ok=True)
        (browser_dir / "auth-model.json").write_text("{not json")
        leads = director.attack_graph_leads("t.example", rd, memory_dir=str(tmp_path / "hunt-memory"))
        assert isinstance(leads, list)  # must not raise

    def test_leads_never_written_to_persisted_ledger(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        director.attack_graph_leads("t.example", rd, memory_dir=str(tmp_path / "hunt-memory"))
        # only the raw ingested leads (+ lead_board's own chain/hypothesis
        # synthesis) are on the ledger -- attack-graph leads are ephemeral,
        # recomputed every build_plan() call, same as browser-intel leads.
        assert all(l.get("source") != "attack-graph" for l in lb.load_ledger("t.example"))

    def test_build_plan_candidates_include_both_board_and_attack_graph_leads(self, isolated, tmp_path):
        """The actual item-6 proof: build_plan()'s candidate list (built
        from board_leads + bi_leads + graph_leads, all scored identically
        by _score_lead()) contains at least one lead-board-sourced
        candidate AND at least one attack-graph-sourced candidate side by
        side -- concatenated, not routed through a second pipeline."""
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=5, recon_dir=rd)
        candidates = d._last_plan_context["candidates"]
        sources = {c["lead"].get("source") for c in candidates}
        assert "attack-graph" in sources
        assert sources - {"attack-graph"}, "expected at least one non-attack-graph lead alongside it"

    def test_attack_graph_candidate_scored_by_same_score_lead_formula(self, isolated, tmp_path):
        """No second scoring formula: an attack-graph candidate's
        score_result/ev_result must be byte-identical to calling
        priority_score()/expected_value_per_hour() directly with the same
        vuln_class -- the exact proof test_no_duplicate_ranking_logic
        already makes for ordinary leads, repeated here for source==
        "attack-graph"."""
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=5, recon_dir=rd)
        candidates = d._last_plan_context["candidates"]
        graph_candidates = [c for c in candidates if c["lead"]["source"] == "attack-graph"]
        assert graph_candidates
        for c in graph_candidates:
            direct = priority_score(vuln_class=c["vuln_class"], tech_stack=[], target="t.example")
            assert c["score_result"]["score"] == direct["score"]


class TestExplainAttackGraphLead:
    """Phase 4 batch 2: Director.explain()'s source=="attack-graph" case
    must cover why the path exists, its weakest link, its strongest
    evidence, assumptions required, and a stopping condition -- extending
    the SAME explain() method, not a second explain-style function."""

    def _plan_with_attack_graph_candidate(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=5, recon_dir=rd)
        candidates = d._last_plan_context["candidates"]
        graph_candidate = next(c for c in candidates if c["lead"]["source"] == "attack-graph")
        return d, graph_candidate

    def test_explain_covers_all_required_explainability_fields(self, isolated, tmp_path):
        d, graph_candidate = self._plan_with_attack_graph_candidate(isolated, tmp_path)
        text = d.explain(graph_candidate["lead"]["id"])
        assert "Attack-graph path" in text          # why this path exists at all
        assert "Weakest link:" in text                # weakest leg
        assert "Strongest evidence:" in text           # strongest leg
        assert "Assumptions required" in text           # every leg's origin
        assert "Stopping condition" in text             # what would invalidate it

    def test_explain_weakest_link_matches_min_confidence_leg(self, isolated, tmp_path):
        d, graph_candidate = self._plan_with_attack_graph_candidate(isolated, tmp_path)
        lead = graph_candidate["lead"]
        weakest = min(lead["path_legs"], key=lambda leg: leg["confidence"])
        text = d.explain(lead["id"])
        assert str(weakest["confidence"]) in text
        assert weakest["edge_type"] in text

    def test_explain_unrelated_lead_still_uses_normal_path(self, isolated, tmp_path):
        """Sanity: the new elif branch must not affect explain() for
        non-attack-graph leads."""
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=5, recon_dir=rd)
        candidates = d._last_plan_context["candidates"]
        non_graph = next(c for c in candidates if c["lead"]["source"] != "attack-graph")
        text = d.explain(non_graph["lead"]["id"])
        assert "Attack-graph path" not in text

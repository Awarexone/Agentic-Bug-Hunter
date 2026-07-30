"""Tests for agent.py — the standalone ReAct hunting loop's tool-dispatch surface
and its wiring into the intelligence layer (hunt-memory/ priority ranking,
duplicate/noise gating on finish, session-summary write-back).

Never touches the network: h.run_recon/h.run_vuln_scan are monkeypatched, and
RECON_DIR/FINDINGS_DIR/BASE_DIR are pointed at a tmp_path scratch tree.
"""

import json
import os

import pytest

import agent


@pytest.fixture
def h(monkeypatch, tmp_path):
    """The lazily-loaded tools/hunt.py module, repointed at a scratch tree."""
    hunt_mod = agent._h()
    monkeypatch.setattr(hunt_mod, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt_mod, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt_mod, "BASE_DIR", str(tmp_path))
    return hunt_mod


@pytest.fixture
def domain():
    return "test.example"


@pytest.fixture
def recon_dir(h, domain):
    d = os.path.join(h.RECON_DIR, domain)
    os.makedirs(d, exist_ok=True)
    return d


@pytest.fixture
def dispatcher(h, domain, recon_dir):
    session_file = os.path.join(recon_dir, "agent_session.json")
    memory = agent.HuntMemory(session_file)
    return agent.ToolDispatcher(domain, memory)


class TestHuntModuleWiring:
    """The core Phase-A fix: _h() must load tools/hunt.py, not a stale root path."""

    def test_h_loads_tools_hunt_py(self):
        hunt_mod = agent._h()
        assert hunt_mod.__file__.endswith(os.path.join("tools", "hunt.py"))

    def test_h_exposes_expected_functions(self):
        hunt_mod = agent._h()
        assert hasattr(hunt_mod, "run_recon")
        assert hasattr(hunt_mod, "run_vuln_scan")
        assert hasattr(hunt_mod, "RECON_DIR")
        assert hasattr(hunt_mod, "FINDINGS_DIR")

    def test_recon_dir_for_matches_hunt_module_recon_dir(self, h, domain):
        assert agent._recon_dir_for(domain) == os.path.join(h.RECON_DIR, domain)

    def test_findings_dir_for_matches_hunt_module_findings_dir(self, h, domain):
        assert agent._findings_dir_for(domain) == os.path.join(h.FINDINGS_DIR, domain)


class TestToolDispatch:
    """Every surviving tool dispatches without AttributeError/TypeError against
    the current tools/hunt.py API — this was completely broken before Phase A."""

    def test_run_recon_calls_hunt_module_with_correct_kwargs(self, monkeypatch, h, dispatcher, domain):
        calls = []
        monkeypatch.setattr(h, "run_recon", lambda d, quick=False, scope_lock=False:
                             calls.append((d, quick, scope_lock)) or True)
        obs = dispatcher.dispatch("run_recon", {"quick": True, "scope_lock": True})
        assert calls == [(domain, True, True)]
        assert "run_recon" in obs

    def test_run_vuln_scan_calls_hunt_module_with_correct_kwargs(self, monkeypatch, h, dispatcher, domain):
        calls = []
        monkeypatch.setattr(h, "run_vuln_scan", lambda d, quick=False, full=False:
                             calls.append((d, quick, full)) or True)
        obs = dispatcher.dispatch("run_vuln_scan", {"full": True})
        assert calls == [(domain, False, True)]
        assert "scan" in obs

    def test_run_secret_hunt_errors_cleanly_without_recon(self, h):
        # A domain that never got a recon_dir created -> must not crash
        session_file = os.path.join(h.RECON_DIR, "never-reconned.example", "agent_session.json")
        memory = agent.HuntMemory(session_file)
        d = agent.ToolDispatcher("never-reconned.example", memory)
        obs = d.dispatch("run_secret_hunt", {})
        assert "ERROR" in obs and "run_recon" in obs

    def test_run_param_discovery_errors_cleanly_without_urls(self, dispatcher, recon_dir):
        # recon_dir exists but urls/all.txt doesn't -> must not crash
        obs = dispatcher.dispatch("run_param_discovery", {})
        assert "ERROR" in obs

    def test_removed_tool_reports_unknown_not_crash(self, dispatcher):
        for dead_tool in ("run_js_analysis", "run_cms_exploit", "run_rce_scan",
                           "run_cors_check", "run_jwt_audit", "run_sqlmap_targeted",
                           "run_sqlmap_on_file", "run_api_fuzz", "run_post_param_discovery"):
            obs = dispatcher.dispatch(dead_tool, {})
            assert obs == f"Unknown tool: {dead_tool}"

    def test_update_working_memory_persists(self, dispatcher):
        dispatcher.dispatch("update_working_memory", {"notes": "hello"})
        assert dispatcher.memory.working_memory == "hello"

    def test_tools_list_matches_dispatch_surface(self):
        # Every schema in TOOLS must be dispatchable (no orphaned schema entries).
        names = {t["function"]["name"] for t in agent.TOOLS}
        assert names == {
            "run_recon", "run_vuln_scan", "run_secret_hunt", "run_param_discovery",
            "read_recon_summary", "read_findings_summary", "update_working_memory", "finish",
        }


class TestHuntMemoryPersistence:

    def test_save_and_reload_round_trip(self, recon_dir):
        session_file = os.path.join(recon_dir, "agent_session.json")
        m1 = agent.HuntMemory(session_file)
        m1.working_memory = "notes here"
        m1.completed_steps.append("run_recon")
        m1.add_finding("run_vuln_scan", "HIGH", "something bad")
        m1.save()

        m2 = agent.HuntMemory(session_file)
        assert m2.working_memory == "notes here"
        assert m2.completed_steps == ["run_recon"]
        assert len(m2.findings_log) == 1


class TestPriorityBriefing:
    """Phase B1 — live tech->vuln affinity/EV ranking replacing the old static prose."""

    def test_no_tech_stack_detected_yet(self, dispatcher):
        briefing = dispatcher.priority_briefing()
        assert "no tech stack detected" in briefing

    def test_detects_tech_stack_from_httpx_output(self, dispatcher, recon_dir):
        os.makedirs(os.path.join(recon_dir, "live"), exist_ok=True)
        with open(os.path.join(recon_dir, "live", "httpx_full.txt"), "w") as f:
            f.write("https://test.example [200] [nginx] [express] [postgresql]\n")
        assert dispatcher._detect_tech_stack() == ["express", "nginx", "postgresql"]

    def test_no_memory_data_for_tech_stack(self, dispatcher, recon_dir):
        os.makedirs(os.path.join(recon_dir, "live"), exist_ok=True)
        with open(os.path.join(recon_dir, "live", "httpx_full.txt"), "w") as f:
            f.write("https://test.example [somewholly_novel_tech_xyz]\n")
        briefing = dispatcher.priority_briefing()
        assert "no prior hunt-memory data" in briefing

    def test_ranks_vuln_classes_from_real_memory(self, h, dispatcher, recon_dir, domain):
        os.makedirs(os.path.join(recon_dir, "live"), exist_ok=True)
        with open(os.path.join(recon_dir, "live", "httpx_full.txt"), "w") as f:
            f.write("https://test.example [express] [postgresql]\n")

        from memory.pattern_db import PatternDB
        from memory.schemas import make_pattern_entry, make_failed_pattern_entry
        from memory.vuln_intelligence import FailedPatternDB

        memory_dir = os.path.join(h.BASE_DIR, "hunt-memory")
        PatternDB(os.path.join(memory_dir, "patterns.jsonl")).save(
            make_pattern_entry(target="other.com", vuln_class="idor", technique="id_swap",
                                tech_stack=["express", "postgresql"], payout=1500)
        )
        FailedPatternDB(os.path.join(memory_dir, "failed_patterns.jsonl")).save(
            make_failed_pattern_entry(target="other2.com", vuln_class="ssrf", technique="webhook",
                                       tech_stack=["express"], reason="egress filtered")
        )

        briefing = dispatcher.priority_briefing()
        assert "idor" in briefing
        assert "EV/hr" in briefing

    def test_build_context_includes_priority_briefing(self, dispatcher, domain):
        ctx = agent.ReActAgent.__new__(agent.ReActAgent)
        ctx.domain = domain
        ctx.dispatcher = dispatcher
        ctx.memory = dispatcher.memory
        ctx.max_steps = 20
        import time
        ctx.time_start = time.time()
        ctx.time_budget_secs = 7200
        built = agent.ReActAgent._build_context(ctx)
        assert "Memory-informed priority" in built


class TestFinishDuplicateGate:
    """Phase B2 — don't let the loop finish on findings already known to memory."""

    def test_no_findings_not_blocked(self, dispatcher):
        result = dispatcher.check_finish_for_duplicates()
        assert result["blocked"] is False

    def test_known_duplicate_high_finding_blocks(self, h, dispatcher, domain):
        from memory.vuln_intelligence import ReportOutcomeDB
        from memory.schemas import make_report_outcome_entry

        memory_dir = os.path.join(h.BASE_DIR, "hunt-memory")
        ReportOutcomeDB(os.path.join(memory_dir, "report_outcomes.jsonl")).save(
            make_report_outcome_entry(target=domain, vuln_class="info-disclosure",
                                       outcome="accepted", payout=500)
        )
        dispatcher.memory.add_finding("run_secret_hunt", "HIGH", "Found exposed AWS secret key")
        result = dispatcher.check_finish_for_duplicates()
        assert result["blocked"] is True
        assert "report_outcomes.jsonl" in result["reason"]

    def test_new_vuln_class_not_blocked(self, dispatcher):
        dispatcher.memory.add_finding("run_vuln_scan", "HIGH", "SQL injection confirmed on /api/search")
        result = dispatcher.check_finish_for_duplicates()
        assert result["blocked"] is False

    def test_unclassifiable_finding_not_blocked(self, dispatcher):
        dispatcher.memory.add_finding("run_vuln_scan", "HIGH", "Something odd happened")
        result = dispatcher.check_finish_for_duplicates()
        assert result["blocked"] is False
        assert "no findings text matched" in result["reason"]

    def test_low_severity_findings_ignored(self, h, dispatcher, domain):
        from memory.vuln_intelligence import ReportOutcomeDB
        from memory.schemas import make_report_outcome_entry

        memory_dir = os.path.join(h.BASE_DIR, "hunt-memory")
        ReportOutcomeDB(os.path.join(memory_dir, "report_outcomes.jsonl")).save(
            make_report_outcome_entry(target=domain, vuln_class="info-disclosure", outcome="accepted")
        )
        dispatcher.memory.add_finding("run_secret_hunt", "LOW", "minor exposed secret")
        result = dispatcher.check_finish_for_duplicates()
        assert result["blocked"] is False
        assert "no HIGH/CRITICAL" in result["reason"]


class TestSessionSummaryWriteback:
    """Phase B3 — standalone hunts should leave a journal.jsonl trace, not vanish."""

    def test_finish_writes_journal_entry(self, h, dispatcher, domain):
        dispatcher.memory.completed_steps = ["run_recon", "run_vuln_scan"]
        dispatcher.memory.add_finding("run_vuln_scan", "HIGH", "SQL injection confirmed")

        obs = dispatcher.dispatch("finish", {"verdict": "done"})
        assert obs.startswith("FINISH:")

        journal_path = os.path.join(h.BASE_DIR, "hunt-memory", "journal.jsonl")
        assert os.path.isfile(journal_path)
        entries = [json.loads(l) for l in open(journal_path) if l.strip()]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["target"] == domain
        assert entry["vuln_class"] == "session_summary"
        assert "auto_logged" in entry["tags"]
        assert "sqli" in entry["notes"]

    def test_second_finish_appends_not_overwrites(self, h, dispatcher):
        dispatcher.dispatch("finish", {"verdict": "first"})
        dispatcher.dispatch("finish", {"verdict": "second"})
        journal_path = os.path.join(h.BASE_DIR, "hunt-memory", "journal.jsonl")
        entries = [json.loads(l) for l in open(journal_path) if l.strip()]
        assert len(entries) == 2

    def test_journal_entry_is_schema_valid(self, h, dispatcher):
        from memory.schemas import validate_journal_entry

        dispatcher.dispatch("finish", {"verdict": "done"})
        journal_path = os.path.join(h.BASE_DIR, "hunt-memory", "journal.jsonl")
        entry = json.loads(open(journal_path).readline())
        validate_journal_entry(entry)  # raises SchemaError if invalid

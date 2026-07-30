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


class TestExperimentMemoryWiring:
    """Item 1 — agent.py now writes granular per-category experiments.jsonl
    entries (vuln_scanner.sh's own FINDINGS_DIR subdirs, content vs empty) and
    surfaces should_stop()/payload_category_affinity() in priority_briefing()."""

    @pytest.fixture
    def findings_dir(self, h, domain):
        d = os.path.join(h.FINDINGS_DIR, domain)
        for sub in agent.ToolDispatcher._VULN_SCAN_SUBDIRS:
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        return d

    def test_logs_one_entry_per_subdir(self, dispatcher, findings_dir):
        dispatcher._log_experiments_from_findings("run_vuln_scan", agent.ToolDispatcher._VULN_SCAN_SUBDIRS)
        from memory.experiment_memory import ExperimentDB
        db = ExperimentDB(os.path.join(_hunt_memory_dir(dispatcher), "experiments.jsonl"))
        entries = db.read_all()
        assert len(entries) == len(agent.ToolDispatcher._VULN_SCAN_SUBDIRS)

    def test_nonempty_subdir_logs_success_empty_logs_fail(self, dispatcher, findings_dir):
        with open(os.path.join(findings_dir, "sqli", "hit.txt"), "w") as f:
            f.write("[CONFIRMED] [SQLI-POC-VERIFIED] url=https://test.example/api?id=1\n")

        dispatcher._log_experiments_from_findings("run_vuln_scan", agent.ToolDispatcher._VULN_SCAN_SUBDIRS)

        from memory.experiment_memory import ExperimentDB
        db = ExperimentDB(os.path.join(_hunt_memory_dir(dispatcher), "experiments.jsonl"))
        entries = {e["payload_category"]: e for e in db.read_all()}
        assert entries["vuln_scan_sqli"]["result"] == "success"
        assert entries["vuln_scan_xss"]["result"] == "fail"

    def test_secret_hunt_uses_its_own_subdir_map(self, dispatcher, h, domain):
        secrets_dir = os.path.join(h.FINDINGS_DIR, domain, "secrets")
        os.makedirs(secrets_dir, exist_ok=True)
        with open(os.path.join(secrets_dir, "trufflehog.jsonl"), "w") as f:
            f.write('{"key": "leaked"}\n')

        dispatcher._log_experiments_from_findings("run_secret_hunt", agent.ToolDispatcher._SECRET_HUNT_SUBDIRS)

        from memory.experiment_memory import ExperimentDB
        db = ExperimentDB(os.path.join(_hunt_memory_dir(dispatcher), "experiments.jsonl"))
        entries = db.read_all()
        assert len(entries) == 1
        assert entries[0]["payload_category"] == "vuln_scan_secrets"
        assert entries[0]["vuln_class"] == "info-disclosure"
        assert entries[0]["result"] == "success"

    def test_priority_briefing_includes_experiment_signal(self, dispatcher, findings_dir, h, domain):
        os.makedirs(os.path.join(h.RECON_DIR, domain, "live"), exist_ok=True)
        with open(os.path.join(h.RECON_DIR, domain, "live", "httpx_full.txt"), "w") as f:
            f.write("https://test.example [express]\n")

        dispatcher._log_experiments_from_findings("run_vuln_scan", agent.ToolDispatcher._VULN_SCAN_SUBDIRS)
        briefing = dispatcher.priority_briefing()
        assert "Experiment memory:" in briefing

    def test_no_experiments_yet_no_signal_line(self, dispatcher, h, domain):
        os.makedirs(os.path.join(h.RECON_DIR, domain, "live"), exist_ok=True)
        with open(os.path.join(h.RECON_DIR, domain, "live", "httpx_full.txt"), "w") as f:
            f.write("https://test.example [express]\n")
        briefing = dispatcher.priority_briefing()
        assert "Experiment memory:" not in briefing

    def test_dispatch_run_vuln_scan_logs_experiments(self, monkeypatch, h, dispatcher, findings_dir):
        monkeypatch.setattr(h, "run_vuln_scan", lambda d, quick=False, full=False: True)
        dispatcher.dispatch("run_vuln_scan", {})
        exp_path = os.path.join(_hunt_memory_dir(dispatcher), "experiments.jsonl")
        assert os.path.isfile(exp_path)


def _hunt_memory_dir(dispatcher) -> str:
    return os.path.join(agent._h().BASE_DIR, "hunt-memory")


class TestChainSignal:
    """Item 2 — a HIGH/CRITICAL finding checks chains.jsonl for a confirmed
    A->B shape already proven on this tech stack (chain-builder.md's own
    memory consultation, ported into this loop since it can't invoke that
    agent directly)."""

    def _seed_recon(self, h, domain, tech_line="https://test.example [express] [postgresql]\n"):
        live_dir = os.path.join(h.RECON_DIR, domain, "live")
        os.makedirs(live_dir, exist_ok=True)
        with open(os.path.join(live_dir, "httpx_full.txt"), "w") as f:
            f.write(tech_line)

    def _seed_chain(self, h, **overrides):
        from memory.vuln_intelligence import ChainDB
        from memory.schemas import make_chain_entry

        kwargs = dict(
            target="other.com", chain_name="idor_read_write_asymmetry",
            steps=["idor read on /api/orders/{id}", "same endpoint PUT with attacker session"],
            tech_stack=["express", "postgresql"], payout=3000, severity="critical",
        )
        kwargs.update(overrides)
        ChainDB(os.path.join(h.BASE_DIR, "hunt-memory", "chains.jsonl")).save(make_chain_entry(**kwargs))

    def test_critical_finding_gets_chain_hint(self, h, dispatcher, domain):
        self._seed_recon(h, domain)
        self._seed_chain(h)
        dispatcher._classify_obs("run_vuln_scan", "CRITICAL: IDOR confirmed on /api/orders/42")
        assert len(dispatcher.memory.findings_log) == 1
        text = dispatcher.memory.findings_log[0]["text"]
        assert "CHAIN CONTEXT" in text
        assert "idor_read_write_asymmetry" in text

    def test_medium_finding_gets_no_chain_hint(self, h, dispatcher, domain):
        self._seed_recon(h, domain)
        self._seed_chain(h)
        dispatcher._classify_obs("run_vuln_scan", "MEDIUM: open redirect found at /go?url=x")
        text = dispatcher.memory.findings_log[0]["text"]
        assert "CHAIN CONTEXT" not in text

    def test_no_chain_data_no_hint(self, h, dispatcher, domain):
        self._seed_recon(h, domain)
        dispatcher._classify_obs("run_vuln_scan", "CRITICAL: RCE confirmed via upload")
        text = dispatcher.memory.findings_log[0]["text"]
        assert "CHAIN CONTEXT" not in text

    def test_no_tech_stack_no_hint(self, h, dispatcher, domain):
        self._seed_chain(h)
        dispatcher._classify_obs("run_vuln_scan", "CRITICAL: IDOR confirmed on /api/orders/42")
        text = dispatcher.memory.findings_log[0]["text"]
        assert "CHAIN CONTEXT" not in text

    def test_chain_for_different_tech_stack_not_matched(self, h, dispatcher, domain):
        self._seed_recon(h, domain)
        self._seed_chain(h, tech_stack=["django", "mysql"])
        dispatcher._classify_obs("run_vuln_scan", "CRITICAL: IDOR confirmed on /api/orders/42")
        text = dispatcher.memory.findings_log[0]["text"]
        assert "CHAIN CONTEXT" not in text


class TestScannerTagClassification:
    """Item 5 — vuln_scanner.sh's own [CONFIRMED]/[POSSIBLE] tags (real PoC
    verification) must win over keyword guessing, which discarded that work."""

    def test_confirmed_tag_is_always_critical_and_confirmed(self, dispatcher):
        dispatcher._classify_obs(
            "run_vuln_scan",
            "[CONFIRMED] [SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://test.example/api?id=1",
        )
        f = dispatcher.memory.findings_log[0]
        assert f["severity"] == "CRITICAL"
        assert f["confirmed"] is True

    def test_possible_tag_severity_comes_from_content_not_flattened(self, dispatcher):
        dispatcher._classify_obs(
            "run_vuln_scan",
            "[POSSIBLE] [SQLI-CANDIDATE] dialect=mysql param=2 url=https://test.example/api?id=2",
        )
        f = dispatcher.memory.findings_log[0]
        assert f["severity"] == "HIGH"  # content-driven, not a fixed POSSIBLE->MEDIUM flattening
        assert f["confirmed"] is False

    def test_possible_tag_with_no_severity_keyword_defaults_medium(self, dispatcher):
        dispatcher._classify_obs(
            "run_vuln_scan", "[POSSIBLE] [UNCLASSIFIED-SIGNAL] endpoint returned 200 unexpectedly",
        )
        f = dispatcher.memory.findings_log[0]
        assert f["severity"] == "MEDIUM"
        assert f["confirmed"] is False

    def test_untagged_output_falls_back_to_keyword_guess_unconfirmed(self, dispatcher):
        dispatcher._classify_obs("run_vuln_scan", "CRITICAL: something bad happened, rce detected")
        f = dispatcher.memory.findings_log[0]
        assert f["severity"] == "CRITICAL"
        assert f["confirmed"] is False

    def test_confirmed_takes_priority_over_possible_in_same_observation(self, dispatcher):
        obs = (
            "[POSSIBLE] [SQLI-CANDIDATE] url=https://test.example/api?id=1\n"
            "[CONFIRMED] [RCE-POC] url=https://test.example/upload/shell.php"
        )
        dispatcher._classify_obs("run_vuln_scan", obs)
        assert len(dispatcher.memory.findings_log) == 1
        f = dispatcher.memory.findings_log[0]
        assert f["confirmed"] is True
        assert "RCE-POC" in f["text"]

    def test_no_tag_no_keyword_no_finding_logged(self, dispatcher):
        dispatcher._classify_obs("run_vuln_scan", "scan completed, nothing notable")
        assert dispatcher.memory.findings_log == []


class TestFinishUnconfirmedGate:
    """Item 5 — don't let the loop finish declaring HIGH/CRITICAL impact when
    nothing verified it (agent.py's version of validation-engine's impact-proven
    check)."""

    def test_no_findings_not_blocked(self, dispatcher):
        assert dispatcher.check_finish_for_unconfirmed()["blocked"] is False

    def test_unconfirmed_high_finding_blocks(self, dispatcher):
        dispatcher._classify_obs(
            "run_vuln_scan", "[POSSIBLE] [SQLI-CANDIDATE] url=https://test.example/api?id=1",
        )
        result = dispatcher.check_finish_for_unconfirmed()
        assert result["blocked"] is True
        assert "[CONFIRMED]" in result["reason"]

    def test_confirmed_finding_among_notable_unblocks(self, dispatcher):
        dispatcher._classify_obs(
            "run_vuln_scan", "[POSSIBLE] [SQLI-CANDIDATE] url=https://test.example/api?id=1",
        )
        dispatcher._classify_obs(
            "run_vuln_scan", "[CONFIRMED] [RCE-POC] url=https://test.example/upload/shell.php",
        )
        result = dispatcher.check_finish_for_unconfirmed()
        assert result["blocked"] is False

    def test_medium_finding_not_checked(self, dispatcher):
        dispatcher._classify_obs(
            "run_vuln_scan", "[POSSIBLE] [UNCLASSIFIED-SIGNAL] nothing severity-worthy here",
        )
        result = dispatcher.check_finish_for_unconfirmed()
        assert result["blocked"] is False
        assert "no HIGH/CRITICAL" in result["reason"]

    def test_warn_flags_exist_on_react_agent_for_once_only_gating(self):
        # ReActAgent.__init__ needs a live Ollama server to construct (not
        # available in this test env) -- verify the warn-once flags it sets
        # exist in source instead of constructing a real instance.
        import inspect
        src = inspect.getsource(agent.ReActAgent.__init__)
        assert "_finish_duplicate_warned" in src
        assert "_finish_unconfirmed_warned" in src


class TestImpactRecalibrationInBriefing:
    """Item 6 — priority_briefing() surfaces when the impact prior was
    recalibrated from real report_outcomes.jsonl data, not just the score."""

    def _seed_recon(self, h, domain):
        live_dir = os.path.join(h.RECON_DIR, domain, "live")
        os.makedirs(live_dir, exist_ok=True)
        with open(os.path.join(live_dir, "httpx_full.txt"), "w") as f:
            f.write("https://test.example [express] [postgresql]\n")

    def _seed_pattern_and_outcomes(self, h, domain, n=5, outcome="accepted"):
        from memory.pattern_db import PatternDB
        from memory.schemas import make_pattern_entry, make_report_outcome_entry
        from memory.vuln_intelligence import ReportOutcomeDB

        memory_dir = os.path.join(h.BASE_DIR, "hunt-memory")
        PatternDB(os.path.join(memory_dir, "patterns.jsonl")).save(
            make_pattern_entry(target="other.com", vuln_class="idor", technique="id_swap",
                                tech_stack=["express", "postgresql"], payout=1500)
        )
        odb = ReportOutcomeDB(os.path.join(memory_dir, "report_outcomes.jsonl"))
        for i in range(n):
            odb.save(make_report_outcome_entry(
                target=f"target{i}.com", vuln_class="idor", outcome=outcome,
            ))

    def test_briefing_shows_recalibration_note_when_sample_large_enough(self, h, dispatcher, domain):
        self._seed_recon(h, domain)
        self._seed_pattern_and_outcomes(h, domain, n=5, outcome="accepted")
        briefing = dispatcher.priority_briefing()
        assert "impact recalibrated" in briefing

    def test_briefing_has_no_recalibration_note_below_threshold(self, h, dispatcher, domain):
        self._seed_recon(h, domain)
        self._seed_pattern_and_outcomes(h, domain, n=2, outcome="accepted")
        briefing = dispatcher.priority_briefing()
        assert "impact recalibrated" not in briefing

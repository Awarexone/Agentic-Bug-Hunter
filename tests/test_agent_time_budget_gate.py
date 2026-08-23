"""ToolDispatcher must refuse to start a new network-facing tool once the
time budget is nearly exhausted (< 10% remaining). `time_budget_hours` was
previously checked only between ReActAgent steps (see ReActAgent.step()),
so a single scanner subprocess launched right before the budget ran out
could overrun it by up to its own internal timeout (run_recon: 3600s,
run_vuln_scan: 1800s regardless of --quick — see tools/hunt.py). This
doesn't preempt an in-flight subprocess; it reduces the blast radius by
refusing to *start* another one this late. See
SECURITY-REVIEW-2026-08-22.md finding #16 (LOW-MEDIUM)."""
import time

import pytest

import agent
from agent import HuntMemory, ToolDispatcher
from tools.scope_checker import ScopeChecker


@pytest.fixture
def memory(tmp_path):
    return HuntMemory(str(tmp_path / "agent_session.json"))


@pytest.fixture
def fake_hunt(monkeypatch, tmp_path):
    class FakeHunt:
        def __init__(self):
            self.calls = []

        def run_recon(self, domain, **kwargs):
            self.calls.append(("run_recon", domain, kwargs))
            return True

        def run_vuln_scan(self, domain, **kwargs):
            self.calls.append(("run_vuln_scan", domain, kwargs))
            return True

        def _resolve_recon_dir(self, domain):
            recon_dir = tmp_path / "recon" / domain
            recon_dir.mkdir(parents=True, exist_ok=True)
            return str(recon_dir)

    fake = FakeHunt()
    monkeypatch.setattr(agent, "_h", lambda: fake)
    return fake


class TestTimeRemainingFraction:
    def test_fresh_dispatcher_has_full_budget(self, memory):
        checker = ScopeChecker(domains=["target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker,
                                     time_budget_hours=2.0)
        assert dispatcher._time_remaining_fraction() > 0.99

    def test_nearly_exhausted_budget_reports_low_fraction(self, memory):
        checker = ScopeChecker(domains=["target.com"])
        # 1-hour budget, started 57 minutes ago -> 5% remaining.
        start_time = time.time() - (57 * 60)
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker,
                                     time_budget_hours=1.0, start_time=start_time)
        frac = dispatcher._time_remaining_fraction()
        assert 0.0 <= frac < 0.10

    def test_fraction_never_goes_negative_past_budget(self, memory):
        checker = ScopeChecker(domains=["target.com"])
        start_time = time.time() - (10 * 3600)  # way past a 1-hour budget
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker,
                                     time_budget_hours=1.0, start_time=start_time)
        assert dispatcher._time_remaining_fraction() == 0.0


class TestTimeBudgetGateBlocksNetworkTools:
    def test_network_tool_blocked_when_budget_nearly_exhausted(self, memory, fake_hunt):
        checker = ScopeChecker(domains=["target.com"])
        start_time = time.time() - (57 * 60)  # 5% left of a 1-hour budget
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker,
                                     time_budget_hours=1.0, start_time=start_time)

        result = dispatcher.dispatch("run_recon", {})

        assert result.startswith("BLOCKED")
        assert "time budget" in result.lower()
        assert not fake_hunt.calls  # never actually ran

    def test_network_tool_allowed_with_ample_budget_remaining(self, memory, fake_hunt):
        checker = ScopeChecker(domains=["target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker,
                                     time_budget_hours=2.0)

        result = dispatcher.dispatch("run_recon", {})

        assert "BLOCKED" not in result
        assert fake_hunt.calls

    def test_local_bookkeeping_tool_not_gated_by_time_budget(self, memory, fake_hunt):
        # update_working_memory touches only session state on disk, never
        # the network, so it must not be subject to the network-tool time
        # gate even when the budget is nearly exhausted.
        checker = ScopeChecker(domains=["target.com"])
        start_time = time.time() - (57 * 60)
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker,
                                     time_budget_hours=1.0, start_time=start_time)

        result = dispatcher.dispatch("update_working_memory", {"notes": "still here"})

        assert "BLOCKED" not in result

    def test_default_construction_does_not_block_existing_callers(self, memory, fake_hunt):
        # Callers/tests that don't pass time_budget_hours/start_time at all
        # (e.g. pre-existing tests constructing ToolDispatcher with just
        # scope_checker=...) must see no behavior change.
        checker = ScopeChecker(domains=["target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)

        result = dispatcher.dispatch("run_recon", {})

        assert "BLOCKED" not in result
        assert fake_hunt.calls

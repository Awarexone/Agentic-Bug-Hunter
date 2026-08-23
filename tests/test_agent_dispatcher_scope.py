"""Tests for ToolDispatcher's scope gate — the live autopilot path that
AutopilotGuard was NOT previously wired into.

Before this fix, agent.py's ToolDispatcher.dispatch() called straight into
hunt.py's run_* functions with no gate at all: no scope check, no circuit
breaker, no method policy, regardless of whether a scope_checker was even
supplied to run_agent_hunt(). These tests exercise the actual dispatch path,
not just AutopilotGuard in isolation (see test_autopilot_guard.py for that).
"""

import pytest

import agent
from agent import HuntMemory, ToolDispatcher
from tools.scope_checker import ScopeChecker


@pytest.fixture
def memory(tmp_path):
    return HuntMemory(str(tmp_path / "agent_session.json"))


@pytest.fixture
def fake_hunt(monkeypatch):
    """Stub out agent._h() so network tools don't actually shell out."""

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
            return str(domain)

    fake = FakeHunt()
    monkeypatch.setattr(agent, "_h", lambda: fake)
    return fake


class TestNoScopeConfigured:
    """fail_closed=True is the AutopilotGuard default — dispatch() must
    inherit it even when nobody threads a scope_checker through."""

    def test_network_tool_blocked_with_no_scope_checker(self, memory, fake_hunt):
        dispatcher = ToolDispatcher("target.com", memory)
        result = dispatcher.dispatch("run_recon", {})
        assert result.startswith("BLOCKED by scope guard:")
        assert "no scope" in result.lower()
        assert fake_hunt.calls == []  # the real tool must never have run

    def test_local_tools_unaffected_by_missing_scope(self, memory, fake_hunt):
        dispatcher = ToolDispatcher("target.com", memory)
        result = dispatcher.dispatch("update_working_memory", {"notes": "hi"})
        assert "Working memory updated" in result
        result = dispatcher.dispatch("finish", {"verdict": "done"})
        assert result.startswith("FINISH:")


class TestScopeConfigured:
    def test_in_scope_domain_allowed_through(self, memory, fake_hunt):
        checker = ScopeChecker(domains=["target.com", "*.target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        result = dispatcher.dispatch("run_recon", {})
        assert not result.startswith("BLOCKED")
        assert fake_hunt.calls and fake_hunt.calls[0][0] == "run_recon"

    def test_out_of_scope_domain_blocked(self, memory, fake_hunt):
        """The dispatcher was constructed for a domain that isn't actually
        on the program's allowlist — e.g. --target typo'd against --domain."""
        checker = ScopeChecker(domains=["other-program.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        result = dispatcher.dispatch("run_vuln_scan", {})
        assert result.startswith("BLOCKED by scope guard:")
        assert "scope" in result.lower()
        assert fake_hunt.calls == []

    def test_lookalike_domain_blocked(self, memory, fake_hunt):
        checker = ScopeChecker(domains=["*.target.com"])
        dispatcher = ToolDispatcher("evil-target.com", memory, scope_checker=checker)
        result = dispatcher.dispatch("run_recon", {})
        assert result.startswith("BLOCKED by scope guard:")
        assert fake_hunt.calls == []

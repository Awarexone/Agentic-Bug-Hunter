"""ToolDispatcher must scope-filter recon-discovered URLs before scanning
them (not just check the base --target domain), and must actually record
success/failure against AutopilotGuard's circuit breaker, and must use
each tool's real HTTP method semantics instead of a hardcoded GET (so the
unsafe-method approval gate can fire). See SECURITY-REVIEW-2026-08-22.md
finding #2 (HIGH) and finding #7 (MEDIUM)."""
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

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

        def run_post_param_discovery(self, domain, **kwargs):
            self.calls.append(("run_post_param_discovery", domain, kwargs))
            return True

        def _resolve_recon_dir(self, domain):
            recon_dir = tmp_path / "recon" / domain
            recon_dir.mkdir(parents=True, exist_ok=True)
            return str(recon_dir)

    fake = FakeHunt()
    monkeypatch.setattr(agent, "_h", lambda: fake)
    return fake


class TestScopeFiltersReconUrls:
    def test_out_of_scope_recon_urls_are_dropped_before_scan(self, memory, fake_hunt, tmp_path):
        checker = ScopeChecker(domains=["target.com", "*.target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        recon_dir = fake_hunt._resolve_recon_dir("target.com")
        urls_dir = os.path.join(recon_dir, "urls")
        os.makedirs(urls_dir, exist_ok=True)
        with open(os.path.join(urls_dir, "all.txt"), "w") as f:
            f.write("https://api.target.com/x\nhttps://evil.com/y\n")

        dispatcher.dispatch("run_vuln_scan", {})

        with open(os.path.join(urls_dir, "all.txt")) as f:
            remaining = f.read()
        assert "api.target.com" in remaining
        assert "evil.com" not in remaining


class TestCircuitBreakerRecording:
    def test_failed_tool_records_failure_against_guard(self, memory, tmp_path, monkeypatch):
        class FailingHunt:
            def run_recon(self, domain, **kwargs):
                raise RuntimeError("scan failed")

            def _resolve_recon_dir(self, domain):
                return str(tmp_path)

        monkeypatch.setattr(agent, "_h", lambda: FailingHunt())
        checker = ScopeChecker(domains=["target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        dispatcher.dispatch("run_recon", {})
        status = dispatcher._guard.get_host_status("target.com")
        assert status["failures"] == 1

    def test_successful_tool_records_success(self, memory, fake_hunt):
        checker = ScopeChecker(domains=["target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        dispatcher._guard.record_failure("target.com")
        dispatcher.dispatch("run_recon", {})
        status = dispatcher._guard.get_host_status("target.com")
        assert status["failures"] == 0

    def test_tripped_circuit_blocks_further_dispatch(self, memory, fake_hunt):
        checker = ScopeChecker(domains=["target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker, circuit_threshold=2)
        dispatcher._guard.record_failure("target.com")
        dispatcher._guard.record_failure("target.com")
        result = dispatcher.dispatch("run_recon", {})
        assert "BLOCKED" in result
        assert "circuit" in result.lower() or "tripped" in result.lower()


class TestMethodPolicyEnforced:
    def test_state_changing_tool_requires_approval(self, memory, fake_hunt):
        checker = ScopeChecker(domains=["target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        result = dispatcher.dispatch("run_post_param_discovery", {})
        assert "APPROVAL" in result.upper() or "require_approval" in result.lower()
        assert not fake_hunt.calls  # never actually ran without approval

    def test_safe_tool_does_not_require_approval(self, memory, fake_hunt):
        checker = ScopeChecker(domains=["target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        result = dispatcher.dispatch("run_recon", {})
        assert "APPROVAL" not in result.upper()
        assert fake_hunt.calls

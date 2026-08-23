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

        def run_sqlmap_request_file(self, request_file, **kwargs):
            self.calls.append(("run_sqlmap_request_file", request_file, kwargs))
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

    def test_out_of_scope_urls_dropped_from_derived_recon_files_too(self, memory, fake_hunt, tmp_path):
        """all.txt isn't the only file scanners read: tools/vuln_scanner.sh
        does active SQLi/XSS/SSTI probing straight off
        urls/with_params.txt (and also reads urls/js_files.txt,
        urls/api_endpoints.txt, live/urls.txt), all of which are derived
        from recon and were previously never re-filtered even after
        all.txt itself was cleaned. See SECURITY-REVIEW-2026-08-22.md
        finding #2 follow-up."""
        checker = ScopeChecker(domains=["target.com", "*.target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        recon_dir = fake_hunt._resolve_recon_dir("target.com")
        urls_dir = os.path.join(recon_dir, "urls")
        live_dir = os.path.join(recon_dir, "live")
        os.makedirs(urls_dir, exist_ok=True)
        os.makedirs(live_dir, exist_ok=True)
        with open(os.path.join(urls_dir, "all.txt"), "w") as f:
            f.write("https://api.target.com/x\nhttps://evil.com/y\n")
        with open(os.path.join(urls_dir, "with_params.txt"), "w") as f:
            f.write("https://api.target.com/x?id=1\nhttps://evil.com/y?id=1\n")
        with open(os.path.join(urls_dir, "js_files.txt"), "w") as f:
            f.write("https://api.target.com/app.js\nhttps://evil.com/app.js\n")
        with open(os.path.join(urls_dir, "api_endpoints.txt"), "w") as f:
            f.write("https://api.target.com/v1/users\nhttps://evil.com/v1/users\n")
        with open(os.path.join(live_dir, "urls.txt"), "w") as f:
            f.write("https://api.target.com/\nhttps://evil.com/\n")

        dispatcher.dispatch("run_vuln_scan", {})

        for fn in (
            os.path.join(urls_dir, "with_params.txt"),
            os.path.join(urls_dir, "js_files.txt"),
            os.path.join(urls_dir, "api_endpoints.txt"),
            os.path.join(live_dir, "urls.txt"),
        ):
            with open(fn) as f:
                remaining = f.read()
            assert "api.target.com" in remaining, f"{fn} lost in-scope entries"
            assert "evil.com" not in remaining, f"{fn} still has out-of-scope entries"


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


class TestSqlmapRequestFileScope:
    """run_sqlmap_on_file's actual target is data-driven from a request
    file, not self.domain — a --target that's in scope says nothing about
    what host the request file itself targets. This is the sharp edge:
    self.domain passes scope, but the file smuggles in an out-of-scope
    host. See SECURITY-REVIEW-2026-08-22.md finding #2."""

    def test_out_of_scope_request_file_host_hard_blocked(self, memory, fake_hunt, tmp_path):
        checker = ScopeChecker(domains=["target.com", "*.target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        req_file = tmp_path / "request.txt"
        req_file.write_text(
            "POST /api/login HTTP/1.1\r\n"
            "Host: evil.other-corp.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"user":"a"}'
        )

        result = dispatcher.dispatch("run_sqlmap_on_file", {"request_file": str(req_file)})

        assert result.startswith("BLOCKED by scope guard:")
        assert "evil.other-corp.com" in result
        assert not fake_hunt.calls  # never actually ran

    def test_unparseable_host_blocked_not_bypassed(self, memory, fake_hunt, tmp_path):
        checker = ScopeChecker(domains=["target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        req_file = tmp_path / "request.txt"
        req_file.write_text("POST /api/login HTTP/1.1\r\n\r\n{}")  # no Host: header

        result = dispatcher.dispatch("run_sqlmap_on_file", {"request_file": str(req_file)})

        assert result.startswith("BLOCKED by scope guard:")
        assert not fake_hunt.calls

    def test_in_scope_request_file_host_still_requires_approval_and_names_host(self, memory, fake_hunt, tmp_path):
        checker = ScopeChecker(domains=["target.com", "*.target.com"])
        dispatcher = ToolDispatcher("target.com", memory, scope_checker=checker)
        req_file = tmp_path / "request.txt"
        req_file.write_text(
            "POST /api/login HTTP/1.1\r\n"
            "Host: api.target.com\r\n"
            "\r\n"
            "{}"
        )

        result = dispatcher.dispatch("run_sqlmap_on_file", {"request_file": str(req_file)})

        assert "APPROVAL" in result.upper()
        assert "api.target.com" in result
        assert not fake_hunt.calls  # still not executed without approval

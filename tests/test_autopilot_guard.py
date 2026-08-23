"""Tests for AutopilotGuard — unified pre-request guard for autopilot mode."""

import time
import pytest

from memory.audit_log import (
    AutopilotGuard,
    CircuitBreaker,
    RateLimiter,
    SafeMethodPolicy,
)


class TestAutopilotGuardAllow:
    """Safe requests on healthy hosts should be allowed."""

    def test_safe_get_on_healthy_host(self):
        guard = AutopilotGuard(fail_closed=False)
        result = guard.check_request("GET", "https://target.com/api/users")
        assert result["decision"] == "allow"

    def test_safe_head_allowed(self):
        guard = AutopilotGuard(fail_closed=False)
        result = guard.check_request("HEAD", "https://target.com/")
        assert result["decision"] == "allow"

    def test_safe_options_allowed(self):
        guard = AutopilotGuard(fail_closed=False)
        result = guard.check_request("OPTIONS", "https://target.com/api")
        assert result["decision"] == "allow"


class TestAutopilotGuardUnsafeMethods:
    """Unsafe methods should require approval."""

    def test_post_requires_approval(self):
        guard = AutopilotGuard(fail_closed=False)
        result = guard.check_request("POST", "https://target.com/api/users")
        assert result["decision"] == "require_approval"
        assert "unsafe method" in result["reason"].lower() or "method" in result["reason"].lower()

    def test_put_requires_approval(self):
        guard = AutopilotGuard(fail_closed=False)
        result = guard.check_request("PUT", "https://target.com/api/users/1")
        assert result["decision"] == "require_approval"

    def test_delete_requires_approval(self):
        guard = AutopilotGuard(fail_closed=False)
        result = guard.check_request("DELETE", "https://target.com/api/users/1")
        assert result["decision"] == "require_approval"

    def test_patch_requires_approval(self):
        guard = AutopilotGuard(fail_closed=False)
        result = guard.check_request("PATCH", "https://target.com/api/users/1")
        assert result["decision"] == "require_approval"


class TestAutopilotGuardCircuitBreaker:
    """Requests to tripped hosts should be blocked."""

    def test_block_when_circuit_tripped(self):
        guard = AutopilotGuard(circuit_threshold=2, fail_closed=False)
        # Trip the breaker
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        result = guard.check_request("GET", "https://target.com/api")
        assert result["decision"] == "block"
        assert "circuit" in result["reason"].lower() or "tripped" in result["reason"].lower()

    def test_allow_after_cooldown(self):
        guard = AutopilotGuard(circuit_threshold=2, circuit_cooldown=0.1, fail_closed=False)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        assert guard.check_request("GET", "https://target.com/api")["decision"] == "block"
        time.sleep(0.15)
        assert guard.check_request("GET", "https://target.com/api")["decision"] == "allow"

    def test_success_resets_breaker(self):
        guard = AutopilotGuard(circuit_threshold=3, fail_closed=False)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        guard.record_success("target.com")
        guard.record_failure("target.com")
        # Only 1 failure after reset — not tripped
        result = guard.check_request("GET", "https://target.com/api")
        assert result["decision"] == "allow"

    def test_different_hosts_independent(self):
        guard = AutopilotGuard(circuit_threshold=2, fail_closed=False)
        guard.record_failure("bad.com")
        guard.record_failure("bad.com")
        # bad.com is tripped, but good.com is fine
        assert guard.check_request("GET", "https://bad.com/api")["decision"] == "block"
        assert guard.check_request("GET", "https://good.com/api")["decision"] == "allow"


class TestAutopilotGuardHostExtraction:
    """Guard should extract host from URL for circuit breaker checks."""

    def test_extracts_host_from_https(self):
        guard = AutopilotGuard(circuit_threshold=2, fail_closed=False)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        result = guard.check_request("GET", "https://target.com/api/users")
        assert result["decision"] == "block"

    def test_extracts_host_with_port(self):
        guard = AutopilotGuard(circuit_threshold=2, fail_closed=False)
        guard.record_failure("target.com:8080")
        guard.record_failure("target.com:8080")
        result = guard.check_request("GET", "https://target.com:8080/api")
        assert result["decision"] == "block"


class TestAutopilotGuardCombined:
    """Multiple guards interact correctly — circuit breaker checked before method policy."""

    def test_circuit_breaker_takes_precedence(self):
        """If host is tripped, block even for safe methods."""
        guard = AutopilotGuard(circuit_threshold=2, fail_closed=False)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        result = guard.check_request("GET", "https://target.com/api")
        assert result["decision"] == "block"

    def test_unsafe_method_on_healthy_host(self):
        """Healthy host + unsafe method = require_approval, not block."""
        guard = AutopilotGuard(fail_closed=False)
        result = guard.check_request("DELETE", "https://target.com/api/users/1")
        assert result["decision"] == "require_approval"

    def test_unsafe_method_on_tripped_host(self):
        """Tripped host + unsafe method = block (circuit breaker wins)."""
        guard = AutopilotGuard(circuit_threshold=2, fail_closed=False)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        result = guard.check_request("DELETE", "https://target.com/api")
        assert result["decision"] == "block"


class TestAutopilotGuardStatus:
    """Getting guard status for a host."""

    def test_status_healthy(self):
        guard = AutopilotGuard(fail_closed=False)
        status = guard.get_host_status("target.com")
        assert status["circuit_tripped"] is False
        assert status["failures"] == 0

    def test_status_after_failures(self):
        guard = AutopilotGuard(circuit_threshold=5, fail_closed=False)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        status = guard.get_host_status("target.com")
        assert status["failures"] == 2
        assert status["circuit_tripped"] is False

    def test_status_tripped(self):
        guard = AutopilotGuard(circuit_threshold=2, fail_closed=False)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        status = guard.get_host_status("target.com")
        assert status["circuit_tripped"] is True


class TestAutopilotGuardDisabledPolicy:
    """When safe_methods_only is disabled, all methods pass method check."""

    def test_disabled_allows_delete(self):
        guard = AutopilotGuard(safe_methods_only=False, fail_closed=False)
        result = guard.check_request("DELETE", "https://target.com/api/users/1")
        assert result["decision"] == "allow"


# ---------------------------------------------------------------------------
# Scope enforcement (added: wire ScopeChecker into the autopilot guard so an
# out-of-scope request is a hard block, and a missing scope config fails closed)
# ---------------------------------------------------------------------------

from tools.scope_checker import ScopeChecker


def _scoped(**kwargs):
    """AutopilotGuard scoped to *.target.com for scope tests."""
    checker = ScopeChecker(domains=["target.com", "*.target.com"])
    return AutopilotGuard(scope_checker=checker, **kwargs)


class TestAutopilotGuardScope:
    """A ScopeChecker turns scope into an automatic hard block."""

    def test_in_scope_host_allowed(self):
        guard = _scoped()
        result = guard.check_request("GET", "https://api.target.com/users")
        assert result["decision"] == "allow"

    def test_out_of_scope_host_blocked(self):
        guard = _scoped()
        result = guard.check_request("GET", "https://evil.com/users")
        assert result["decision"] == "block"
        assert "scope" in result["reason"].lower()

    def test_lookalike_domain_blocked(self):
        """evil-target.com must not match *.target.com."""
        guard = _scoped()
        result = guard.check_request("GET", "https://evil-target.com/")
        assert result["decision"] == "block"
        assert "scope" in result["reason"].lower()

    def test_scope_checked_before_method_policy(self):
        """An out-of-scope unsafe method is blocked, not merely held for approval."""
        guard = _scoped()
        result = guard.check_request("DELETE", "https://evil.com/api")
        assert result["decision"] == "block"
        assert "scope" in result["reason"].lower()

    def test_scope_checked_before_circuit_breaker(self):
        """Scope is the first gate: out-of-scope blocks with a scope reason,
        even on a host that would otherwise be healthy."""
        guard = _scoped(circuit_threshold=2)
        result = guard.check_request("GET", "https://evil.com/api")
        assert result["decision"] == "block"
        assert "scope" in result["reason"].lower()

    def test_in_scope_unsafe_method_still_needs_approval(self):
        """Being in scope doesn't waive the method policy."""
        guard = _scoped()
        result = guard.check_request("POST", "https://api.target.com/users")
        assert result["decision"] == "require_approval"


class TestAutopilotGuardFailClosed:
    """With no scope configured, the default is to block everything."""

    def test_no_scope_blocks_by_default(self):
        guard = AutopilotGuard()  # fail_closed defaults to True
        result = guard.check_request("GET", "https://anything.com/")
        assert result["decision"] == "block"
        assert "no scope" in result["reason"].lower()

    def test_fail_open_opt_out_allows(self):
        """Explicit fail_closed=False restores the old permissive behavior."""
        guard = AutopilotGuard(fail_closed=False)
        result = guard.check_request("GET", "https://anything.com/")
        assert result["decision"] == "allow"

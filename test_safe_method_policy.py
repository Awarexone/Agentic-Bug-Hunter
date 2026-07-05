"""Tests for SafeMethodPolicy — enforces safe HTTP methods in autopilot mode."""

import pytest

from memory.audit_log import SafeMethodPolicy


class TestSafeMethodPolicyDefaults:
    """Default policy: GET/HEAD/OPTIONS are safe, everything else requires approval."""

    def test_get_is_safe(self):
        policy = SafeMethodPolicy()
        assert policy.is_safe("GET") is True

    def test_head_is_safe(self):
        policy = SafeMethodPolicy()
        assert policy.is_safe("HEAD") is True

    def test_options_is_safe(self):
        policy = SafeMethodPolicy()
        assert policy.is_safe("OPTIONS") is True

    def test_post_is_unsafe(self):
        policy = SafeMethodPolicy()
        assert policy.is_safe("POST") is False

    def test_put_is_unsafe(self):
        policy = SafeMethodPolicy()
        assert policy.is_safe("PUT") is False

    def test_delete_is_unsafe(self):
        policy = SafeMethodPolicy()
        assert policy.is_safe("DELETE") is False

    def test_patch_is_unsafe(self):
        policy = SafeMethodPolicy()
        assert policy.is_safe("PATCH") is False

    def test_case_insensitive(self):
        policy = SafeMethodPolicy()
        assert policy.is_safe("get") is True
        assert policy.is_safe("Get") is True
        assert policy.is_safe("post") is False


class TestSafeMethodPolicyCheck:
    """check() returns a structured decision dict."""

    def test_check_safe_returns_allow(self):
        policy = SafeMethodPolicy()
        result = policy.check("GET", "https://target.com/api")
        assert result["decision"] == "allow"
        assert result["method"] == "GET"

    def test_check_unsafe_returns_require_approval(self):
        policy = SafeMethodPolicy()
        result = policy.check("DELETE", "https://target.com/api/users/1")
        assert result["decision"] == "require_approval"
        assert result["method"] == "DELETE"
        assert "reason" in result

    def test_check_includes_url(self):
        policy = SafeMethodPolicy()
        result = policy.check("PUT", "https://target.com/api/data")
        assert result["url"] == "https://target.com/api/data"


class TestSafeMethodPolicyCustom:
    """Custom safe method sets."""

    def test_custom_safe_methods(self):
        policy = SafeMethodPolicy(safe_methods={"GET", "HEAD", "OPTIONS", "POST"})
        assert policy.is_safe("POST") is True
        assert policy.is_safe("DELETE") is False

    def test_empty_safe_methods_blocks_everything(self):
        policy = SafeMethodPolicy(safe_methods=set())
        assert policy.is_safe("GET") is False


class TestSafeMethodPolicyDisabled:
    """When disabled, all methods are safe (for --paranoid mode where human approves everything)."""

    def test_disabled_allows_all(self):
        policy = SafeMethodPolicy(enabled=False)
        assert policy.is_safe("DELETE") is True
        assert policy.is_safe("PUT") is True

    def test_disabled_check_returns_allow(self):
        policy = SafeMethodPolicy(enabled=False)
        result = policy.check("DELETE", "https://target.com/api")
        assert result["decision"] == "allow"

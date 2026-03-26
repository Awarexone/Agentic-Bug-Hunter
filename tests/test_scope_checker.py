"""Tests for scope_checker.py — all is_in_scope variants + filter_file.

This is safety-critical code: 100% coverage required.
"""

import pytest

from scope_checker import ScopeChecker


class TestWildcardMatch:

    def test_wildcard_matches_subdomain(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://sub.target.com/path") is True

    def test_wildcard_matches_deep_subdomain(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://a.b.c.target.com") is True

    def test_wildcard_does_not_match_evil_prefix(self, scope_domains, scope_excluded):
        """Critical: *.target.com must NOT match evil-target.com."""
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://evil-target.com") is False

    def test_wildcard_does_not_match_apex_alone(self):
        """*.target.com should NOT match target.com (need explicit target.com in list)."""
        sc = ScopeChecker(["*.target.com"])  # no explicit target.com
        assert sc.is_in_scope("https://target.com") is False


class TestExactMatch:

    def test_exact_domain_match(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://api.target.com/v2/users") is True

    def test_apex_domain_match(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://target.com") is True


class TestExcludedDomains:

    def test_excluded_domain_blocked(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://blog.target.com") is False

    def test_excluded_takes_priority(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://status.target.com") is False


class TestOutOfScope:

    def test_completely_different_domain(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://other.com") is False

    def test_similar_domain_name(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://nottarget.com") is False


class TestEdgeCases:

    def test_empty_url(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("") is False

    def test_none_url(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope(None) is False

    def test_malformed_url(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("://broken") is False

    def test_ip_address_returns_false(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://192.168.1.1/admin") is False

    def test_ipv6_returns_false(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://[::1]/admin") is False

    def test_url_with_port(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://api.target.com:8443/endpoint") is True

    def test_case_insensitive(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://API.TARGET.COM/v2") is True
        assert sc.is_in_scope("https://Sub.Target.Com/path") is True

    def test_url_without_scheme(self, scope_domains, scope_excluded):
        """Bare hostnames should still work."""
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("api.target.com") is True

    def test_url_with_path_only(self):
        sc = ScopeChecker(["target.com"])
        assert sc.is_in_scope("/just/a/path") is False


class TestVulnClassFiltering:

    def test_allowed_class(self):
        sc = ScopeChecker(["target.com"], excluded_classes=["dos", "social_engineering"])
        assert sc.is_vuln_class_allowed("idor") is True

    def test_excluded_class(self):
        sc = ScopeChecker(["target.com"], excluded_classes=["dos", "social_engineering"])
        assert sc.is_vuln_class_allowed("dos") is False

    def test_excluded_class_case_insensitive(self):
        sc = ScopeChecker(["target.com"], excluded_classes=["dos"])
        assert sc.is_vuln_class_allowed("DOS") is False


class TestFilterUrls:

    def test_split_urls(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        urls = [
            "https://api.target.com/v1",
            "https://evil.com/attack",
            "https://sub.target.com/page",
            "https://blog.target.com/post",  # excluded
        ]
        in_scope, out_of_scope = sc.filter_urls(urls)
        assert len(in_scope) == 2
        assert len(out_of_scope) == 2


class TestFilterFile:

    def test_filter_file_in_place(self, tmp_path, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        url_file = tmp_path / "urls.txt"
        url_file.write_text(
            "https://api.target.com/v1\n"
            "https://evil.com/bad\n"
            "https://sub.target.com/ok\n"
        )

        in_count, out_count = sc.filter_file(str(url_file))
        assert in_count == 2
        assert out_count == 1

        # File should now contain only in-scope URLs
        lines = url_file.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_filter_file_to_output(self, tmp_path, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        input_file = tmp_path / "input.txt"
        output_file = tmp_path / "output.txt"
        input_file.write_text("https://api.target.com/v1\nhttps://evil.com\n")

        in_count, out_count = sc.filter_file(str(input_file), str(output_file))
        assert in_count == 1
        assert out_count == 1

        # Original unchanged
        assert len(input_file.read_text().strip().split("\n")) == 2
        # Output has only in-scope
        assert len(output_file.read_text().strip().split("\n")) == 1

    def test_filter_empty_file(self, tmp_path, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        url_file = tmp_path / "empty.txt"
        url_file.write_text("")

        in_count, out_count = sc.filter_file(str(url_file))
        assert in_count == 0
        assert out_count == 0

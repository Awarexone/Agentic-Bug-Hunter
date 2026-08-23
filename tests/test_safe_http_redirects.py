"""safe_urlopen must reject redirects to private/link-local/loopback
addresses and cloud metadata hosts, even when the initial request target
was fine. See SECURITY-REVIEW-2026-08-22.md finding #8 (MEDIUM)."""
import os
import sys
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tools.safe_http import _is_blocked_redirect_target, safe_urlopen


class TestIsBlockedRedirectTarget:
    def test_blocks_cloud_metadata(self):
        assert _is_blocked_redirect_target("169.254.169.254") is True

    def test_blocks_localhost_variants(self):
        assert _is_blocked_redirect_target("127.0.0.1") is True
        assert _is_blocked_redirect_target("localhost") is True
        assert _is_blocked_redirect_target("::1") is True

    def test_blocks_rfc1918(self):
        assert _is_blocked_redirect_target("10.0.0.5") is True
        assert _is_blocked_redirect_target("192.168.1.1") is True
        assert _is_blocked_redirect_target("172.16.0.1") is True

    def test_allows_public_hostname(self):
        assert _is_blocked_redirect_target("example.com") is False
        assert _is_blocked_redirect_target("8.8.8.8") is False


class TestSafeUrlopenRejectsRedirectToBlockedHost:
    def test_redirect_to_metadata_ip_raises(self):
        req = urllib.request.Request("https://target.example/start")
        with patch("tools.safe_http._one_hop") as mock_hop:
            resp = MagicMock()
            resp.status = 302
            resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
            mock_hop.return_value = resp
            try:
                safe_urlopen(req)
                assert False, "expected a rejection"
            except urllib.error.URLError as e:
                assert "blocked" in str(e).lower() or "ssrf" in str(e).lower()

    def test_redirect_to_public_host_is_followed(self):
        req = urllib.request.Request("https://target.example/start")
        final = MagicMock()
        final.status = 200
        with patch("tools.safe_http._one_hop") as mock_hop:
            redirect_resp = MagicMock()
            redirect_resp.status = 302
            redirect_resp.headers = {"Location": "https://target.example/final"}
            mock_hop.side_effect = [redirect_resp, final]
            result = safe_urlopen(req)
            assert result is final

    def test_too_many_redirects_raises(self):
        req = urllib.request.Request("https://target.example/start")
        loop_resp = MagicMock()
        loop_resp.status = 302
        loop_resp.headers = {"Location": "https://target.example/start"}
        with patch("tools.safe_http._one_hop", return_value=loop_resp):
            try:
                safe_urlopen(req, max_redirects=3)
                assert False, "expected too-many-redirects error"
            except urllib.error.URLError as e:
                assert "redirect" in str(e).lower()

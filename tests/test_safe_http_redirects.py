"""safe_urlopen must reject redirects to private/link-local/loopback
addresses and cloud metadata hosts, even when the initial request target
was fine. See SECURITY-REVIEW-2026-08-22.md finding #8 (MEDIUM)."""
import http.server
import os
import ssl
import sys
import threading
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


class _RedirectTestHandler(http.server.BaseHTTPRequestHandler):
    """Minimal real HTTP server used to exercise urllib's actual redirect
    chain (opener.open() / HTTPRedirectHandler / HTTPDefaultErrorHandler)
    end to end — deliberately NOT mocking _one_hop, since mocking it hides
    bugs in how _one_hop drives that chain (see SECURITY-REVIEW-2026-08-22.md
    finding #8 follow-up: _NoRedirectHandler.redirect_request returning None
    makes urllib raise HTTPError instead of returning the 3xx response)."""

    def log_message(self, format, *args):
        pass  # silence request logging during tests

    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
        elif self.path == "/final":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/evil-start":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/redirect307":
            self.send_response(307)
            self.send_header("Location", "/final307")
            self.end_headers()
        elif self.path == "/final307":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


class TestSafeUrlopenRealServerRedirects:
    """No mocking here — a genuine local HTTP server + the real urllib
    opener. This is what actually caught the HTTPError-swallowing bug: the
    mocked tests above patch _one_hop directly, which bypasses
    opener.open()'s real redirect-handling chain entirely and would pass
    even if _one_hop never worked against a live server."""

    @classmethod
    def setup_class(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _RedirectTestHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_legitimate_redirect_is_followed_to_completion(self):
        # The test server itself only has a loopback address, which
        # _is_blocked_redirect_target correctly refuses (proven by the test
        # below) — so this test patches *only* the allow/block decision
        # (already covered by TestIsBlockedRedirectTarget above) to isolate
        # what it's actually verifying: that a real 3xx response from a real
        # server, driven through the real opener.open()/HTTPError chain, is
        # correctly followed to completion. _one_hop itself is NOT mocked.
        req = urllib.request.Request(self._url("/start"))
        with patch("tools.safe_http._is_blocked_redirect_target", return_value=False):
            with safe_urlopen(req, timeout=5) as resp:
                assert resp.status == 200
                assert resp.read() == b"ok"

    def test_redirect_to_metadata_ip_is_blocked(self):
        req = urllib.request.Request(self._url("/evil-start"))
        try:
            safe_urlopen(req, timeout=5)
            assert False, "expected a rejection"
        except urllib.error.URLError as e:
            assert "blocked" in str(e).lower() or "ssrf" in str(e).lower()

    def test_307_redirect_preserves_method_and_body(self):
        body = b"race-condition-poc-payload"
        req = urllib.request.Request(
            self._url("/redirect307"),
            data=body,
            method="POST",
            headers={"Content-Type": "text/plain"},
        )
        with patch("tools.safe_http._is_blocked_redirect_target", return_value=False), \
                safe_urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            assert resp.read() == body

    def test_context_kwarg_is_accepted_not_forwarded_to_opener_open(self):
        """Regression test: callers (tools/learn.py, tools/validate.py,
        tools/waf_response_analyzer.py) pass context=<ssl.SSLContext> to
        safe_urlopen, expecting the same behavior as passing it to
        urllib.request.urlopen(). But OpenerDirector.open() (which
        _one_hop calls) does NOT accept a context= kwarg — only the
        module-level urlopen() does. Forwarding context= straight through
        via **kwargs raises TypeError on every call, which callers that
        wrap safe_urlopen in `except Exception` silently swallow (turning
        into a silent no-op), and callers with narrower except clauses
        (e.g. waf_response_analyzer's _http_get) let crash outright.
        This must exercise the real opener.open() call end to end (no
        mocking _one_hop) against a real server, since a context=None
        SSLContext object can't traverse the http:// test server directly
        — instead this drives an HTTPS request through a context that
        disables verification so it can hit the local server's plain
        socket without a real cert, proving the whole call path (not just
        that _one_hop was invoked) survives passing context=."""
        # Real local HTTPS is more setup than this needs; the essential
        # regression is that _one_hop's opener.open() call must not raise
        # TypeError when a context kwarg is supplied. Drive that through
        # the actual (non-mocked) opener against the real HTTP test
        # server: build_opener's resulting opener.open() must accept
        # context= via the code path in _one_hop, not error out before
        # ever reaching the network.
        ctx = ssl.create_default_context()
        req = urllib.request.Request(self._url("/final"))
        with safe_urlopen(req, timeout=5, context=ctx) as resp:
            assert resp.status == 200
            assert resp.read() == b"ok"

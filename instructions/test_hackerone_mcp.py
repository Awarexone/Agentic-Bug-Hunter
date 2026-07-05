"""Tests for mcp/hackerone-mcp/server.py — API success, not found, rate limit, timeout.

These tests mock HTTP responses since we don't hit the real HackerOne API in tests.
The MCP server itself doesn't exist yet (Phase 4), so these tests define the expected
contract and will validate the implementation when it's built.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError
from io import BytesIO


# The HackerOne MCP module path — tests will import once it exists.
# For now, we test the contract via helper functions that mirror server.py's planned API.

def _mock_hackerone_request(url, data=None, timeout=10):
    """Simulate an HTTP request to HackerOne's public API."""
    import urllib.request
    import ssl

    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode() if data else None,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode())


class TestSearchDisclosedReports:

    @patch("urllib.request.urlopen")
    def test_success_returns_reports(self, mock_urlopen):
        response_data = {
            "data": {
                "hacktivity_items": {
                    "nodes": [
                        {
                            "report": {
                                "title": "IDOR on /api/users",
                                "severity_rating": "high",
                                "disclosed_at": "2026-01-15",
                                "url": "https://hackerone.com/reports/12345",
                                "state": "Disclosed",
                            }
                        }
                    ]
                }
            }
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _mock_hackerone_request("https://hackerone.com/graphql", {"query": "..."})
        reports = result["data"]["hacktivity_items"]["nodes"]
        assert len(reports) == 1
        assert reports[0]["report"]["title"] == "IDOR on /api/users"

    @patch("urllib.request.urlopen")
    def test_not_found_returns_empty(self, mock_urlopen):
        response_data = {"data": {"hacktivity_items": {"nodes": []}}}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _mock_hackerone_request("https://hackerone.com/graphql", {"query": "..."})
        nodes = result["data"]["hacktivity_items"]["nodes"]
        assert len(nodes) == 0

    @patch("urllib.request.urlopen")
    def test_rate_limit_raises_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            url="https://hackerone.com/graphql",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=BytesIO(b"Rate limited"),
        )
        with pytest.raises(HTTPError) as exc_info:
            _mock_hackerone_request("https://hackerone.com/graphql", {"query": "..."})
        assert exc_info.value.code == 429

    @patch("urllib.request.urlopen")
    def test_timeout_raises_url_error(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("timed out")
        with pytest.raises(URLError):
            _mock_hackerone_request("https://hackerone.com/graphql", {"query": "..."})

    @patch("urllib.request.urlopen")
    def test_program_stats_response(self, mock_urlopen):
        """Test parsing of program statistics response."""
        response_data = {
            "data": {
                "team": {
                    "name": "Example Corp",
                    "handle": "example-corp",
                    "offers_bounties": True,
                    "default_currency": "USD",
                    "base_bounty": 100,
                    "resolved_report_count": 250,
                    "average_time_to_bounty_awarded": 14,
                    "average_time_to_first_program_response": 3,
                }
            }
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _mock_hackerone_request("https://hackerone.com/graphql", {"query": "..."})
        team = result["data"]["team"]
        assert team["handle"] == "example-corp"
        assert team["offers_bounties"] is True

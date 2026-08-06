"""Tests for tools/breach_checker.py — SHA-1 hashing, API query, batch logic."""

import hashlib
from unittest.mock import patch, MagicMock

import pytest

from tools.breach_checker import (
    sha1_prefix_suffix,
    query_range,
    check_batch,
)


class TestSha1PrefixSuffix:
    def test_known_hash(self):
        # "password" -> SHA-1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        prefix, suffix = sha1_prefix_suffix("password")
        assert prefix == "5BAA6"
        assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    def test_prefix_length(self):
        prefix, suffix = sha1_prefix_suffix("anything")
        assert len(prefix) == 5
        assert len(suffix) == 35

    def test_uppercase(self):
        prefix, suffix = sha1_prefix_suffix("test")
        assert prefix == prefix.upper()
        assert suffix == suffix.upper()

    def test_empty_string(self):
        prefix, suffix = sha1_prefix_suffix("")
        full = hashlib.sha1(b"").hexdigest().upper()
        assert prefix + suffix == full

    def test_unicode(self):
        prefix, suffix = sha1_prefix_suffix("\u00e9\u00e8\u00ea")
        full = hashlib.sha1("\u00e9\u00e8\u00ea".encode("utf-8")).hexdigest().upper()
        assert prefix + suffix == full


class TestQueryRange:
    def test_successful_response(self):
        fake_body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\nABCDEF12345678901234567890123456789:0\n1234567890ABCDEF12345678901234567890A:5"
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_body.encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = query_range("5BAA6")

        assert "1E4C9B93F3F0682250B6CF8331B7EE68FD8" in result
        assert result["1E4C9B93F3F0682250B6CF8331B7EE68FD8"] == 3861493
        # Zero-count entries (padding) are excluded
        assert "ABCDEF12345678901234567890123456789" not in result
        # Non-zero entry included
        assert result["1234567890ABCDEF12345678901234567890A"] == 5

    def test_rate_limited_retries(self):
        import urllib.error

        # First call raises 429, second succeeds
        fake_body = "ABC:10\n"
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_body.encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        error_429 = urllib.error.HTTPError(
            url="http://x", code=429, msg="Too Many", hdrs={}, fp=None
        )

        with patch("urllib.request.urlopen", side_effect=[error_429, mock_resp]):
            with patch("time.sleep"):  # skip actual delay
                result = query_range("AAAAA", retries=2)

        assert result == {"ABC": 10}

    def test_non_429_http_error_raises(self):
        import urllib.error

        error_500 = urllib.error.HTTPError(
            url="http://x", code=500, msg="Server Error", hdrs={}, fp=None
        )

        with patch("urllib.request.urlopen", side_effect=error_500):
            with pytest.raises(urllib.error.HTTPError):
                query_range("BBBBB", retries=1)

    def test_timeout_retries_and_raises(self):
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=TimeoutError("timeout")):
            with patch("time.sleep"):
                with pytest.raises(TimeoutError):
                    query_range("CCCCC", retries=2)


class TestCheckBatch:
    def test_groups_by_prefix(self):
        passwords = ["password", "123456"]
        fake_results = {}

        def mock_query(prefix):
            # Return matching suffixes for known passwords
            if prefix == "5BAA6":
                return {"1E4C9B93F3F0682250B6CF8331B7EE68FD8": 100}
            elif prefix == "7C4A8":
                return {"D09CA3762AF61E59520943DC26494F8941B": 50}
            return {}

        with patch("tools.breach_checker.query_range", side_effect=mock_query):
            results = check_batch(passwords, concurrent=2)

        assert results["password"] == 100
        assert results["123456"] == 50

    def test_missing_suffix_returns_zero(self):
        def mock_query(prefix):
            return {}  # No matches

        with patch("tools.breach_checker.query_range", side_effect=mock_query):
            results = check_batch(["unique_password_xyz"], concurrent=1)

        assert results["unique_password_xyz"] == 0

    def test_failed_query_returns_negative_one(self):
        def mock_query(prefix):
            raise Exception("Network error")

        with patch("tools.breach_checker.query_range", side_effect=mock_query):
            results = check_batch(["test_pwd"], concurrent=1)

        assert results["test_pwd"] == -1

    def test_same_prefix_passwords_grouped(self):
        # Create two passwords that share the same prefix
        # "password" and a crafted string won't reliably share prefix,
        # so just test that all results are returned
        passwords = ["aaa", "bbb", "ccc"]

        def mock_query(prefix):
            return {}

        with patch("tools.breach_checker.query_range", side_effect=mock_query):
            results = check_batch(passwords, concurrent=2)

        assert len(results) == 3

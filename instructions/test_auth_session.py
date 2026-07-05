"""Tests for tools/auth_session.py — auth-aware hunting plumbing.

Covers:
  - Env loading (BBHUNT_AUTH_HEADER, BBHUNT_COOKIE, BBHUNT_BEARER, BBHUNT_API_KEY)
  - File loading (JSON + .env style)
  - Explicit headers/cookie/bearer
  - session_id stability + sensitivity to header content
  - shell args = `-H 'Name: value'` pairs, no shell quoting tricks
  - Secrets never leak via repr/str/describe/redacted
  - CR/LF injection in header values is rejected
"""

import argparse
import os

import pytest

from tools.auth_session import (
    AuthSession,
    ENV_HEADER_IN,
    ENV_COOKIE,
    ENV_BEARER,
    ENV_API_KEY,
    ENV_HEADERS,
    ENV_SESSION_ID,
    add_cli_args,
    session_from_args,
)


# ── Basic construction ────────────────────────────────────────────────────────

class TestAuthSessionBasic:

    def test_empty_session_is_inert(self):
        s = AuthSession()
        assert s.is_empty()
        assert s.headers_list() == []
        assert s.curl_args() == []
        assert s.session_id() == ""
        assert s.env_overlay() == {}

    def test_add_header_simple(self):
        s = AuthSession()
        s.add_header("Cookie: session=abc")
        assert s.headers_list() == ["Cookie: session=abc"]
        assert s.headers_dict() == {"Cookie": "session=abc"}

    def test_add_header_strips_surrounding_whitespace(self):
        s = AuthSession()
        s.add_header("  X-Foo:  bar  ")
        # Leading/trailing whitespace on the whole line is stripped; the
        # internal "Name: value" canonical form preserves the value as given.
        assert s.headers_list() == ["X-Foo: bar"]

    def test_add_header_rejects_malformed(self):
        s = AuthSession()
        with pytest.raises(ValueError, match="invalid header"):
            s.add_header("no-colon-here")

    def test_add_header_rejects_crlf_injection(self):
        s = AuthSession()
        with pytest.raises(ValueError, match="CR/LF"):
            s.add_header("X-Foo: bar\r\nInjected: pwn")

    def test_add_header_deduplicates_same_name(self):
        s = AuthSession()
        s.add_header("Cookie: old=1")
        s.add_header("Cookie: new=2")
        assert s.headers_list() == ["Cookie: new=2"]

    def test_add_header_keeps_distinct_names(self):
        s = AuthSession()
        s.add_header("Cookie: x=1")
        s.add_header("Authorization: Bearer t")
        assert set(s.headers_list()) == {"Cookie: x=1", "Authorization: Bearer t"}

    def test_add_cookie_helper(self):
        s = AuthSession()
        s.add_cookie("session=abc")
        assert "Cookie: session=abc" in s.headers_list()

    def test_add_bearer_helper(self):
        s = AuthSession()
        s.add_bearer("eyJabc")
        assert "Authorization: Bearer eyJabc" in s.headers_list()

    def test_add_api_key_default_header_name(self):
        s = AuthSession()
        s.add_api_key("secret-key")
        assert "X-API-Key: secret-key" in s.headers_list()

    def test_add_api_key_custom_header_name(self):
        s = AuthSession()
        s.add_api_key("k", header_name="X-Custom-Token")
        assert "X-Custom-Token: k" in s.headers_list()


# ── Env loading ───────────────────────────────────────────────────────────────

class TestFromEnv:

    def test_empty_env_yields_empty_session(self):
        s = AuthSession.from_env({})
        assert s.is_empty()

    def test_bearer_env(self):
        s = AuthSession.from_env({ENV_BEARER: "eyJabc"})
        assert s.headers_dict() == {"Authorization": "Bearer eyJabc"}

    def test_cookie_env(self):
        s = AuthSession.from_env({ENV_COOKIE: "session=abc"})
        assert s.headers_dict() == {"Cookie": "session=abc"}

    def test_api_key_env(self):
        s = AuthSession.from_env({ENV_API_KEY: "k1"})
        assert s.headers_dict() == {"X-API-Key": "k1"}

    def test_header_in_env_multiline(self):
        raw = "X-A: 1\nX-B: 2\n# comment\n\nX-C: 3"
        s = AuthSession.from_env({ENV_HEADER_IN: raw})
        names = sorted(s.headers_dict().keys())
        assert names == ["X-A", "X-B", "X-C"]

    def test_all_env_sources_merge(self):
        env = {
            ENV_HEADER_IN: "X-Foo: 1",
            ENV_COOKIE: "session=abc",
            ENV_BEARER: "tok",
            ENV_API_KEY: "key",
        }
        s = AuthSession.from_env(env)
        names = sorted(s.headers_dict().keys())
        assert names == ["Authorization", "Cookie", "X-API-Key", "X-Foo"]


# ── File loading ──────────────────────────────────────────────────────────────

class TestFromFile:

    def test_missing_file_returns_empty(self, tmp_path):
        s = AuthSession.from_file(tmp_path / "nope.json")
        assert s.is_empty()

    def test_json_headers_list(self, tmp_path):
        p = tmp_path / "auth.json"
        p.write_text('{"headers": ["Cookie: a=1", "X-Foo: bar"]}')
        s = AuthSession.from_file(p)
        assert set(s.headers_list()) == {"Cookie: a=1", "X-Foo: bar"}

    def test_json_bare_array(self, tmp_path):
        p = tmp_path / "auth.json"
        p.write_text('["Cookie: a=1", "X-Foo: bar"]')
        s = AuthSession.from_file(p)
        assert set(s.headers_list()) == {"Cookie: a=1", "X-Foo: bar"}

    def test_json_cookie_bearer_apikey(self, tmp_path):
        p = tmp_path / "auth.json"
        p.write_text(
            '{"cookie": "s=1", "bearer": "tok", "api_key": "k", "api_key_header": "X-Token"}'
        )
        s = AuthSession.from_file(p)
        d = s.headers_dict()
        assert d["Cookie"] == "s=1"
        assert d["Authorization"] == "Bearer tok"
        assert d["X-Token"] == "k"

    def test_env_style_file(self, tmp_path):
        p = tmp_path / "auth.env"
        p.write_text(
            "# comment\n"
            "BBHUNT_COOKIE=session=abc\n"
            "BBHUNT_BEARER=eyJtoken\n"
            "API_KEY=mykey\n"
        )
        s = AuthSession.from_file(p)
        d = s.headers_dict()
        assert d["Cookie"] == "session=abc"
        assert d["Authorization"] == "Bearer eyJtoken"
        assert d["X-API-Key"] == "mykey"

    def test_env_style_strips_quotes(self, tmp_path):
        p = tmp_path / "auth.env"
        p.write_text('BBHUNT_COOKIE="session=abc"\n')
        s = AuthSession.from_file(p)
        assert s.headers_dict() == {"Cookie": "session=abc"}


# ── session_id ────────────────────────────────────────────────────────────────

class TestSessionId:

    def test_empty_session_id_is_empty_string(self):
        assert AuthSession().session_id() == ""

    def test_session_id_is_stable_across_instances(self):
        s1 = AuthSession(["Cookie: abc", "X-Foo: bar"])
        s2 = AuthSession(["X-Foo: bar", "Cookie: abc"])  # different order
        assert s1.session_id() == s2.session_id()

    def test_session_id_changes_with_value(self):
        s1 = AuthSession(["Cookie: a"])
        s2 = AuthSession(["Cookie: b"])
        assert s1.session_id() != s2.session_id()

    def test_session_id_length_is_12_hex(self):
        sid = AuthSession(["Cookie: abc"]).session_id()
        assert len(sid) == 12
        assert all(c in "0123456789abcdef" for c in sid)


# ── Output ────────────────────────────────────────────────────────────────────

class TestOutput:

    def test_curl_args_pairs(self):
        s = AuthSession(["Cookie: abc", "X-Foo: bar"])
        args = s.curl_args()
        # Two pairs of (-H, value).
        assert len(args) == 4
        assert args.count("-H") == 2
        joined = " ".join(args)
        assert "Cookie: abc" in joined
        assert "X-Foo: bar" in joined

    def test_env_overlay_keys(self):
        s = AuthSession(["Cookie: abc"])
        overlay = s.env_overlay()
        assert ENV_HEADERS in overlay
        assert ENV_SESSION_ID in overlay
        assert overlay[ENV_HEADERS] == "Cookie: abc"
        assert overlay[ENV_SESSION_ID] == s.session_id()

    def test_export_to_env_sets_vars(self):
        s = AuthSession(["Cookie: abc"])
        env = {}
        s.export_to_env(env)
        assert env[ENV_HEADERS] == "Cookie: abc"
        assert env[ENV_SESSION_ID] == s.session_id()

    def test_export_to_env_clears_stale_values_when_empty(self):
        env = {ENV_HEADERS: "stale", ENV_SESSION_ID: "stale"}
        AuthSession().export_to_env(env)
        assert ENV_HEADERS not in env
        assert ENV_SESSION_ID not in env

    def test_export_to_env_does_not_mutate_os_environ(self, monkeypatch):
        # Caller passes their own dict — os.environ untouched.
        monkeypatch.delenv(ENV_HEADERS, raising=False)
        env = {}
        AuthSession(["Cookie: abc"]).export_to_env(env)
        assert ENV_HEADERS in env
        assert ENV_HEADERS not in os.environ


# ── Secrets safety ────────────────────────────────────────────────────────────

class TestSecrets:

    SECRET = "super-secret-value-that-must-not-leak"

    def test_repr_does_not_expose_value(self):
        s = AuthSession([f"Cookie: {self.SECRET}"])
        assert self.SECRET not in repr(s)

    def test_str_does_not_expose_value(self):
        s = AuthSession([f"Cookie: {self.SECRET}"])
        assert self.SECRET not in str(s)

    def test_describe_does_not_expose_value(self):
        s = AuthSession([f"Authorization: Bearer {self.SECRET}"])
        d = s.describe()
        assert self.SECRET not in d
        assert "Authorization" in d  # header name is fine to show

    def test_describe_anonymous(self):
        assert "anonymous" in AuthSession().describe()

    def test_redacted_masks_long_values(self):
        s = AuthSession([f"Cookie: {self.SECRET}"])
        red = s.redacted()
        assert self.SECRET not in red["Cookie"]
        assert "***" in red["Cookie"]

    def test_redacted_masks_short_values_completely(self):
        s = AuthSession(["X-Foo: ab"])
        assert s.redacted()["X-Foo"] == "***"


# ── from_sources merge ────────────────────────────────────────────────────────

class TestFromSources:

    def test_explicit_args_override_env(self):
        env = {ENV_COOKIE: "from-env"}
        s = AuthSession.from_sources(env=env, cookie="from-cli")
        assert s.headers_dict()["Cookie"] == "from-cli"

    def test_merge_disjoint_names(self):
        env = {ENV_COOKIE: "c=1"}
        s = AuthSession.from_sources(env=env, bearer="tok")
        d = s.headers_dict()
        assert d["Cookie"] == "c=1"
        assert d["Authorization"] == "Bearer tok"


# ── CLI args integration ──────────────────────────────────────────────────────

class TestCliArgs:

    def _parser(self):
        p = argparse.ArgumentParser()
        add_cli_args(p)
        return p

    def test_no_flags_yields_empty_session(self):
        args = self._parser().parse_args([])
        s = session_from_args(args, env={})
        assert s.is_empty()

    def test_auth_header_repeatable(self):
        args = self._parser().parse_args([
            "--auth-header", "X-A: 1",
            "--auth-header", "X-B: 2",
        ])
        s = session_from_args(args, env={})
        names = sorted(s.headers_dict().keys())
        assert names == ["X-A", "X-B"]

    def test_cookie_bearer_apikey_shorthand(self):
        args = self._parser().parse_args([
            "--cookie", "s=1",
            "--bearer", "tok",
            "--api-key", "k",
        ])
        s = session_from_args(args, env={})
        d = s.headers_dict()
        assert d == {
            "Cookie": "s=1",
            "Authorization": "Bearer tok",
            "X-API-Key": "k",
        }

    def test_auth_file_flag(self, tmp_path):
        p = tmp_path / "auth.json"
        p.write_text('{"cookie": "session=abc"}')
        args = self._parser().parse_args(["--auth-file", str(p)])
        s = session_from_args(args, env={})
        assert s.headers_dict() == {"Cookie": "session=abc"}

    def test_env_auto_detect_without_flag(self):
        """If BBHUNT_* env vars are set, auth is picked up even without --auth-from-env."""
        args = self._parser().parse_args([])
        s = session_from_args(args, env={ENV_COOKIE: "session=abc"})
        assert s.headers_dict() == {"Cookie": "session=abc"}

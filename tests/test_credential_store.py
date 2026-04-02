"""Tests for CredentialStore — secure .env-based credential loading."""

import pytest

from tools.credential_store import CredentialStore


class TestCredentialStoreLoad:
    """Loading credentials from .env files."""

    def test_load_from_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret123\nCOOKIE=session=abc\n")
        store = CredentialStore(env_file)
        assert store.get("API_KEY") == "secret123"

    def test_load_strips_whitespace(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("  API_KEY = secret123  \n")
        store = CredentialStore(env_file)
        assert store.get("API_KEY") == "secret123"

    def test_load_ignores_comments(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("# This is a comment\nAPI_KEY=secret123\n# Another\n")
        store = CredentialStore(env_file)
        assert store.get("API_KEY") == "secret123"
        assert len(store.keys()) == 1

    def test_load_ignores_blank_lines(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("\nAPI_KEY=secret123\n\n\nTOKEN=xyz\n")
        store = CredentialStore(env_file)
        assert len(store.keys()) == 2

    def test_load_handles_quoted_values(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text('API_KEY="secret with spaces"\nTOKEN=\'single quoted\'\n')
        store = CredentialStore(env_file)
        assert store.get("API_KEY") == "secret with spaces"
        assert store.get("TOKEN") == "single quoted"

    def test_load_handles_equals_in_value(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("COOKIE=session=abc123;path=/\n")
        store = CredentialStore(env_file)
        assert store.get("COOKIE") == "session=abc123;path=/"


class TestCredentialStoreMissing:
    """Handling missing files and keys."""

    def test_missing_file_returns_empty_store(self, tmp_path):
        store = CredentialStore(tmp_path / "nonexistent.env")
        assert len(store.keys()) == 0

    def test_missing_key_returns_none(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret123\n")
        store = CredentialStore(env_file)
        assert store.get("NONEXISTENT") is None

    def test_missing_key_returns_default(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret123\n")
        store = CredentialStore(env_file)
        assert store.get("NONEXISTENT", "fallback") == "fallback"


class TestCredentialStoreSecurity:
    """Credentials must never leak via repr/str/logs."""

    def test_repr_does_not_expose_values(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=supersecret\nTOKEN=topsecret\n")
        store = CredentialStore(env_file)
        r = repr(store)
        assert "supersecret" not in r
        assert "topsecret" not in r
        assert "API_KEY" in r  # key names are OK to show

    def test_str_does_not_expose_values(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=supersecret\n")
        store = CredentialStore(env_file)
        s = str(store)
        assert "supersecret" not in s

    def test_masked_value(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=supersecretvalue\n")
        store = CredentialStore(env_file)
        masked = store.get_masked("API_KEY")
        assert masked is not None
        assert "supersecretvalue" not in masked
        assert masked.startswith("sup")  # shows first 3 chars
        assert "***" in masked

    def test_has_key(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret\n")
        store = CredentialStore(env_file)
        assert store.has("API_KEY") is True
        assert store.has("NOPE") is False


class TestCredentialStoreHeaders:
    """Building auth headers from stored credentials."""

    def test_as_cookie_header(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("COOKIE=session=abc123\n")
        store = CredentialStore(env_file)
        headers = store.as_headers("COOKIE", header_type="cookie")
        assert headers == {"Cookie": "session=abc123"}

    def test_as_bearer_header(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("TOKEN=eyJhbG\n")
        store = CredentialStore(env_file)
        headers = store.as_headers("TOKEN", header_type="bearer")
        assert headers == {"Authorization": "Bearer eyJhbG"}

    def test_as_headers_missing_key_returns_empty(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("TOKEN=abc\n")
        store = CredentialStore(env_file)
        headers = store.as_headers("NONEXISTENT", header_type="bearer")
        assert headers == {}

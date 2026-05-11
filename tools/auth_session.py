"""
Auth-session layer — load credentials once, plumb them through the entire hunt.

Three input sources (any combination, deduped):
  1. Environment vars:  BBHUNT_AUTH_HEADER (repeatable via newlines),
                        BBHUNT_COOKIE, BBHUNT_BEARER, BBHUNT_API_KEY
  2. JSON file:         {"headers": ["Cookie: x", "X-Foo: y"]}
                        or {"cookie": "...", "bearer": "...", "api_key": "..."}
  3. CLI args:          --auth-header "Name: value" (repeatable),
                        --cookie "...", --bearer "...", --api-key "..."

Output: an AuthSession that produces
  • a Python dict of headers (for SDK callers)
  • a list[str] of `-H` args (for subprocess.run with shell=False)
  • two env vars (BBHUNT_AUTH_HEADERS, BBHUNT_SESSION_ID) consumed by
    tools/_auth_helper.sh in bash callers
  • a stable session_id = sha256(sorted_canonical_headers)[:12]

Secrets never appear in logs or repr/str. The session_id is the only piece
written to hunt-memory; raw header values stay in process memory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path


_HEADER_RE = re.compile(r"^([A-Za-z0-9!#$%&'*+\-.^_`|~]+)\s*:\s*(.+)$")

ENV_HEADERS = "BBHUNT_AUTH_HEADERS"  # newline-separated, set by Python for bash
ENV_SESSION_ID = "BBHUNT_SESSION_ID"

ENV_HEADER_IN = "BBHUNT_AUTH_HEADER"  # input: newline-separated
ENV_COOKIE = "BBHUNT_COOKIE"
ENV_BEARER = "BBHUNT_BEARER"
ENV_API_KEY = "BBHUNT_API_KEY"


class AuthSession:
    """A bag of HTTP auth headers with a stable, hashed session_id."""

    def __init__(self, headers: list[str] | None = None):
        self._headers: list[str] = []
        for h in headers or []:
            self.add_header(h)

    # ── Mutation ──────────────────────────────────────────────────────────

    def add_header(self, raw: str) -> None:
        """Add a 'Name: value' header. Rejects malformed input."""
        if not raw or not isinstance(raw, str):
            return
        # Reject CRLF first — header injection is the same attack we hunt
        # for, so we refuse to send a request that contains it and report
        # it as such (rather than falling through to the regex error).
        if "\r" in raw or "\n" in raw:
            raise ValueError("header contains CR/LF — refusing (injection risk)")
        raw = raw.strip()
        if not raw:
            return
        m = _HEADER_RE.match(raw)
        if not m:
            raise ValueError(f"invalid header (expected 'Name: value'): {raw[:40]!r}")
        name = m.group(1)
        value = m.group(2)
        canonical = f"{name}: {value}"
        # Deduplicate by case-insensitive name+value (last write wins on name).
        lowered_name = name.lower()
        self._headers = [
            h for h in self._headers
            if not h.lower().startswith(lowered_name + ":")
        ]
        self._headers.append(canonical)

    def add_cookie(self, cookie: str) -> None:
        if cookie:
            self.add_header(f"Cookie: {cookie}")

    def add_bearer(self, token: str) -> None:
        if token:
            self.add_header(f"Authorization: Bearer {token}")

    def add_api_key(self, key: str, header_name: str = "X-API-Key") -> None:
        if key:
            self.add_header(f"{header_name}: {key}")

    # ── Loaders ───────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "AuthSession":
        env = env if env is not None else os.environ
        s = cls()
        raw = env.get(ENV_HEADER_IN, "")
        if raw:
            for line in raw.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    s.add_header(line)
        if env.get(ENV_COOKIE):
            s.add_cookie(env[ENV_COOKIE])
        if env.get(ENV_BEARER):
            s.add_bearer(env[ENV_BEARER])
        if env.get(ENV_API_KEY):
            s.add_api_key(env[ENV_API_KEY])
        return s

    @classmethod
    def from_file(cls, path: str | Path) -> "AuthSession":
        """Load from a JSON file (preferred) or a .env-style key=value file."""
        p = Path(path)
        if not p.exists():
            return cls()
        text = p.read_text(encoding="utf-8")
        s = cls()
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            data = json.loads(text)
            if isinstance(data, list):
                for h in data:
                    s.add_header(h)
                return s
            if not isinstance(data, dict):
                raise ValueError(f"auth file {p}: top level must be object or array")
            for h in data.get("headers", []) or []:
                s.add_header(h)
            if data.get("cookie"):
                s.add_cookie(data["cookie"])
            if data.get("bearer"):
                s.add_bearer(data["bearer"])
            if data.get("api_key"):
                s.add_api_key(data["api_key"], data.get("api_key_header", "X-API-Key"))
            return s
        # .env fallback
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k == ENV_COOKIE or k == "COOKIE":
                s.add_cookie(v)
            elif k == ENV_BEARER or k in ("BEARER", "TOKEN"):
                s.add_bearer(v)
            elif k == ENV_API_KEY or k == "API_KEY":
                s.add_api_key(v)
            elif k == ENV_HEADER_IN or k == "AUTH_HEADER":
                # value may itself contain newlines (rare); split safely
                for h in v.splitlines():
                    s.add_header(h)
        return s

    @classmethod
    def from_sources(
        cls,
        env: dict[str, str] | None = None,
        file: str | Path | None = None,
        headers: list[str] | None = None,
        cookie: str | None = None,
        bearer: str | None = None,
        api_key: str | None = None,
    ) -> "AuthSession":
        """Merge env + file + explicit args. Explicit wins on name-collision."""
        s = cls.from_env(env)
        if file:
            for h in cls.from_file(file).headers_list():
                s.add_header(h)
        for h in headers or []:
            s.add_header(h)
        if cookie:
            s.add_cookie(cookie)
        if bearer:
            s.add_bearer(bearer)
        if api_key:
            s.add_api_key(api_key)
        return s

    # ── Output ────────────────────────────────────────────────────────────

    def is_empty(self) -> bool:
        return not self._headers

    def headers_list(self) -> list[str]:
        return list(self._headers)

    def headers_dict(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for h in self._headers:
            name, _, value = h.partition(":")
            out[name.strip()] = value.strip()
        return out

    def curl_args(self) -> list[str]:
        """List of args for subprocess (`-H`, value, `-H`, value, ...)."""
        out: list[str] = []
        for h in self._headers:
            out.extend(["-H", h])
        return out

    def session_id(self) -> str:
        """Stable 12-char hex hash of canonical headers. Empty session → ''.

        Matches the bash fallback in _auth_helper.sh — both hash
        `sorted_headers_joined_by_newline + final_newline` so a Python-set
        BBHUNT_SESSION_ID and a bash-computed one are interchangeable.
        """
        if not self._headers:
            return ""
        # Trailing newline matches `printf '%s' "$headers" | sort` which
        # appends a final \n when its last input line lacks one.
        canonical = "\n".join(sorted(self._headers)) + "\n"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]

    def env_overlay(self) -> dict[str, str]:
        """Env vars to pass to subprocesses so bash callers can pick them up."""
        if self.is_empty():
            return {}
        return {
            ENV_HEADERS: "\n".join(self._headers),
            ENV_SESSION_ID: self.session_id(),
        }

    def export_to_env(self, env: dict[str, str] | None = None) -> None:
        """Mutate the given env dict (or os.environ) in place."""
        target = env if env is not None else os.environ
        overlay = self.env_overlay()
        if overlay:
            target.update(overlay)
        else:
            # Clear any stale values so a downstream tool doesn't pick up
            # an old session by accident.
            target.pop(ENV_HEADERS, None)
            target.pop(ENV_SESSION_ID, None)

    def redacted(self) -> dict[str, str]:
        """Human-safe view: shows header names + masked values."""
        out: dict[str, str] = {}
        for h in self._headers:
            name, _, value = h.partition(":")
            value = value.strip()
            if len(value) <= 6:
                masked = "***"
            else:
                masked = value[:3] + "***" + value[-2:]
            out[name.strip()] = masked
        return out

    def describe(self) -> str:
        """One-line description for logs. Never includes raw values."""
        if self.is_empty():
            return "auth: none (anonymous)"
        names = sorted({h.partition(":")[0].strip() for h in self._headers})
        return f"auth: session={self.session_id()} headers=[{', '.join(names)}]"

    # ── Safety ────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"AuthSession(session_id={self.session_id()!r}, n_headers={len(self._headers)})"

    def __str__(self) -> str:
        return self.describe()


def add_cli_args(parser) -> None:
    """Attach auth flags to an argparse parser. Centralized for reuse."""
    grp = parser.add_argument_group("auth (optional — opts you into auth-aware hunting)")
    grp.add_argument(
        "--auth-header", action="append", default=[], metavar="'Name: value'",
        help="Add an HTTP header to every outbound request (repeatable).",
    )
    grp.add_argument("--cookie", default=None, help="Shorthand for --auth-header 'Cookie: ...'.")
    grp.add_argument("--bearer", default=None, help="Shorthand for --auth-header 'Authorization: Bearer ...'.")
    grp.add_argument("--api-key", dest="api_key", default=None, help="Shorthand for --auth-header 'X-API-Key: ...'.")
    grp.add_argument(
        "--auth-file", default=None, metavar="PATH",
        help="Load headers from a JSON or .env file (gitignored — put in .private/).",
    )
    grp.add_argument(
        "--auth-from-env", action="store_true",
        help=f"Pick up auth from env vars ({ENV_HEADER_IN}, {ENV_COOKIE}, "
             f"{ENV_BEARER}, {ENV_API_KEY}). Implied if any of these are set.",
    )


def session_from_args(args, env: dict[str, str] | None = None) -> AuthSession:
    """Build an AuthSession from argparse Namespace produced by add_cli_args()."""
    e = env if env is not None else os.environ
    # If any auth env var is set, treat it as opt-in even without --auth-from-env.
    env_arg = e if (
        getattr(args, "auth_from_env", False)
        or any(e.get(k) for k in (ENV_HEADER_IN, ENV_COOKIE, ENV_BEARER, ENV_API_KEY))
    ) else {}
    return AuthSession.from_sources(
        env=env_arg,
        file=getattr(args, "auth_file", None),
        headers=getattr(args, "auth_header", []) or [],
        cookie=getattr(args, "cookie", None),
        bearer=getattr(args, "bearer", None),
        api_key=getattr(args, "api_key", None),
    )

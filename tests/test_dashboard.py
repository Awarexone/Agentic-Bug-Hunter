"""Tests for tools/dashboard.py — ANSI helpers, Dashboard, TailParser."""

import os
import re
import time
from unittest.mock import patch

import pytest

from tools.dashboard import (
    _visible_len,
    _pad_to,
    _render_bigtext,
    _strip_ansi,
    _summarize_done,
    Dashboard,
    Phase,
    TailParser,
    RECON_PHASES,
    RECON_PHASE_BY_NUM,
    SCAN_PHASES,
    SCAN_CHECK_BY_NUM,
    PHASE_RE,
    CHECK_RE,
    DONE_RE,
    CSI,
    GREEN,
    RESET,
)


class TestVisibleLen:
    def test_plain_text(self):
        assert _visible_len("hello") == 5

    def test_with_ansi(self):
        assert _visible_len(f"{GREEN}hello{RESET}") == 5

    def test_empty(self):
        assert _visible_len("") == 0

    def test_only_ansi(self):
        assert _visible_len(f"{GREEN}{RESET}") == 0

    def test_multiple_codes(self):
        text = f"{CSI}1m{CSI}32mBOLD GREEN{CSI}0m"
        assert _visible_len(text) == 10


class TestPadTo:
    def test_shorter_than_width(self):
        result = _pad_to("hi", 10)
        assert len(result) == 10
        assert result == "hi        "

    def test_exact_width(self):
        result = _pad_to("hello", 5)
        assert result == "hello"

    def test_longer_than_width_truncates(self):
        result = _pad_to("hello world", 5)
        assert len(result) == 5
        assert result == "hello"

    def test_with_ansi_pads_correctly(self):
        text = f"{GREEN}hi{RESET}"
        result = _pad_to(text, 10)
        # Visible length should be 10, but actual length includes ANSI codes
        assert _visible_len(result) == 10


class TestRenderBigtext:
    def test_known_letters(self):
        rows = _render_bigtext("BH")
        assert len(rows) == 6
        # Each row should contain block chars
        for row in rows:
            assert len(row) > 0

    def test_unknown_char_uses_space(self):
        rows = _render_bigtext("X")  # X not in _LETTERS
        # Should use the space glyph
        for row in rows:
            assert row.strip() == ""

    def test_empty_string(self):
        rows = _render_bigtext("")
        assert rows == ["", "", "", "", "", ""]


class TestStripAnsi:
    def test_removes_ansi(self):
        assert _strip_ansi(f"{GREEN}hello{RESET}") == "hello"

    def test_plain_unchanged(self):
        assert _strip_ansi("plain text") == "plain text"


class TestSummarizeDone:
    def test_short_text(self):
        assert _summarize_done("1019 subs") == "1019 subs"

    def test_truncates_long(self):
        long = "a" * 100
        assert len(_summarize_done(long)) <= 30

    def test_strips_whitespace(self):
        assert _summarize_done("  result  ") == "result"


class TestPhase:
    def test_defaults(self):
        p = Phase(key="test", label="Test Phase")
        assert p.state == "pending"
        assert p.note == ""
        assert p.elapsed == ""
        assert p.started_at == 0.0


class TestDashboard:
    def _make_dashboard(self, phases=None):
        if phases is None:
            phases = [("p1", "Phase 1"), ("p2", "Phase 2")]
        return Dashboard(title="TEST", target="example.com", phases=phases)

    def test_post_init_creates_phases(self):
        db = self._make_dashboard()
        assert "p1" in db._phases
        assert "p2" in db._phases
        assert db._phase_order == ["p1", "p2"]

    def test_phase_start(self):
        db = self._make_dashboard()
        db._is_tty = False
        db.phase_start("p1", note="starting")
        assert db._phases["p1"].state == "running"
        assert db._phases["p1"].note == "starting"
        assert db._phases["p1"].started_at > 0

    def test_phase_update(self):
        db = self._make_dashboard()
        db._is_tty = False
        db.phase_start("p1")
        db.phase_update("p1", note="50% done")
        assert db._phases["p1"].note == "50% done"

    def test_phase_update_auto_starts(self):
        db = self._make_dashboard()
        db._is_tty = False
        db.phase_update("p1", note="auto start")
        assert db._phases["p1"].state == "running"

    def test_phase_done(self):
        db = self._make_dashboard()
        db._is_tty = False
        db.phase_start("p1")
        db.phase_done("p1", note="1000 results", elapsed="5s")
        assert db._phases["p1"].state == "done"
        assert db._phases["p1"].note == "1000 results"
        assert db._phases["p1"].elapsed == "5s"

    def test_phase_done_auto_elapsed(self):
        db = self._make_dashboard()
        db._is_tty = False
        db.phase_start("p1")
        time.sleep(0.01)
        db.phase_done("p1")
        assert db._phases["p1"].elapsed != ""

    def test_phase_skip(self):
        db = self._make_dashboard()
        db._is_tty = False
        db.phase_skip("p1", reason="not needed")
        assert db._phases["p1"].state == "skipped"
        assert db._phases["p1"].note == "not needed"

    def test_phase_fail(self):
        db = self._make_dashboard()
        db._is_tty = False
        db.phase_start("p1")
        db.phase_fail("p1", reason="timeout")
        assert db._phases["p1"].state == "failed"
        assert db._failed is True

    def test_latest(self):
        db = self._make_dashboard()
        db.latest("  new log line  ")
        assert db._latest == "new log line"

    def test_unknown_phase_key_noop(self):
        db = self._make_dashboard()
        db._is_tty = False
        # Should not raise
        db.phase_start("nonexistent")
        db.phase_update("nonexistent", note="x")
        db.phase_done("nonexistent")

    def test_fmt_elapsed_seconds(self):
        assert Dashboard._fmt_elapsed(5.0) == "5s"
        assert Dashboard._fmt_elapsed(59.0) == "59s"

    def test_fmt_elapsed_minutes(self):
        assert Dashboard._fmt_elapsed(65.0) == "01:05"
        assert Dashboard._fmt_elapsed(600.0) == "10:00"

    def test_fmt_elapsed_hours(self):
        assert Dashboard._fmt_elapsed(3661.0) == "01:01:01"

    @patch.dict(os.environ, {"TERM": "dumb"})
    def test_non_tty_start_stop(self, capsys):
        db = self._make_dashboard()
        db._is_tty = False
        db.start()
        db.stop(ok=True)
        captured = capsys.readouterr()
        assert "TEST" in captured.out
        assert "DONE" in captured.out

    @patch.dict(os.environ, {"TERM": "dumb"})
    def test_non_tty_stop_failed(self, capsys):
        db = self._make_dashboard()
        db._is_tty = False
        db._start_ts = time.time()
        db.stop(ok=False)
        captured = capsys.readouterr()
        assert "FAILED" in captured.out


class TestTailParser:
    def _make_parser(self, phase_map=None):
        if phase_map is None:
            phase_map = RECON_PHASE_BY_NUM
        db = Dashboard(title="RECON", target="test.com", phases=RECON_PHASES)
        db._is_tty = False
        return TailParser(db, phase_map), db

    def test_phase_detection(self):
        parser, db = self._make_parser()
        parser.feed("[*] Phase 1: Subdomain enumeration")
        assert db._phases["subdomain_enum"].state == "running"

    def test_phase_transition(self):
        parser, db = self._make_parser()
        parser.feed("[*] Phase 1: Subdomain enumeration")
        parser.feed("[*] Phase 2: Live host probe")
        assert db._phases["subdomain_enum"].state == "done"
        assert db._phases["live_probe"].state == "running"

    def test_done_marker_updates_note(self):
        parser, db = self._make_parser()
        parser.feed("[*] Phase 1: Subdomain enumeration")
        parser.feed("[+] subfinder: 1019 subdomains")
        # The [+] doesn't match DONE_RE, but let's test with actual done marker
        parser.feed("[\u2713] subfinder: 1019 subdomains")
        assert "1019" in db._phases["subdomain_enum"].note

    def test_ignores_empty_lines(self):
        parser, db = self._make_parser()
        parser.feed("")
        parser.feed("   ")
        # No crash

    def test_scan_phase_map(self):
        phase_map = SCAN_CHECK_BY_NUM
        db = Dashboard(title="SCAN", target="test.com", phases=SCAN_PHASES)
        db._is_tty = False
        parser = TailParser(db, phase_map)
        parser.feed("[*] Check 1: XSS testing")
        assert db._phases["xss"].state == "running"


class TestRegexPatterns:
    def test_phase_re_matches(self):
        m = PHASE_RE.search("[*] Phase 3: Port scan")
        assert m
        assert m.group(1) == "3"

    def test_phase_re_decimal(self):
        m = PHASE_RE.search("[*] Phase 6.5: Config exposure")
        assert m
        assert m.group(1) == "6.5"

    def test_check_re_matches(self):
        m = CHECK_RE.search("[*] Check 2: SQL injection")
        assert m
        assert m.group(1) == "2"

    def test_done_re_matches(self):
        m = DONE_RE.search("[\u2713] Live hosts: 318")
        assert m
        assert m.group(1) == "Live hosts: 318"

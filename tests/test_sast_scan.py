"""Tests for tools/sast_scan.py — pure semgrep cmd build + result normalization."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.sast_scan import (
    build_cmd,
    parse_semgrep,
    summarize,
)


def _result(check_id, severity, path="app.js", line=1, message="msg"):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "extra": {"severity": severity, "message": message},
    }


def test_build_cmd_uses_json_and_each_config():
    cmd = build_cmd("app/", ["p/xss", "p/secrets"])
    assert "--json" in cmd and cmd[-1] == "app/"
    assert cmd.count("--config") == 2


def test_parse_maps_error_to_high():
    fs = parse_semgrep({"results": [_result("rules.generic-xss", "ERROR")]})
    assert fs[0].severity == "HIGH"
    assert fs[0].confidence == "POSSIBLE"


def test_parse_bumps_high_signal_warning_to_high():
    fs = parse_semgrep({"results": [_result("py.sql-injection.foo", "WARNING")]})
    assert fs[0].severity == "HIGH"


def test_parse_plain_warning_stays_medium():
    fs = parse_semgrep({"results": [_result("style.no-var", "WARNING")]})
    assert fs[0].severity == "MEDIUM"


def test_parse_info_is_informational():
    fs = parse_semgrep({"results": [_result("audit.note", "INFO")]})
    assert fs[0].severity == "INFORMATIONAL"


def test_parse_dedupes_same_rule_path_line():
    obj = {"results": [_result("r", "ERROR"), _result("r", "ERROR")]}
    assert len(parse_semgrep(obj)) == 1


def test_summarize_counts_by_severity():
    fs = parse_semgrep({"results": [
        _result("a.sql-injection", "WARNING"),
        _result("b.xss", "ERROR"),
        _result("c.note", "INFO", line=5),
    ]})
    s = summarize(fs)
    assert s["total"] == 3
    assert s["high"] == 2
    assert s["informational"] == 1

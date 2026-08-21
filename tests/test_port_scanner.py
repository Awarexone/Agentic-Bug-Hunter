"""Tests for tools/port_scanner.py — pure parsing + service classification."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.port_scanner import (
    build_naabu_cmd,
    classify,
    parse_naabu,
    summarize,
)


def test_classify_flags_known_non_web_service():
    r = classify("target.com", 6379)
    assert r.service == "redis"
    assert r.is_interesting is True
    assert r.is_web is False


def test_classify_web_port_is_not_interesting():
    r = classify("target.com", 443)
    assert r.is_web is True
    assert r.is_interesting is False


def test_classify_unknown_port_has_no_note():
    r = classify("target.com", 49152)
    assert r.service == ""
    assert r.is_interesting is False


def test_parse_naabu_plain_lines():
    text = "target.com:22\ntarget.com:443\n10.0.0.1:6379\n"
    results = parse_naabu(text)
    assert len(results) == 3
    assert ("target.com", 22) in [(r.host, r.port) for r in results]


def test_parse_naabu_dedupes_and_ignores_junk():
    text = "target.com:22\n\n# comment\ntarget.com:22\nnotaport\n"
    results = parse_naabu(text)
    assert len(results) == 1


def test_parse_naabu_tolerates_json_lines():
    text = '{"host":"target.com","port":27017}\n'
    results = parse_naabu(text)
    assert results and results[0].port == 27017
    assert results[0].service == "mongodb"


def test_summarize_pulls_interesting_to_top():
    results = parse_naabu("t:80\nt:443\nt:6379\nt:3306\n")
    s = summarize(results)
    assert s["total_open"] == 4
    assert s["web"] == 2
    assert s["interesting"] == 2
    assert {f["port"] for f in s["flagged"]} == {6379, 3306}


def test_build_naabu_cmd_top_ports_vs_explicit():
    assert "-top-ports" in build_naabu_cmd("t", None, 100, False)
    cmd = build_naabu_cmd("t", "22,80", 100, False)
    assert "-port" in cmd and "22,80" in cmd


def test_build_naabu_cmd_list_mode():
    cmd = build_naabu_cmd("hosts.txt", None, 100, True)
    assert "-list" in cmd and "hosts.txt" in cmd

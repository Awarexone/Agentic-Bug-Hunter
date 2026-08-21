"""Tests for tools/visual_triage.py — pure tool-selection, cmd build, gallery."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.visual_triage import (
    Shot,
    build_cmd,
    pick_tool,
    render_html,
)


def test_pick_tool_prefers_priority_order():
    assert pick_tool(None, {"httpx", "aquatone"}) == "aquatone"
    assert pick_tool(None, {"httpx"}) == "httpx"
    assert pick_tool(None, set()) is None


def test_pick_tool_honors_explicit_preference():
    assert pick_tool("httpx", {"httpx", "eyewitness"}) == "httpx"


def test_pick_tool_missing_preference_returns_none():
    assert pick_tool("eyewitness", {"httpx"}) is None


def test_build_cmd_per_tool():
    assert build_cmd("eyewitness", "urls.txt", "out")[:1] == ["eyewitness"]
    assert "-out" in build_cmd("aquatone", "urls.txt", "out")
    hx = build_cmd("httpx", "urls.txt", "out")
    assert "-screenshot" in hx and "urls.txt" in hx


def test_build_cmd_unknown_tool_raises():
    try:
        build_cmd("nope", "urls.txt", "out")
    except ValueError:
        return
    assert False, "expected ValueError"


def test_render_html_is_self_contained():
    html = render_html([Shot("https://a.com", "a.png"), Shot("https://b.com", "b.png")])
    assert "http" not in html.split("<style>")[1].split("</style>")[0]  # no remote assets in CSS
    assert "a.png" in html and "https://b.com" in html
    assert html.startswith("<!doctype html>")
